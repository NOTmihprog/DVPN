//! Local control API: msgpack maps over a UDP or unix datagram socket (`doc/api.md`).
//!
//! Client -> node: `{"type": "init", "name": .., "version": 4}` first (answered with
//! `{"type": "init", "version", "key", "name", ..}`), then `get` / `set` / `del` / `route`
//! requests carrying an `id` (answered with `{"type": "res", "id": .., "res": ..}`, or
//! `{"type": "res", "id": .., "err": code, "msg": text}` when they fail), `net` packets
//! `{"rou": route, "key": .., "pack": bin}` and `ping` / `pong` / `close`. Nodes are named by
//! their key (base64url), a unique prefix of a known one or a member name, in the `key` field.
//! Node -> client: responses, `event`s, `net` packets for registered routes, `ping`.
//!
//! An `init` without a `version` (a v2/v3 client) or with one this node does not serve is
//! answered with `{"type": "error", "err": "version_unsupported", "min", "max"}`.

use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rmpv::Value;
use serde_json::Value as Json;
use tokio::net::UdpSocket;
#[cfg(unix)]
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

use crate::crypto::encode_b64;
use crate::identity::NodeId;
use crate::logger::node;
use crate::node::{ApiPacket, Node};
use crate::proto::{KIND_API_MAX, KIND_API_MIN, MAX_DATAGRAM};
use crate::storage::{Event, PeerRecord, PeerUpdate, ResolveError};

const PING_INTERVAL: Duration = Duration::from_secs(15);
const CONN_TIMEOUT: Duration = Duration::from_secs(45);

/// The API protocol version this node speaks, and the oldest one it still serves.
pub const API_VERSION: u64 = 4;
pub const API_VERSION_MIN: u64 = 4;

/// A failed request: a stable code for programs, a message for people.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub msg: String,
}

impl ApiError {
    fn new(code: &'static str, msg: impl Into<String>) -> Self {
        ApiError { code, msg: msg.into() }
    }
}

type Reply = Result<Value, ApiError>;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ApiAddr {
    Inet(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl std::fmt::Display for ApiAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiAddr::Inet(a) => write!(f, "{a}"),
            #[cfg(unix)]
            ApiAddr::Unix(p) => write!(f, "{}", p.display()),
        }
    }
}

pub enum ApiSocket {
    Inet(UdpSocket),
    #[cfg(unix)]
    Unix(UnixDatagram, PathBuf),
}

impl ApiSocket {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        if let Ok(a) = addr.parse::<SocketAddr>() {
            return Ok(ApiSocket::Inet(UdpSocket::bind(a).await?));
        }
        #[cfg(unix)]
        {
            let path = PathBuf::from(addr);
            match path.parent() {
                Some(dir) if !dir.as_os_str().is_empty() && dir.is_dir() => {}
                _ => anyhow::bail!("socket path {addr}: directory does not exist"),
            }
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            Ok(ApiSocket::Unix(UnixDatagram::bind(&path)?, path))
        }
        #[cfg(not(unix))]
        anyhow::bail!("{addr} is not an ip:port address (unix sockets are unsupported on this platform)")
    }

    pub fn describe(&self) -> String {
        match self {
            ApiSocket::Inet(s) => s.local_addr().map_or_else(|e| e.to_string(), |a| a.to_string()),
            #[cfg(unix)]
            ApiSocket::Unix(_, p) => p.display().to_string(),
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Option<ApiAddr>)> {
        match self {
            ApiSocket::Inet(s) => s.recv_from(buf).await.map(|(n, a)| (n, Some(ApiAddr::Inet(a)))),
            #[cfg(unix)]
            ApiSocket::Unix(s, _) => {
                s.recv_from(buf).await.map(|(n, a)| (n, a.as_pathname().map(|p| ApiAddr::Unix(p.to_owned()))))
            }
        }
    }

    async fn send(&self, v: &Value, to: &ApiAddr) {
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, v).expect("write to vec");
        let r = match (self, to) {
            (ApiSocket::Inet(s), ApiAddr::Inet(a)) => s.send_to(&data, a).await,
            #[cfg(unix)]
            (ApiSocket::Unix(s, _), ApiAddr::Unix(p)) => s.send_to(&data, p).await,
            #[cfg(unix)]
            _ => return,
        };
        if let Err(e) = r {
            log::debug!("API | send to {to} error: {e}");
        }
    }
}

impl Drop for ApiSocket {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let ApiSocket::Unix(_, p) = self {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---- msgpack helpers ----

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v).filter(|v| !v.is_nil())
}

fn opt_str(s: Option<impl Into<String>>) -> Value {
    s.map_or(Value::Nil, |s| Value::from(s.into()))
}

fn addr_value(a: Option<SocketAddr>) -> Value {
    a.map_or(Value::Nil, |a| Value::Array(vec![a.ip().to_string().into(), a.port().into()]))
}

fn parse_addr(v: &Value) -> Option<SocketAddr> {
    let a = v.as_array()?;
    let ip = a.first()?.as_str()?.parse().ok()?;
    let port = u16::try_from(a.get(1)?.as_u64()?).ok()?;
    Some(SocketAddr::new(ip, port))
}

fn json_to_mp(j: &Json) -> Value {
    match j {
        Json::Null => Value::Nil,
        Json::Bool(b) => Value::from(*b),
        Json::Number(n) => n
            .as_i64()
            .map(Value::from)
            .or_else(|| n.as_u64().map(Value::from))
            .unwrap_or_else(|| Value::from(n.as_f64().unwrap_or(0.0))),
        Json::String(s) => Value::from(s.as_str()),
        Json::Array(a) => Value::Array(a.iter().map(json_to_mp).collect()),
        Json::Object(o) => Value::Map(o.iter().map(|(k, v)| (Value::from(k.as_str()), json_to_mp(v))).collect()),
    }
}

fn mp_to_json(v: &Value) -> Json {
    match v {
        Value::Nil => Json::Null,
        Value::Boolean(b) => Json::Bool(*b),
        Value::Integer(i) => i.as_i64().map(Json::from).or_else(|| i.as_u64().map(Json::from)).unwrap_or(Json::Null),
        Value::F32(f) => Json::from(*f as f64),
        Value::F64(f) => Json::from(*f),
        Value::String(s) => Json::from(s.as_str().unwrap_or_default()),
        Value::Binary(b) => Json::from(encode_b64(b)),
        Value::Array(a) => Json::Array(a.iter().map(mp_to_json).collect()),
        Value::Map(m) => Json::Object(
            m.iter().map(|(k, v)| (k.as_str().map_or_else(|| k.to_string(), str::to_owned), mp_to_json(v))).collect(),
        ),
        Value::Ext(_, b) => Json::from(encode_b64(b)),
    }
}

fn sub_args_value(rec: &PeerRecord) -> Value {
    rec.sub_args.as_ref().map_or(Value::Nil, |m| json_to_mp(&Json::Object(m.clone())))
}

fn event_value(e: &Event) -> Value {
    match e {
        Event::Peer { action, record, endpoint } => map(vec![
            ("action", action.as_str().into()),
            ("key", record.peer_id.to_string().into()),
            ("name", opt_str(record.name.clone())),
            ("addr", opt_str(record.addr.map(|a| a.to_string()))),
            ("endpoint", addr_value(*endpoint)),
            ("sub_args", sub_args_value(record)),
        ]),
        Event::Server { addr, connected } => {
            map(vec![("server", addr_value(Some(*addr))), ("status", (*connected).into())])
        }
        Event::Ping { peer_id, ms } => map(vec![("key", peer_id.to_string().into()), ("ping", (*ms).into())]),
    }
}

// ---- state ----

struct Conn {
    last_ping: Option<Instant>,
    pings_sent: u32,
    last_pong: Option<Instant>,
    /// The API version from `init`.
    version: u64,
}

#[derive(Default)]
struct State {
    conns: HashMap<ApiAddr, Conn>,
    route_owner: HashMap<u8, ApiAddr>,
}

impl State {
    fn close(&mut self, addr: &ApiAddr) {
        self.conns.remove(addr);
        self.route_owner.retain(|_, a| a != addr);
        log::debug!("API | conn {addr} closed");
    }

    /// Closes connections that stopped answering pings; returns (closed, to ping).
    fn ping_round(&mut self) -> (Vec<ApiAddr>, Vec<ApiAddr>) {
        let dead: Vec<ApiAddr> = self
            .conns
            .iter()
            .filter(|(_, c)| c.pings_sent > 3 && c.last_pong.is_none_or(|t| t.elapsed() > CONN_TIMEOUT))
            .map(|(a, _)| a.clone())
            .collect();
        for a in &dead {
            self.close(a);
        }
        for c in self.conns.values_mut() {
            c.last_ping = Some(Instant::now());
            c.pings_sent += 1;
        }
        (dead, self.conns.keys().cloned().collect())
    }

    fn routes_of(&self, addr: &ApiAddr) -> Value {
        let mut r: Vec<u8> = self.route_owner.iter().filter(|(_, a)| *a == addr).map(|(r, _)| *r).collect();
        r.sort();
        Value::Array(r.into_iter().map(Value::from).collect())
    }
}

pub struct Api {
    node: Arc<Node>,
    sock: ApiSocket,
    state: Mutex<State>,
}

/// The answer to request `id`: `res`, or `err` (code) and `msg` when it failed.
fn res(id: Option<&Value>, r: Reply) -> Value {
    let id = id.cloned().unwrap_or(Value::Nil);
    match r {
        Ok(v) => map(vec![("type", "res".into()), ("id", id), ("res", v)]),
        Err(e) => map(vec![("type", "res".into()), ("id", id), ("err", e.code.into()), ("msg", e.msg.into())]),
    }
}

/// A failure not tied to a request (`{"type": "error"}`), with extra fields.
fn error_msg(code: &str, msg: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut v = vec![("type", Value::from("error")), ("err", code.into()), ("msg", msg.into())];
    v.extend(extra);
    map(v)
}

/// A field as sent, nil included (`field` takes nil for missing).
fn raw_field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v)
}

/// A list of strings: None if not given, empty for nil; trimmed, empty ones dropped.
fn str_list(p: &Value, key: &str) -> Result<Option<Vec<String>>, ApiError> {
    match raw_field(p, key) {
        None => Ok(None),
        Some(Value::Nil) => Ok(Some(Vec::new())),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(|s| s.trim().to_owned()).ok_or_else(|| bad_param(key, "expected strings")))
            .filter(|r| r.as_ref().map_or(true, |s| !s.is_empty()))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(bad_param(key, "expected a list of strings")),
    }
}

/// `min..=max` as `[min, max]`.
fn range<T: Copy + Into<Value>>(r: &std::ops::RangeInclusive<T>) -> Value {
    Value::Array(vec![(*r.start()).into(), (*r.end()).into()])
}

fn bad_param(name: &str, what: &str) -> ApiError {
    ApiError::new("bad_param", format!("{name}: {what}"))
}

impl Api {
    pub fn start(node: Arc<Node>, sock: ApiSocket) -> Arc<Self> {
        log::info!("API | Listen address: {}", sock.describe());
        let api = Arc::new(Api { node: node.clone(), sock, state: Mutex::new(State::default()) });
        let (tx, rx) = mpsc::channel(1024);
        node.set_api_sink(tx);
        tokio::spawn(api.clone().recv_loop());
        tokio::spawn(api.clone().ping_loop());
        tokio::spawn(api.clone().event_loop());
        tokio::spawn(api.clone().net_loop(rx));
        log::info!("API | Full - started");
        api
    }

    async fn broadcast(&self, v: &Value) {
        let conns: Vec<ApiAddr> = self.state.lock().conns.keys().cloned().collect();
        for c in conns {
            self.sock.send(v, &c).await;
        }
    }

    async fn event_loop(self: Arc<Self>) {
        let mut rx = self.node.storage.subscribe();
        loop {
            match rx.recv().await {
                Ok(e) => {
                    let v = map(vec![("type", "event".into()), ("event", event_value(&e))]);
                    self.broadcast(&v).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => log::warn!("API | {n} events dropped"),
                Err(_) => return,
            }
        }
    }

    async fn net_loop(self: Arc<Self>, mut rx: mpsc::Receiver<ApiPacket>) {
        while let Some((route, peer_id, data)) = rx.recv().await {
            let Some(owner) = self.state.lock().route_owner.get(&route).cloned() else {
                log::debug!("API | packet from {} to unregistered route {route} dropped", node(peer_id));
                continue;
            };
            let v = map(vec![
                ("type", "net".into()),
                ("rou", route.into()),
                ("pack", Value::Binary(data)),
                ("key", peer_id.to_string().into()),
            ]);
            self.sock.send(&v, &owner).await;
        }
    }

    async fn ping_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(PING_INTERVAL);
        loop {
            tick.tick().await;
            let (dead, targets) = self.state.lock().ping_round();
            for a in &dead {
                self.sock.send(&map(vec![("type", "close".into())]), a).await;
            }
            let ping = map(vec![("type", "ping".into())]);
            for a in targets {
                self.sock.send(&ping, &a).await;
            }
        }
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, from) = match self.sock.recv(&mut buf).await {
                Ok((n, Some(a))) => (n, a),
                Ok((_, None)) => continue,
                Err(e) => {
                    log::debug!("API | recv error: {e}");
                    continue;
                }
            };
            let Ok(packet) = rmpv::decode::read_value(&mut &buf[..n]) else {
                log::info!("API | msgpack decode error from {from}");
                continue;
            };
            // a ping waits for the answer: in its own task, so the API stays responsive
            let is_ping = field(&packet, "type").and_then(Value::as_str) == Some("get")
                && field(&packet, "req").and_then(Value::as_str) == Some("ping")
                && self.state.lock().conns.contains_key(&from);
            if is_ping {
                tokio::spawn(self.clone().ping_req(packet, from));
                continue;
            }
            if let Some(reply) = self.handle(&packet, &from).await {
                self.sock.send(&reply, &from).await;
            }
        }
    }

    /// `get ping`: the round trip to a member over our session with it, or nil without answer.
    async fn ping_req(self: Arc<Self>, p: Value, from: ApiAddr) {
        let result = match self.peer_arg(&p) {
            Ok(peer) => Ok(match self.node.ping(peer).await {
                Some((ms, mesh)) => {
                    map(vec![("rtt_ms", ms.into()), ("via", if mesh { "relays" } else { "direct" }.into())])
                }
                None => Value::Nil,
            }),
            Err(e) => Err(e),
        };
        self.sock.send(&res(field(&p, "id"), result), &from).await;
    }

    /// `init`: registers the client (again, if it was), answers with the node's identity, or
    /// refuses an API version this node does not speak.
    fn init(&self, p: &Value, from: &ApiAddr) -> Value {
        let name = field(p, "name").and_then(Value::as_str).unwrap_or_default();
        let version = match field(p, "version").map(|v| (v, v.as_u64())) {
            Some((_, Some(v))) if (API_VERSION_MIN..=API_VERSION).contains(&v) => v,
            asked => {
                let asked = asked.map_or_else(|| "none (a v3 client?)".to_owned(), |(v, _)| v.to_string());
                log::info!("API | conn {from} ({name}) asks for API version {asked}: refused");
                self.state.lock().close(from);
                let msg =
                    format!("API version {asked} is not served: this node speaks {API_VERSION_MIN}..{API_VERSION}");
                return error_msg(
                    "version_unsupported",
                    &msg,
                    vec![("min", API_VERSION_MIN.into()), ("max", API_VERSION.into())],
                );
            }
        };
        self.state
            .lock()
            .conns
            .entry(from.clone())
            .or_insert(Conn { last_ping: None, pings_sent: 0, last_pong: None, version })
            .version = version;
        log::debug!("API | conn {from} init, name {name:?}, version {version}");
        let n = &self.node;
        let cert = n.own_cert();
        map(vec![
            ("type", "init".into()),
            ("version", API_VERSION.into()),
            ("min_version", API_VERSION_MIN.into()),
            ("key", n.storage.self_id().to_string().into()),
            ("name", cert.body.name.clone().into()),
            ("group", n.group_id().to_string().into()),
            ("group_name", n.group_name().into()),
            ("admin", n.is_admin().into()),
            ("node_version", env!("CARGO_PKG_VERSION").into()),
        ])
    }

    async fn handle(&self, p: &Value, from: &ApiAddr) -> Option<Value> {
        let kind = field(p, "type")?.as_str()?;
        if kind == "init" {
            return Some(self.init(p, from));
        }
        if kind == "ping" {
            return Some(map(vec![("type", "pong".into())]));
        }
        if !self.state.lock().conns.contains_key(from) {
            log::debug!("API | receive {kind} from unknown conn {from}");
            return Some(map(vec![("type", "close".into())]));
        }
        let id = field(p, "id");
        match kind {
            "pong" => {
                let mut st = self.state.lock();
                if let Some(c) = st.conns.get_mut(from) {
                    c.last_pong = Some(Instant::now());
                    if let Some(t) = c.last_ping {
                        log::debug!("API | receive pong from conn {from} ping: {:.3}", t.elapsed().as_secs_f64() * 1e3);
                    }
                }
                None
            }
            "net" => {
                self.handle_net(p, from).await;
                None
            }
            "get" => Some(res(id, self.handle_get(p))),
            "set" => Some(res(id, self.handle_set(p))),
            "del" => Some(res(id, self.handle_del(p))),
            "route" => Some(res(id, self.handle_route(p, from))),
            "close" => {
                self.state.lock().close(from);
                Some(map(vec![("type", "close".into())]))
            }
            _ => Some(error_msg("unknown_type", &format!("unknown message type {kind:?}"), Vec::new())),
        }
    }

    async fn handle_net(&self, p: &Value, from: &ApiAddr) {
        let route = field(p, "rou").and_then(Value::as_u64).and_then(|r| u8::try_from(r).ok());
        let data = field(p, "pack").and_then(|v| v.as_slice());
        let peer = self.peer_arg(p).ok();
        let (Some(route), Some(data), Some(peer)) = (route, data, peer) else { return };
        if self.state.lock().route_owner.get(&route) != Some(from) {
            log::debug!("API | conn {from} drop packet to {}: route {route} not owned", node(peer));
            return;
        }
        if !self.node.send_routed(&peer, route, data).await {
            log::debug!("API | packet to {} destination addr not found", node(peer));
        }
    }

    /// `get group`: the group as this node sees it, without secrets.
    fn group_info(&self) -> Value {
        let n = &self.node;
        let (g, me) = (n.group_id(), n.storage.self_id());
        let now_ms = crate::state::now_ms();
        let (epoch, prev_until) = n.psk_epoch();
        // an announced epoch we have not switched to yet
        let next = n.group_store().epoch(&g).filter(|(e, _)| *e > epoch).map(|(e, at)| {
            let has_key = n.is_admin() || n.group_store().has_epoch_key(&g, &me, e);
            map(vec![
                ("epoch", e.into()),
                ("at", (at / 1000).into()),
                ("started", (now_ms >= at).into()),
                ("has_key", has_key.into()),
            ])
        });
        let cert = n.own_cert();
        let p = n.links.profile();
        let obfs = map(vec![
            ("junk_count", range(&p.junk_count)),
            ("junk_size", range(&p.junk_size)),
            ("signatures", p.signatures.len().into()),
            ("init_pad", range(&p.init_pad)),
            ("resp_pad", range(&p.resp_pad)),
            ("data_pad", range(&p.data_pad)),
        ]);
        let servers = n.clients.iter().map(|c| {
            map(vec![
                ("addr", c.addr().to_string().into()),
                ("key", encode_b64(&c.key.to_bytes()).into()),
                ("connected", c.is_connected().into()),
            ])
        });
        let statics = n.statics().iter().map(|s| {
            map(vec![
                ("key", s.key.to_string().into()),
                ("name", opt_str(n.storage.name(&s.key))),
                ("endpoints", Value::Array(s.endpoints.iter().map(|e| e.as_str().into()).collect())),
                ("direct", n.direct(&s.key).into()),
            ])
        });
        map(vec![
            ("id", g.to_string().into()),
            ("name", n.group_name().into()),
            ("admin", n.is_admin().into()),
            ("epoch", epoch.into()),
            ("prev_epoch_until", prev_until.map_or(Value::Nil, |ms| (ms / 1000).into())),
            ("next_epoch", next.unwrap_or(Value::Nil)),
            (
                "cert",
                map(vec![
                    ("not_after", cert.body.not_after.into()),
                    ("days", (cert.body.not_after.saturating_sub(crate::clock::now_unix()) / 86400).into()),
                    ("invite", cert.grant.is_some().into()),
                ]),
            ),
            ("obfs", obfs),
            ("servers", Value::Array(servers.collect())),
            ("statics", Value::Array(statics.collect())),
        ])
    }

    /// `get members`: everybody in the group's records and handshakes, offline and revoked ones
    /// included, by name.
    fn members(&self) -> Value {
        let n = &self.node;
        let me = n.storage.self_id();
        let revoked = n.group_store().revoked(&n.group_id());
        let now = crate::clock::now_unix();
        let mut certs = n.member_certs();
        certs.sort_by_cached_key(|c| (c.body.name.clone(), c.body.node.to_string()));
        let mut out: Vec<Value> = certs
            .iter()
            .map(|c| {
                let (b, id) = (&c.body, c.body.node);
                let (hosts, nets): (Vec<&ipnet::IpNet>, Vec<&ipnet::IpNet>) =
                    b.prefixes.iter().partition(|p| p.prefix_len() == p.max_prefix_len());
                let roles = [
                    (crate::group::Roles::ADMIN, "admin"),
                    (crate::group::Roles::RELAY, "relay"),
                    (crate::group::Roles::EXIT_V4, "exit_v4"),
                    (crate::group::Roles::EXIT_V6, "exit_v6"),
                ]
                .into_iter()
                .filter(|(bit, _)| b.roles.has(*bit))
                .map(|(_, name)| Value::from(name));
                let gone = revoked.contains(&id);
                map(vec![
                    ("key", id.to_string().into()),
                    ("name", b.name.clone().into()),
                    ("addrs", Value::Array(hosts.iter().map(|p| p.addr().to_string().into()).collect())),
                    ("routes", Value::Array(nets.iter().map(|p| p.to_string().into()).collect())),
                    ("roles", Value::Array(roles.collect())),
                    ("not_after", b.not_after.into()),
                    ("days", (b.not_after.saturating_sub(now) / 86400).into()),
                    ("expired", (b.not_after < now).into()),
                    ("invite", c.grant.is_some().into()),
                    ("revoked", gone.into()),
                    ("self", (id == me).into()),
                    ("online", (id == me || (!gone && n.reachable(&id))).into()),
                    ("direct", (id != me && !gone && n.direct(&id)).into()),
                ])
            })
            .collect();
        // revoked before we ever saw their certificate
        let mut unseen: Vec<NodeId> =
            revoked.into_iter().filter(|k| !certs.iter().any(|c| c.body.node == *k)).collect();
        unseen.sort_by_cached_key(|k| k.to_string());
        out.extend(unseen.into_iter().map(|k| {
            map(vec![
                ("key", k.to_string().into()),
                ("name", Value::Nil),
                ("addrs", Value::Array(Vec::new())),
                ("routes", Value::Array(Vec::new())),
                ("roles", Value::Array(Vec::new())),
                ("not_after", Value::Nil),
                ("days", Value::Nil),
                ("expired", false.into()),
                ("invite", false.into()),
                ("revoked", true.into()),
                ("self", false.into()),
                ("online", false.into()),
                ("direct", false.into()),
            ])
        }));
        Value::Array(out)
    }

    /// Member names by key, from every certificate we know of.
    fn names(&self) -> HashMap<NodeId, String> {
        self.node.member_certs().into_iter().map(|c| (c.body.node, c.body.name)).collect()
    }

    /// A gateway as `[exit]` names it: a node key, or the name of exactly one member.
    fn resolve_gateway(names: &HashMap<NodeId, String>, s: &str) -> Option<NodeId> {
        if let Ok(k) = s.parse() {
            return Some(k);
        }
        let mut hits = names.iter().filter(|(_, n)| n.as_str() == s).map(|(k, _)| *k);
        match (hits.next(), hits.next()) {
            (Some(k), None) => Some(k),
            _ => None,
        }
    }

    /// `get exit`: `[exit]`, the gateways in use and the kill switch.
    fn exit_info(&self) -> Value {
        let n = &self.node;
        let (e, gw4, gw6, (block4, block6)) = n.exit_detail();
        let names = self.names();
        let list = |l: &[String]| {
            Value::Array(
                l.iter()
                    .map(|g| {
                        let id = Self::resolve_gateway(&names, g);
                        map(vec![
                            ("gateway", g.as_str().into()),
                            ("key", opt_str(id.map(|i| i.to_string()))),
                            ("name", opt_str(id.and_then(|i| names.get(&i).cloned()))),
                            ("alive", id.is_some_and(|i| n.reachable(&i)).into()),
                        ])
                    })
                    .collect(),
            )
        };
        let active = |id: Option<NodeId>| {
            id.map_or(Value::Nil, |i| {
                map(vec![("key", i.to_string().into()), ("name", opt_str(names.get(&i).cloned()))])
            })
        };
        let strings = |v: Vec<String>| Value::Array(v.into_iter().map(Value::from).collect());
        map(vec![
            ("v4", list(&e.v4)),
            ("v6", list(&e.v6)),
            ("kill_switch", e.kill_switch().into()),
            ("dns", strings(e.dns.iter().map(|d| d.to_string()).collect())),
            ("sources", strings(e.sources().iter().map(|s| s.to_string()).collect())),
            ("table", e.table.map_or(Value::Nil, Value::from)),
            ("active", map(vec![("v4", active(gw4)), ("v6", active(gw6))])),
            ("blocked", map(vec![("v4", block4.into()), ("v6", block6.into())])),
        ])
    }

    /// `set exit`: changes `[exit]` like `dvpn exit`. Fields not given stay; a list given
    /// replaces the old one (empty or nil: none); `kill_switch` / `table` nil: the default;
    /// `clear: true` starts from no `[exit]` at all. Answers like `get exit`.
    fn set_exit(&self, p: &Value) -> Reply {
        let n = &self.node;
        let me = n.storage.self_id();
        let mut e = n.exit_detail().0;
        match raw_field(p, "clear") {
            None | Some(Value::Nil) | Some(Value::Boolean(false)) => {}
            Some(Value::Boolean(true)) => e = crate::config::Exits::default(),
            Some(_) => return Err(bad_param("clear", "expected true or false")),
        }
        let names = self.names();
        let revoked = n.group_store().revoked(&n.group_id());
        for (k, list) in [("v4", &mut e.v4), ("v6", &mut e.v6)] {
            let Some(given) = str_list(p, k)? else { continue };
            for g in &given {
                match Self::resolve_gateway(&names, g) {
                    None => {
                        return Err(ApiError::new(
                            "gateway_unknown",
                            format!("{k}: {g}: not a node key nor the name of one member"),
                        ));
                    }
                    Some(id) if id == me => {
                        return Err(ApiError::new("gateway_self", format!("{k}: {g} is this node")));
                    }
                    Some(id) if revoked.contains(&id) => {
                        return Err(ApiError::new("gateway_unknown", format!("{k}: {g} is revoked")));
                    }
                    Some(_) => {}
                }
            }
            *list = given;
        }
        match raw_field(p, "kill_switch") {
            None => {}
            Some(Value::Nil) => e.kill_switch = None,
            Some(Value::Boolean(b)) => e.kill_switch = Some(*b),
            Some(_) => return Err(bad_param("kill_switch", "expected true, false or nil")),
        }
        if let Some(dns) = str_list(p, "dns")? {
            e.dns = dns
                .iter()
                .map(|s| s.parse().map_err(|_| ApiError::new("dns_invalid", format!("dns: {s} is not an IP address"))))
                .collect::<Result<_, _>>()?;
        }
        if let Some(sources) = str_list(p, "sources")? {
            (e.v4_sources, e.v6_sources) = (Vec::new(), Vec::new());
            for s in &sources {
                let net = s
                    .parse::<ipnet::IpNet>()
                    .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|_| ApiError::new("sources_invalid", format!("sources: {s} is not a network")))?;
                match net {
                    ipnet::IpNet::V4(n) => e.v4_sources.push(n),
                    ipnet::IpNet::V6(n) => e.v6_sources.push(n),
                }
            }
        }
        match raw_field(p, "table") {
            None => {}
            Some(Value::Nil) => e.table = None,
            Some(v) => {
                let t = v.as_i64().ok_or_else(|| bad_param("table", "expected a table number or nil"))?;
                e.table =
                    Some(crate::config::check_table(t).map_err(|err| ApiError::new("table_invalid", err.to_string()))?);
            }
        }
        n.set_exits(&e).map_err(|err| ApiError::new("config_write", format!("{err:#}")))?;
        Ok(self.exit_info())
    }

    /// `get acl`: the group's access rules, as TOML (`dvpn acl show`) and taken apart.
    fn acl_info(&self) -> Value {
        use crate::acl::{Proto, Who};
        let n = &self.node;
        let names = self.names();
        let name = |id: &NodeId| names.get(id).cloned().unwrap_or_else(|| id.to_string());
        let acl = n.group_store().acl(&n.group_id());
        let set = acl.is_some();
        let acl = acl.unwrap_or_default();
        let who = |l: &[Who]| {
            Value::Array(
                l.iter()
                    .map(|w| match w {
                        Who::Anybody => Value::from("*"),
                        Who::Tag(t) => Value::from(t.as_str()),
                        Who::Node(id) => Value::from(name(id)),
                    })
                    .collect(),
            )
        };
        let rules = acl.rules.iter().map(|r| {
            let proto = match r.proto {
                Proto::Any => "any",
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
                Proto::Icmp => "icmp",
            };
            map(vec![
                ("from", who(&r.from)),
                ("to", who(&r.to)),
                ("proto", proto.into()),
                (
                    "ports",
                    Value::Array(r.ports.iter().map(|(a, b)| Value::Array(vec![(*a).into(), (*b).into()])).collect()),
                ),
                ("allow", r.allow.into()),
            ])
        });
        let tags = acl
            .tags
            .iter()
            .map(|(t, ids)| (Value::from(t.as_str()), Value::Array(ids.iter().map(|i| Value::from(name(i))).collect())))
            .collect();
        map(vec![
            ("set", set.into()),
            ("default", if acl.default_deny { "deny" } else { "allow" }.into()),
            ("toml", acl.to_toml(&name).into()),
            ("tags", Value::Map(tags)),
            ("rules", Value::Array(rules.collect())),
        ])
    }

    /// `key`: a full node key, a unique prefix of a known one or a member name. Errors:
    /// `key_validate_error` (missing, invalid or unknown), `key_ambiguous`.
    fn peer_arg(&self, p: &Value) -> Result<NodeId, ApiError> {
        let s = field(p, "key")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new("key_validate_error", "key: a node key, key prefix or name is needed"))?;
        let storage = &self.node.storage;
        // a member name works too, if it names exactly one peer
        let by_name: Vec<NodeId> =
            storage.ids().into_iter().filter(|i| storage.name(i).as_deref() == Some(s)).collect();
        if let [one] = by_name.as_slice() {
            return Ok(*one);
        }
        storage.resolve(s).map_err(|e| match e {
            ResolveError::NotFound => ApiError::new("key_validate_error", format!("{s}: no such node key or name")),
            ResolveError::Ambiguous(n) => {
                ApiError::new("key_ambiguous", format!("{s} matches {n} nodes: give more of the key"))
            }
        })
    }

    /// `addr: [ip, port]` of a discovery server this node uses.
    fn server_arg(&self, p: &Value) -> Result<Arc<crate::tracker_client::TrackerClient>, ApiError> {
        let a = field(p, "addr").and_then(parse_addr).ok_or_else(|| bad_param("addr", "expected [ip, port]"))?;
        self.node
            .client(&a)
            .cloned()
            .ok_or_else(|| ApiError::new("server_not_found", format!("{a}: not a discovery server of this node")))
    }

    fn handle_get(&self, p: &Value) -> Reply {
        let storage = &self.node.storage;
        let req = field(p, "req").and_then(Value::as_str).ok_or_else(|| bad_param("req", "missing"))?;
        // the record of the node in `key`
        let rec = || -> Result<_, ApiError> {
            let id = self.peer_arg(p)?;
            Ok(storage.get(&id).map(|(r, e)| (id, r, e)))
        };
        Ok(match req {
            "key" => storage.self_id().to_string().into(),
            "peers" => Value::Array(storage.ids().iter().map(|i| i.to_string().into()).collect()),
            "peer_exist" => match self.peer_arg(p) {
                Ok(id) => storage.exists(&id).into(),
                Err(e) if e.code == "key_validate_error" => false.into(),
                Err(e) => return Err(e),
            },
            "peer_name" => opt_str(rec()?.and_then(|(_, r, _)| r.name)),
            "peer_addr" => opt_str(rec()?.and_then(|(_, r, _)| r.addr.map(|a| a.to_string()))),
            "peer_sub_args" => rec()?.map_or(Value::Nil, |(_, r, _)| sub_args_value(&r)),
            "peer_sub_arg" => {
                let arg = field(p, "arg").and_then(Value::as_str).ok_or_else(|| bad_param("arg", "missing"))?;
                rec()?.and_then(|(_, r, _)| r.sub_args?.get(arg).map(json_to_mp)).unwrap_or(Value::Nil)
            }
            "peer_endpoint" => addr_value(rec()?.and_then(|(_, _, e)| e)),
            "peer_status" => rec()?.is_some_and(|(_, _, e)| e.is_some()).into(),
            "peer_ping" => storage.rtt_ms(&self.peer_arg(p)?).unwrap_or(0.0).into(),
            // Encryption is always on; this tells whether a Noise session is up.
            "peer_crypto_status" => {
                if self.node.links.current(&self.peer_arg(p)?).is_some() { "noise_ikpsk2" } else { "no" }.into()
            }
            "servers" => Value::Array(self.node.clients.iter().map(|c| addr_value(Some(c.addr()))).collect()),
            "server_status" => self.server_arg(p)?.is_connected().into(),
            "server_key" => Value::Binary(self.server_arg(p)?.key.to_bytes().to_vec()),
            "server_last_announce" => self.server_arg(p)?.timestamps().0.into(),
            "server_last_search" => self.server_arg(p)?.timestamps().1.into(),
            "server_last_response" => self.server_arg(p)?.timestamps().2.into(),
            "local_addr" => addr_value(self.node.transport.local_addr().ok()),
            // diagnostics (dvpn status / neighbors / routes / path)
            "status" => {
                let n = &self.node;
                let cert = n.own_cert();
                let (gw4, gw6, kill) = n.exit_state();
                let name = |id: Option<NodeId>| opt_str(id.map(|i| storage.name(&i).unwrap_or_else(|| i.short())));
                map(vec![
                    ("key", storage.self_id().to_string().into()),
                    ("name", cert.body.name.clone().into()),
                    ("group", n.group_id().to_string().into()),
                    ("prefixes", Value::Array(cert.body.prefixes.iter().map(|p| p.to_string().into()).collect())),
                    ("relay", cert.body.roles.has(crate::group::Roles::RELAY).into()),
                    ("cert_days", (cert.body.not_after.saturating_sub(crate::clock::now_unix()) / 86400).into()),
                    (
                        "servers",
                        Value::Array(
                            n.clients
                                .iter()
                                .map(|c| {
                                    map(vec![
                                        ("addr", c.addr().to_string().into()),
                                        ("connected", c.is_connected().into()),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                    ("exit_v4", name(gw4)),
                    ("exit_v6", name(gw6)),
                    ("kill_switch", kill.into()),
                    ("local_addr", opt_str(n.transport.local_addr().ok().map(|a| a.to_string()))),
                    ("group_name", n.group_name().into()),
                    ("admin", n.is_admin().into()),
                    ("ula", crate::ckr::ula_addr(&n.group_id(), &storage.self_id()).to_string().into()),
                    ("epoch", n.psk_epoch().0.into()),
                    ("uptime_secs", n.metrics.uptime_secs().into()),
                ])
            }
            "neighbors" => Value::Array(
                self.node
                    .direct_links()
                    .into_iter()
                    .map(|l| {
                        let (id, ep, rtt, alive, age) = (l.peer, l.endpoint, l.rtt_ms, l.alive, l.age);
                        let c = self.node.metrics.peer(&id);
                        let ((tx_packets, tx_bytes), (rx_packets, rx_bytes)) = (c.wire_tx.get(), c.wire_rx.get());
                        map(vec![
                            ("key", id.to_string().into()),
                            ("name", opt_str(storage.name(&id))),
                            ("endpoint", opt_str(ep.map(|e| e.to_string()))),
                            ("rtt_ms", rtt.map_or(Value::Nil, Value::from)),
                            ("alive", alive.into()),
                            ("session_secs", age.as_secs().into()),
                            ("tx_packets", tx_packets.into()),
                            ("tx_bytes", tx_bytes.into()),
                            ("rx_packets", rx_packets.into()),
                            ("rx_bytes", rx_bytes.into()),
                        ])
                    })
                    .collect(),
            ),
            "routes" => {
                let mesh = self.node.mesh_routes().into_iter().map(|(d, f, c)| {
                    map(vec![
                        ("key", d.to_string().into()),
                        ("name", opt_str(storage.name(&d))),
                        ("via", f.to_string().into()),
                        ("via_name", opt_str(storage.name(&f))),
                        ("cost", c.into()),
                    ])
                });
                let table = self.node.ckr();
                let ckr = table.routes().iter().map(|r| {
                    let target = match r.target {
                        crate::ckr::Target::Node(n) => storage.name(&n).unwrap_or_else(|| n.short()),
                        crate::ckr::Target::Exclude => "(not through the tunnel)".into(),
                        crate::ckr::Target::Blackhole => "(kill switch: dropped)".into(),
                    };
                    map(vec![("net", r.net.to_string().into()), ("to", target.into()), ("system", r.system.into())])
                });
                map(vec![("mesh", Value::Array(mesh.collect())), ("ckr", Value::Array(ckr.collect()))])
            }
            "metrics" => {
                let m = &self.node.metrics;
                let pair = |p: &crate::metrics::Pair| {
                    let (packets, bytes) = p.get();
                    map(vec![("packets", packets.into()), ("bytes", bytes.into())])
                };
                let peers = m.peers().into_iter().map(|(id, c)| {
                    map(vec![
                        ("key", id.to_string().into()),
                        ("name", opt_str(storage.name(&id))),
                        ("ip_tx", pair(&c.ip_tx)),
                        ("ip_rx", pair(&c.ip_rx)),
                        ("wire_tx", pair(&c.wire_tx)),
                        ("wire_rx", pair(&c.wire_rx)),
                    ])
                });
                let drops = m.drops().into_iter().map(|(d, n)| (Value::from(d.name()), Value::from(n))).collect();
                map(vec![
                    ("uptime_secs", m.uptime_secs().into()),
                    ("handshakes", m.handshakes.load(std::sync::atomic::Ordering::Relaxed).into()),
                    ("relayed", pair(&m.relayed)),
                    ("drops", Value::Map(drops)),
                    ("peers", Value::Array(peers.collect())),
                ])
            }
            "version" => map(vec![
                ("api", API_VERSION.into()),
                ("api_min", API_VERSION_MIN.into()),
                ("node", env!("CARGO_PKG_VERSION").into()),
                ("wire", String::from_utf8_lossy(crate::noise::PROLOGUE).into_owned().into()),
            ]),
            "group" => self.group_info(),
            "members" => self.members(),
            "exit" => self.exit_info(),
            "acl" => self.acl_info(),
            // nil: no path known now (not an error)
            "path" => match self.node.path(&self.peer_arg(p)?) {
                Some(hops) => Value::Array(
                    hops.iter()
                        .map(|h| map(vec![("key", h.to_string().into()), ("name", opt_str(storage.name(h)))]))
                        .collect(),
                ),
                None => Value::Nil,
            },
            other => return Err(ApiError::new("unknown_request", format!("get {other:?}: no such request"))),
        })
    }

    fn handle_set(&self, p: &Value) -> Reply {
        match field(p, "req").and_then(Value::as_str) {
            Some("peer") => self.set_peer(p),
            Some("exit") => self.set_exit(p),
            Some(other) => Err(ApiError::new("unknown_request", format!("set {other:?}: no such request"))),
            None => Err(bad_param("req", "missing")),
        }
    }

    /// `set peer`: local data of a known node (its certificate gives name and address).
    fn set_peer(&self, p: &Value) -> Reply {
        let peer = self.peer_arg(p)?;
        let force = match field(p, "force") {
            None => false,
            Some(Value::Boolean(b)) => *b,
            Some(_) => return Err(ApiError::new("force_not_bool", "force: expected true or false")),
        };
        // `force` means "fields not given are cleared", like in v2.
        fn pick<T>(given: Option<T>, force: bool) -> Option<Option<T>> {
            if given.is_some() || force { Some(given) } else { None }
        }

        let name = match field(p, "name") {
            None => None,
            Some(v) => match v.as_str() {
                Some(s) => Some(s.to_owned()),
                None => return Err(ApiError::new("name_not_str", "name: expected a string")),
            },
        };
        let addr = match field(p, "addr") {
            None => None,
            Some(v) => match v.as_str().and_then(|s| s.parse().ok()) {
                Some(a) => Some(a),
                None => return Err(ApiError::new("addr_validate_error", "addr: expected an IPv4 address")),
            },
        };
        let endpoint = match field(p, "endpoint") {
            None => None,
            Some(v) => match parse_addr(v) {
                Some(a) => Some(a),
                None => return Err(ApiError::new("endpoint_validate_error", "endpoint: expected [ip, port]")),
            },
        };
        let sub_args = match field(p, "sub_args") {
            None => None,
            Some(v) if v.is_map() => match mp_to_json(v) {
                Json::Object(m) => Some(m),
                _ => unreachable!(),
            },
            Some(_) => return Err(ApiError::new("sub_args_not_dict", "sub_args: expected a map")),
        };
        self.node.storage.set_peer(
            peer,
            PeerUpdate {
                name: pick(name, force),
                addr: pick(addr, force),
                endpoint: pick(endpoint, force),
                sub_args: pick(sub_args, force),
            },
        );
        Ok(Value::Nil)
    }

    fn handle_del(&self, p: &Value) -> Reply {
        let storage = &self.node.storage;
        let req = field(p, "req").and_then(Value::as_str).ok_or_else(|| bad_param("req", "missing"))?;
        if !matches!(req, "peer" | "peer_endpoint") {
            return Err(ApiError::new("unknown_request", format!("del {req:?}: no such request")));
        }
        let peer = self.peer_arg(p)?;
        if !storage.exists(&peer) {
            return Err(ApiError::new("peer_not_exist", format!("{}: not a known node", peer.short())));
        }
        Ok(match req {
            "peer" if storage.is_self(&peer) => {
                return Err(ApiError::new("error_delete_self_peer", "this node cannot delete itself"));
            }
            "peer" => storage.del_peer(&peer).into(),
            _ => storage.del_endpoint(&peer).into(),
        })
    }

    fn handle_route(&self, p: &Value, from: &ApiAddr) -> Reply {
        let mut st = self.state.lock();
        let not_int = || ApiError::new("not_int", "route: expected an integer");
        let route = field(p, "route").and_then(Value::as_u64);
        match field(p, "req").and_then(Value::as_str) {
            Some("reg") => {
                let r = route.ok_or_else(not_int)?;
                if !(KIND_API_MIN as u64..=KIND_API_MAX as u64).contains(&r) {
                    return Err(ApiError::new(
                        "out_of_range",
                        format!("route {r}: API routes are {KIND_API_MIN}..={KIND_API_MAX}"),
                    ));
                }
                let r = r as u8;
                if st.route_owner.contains_key(&r) {
                    return Err(ApiError::new("route_exist", format!("route {r} is taken by another client")));
                }
                st.route_owner.insert(r, from.clone());
                log::debug!("API | conn {from} route {r} added");
                Ok(Value::Nil)
            }
            Some("del") => {
                let r = route.and_then(|r| u8::try_from(r).ok()).ok_or_else(not_int)?;
                match st.route_owner.get(&r) {
                    None => Err(ApiError::new("route_not_exist", format!("route {r} is not taken"))),
                    Some(a) if a != from => {
                        Err(ApiError::new("not_permission", format!("route {r} is taken by another client")))
                    }
                    Some(_) => {
                        st.route_owner.remove(&r);
                        Ok(Value::Nil)
                    }
                }
            }
            Some("routes") => Ok(st.routes_of(from)),
            Some(other) => Err(ApiError::new("unknown_request", format!("route {other:?}: no such request"))),
            None => Err(bad_param("req", "missing")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{CertBody, GroupSecret};
    use crate::identity::Identity;
    use crate::state::StateStore;
    use crate::storage::PeerStorage;

    /// A node with no TUN, no trackers and no peers, and its API (not started: requests go to
    /// `handle` directly).
    async fn api(admin: bool) -> Api {
        api_with_secret(admin).await.0
    }

    /// The test node and its group's secret (to write group records as an admin would).
    async fn api_with_secret(admin: bool) -> (Api, GroupSecret) {
        let identity = Arc::new(Identity::generate());
        let secret = GroupSecret::generate();
        let mut body = CertBody::new(identity.id(), "alice", vec!["10.10.33.1/32".parse().unwrap()]);
        if admin {
            body.roles.0 |= crate::group::Roles::ADMIN;
        }
        let cert = secret.issue(body);
        let storage = Arc::new(PeerStorage::new(identity.id()));
        storage.set_peer(identity.id(), PeerUpdate::from_cert(&cert));
        let transport = crate::transport::Transport::new("127.0.0.1".parse().unwrap(), (0, 0)).await.unwrap();
        let group = crate::link::Group {
            id: secret.id(),
            psk: secret.psk(0),
            obfs: crate::obfs::Profile::none(),
            cert: cert.clone(),
        };
        let links = crate::link::Links::new(identity.clone(), group.clone());
        let e2e = crate::link::Links::new(identity.clone(), group);
        let ctx = crate::node::GroupCtx {
            id: secret.id(),
            secret: admin.then(|| secret.clone()),
            cert: cert.clone(),
            store: Arc::new(StateStore::memory()),
            epoch: 0,
            psk: secret.psk(0),
            identity,
            on_cert: Box::new(|_| {}),
            on_epoch: Box::new(|_, _| {}),
            statics: Vec::new(),
            routes: Vec::new(),
            tun_prefix: 24,
            group_name: "home".into(),
            dns: None,
            dns_upstream: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            resolved_tun: None,
            tun_dns: false,
            exits: Default::default(),
            config_path: test_config(),
        };
        let node = Node::new(storage, transport, (links, e2e), Vec::new(), None, cert.body.ipv4(), ctx);
        (Api { node, sock: ApiSocket::bind("127.0.0.1:0").await.unwrap(), state: Mutex::new(State::default()) }, secret)
    }

    /// A config file of its own for each test node (`set exit` writes `[exit]` to it).
    fn test_config() -> std::path::PathBuf {
        let tag = encode_b64(&crate::crypto::random_bytes::<9>());
        let dir = std::env::temp_dir().join(format!("dvpn-api-test-{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "# my own comment\n[peer]\nbind_port = 8647\n").unwrap();
        path
    }

    /// Members as an admin issues them: bob (relay, a subnet behind it), dave (revoked).
    fn add_members(api: &Api, secret: &GroupSecret) -> (NodeId, NodeId) {
        let store = api.node.group_store();
        let issue = |name: &str, prefixes: &[&str], roles: u8| {
            let mut b =
                CertBody::new(Identity::generate().id(), name, prefixes.iter().map(|p| p.parse().unwrap()).collect());
            b.roles.0 = roles;
            let c = secret.issue(b);
            store.add(secret, crate::state::Body::Cert(Box::new(c.clone())), false);
            c.body.node
        };
        let bob = issue("bob", &["10.10.33.2/32", "192.168.1.0/24"], crate::group::Roles::RELAY);
        let dave = issue("dave", &["10.10.33.4/32"], 0);
        store.add(secret, crate::state::Body::Revoke { key: dave }, false);
        (bob, dave)
    }

    fn client() -> ApiAddr {
        ApiAddr::Inet("127.0.0.1:40000".parse().unwrap())
    }

    fn msg(pairs: Vec<(&str, Value)>) -> Value {
        map(pairs)
    }

    fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
        field(v, k).and_then(Value::as_str)
    }

    async fn init(api: &Api, version: Option<Value>) -> Value {
        let mut m = vec![("type", Value::from("init")), ("name", "test".into())];
        if let Some(v) = version {
            m.push(("version", v));
        }
        api.handle(&msg(m), &client()).await.expect("init is answered")
    }

    async fn request(api: &Api, kind: &str, fields: Vec<(&str, Value)>) -> Value {
        let mut m = vec![("type", Value::from(kind)), ("id", Value::from(7))];
        m.extend(fields);
        api.handle(&msg(m), &client()).await.expect("a request is answered")
    }

    #[tokio::test]
    async fn init_answers_with_the_node() {
        let api = api(true).await;
        let r = init(&api, Some(API_VERSION.into())).await;
        assert_eq!(s(&r, "type"), Some("init"));
        assert_eq!(field(&r, "version").and_then(Value::as_u64), Some(API_VERSION));
        assert_eq!(field(&r, "min_version").and_then(Value::as_u64), Some(API_VERSION_MIN));
        assert_eq!(s(&r, "key"), Some(api.node.storage.self_id().to_string().as_str()));
        assert_eq!(s(&r, "name"), Some("alice"));
        assert_eq!(s(&r, "group"), Some(api.node.group_id().to_string().as_str()));
        assert_eq!(s(&r, "group_name"), Some("home"));
        assert_eq!(field(&r, "admin").and_then(Value::as_bool), Some(true));
        assert_eq!(s(&r, "node_version"), Some(env!("CARGO_PKG_VERSION")));
        // registered: requests are served
        let r = request(&api, "get", vec![("req", "key".into())]).await;
        assert_eq!(s(&r, "type"), Some("res"));
        assert_eq!(field(&r, "id").and_then(Value::as_u64), Some(7));
        assert_eq!(s(&r, "res"), Some(api.node.storage.self_id().to_string().as_str()));
        assert!(field(&r, "err").is_none());

        let member = self::api(false).await;
        let r = init(&member, Some(API_VERSION.into())).await;
        assert_eq!(field(&r, "admin").and_then(Value::as_bool), Some(false));
    }

    #[tokio::test]
    async fn init_refuses_other_versions() {
        let api = api(false).await;
        for v in [None, Some(Value::from(3)), Some(Value::from(API_VERSION + 1)), Some(Value::from("4"))] {
            let r = init(&api, v.clone()).await;
            assert_eq!(s(&r, "type"), Some("error"), "{v:?}");
            assert_eq!(s(&r, "err"), Some("version_unsupported"), "{v:?}");
            assert!(s(&r, "msg").is_some_and(|m| m.contains("not served")), "{r}");
            assert_eq!(field(&r, "min").and_then(Value::as_u64), Some(API_VERSION_MIN));
            assert_eq!(field(&r, "max").and_then(Value::as_u64), Some(API_VERSION));
            // not registered: told to go away
            let r = request(&api, "get", vec![("req", "key".into())]).await;
            assert_eq!(s(&r, "type"), Some("close"));
        }
        // a connection that re-inits with a bad version is dropped
        init(&api, Some(API_VERSION.into())).await;
        init(&api, Some(3.into())).await;
        assert_eq!(s(&request(&api, "get", vec![("req", "key".into())]).await, "type"), Some("close"));
    }

    #[tokio::test]
    async fn errors_come_in_err_and_msg() {
        let api = api(false).await;
        init(&api, Some(API_VERSION.into())).await;
        let err = |r: &Value| (s(r, "err").map(str::to_owned), field(r, "res").is_some(), s(r, "msg").is_some());
        // (message type, fields, expected error code)
        type Case<'a> = (&'a str, Vec<(&'a str, Value)>, &'a str);
        let cases: Vec<Case> = vec![
            ("get", vec![], "bad_param"),
            ("get", vec![("req", "nope".into())], "unknown_request"),
            ("get", vec![("req", "peer_name".into())], "key_validate_error"),
            ("get", vec![("req", "peer_name".into()), ("key", "bob".into())], "key_validate_error"),
            ("get", vec![("req", "path".into()), ("key", "!!".into())], "key_validate_error"),
            ("get", vec![("req", "peer_sub_arg".into()), ("key", "alice".into())], "bad_param"),
            ("get", vec![("req", "server_status".into())], "bad_param"),
            (
                "get",
                vec![("req", "server_key".into()), ("addr", Value::Array(vec!["192.0.2.1".into(), 6485.into()]))],
                "server_not_found",
            ),
            ("set", vec![("req", "nope".into())], "unknown_request"),
            ("set", vec![("req", "peer".into()), ("key", "alice".into()), ("force", 1.into())], "force_not_bool"),
            ("set", vec![("req", "peer".into()), ("key", "alice".into()), ("addr", "x".into())], "addr_validate_error"),
            ("del", vec![("req", "nope".into()), ("key", "alice".into())], "unknown_request"),
            ("del", vec![("req", "peer".into()), ("key", "alice".into())], "error_delete_self_peer"),
            ("route", vec![("req", "reg".into())], "not_int"),
            ("route", vec![("req", "reg".into()), ("route", 10.into())], "out_of_range"),
            ("route", vec![("req", "del".into()), ("route", 40.into())], "route_not_exist"),
            ("route", vec![("req", "nope".into())], "unknown_request"),
        ];
        for (kind, fields, code) in cases {
            let what = format!("{kind} {fields:?}");
            let r = request(&api, kind, fields).await;
            assert_eq!(s(&r, "type"), Some("res"), "{what}");
            assert_eq!(field(&r, "id").and_then(Value::as_u64), Some(7), "{what}");
            assert_eq!(err(&r), (Some(code.to_owned()), false, true), "{what}: {r}");
        }
        // a name, a key prefix, the key: all the same node
        let me = api.node.storage.self_id().to_string();
        for key in ["alice", &me[..6], &me] {
            let r = request(&api, "get", vec![("req", "peer_name".into()), ("key", key.into())]).await;
            assert_eq!(s(&r, "res"), Some("alice"), "{key}");
        }
        let r = request(&api, "get", vec![("req", "peer_exist".into()), ("key", "bob".into())]).await;
        assert_eq!(field(&r, "res").and_then(Value::as_bool), Some(false), "an unknown node does not exist");
    }

    #[tokio::test]
    async fn routes_and_unknown_types() {
        let api = api(false).await;
        init(&api, Some(API_VERSION.into())).await;
        let reg = request(&api, "route", vec![("req", "reg".into()), ("route", 40.into())]).await;
        assert!(field(&reg, "err").is_none() && field(&reg, "res").is_none(), "{reg}"); // nil result
        let again = request(&api, "route", vec![("req", "reg".into()), ("route", 40.into())]).await;
        assert_eq!(s(&again, "err"), Some("route_exist"));
        let list = request(&api, "route", vec![("req", "routes".into())]).await;
        assert_eq!(field(&list, "res"), Some(&Value::Array(vec![40.into()])));

        let r = api.handle(&msg(vec![("type", "frobnicate".into())]), &client()).await.unwrap();
        assert_eq!((s(&r, "type"), s(&r, "err")), (Some("error"), Some("unknown_type")));
        // ping is answered even before init
        let other = ApiAddr::Inet("127.0.0.1:40001".parse().unwrap());
        let r = api.handle(&msg(vec![("type", "ping".into())]), &other).await.unwrap();
        assert_eq!(s(&r, "type"), Some("pong"));
    }

    fn get_ok(r: &Value) -> &Value {
        assert!(field(r, "err").is_none(), "{r}");
        field(r, "res").unwrap_or(&Value::Nil)
    }

    fn strs(v: &Value, k: &str) -> Vec<String> {
        field(v, k)
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
    }

    #[tokio::test]
    async fn group_and_status() {
        let (api, secret) = api_with_secret(true).await;
        init(&api, Some(API_VERSION.into())).await;
        let r = request(&api, "get", vec![("req", "group".into())]).await;
        let g = get_ok(&r);
        assert_eq!(s(g, "id"), Some(secret.id().to_string().as_str()));
        assert_eq!(s(g, "name"), Some("home"));
        assert_eq!(field(g, "admin").and_then(Value::as_bool), Some(true));
        assert_eq!(field(g, "epoch").and_then(Value::as_u64), Some(0));
        assert!(field(g, "next_epoch").is_none() && field(g, "prev_epoch_until").is_none(), "{g}");
        let cert = field(g, "cert").unwrap();
        // issued just now: a full TTL, or a second less of it
        let ttl_days = crate::group::CERT_TTL_SECS / 86400;
        let days = field(cert, "days").and_then(Value::as_u64).unwrap();
        assert!(days == ttl_days || days + 1 == ttl_days, "{days}");
        assert_eq!(field(cert, "invite").and_then(Value::as_bool), Some(false));
        let obfs = field(g, "obfs").unwrap();
        assert_eq!(field(obfs, "data_pad"), Some(&Value::Array(vec![0.into(), 0.into()])));
        assert_eq!(field(obfs, "signatures").and_then(Value::as_u64), Some(0));
        assert_eq!(field(g, "servers"), Some(&Value::Array(Vec::new())));
        assert_eq!(field(g, "statics"), Some(&Value::Array(Vec::new())));

        // a psk change announced for a minute from now
        api.node.group_store().rotate(&secret, 0, 60_000);
        let r = request(&api, "get", vec![("req", "group".into())]).await;
        let next = field(get_ok(&r), "next_epoch").expect("announced epoch");
        assert_eq!(field(next, "epoch").and_then(Value::as_u64), Some(1));
        assert_eq!(field(next, "started").and_then(Value::as_bool), Some(false));
        assert_eq!(field(next, "has_key").and_then(Value::as_bool), Some(true), "an admin has every psk");
        let at = field(next, "at").and_then(Value::as_u64).unwrap();
        assert!(at > crate::clock::now_unix() && at <= crate::clock::now_unix() + 61, "{at}");

        let r = request(&api, "get", vec![("req", "status".into())]).await;
        let st = get_ok(&r);
        assert_eq!((s(st, "group_name"), field(st, "admin").and_then(Value::as_bool)), (Some("home"), Some(true)));
        assert_eq!(field(st, "epoch").and_then(Value::as_u64), Some(0));
        assert!(s(st, "ula").is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()), "{st}");
        assert!(field(st, "uptime_secs").and_then(Value::as_u64).is_some());

        let r = request(&api, "get", vec![("req", "version".into())]).await;
        let v = get_ok(&r);
        assert_eq!(field(v, "api").and_then(Value::as_u64), Some(API_VERSION));
        assert_eq!((s(v, "node"), s(v, "wire")), (Some(env!("CARGO_PKG_VERSION")), Some("dvpn/4")));
    }

    #[tokio::test]
    async fn members_from_records() {
        let (api, secret) = api_with_secret(true).await;
        init(&api, Some(API_VERSION.into())).await;
        let (bob, dave) = add_members(&api, &secret);
        let _ = dave;
        let carol = Identity::generate().id(); // revoked before anybody saw it
        api.node.group_store().add(&secret, crate::state::Body::Revoke { key: carol }, false);

        let r = request(&api, "get", vec![("req", "members".into())]).await;
        let list = get_ok(&r).as_array().expect("a list").clone();
        let names: Vec<Option<&str>> = list.iter().map(|m| s(m, "name")).collect();
        assert_eq!(names, vec![Some("alice"), Some("bob"), Some("dave"), None], "by name, unseen revoked last");

        let me = &list[0];
        assert_eq!(s(me, "key"), Some(api.node.storage.self_id().to_string().as_str()));
        assert_eq!(strs(me, "roles"), vec!["admin"]);
        assert_eq!(strs(me, "addrs"), vec!["10.10.33.1"]);
        let flags =
            |m: &Value| ["self", "online", "direct", "revoked"].map(|k| field(m, k).and_then(Value::as_bool).unwrap());
        assert_eq!(flags(me), [true, true, false, false]);

        let b = &list[1];
        assert_eq!(s(b, "key"), Some(bob.to_string().as_str()));
        assert_eq!(strs(b, "addrs"), vec!["10.10.33.2"]);
        assert_eq!(strs(b, "routes"), vec!["192.168.1.0/24"]);
        assert_eq!(strs(b, "roles"), vec!["relay"]);
        assert_eq!(flags(b), [false, false, false, false], "offline: no link, no route");
        assert_eq!(field(b, "expired").and_then(Value::as_bool), Some(false));
        assert!(field(b, "days").and_then(Value::as_u64).is_some_and(|d| d >= 29));

        assert_eq!(flags(&list[2]), [false, false, false, true], "dave: revoked, certificate known");
        let c = &list[3];
        assert_eq!(s(c, "key"), Some(carol.to_string().as_str()));
        assert_eq!(flags(c), [false, false, false, true]);
        assert!(field(c, "days").is_none() && strs(c, "addrs").is_empty());
    }

    // applying a plan blocks in place: the node runs on a multi-threaded runtime
    #[tokio::test(flavor = "multi_thread")]
    async fn exit_get_and_set() {
        let (api, secret) = api_with_secret(true).await;
        init(&api, Some(API_VERSION.into())).await;
        let (bob, dave) = add_members(&api, &secret);
        let path = test_config_of(&api);

        let r = request(&api, "get", vec![("req", "exit".into())]).await;
        let e = get_ok(&r);
        assert_eq!(field(e, "v4"), Some(&Value::Array(Vec::new())));
        assert_eq!(field(e, "kill_switch").and_then(Value::as_bool), Some(true), "on by default");
        assert!(field(field(e, "active").unwrap(), "v4").is_none());

        let list = |v: &[&str]| Value::Array(v.iter().map(|s| Value::from(*s)).collect());
        let r = request(
            &api,
            "set",
            vec![
                ("req", "exit".into()),
                ("v4", list(&[&bob.to_string()])),
                ("v6", list(&["bob"])),
                ("dns", list(&["1.1.1.1"])),
                ("sources", list(&["10.10.33.1", "fd00::/64"])),
                ("table", 100.into()),
            ],
        )
        .await;
        let e = get_ok(&r);
        let gw = &field(e, "v4").unwrap().as_array().unwrap()[0];
        assert_eq!((s(gw, "key"), s(gw, "name")), (Some(bob.to_string().as_str()), Some("bob")));
        assert_eq!(field(gw, "alive").and_then(Value::as_bool), Some(false));
        assert_eq!(strs(e, "dns"), vec!["1.1.1.1"]);
        assert_eq!(strs(e, "sources"), vec!["10.10.33.1/32", "fd00::/64"]);
        assert_eq!(field(e, "table").and_then(Value::as_u64), Some(100));
        // a gateway configured, none alive: the kill switch blocks at once (no wait for a tick)
        let blocked = field(e, "blocked").unwrap();
        assert_eq!(field(blocked, "v4").and_then(Value::as_bool), Some(true), "{e}");
        // also for a gateway named, known from the records only (no handshake with it yet)
        assert_eq!(field(blocked, "v6").and_then(Value::as_bool), Some(true), "{e}");
        // written to the config, the rest of it kept
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# my own comment") && text.contains("bind_port = 8647"), "{text}");
        let on_disk = crate::config::read_exits(&path).unwrap();
        assert_eq!((on_disk.v4, on_disk.v6), (vec![bob.to_string()], vec!["bob".to_owned()]));
        assert_eq!(on_disk.table, Some(100));

        // refused changes leave everything as it was
        let me = api.node.storage.self_id().to_string();
        let bad: Vec<(&str, Value, &str)> = vec![
            ("v4", list(&["nobody"]), "gateway_unknown"),
            ("v4", list(&["alice"]), "gateway_self"),
            ("v6", list(&[&me]), "gateway_self"),
            ("v4", list(&[&dave.to_string()]), "gateway_unknown"),
            ("v4", "bob".into(), "bad_param"),
            ("dns", list(&["one.one"]), "dns_invalid"),
            ("sources", list(&["10.10.33.0/99"]), "sources_invalid"),
            ("table", 254.into(), "table_invalid"),
            ("table", "main".into(), "bad_param"),
            ("kill_switch", "on".into(), "bad_param"),
        ];
        for (k, v, code) in bad {
            let what = format!("{k} = {v}");
            let r = request(&api, "set", vec![("req", "exit".into()), (k, v)]).await;
            assert_eq!(s(&r, "err"), Some(code), "{what}: {r}");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        // nil: back to the default; an empty list: none
        let r = request(
            &api,
            "set",
            vec![("req", "exit".into()), ("kill_switch", false.into()), ("v6", Value::Array(Vec::new()))],
        )
        .await;
        let e = get_ok(&r);
        assert_eq!(field(e, "kill_switch").and_then(Value::as_bool), Some(false));
        assert_eq!(field(e, "v6"), Some(&Value::Array(Vec::new())));
        assert_eq!(field(field(e, "blocked").unwrap(), "v4").and_then(Value::as_bool), Some(false));
        let r = request(&api, "set", vec![("req", "exit".into()), ("kill_switch", Value::Nil), ("table", Value::Nil)])
            .await;
        let e = get_ok(&r);
        assert_eq!(field(e, "kill_switch").and_then(Value::as_bool), Some(true));
        assert!(field(e, "table").is_none());
        assert_eq!(crate::config::read_exits(&path).unwrap().kill_switch, None);

        // a name nobody has (a typo, or a member not heard of yet; the API refuses it, an edited
        // config.toml does not): the kill switch still holds; only this node itself is no gateway
        let ghost = crate::config::Exits { v4: vec!["ghost".into()], v6: vec!["alice".into()], ..Default::default() };
        api.node.set_exits(&ghost).unwrap();
        let r = request(&api, "get", vec![("req", "exit".into())]).await;
        let blocked = field(get_ok(&r), "blocked").unwrap().clone();
        assert_eq!(field(&blocked, "v4").and_then(Value::as_bool), Some(true), "{blocked}");
        assert_eq!(field(&blocked, "v6").and_then(Value::as_bool), Some(false), "{blocked}");

        let r = request(&api, "set", vec![("req", "exit".into()), ("clear", true.into())]).await;
        assert_eq!(field(get_ok(&r), "v4"), Some(&Value::Array(Vec::new())));
        assert_eq!(crate::config::read_exits(&path).unwrap(), crate::config::Exits::default());
        assert!(!std::fs::read_to_string(&path).unwrap().contains("[exit]"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    fn test_config_of(api: &Api) -> std::path::PathBuf {
        api.node.config_path().to_owned()
    }

    #[tokio::test]
    async fn acl_as_text_and_rules() {
        let (api, secret) = api_with_secret(true).await;
        init(&api, Some(API_VERSION.into())).await;
        let (bob, _) = add_members(&api, &secret);
        let r = request(&api, "get", vec![("req", "acl".into())]).await;
        let a = get_ok(&r);
        assert_eq!((field(a, "set").and_then(Value::as_bool), s(a, "default")), (Some(false), Some("allow")));
        assert_eq!(field(a, "rules"), Some(&Value::Array(Vec::new())));

        let alice = api.node.storage.self_id();
        let member = |s: &str| match s {
            "alice" => Some(alice),
            "bob" => Some(bob),
            _ => None,
        };
        let text = "default = \"deny\"\n[tags]\nservers = [\"bob\"]\n\n[[rule]]\nfrom = [\"alice\"]\nto = [\"servers\"]\nproto = \"tcp\"\nports = [\"22\", \"8000-8080\"]\naction = \"allow\"\n";
        let acl = crate::acl::Acl::parse(text, &member).unwrap();
        api.node.group_store().add(&secret, crate::state::Body::Acl(Box::new(acl)), false);

        let r = request(&api, "get", vec![("req", "acl".into())]).await;
        let a = get_ok(&r);
        assert_eq!((field(a, "set").and_then(Value::as_bool), s(a, "default")), (Some(true), Some("deny")));
        assert!(s(a, "toml").is_some_and(|t| t.contains("\"bob\"") && t.contains("deny")), "{a}");
        assert_eq!(strs(field(a, "tags").unwrap(), "servers"), vec!["bob"]);
        let rule = &field(a, "rules").unwrap().as_array().unwrap()[0];
        assert_eq!((strs(rule, "from"), strs(rule, "to")), (vec!["alice".to_owned()], vec!["servers".to_owned()]));
        assert_eq!(s(rule, "proto"), Some("tcp"));
        let ports =
            Value::Array(vec![Value::Array(vec![22.into(), 22.into()]), Value::Array(vec![8000.into(), 8080.into()])]);
        assert_eq!(field(rule, "ports"), Some(&ports));
        assert_eq!(field(rule, "allow").and_then(Value::as_bool), Some(true));
    }

    /// The API started on a real socket, and `dvpn-client` (as the CLI, TUI and apps use it)
    /// talking to it: every answer is taken apart into the client's types, so a field renamed or
    /// retyped on either side fails here.
    async fn client_session(addr: &str) {
        use dvpn_client::{Client, ErrorCode, ExitUpdate};
        let (api, secret) = api_with_secret(true).await;
        add_members(&api, &secret);
        let node = api.node.clone();
        let sock = ApiSocket::bind(addr).await.unwrap();
        let at: dvpn_client::ApiAddr = sock.describe().parse().unwrap();
        let _api = Api::start(node.clone(), sock);
        let c = Client::connect(at.clone(), "test").await.unwrap_or_else(|e| panic!("{at}: {e}"));
        fn code<T>(r: Result<T, dvpn_client::Error>) -> Option<dvpn_client::ErrorCode> {
            r.err().and_then(|e| e.code().cloned())
        }

        let info = c.info();
        assert_eq!((info.name.as_str(), info.group_name.as_str(), info.admin), ("alice", "home", true));
        assert_eq!(info.version, dvpn_client::API_VERSION);
        assert_eq!(info.key, node.storage.self_id().to_string());

        let st = c.status().await.unwrap();
        assert_eq!((st.group_name.as_str(), st.prefixes.as_slice()), ("home", &["10.10.33.1/32".to_owned()][..]));
        assert_eq!(c.version().await.unwrap().wire, "dvpn/4");
        assert!(c.neighbors().await.unwrap().is_empty());
        assert!(c.routes().await.unwrap().mesh.is_empty());
        assert!(c.metrics().await.unwrap().peers.is_empty());
        assert_eq!(c.path("alice").await.unwrap(), None);
        assert_eq!(code(c.path("nobody").await), Some(ErrorCode::KeyValidate));
        assert_eq!(code(c.ping("nobody").await), Some(ErrorCode::KeyValidate));
        assert_eq!(code(c.reset_endpoint("nobody").await), Some(ErrorCode::KeyValidate));
        assert_eq!(code(c.raw("get", "nope", Vec::new()).await), Some(ErrorCode::UnknownRequest));

        let g = c.group().await.unwrap();
        assert_eq!((g.name.as_str(), g.admin, g.epoch, g.next_epoch), ("home", true, 0, None));
        let m = c.members().await.unwrap();
        let names: Vec<_> = m.iter().map(|m| m.name.as_deref()).collect();
        assert_eq!(names, vec![Some("alice"), Some("bob"), Some("dave")]);
        assert!(m[0].is_self && m[0].has_role("admin") && m[1].has_role("relay") && m[2].revoked);
        assert_eq!(m[1].routes, vec!["192.168.1.0/24"]);

        let e = c.exit().await.unwrap();
        assert!(e.v4.is_empty() && e.active.v4.is_none() && !e.blocked.v4 && e.kill_switch);
        let e = c.set_exit(&ExitUpdate { v4: Some(vec!["bob".into()]), ..Default::default() }).await.unwrap();
        assert_eq!((e.v4[0].name.as_deref(), e.v4[0].alive, e.blocked.v4), (Some("bob"), false, true));
        let e = c.set_exit(&ExitUpdate { kill_switch: Some(Some(false)), ..Default::default() }).await.unwrap();
        assert!(!e.kill_switch && !e.blocked.v4);
        let bad = ExitUpdate { v4: Some(vec!["nobody".into()]), ..Default::default() };
        assert_eq!(code(c.set_exit(&bad).await), Some(ErrorCode::GatewayUnknown));
        let e = c.set_exit(&ExitUpdate { clear: true, ..Default::default() }).await.unwrap();
        assert!(e.v4.is_empty() && e.kill_switch);
        let acl = c.acl().await.unwrap();
        assert!(!acl.set && acl.default == "allow" && acl.rules.is_empty());
        drop(c);
        std::fs::remove_dir_all(node.config_path().parent().unwrap()).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_over_udp() {
        client_session("127.0.0.1:0").await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn client_over_a_unix_socket() {
        let tag = encode_b64(&crate::crypto::random_bytes::<9>());
        let path = std::env::temp_dir().join(format!("dvpn-api-test-{tag}.sock"));
        client_session(path.to_str().unwrap()).await;
    }

    #[test]
    fn res_shapes() {
        let ok = res(Some(&Value::from(1)), Ok(Value::from(5)));
        assert_eq!(field(&ok, "res").and_then(Value::as_u64), Some(5));
        assert!(field(&ok, "err").is_none());
        let failed = res(None, Err(ApiError::new("not_admin", "only admins")));
        assert_eq!((s(&failed, "err"), s(&failed, "msg")), (Some("not_admin"), Some("only admins")));
        assert!(failed.as_map().unwrap().iter().any(|(k, v)| k.as_str() == Some("id") && v.is_nil()));
        assert!(field(&failed, "res").is_none());
    }
}
