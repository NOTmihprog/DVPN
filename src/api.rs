//! Local control API: msgpack maps over a UDP or unix datagram socket, same request set as v2.
//!
//! Client -> node: `{"type": "init", "name": ..}` first, then `get` / `set` / `del` / `route`
//! requests carrying an `id` (answered with `{"type": "res", "id": .., "res": ..}`), `net`
//! packets `{"rou": route, "peer_id": .., "pack": bin}` and `ping` / `pong` / `close`.
//! Node -> client: responses, `event`s, `net` packets for registered routes, `ping`.

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
use crate::proto::{MAX_DATAGRAM, ROUTE_API_MAX, ROUTE_API_MIN};
use crate::storage::{Event, PeerRecord, PeerUpdate, ResolveError, normalize_key};

const PING_INTERVAL: Duration = Duration::from_secs(15);
const CONN_TIMEOUT: Duration = Duration::from_secs(45);

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

fn crypto_value(rec: &PeerRecord) -> Value {
    rec.key.as_ref().map_or(Value::Nil, |k| map(vec![("key", Value::from(k.as_str()))]))
}

fn event_value(e: &Event) -> Value {
    match e {
        Event::Peer { action, record, endpoint } => map(vec![
            ("action", action.as_str().into()),
            ("peer_id", record.peer_id.to_string().into()),
            ("name", opt_str(record.name.clone())),
            ("addr", opt_str(record.addr.map(|a| a.to_string()))),
            ("endpoint", addr_value(*endpoint)),
            ("crypto", crypto_value(record)),
            ("sub_args", sub_args_value(record)),
        ]),
        Event::Server { addr, connected } => {
            map(vec![("server", addr_value(Some(*addr))), ("status", (*connected).into())])
        }
        Event::Ping { peer_id, ms } => map(vec![("peer_id", peer_id.to_string().into()), ("ping", (*ms).into())]),
    }
}

// ---- state ----

struct Conn {
    last_ping: Option<Instant>,
    pings_sent: u32,
    last_pong: Option<Instant>,
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

fn res(id: Option<&Value>, v: Value) -> Value {
    map(vec![("type", "res".into()), ("id", id.cloned().unwrap_or(Value::Nil)), ("res", v)])
}

fn err(s: &str) -> Value {
    Value::from(s)
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
                ("peer_id", peer_id.to_string().into()),
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
            if let Some(reply) = self.handle(&packet, &from).await {
                self.sock.send(&reply, &from).await;
            }
        }
    }

    async fn handle(&self, p: &Value, from: &ApiAddr) -> Option<Value> {
        let kind = field(p, "type")?.as_str()?;
        let known = self.state.lock().conns.contains_key(from);
        match (known, kind) {
            (false, "init") => {
                self.state.lock().conns.insert(from.clone(), Conn { last_ping: None, pings_sent: 0, last_pong: None });
                log::debug!("API | conn {from} init, name {:?}", field(p, "name").and_then(Value::as_str));
                None
            }
            (_, "ping") => Some(map(vec![("type", "pong".into())])),
            (false, _) => {
                log::debug!("API | receive {kind} from unknown conn {from}");
                Some(map(vec![("type", "close".into())]))
            }
            (true, "pong") => {
                let mut st = self.state.lock();
                if let Some(c) = st.conns.get_mut(from) {
                    c.last_pong = Some(Instant::now());
                    if let Some(t) = c.last_ping {
                        log::debug!("API | receive pong from conn {from} ping: {:.3}", t.elapsed().as_secs_f64() * 1e3);
                    }
                }
                None
            }
            (true, "net") => {
                self.handle_net(p, from).await;
                None
            }
            (true, "get") => Some(res(field(p, "id"), self.handle_get(p))),
            (true, "set") => Some(res(field(p, "id"), self.handle_set(p))),
            (true, "del") => Some(res(field(p, "id"), self.handle_del(p))),
            (true, "route") => Some(res(field(p, "id"), self.handle_route(p, from))),
            (true, "close") => {
                self.state.lock().close(from);
                Some(map(vec![("type", "close".into())]))
            }
            _ => None,
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

    /// `peer_id`: a full node key or a unique prefix of a known one. Error codes for replies:
    /// `peer_id_validate_error` (missing, invalid or unknown), `peer_id_ambiguous`.
    fn peer_arg(&self, p: &Value) -> Result<NodeId, &'static str> {
        let s = field(p, "peer_id").and_then(Value::as_str).ok_or("peer_id_validate_error")?;
        self.node.storage.resolve(s).map_err(|e| match e {
            ResolveError::NotFound => "peer_id_validate_error",
            ResolveError::Ambiguous(_) => "peer_id_ambiguous",
        })
    }

    fn handle_get(&self, p: &Value) -> Value {
        let storage = &self.node.storage;
        let req = field(p, "req").and_then(Value::as_str).unwrap_or_default();
        let peer = self.peer_arg(p).ok();
        let rec = || peer.and_then(|id| storage.get(&id));
        let client = || field(p, "addr").and_then(parse_addr).and_then(|a| self.node.client(&a).cloned());
        match req {
            "peer_id" => storage.self_id().to_string().into(),
            "peers" => Value::Array(storage.ids().iter().map(|i| i.to_string().into()).collect()),
            "peer_exist" => peer.is_some_and(|id| storage.exists(&id)).into(),
            "peer_name" => opt_str(rec().and_then(|(r, _)| r.name)),
            "peer_addr" => opt_str(rec().and_then(|(r, _)| r.addr.map(|a| a.to_string()))),
            "peer_crypto" => rec().map_or(Value::Nil, |(r, _)| crypto_value(&r)),
            "peer_sub_args" => rec().map_or(Value::Nil, |(r, _)| sub_args_value(&r)),
            "peer_sub_arg" => {
                let arg = field(p, "arg").and_then(Value::as_str).unwrap_or_default();
                rec().and_then(|(r, _)| r.sub_args?.get(arg).map(json_to_mp)).unwrap_or(Value::Nil)
            }
            "peer_endpoint" => addr_value(rec().and_then(|(_, e)| e)),
            "peer_status" => rec().is_some_and(|(_, e)| e.is_some()).into(),
            "peer_ping" => peer.and_then(|id| storage.rtt_ms(&id)).unwrap_or(0.0).into(),
            "peer_crypto_status" => {
                if peer.is_some_and(|id| storage.has_cipher(&id)) { "xchacha20poly1305" } else { "no" }.into()
            }
            "servers" => Value::Array(self.node.clients.iter().map(|c| addr_value(Some(c.addr))).collect()),
            "server_status" => client().map_or(Value::Nil, |c| c.is_connected().into()),
            "server_key" => client().map_or(Value::Nil, |c| Value::Binary(c.key.to_bytes().to_vec())),
            "server_last_announce" => client().map_or(Value::Nil, |c| c.timestamps().0.into()),
            "server_last_search" => client().map_or(Value::Nil, |c| c.timestamps().1.into()),
            "server_last_response" => client().map_or(Value::Nil, |c| c.timestamps().2.into()),
            "local_addr" => addr_value(self.node.transport.local_addr().ok()),
            _ => Value::Nil,
        }
    }

    fn handle_set(&self, p: &Value) -> Value {
        if field(p, "req").and_then(Value::as_str) != Some("peer") {
            return Value::Nil;
        }
        let peer = match self.peer_arg(p) {
            Ok(id) => id,
            Err(code) => return err(code),
        };
        let force = match field(p, "force") {
            None => false,
            Some(Value::Boolean(b)) => *b,
            Some(_) => return err("force_not_bool"),
        };
        // `force` means "fields not given are cleared", like in v2.
        fn pick<T>(given: Option<T>, force: bool) -> Option<Option<T>> {
            if given.is_some() || force { Some(given) } else { None }
        }

        let name = match field(p, "name") {
            None => None,
            Some(v) => match v.as_str() {
                Some(s) => Some(s.to_owned()),
                None => return err("name_not_str"),
            },
        };
        let addr = match field(p, "addr") {
            None => None,
            Some(v) => match v.as_str().and_then(|s| s.parse().ok()) {
                Some(a) => Some(a),
                None => return err("addr_validate_error"),
            },
        };
        let endpoint = match field(p, "endpoint") {
            None => None,
            Some(v) => match parse_addr(v) {
                Some(a) => Some(a),
                None => return err("endpoint_validate_error"),
            },
        };
        let key_val = field(p, "key").or_else(|| field(p, "crypto").and_then(|c| field(c, "key")));
        if field(p, "crypto").is_some_and(|c| !c.is_map()) {
            return err("crypto_not_dict");
        }
        let key = match key_val {
            None => None,
            Some(v) => match v.as_str().map(normalize_key) {
                Some(Ok(k)) => Some(k),
                _ => return err("key_validate_error"),
            },
        };
        let sub_args = match field(p, "sub_args") {
            None => None,
            Some(v) if v.is_map() => match mp_to_json(v) {
                Json::Object(m) => Some(m),
                _ => unreachable!(),
            },
            Some(_) => return err("sub_args_not_dict"),
        };
        self.node.storage.set_peer(
            peer,
            PeerUpdate {
                name: pick(name, force),
                addr: pick(addr, force),
                key: pick(key, force),
                endpoint: pick(endpoint, force),
                sub_args: pick(sub_args, force),
            },
        );
        Value::Nil
    }

    fn handle_del(&self, p: &Value) -> Value {
        let storage = &self.node.storage;
        let peer = match self.peer_arg(p) {
            Ok(id) => id,
            Err(code) => return err(code),
        };
        if !storage.exists(&peer) {
            return err("peer_not_exist");
        }
        match field(p, "req").and_then(Value::as_str) {
            Some("peer") if storage.is_self(&peer) => err("error_delete_self_peer"),
            Some("peer") => storage.del_peer(&peer).into(),
            Some("peer_endpoint") => storage.del_endpoint(&peer).into(),
            _ => Value::Nil,
        }
    }

    fn handle_route(&self, p: &Value, from: &ApiAddr) -> Value {
        let mut st = self.state.lock();
        let route = field(p, "route").and_then(Value::as_u64);
        match field(p, "req").and_then(Value::as_str) {
            Some("reg") => {
                let Some(r) = route else { return err("not_int") };
                if !(ROUTE_API_MIN as u64..=ROUTE_API_MAX as u64).contains(&r) {
                    return err("out_of_range");
                }
                let r = r as u8;
                if st.route_owner.contains_key(&r) {
                    return err("route_exist");
                }
                st.route_owner.insert(r, from.clone());
                log::debug!("API | conn {from} route {r} added");
                Value::Nil
            }
            Some("del") => {
                let Some(r) = route.and_then(|r| u8::try_from(r).ok()) else { return err("not_int") };
                match st.route_owner.get(&r) {
                    None => err("route_not_exist"),
                    Some(a) if a != from => err("not_permission"),
                    Some(_) => {
                        st.route_owner.remove(&r);
                        Value::Nil
                    }
                }
            }
            Some("routes") => st.routes_of(from),
            _ => Value::Nil,
        }
    }
}
