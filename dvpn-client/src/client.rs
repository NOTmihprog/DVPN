use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rmpv::Value;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::transport::Socket;
use crate::types::*;
use crate::wire::{decode, encode, field, field_str, from_value, map};
use crate::{API_VERSION, ApiAddr, Error, ErrorCode};

/// How long a request waits for its answer (`ping` waits up to 2 s for the member).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

type Reply = Result<Value, Error>;

struct Shared {
    sock: Socket,
    name: String,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    /// The answer to our `init`, while we wait for it.
    init: Mutex<Option<oneshot::Sender<Reply>>>,
    events: broadcast::Sender<Value>,
    typed: broadcast::Sender<Event>,
    net: broadcast::Sender<NetPacket>,
    /// The last `sub` sent (with the token), sent again when the node forgot us.
    sub: Mutex<Option<Vec<u8>>>,
    /// API routes this client holds, as `route reg` messages: taken again when the node forgot us.
    routes: Mutex<std::collections::BTreeMap<u8, Vec<u8>>>,
}

impl Shared {
    fn init_msg(&self) -> Vec<u8> {
        encode(&map(vec![
            ("type", "init".into()),
            ("name", self.name.as_str().into()),
            ("version", API_VERSION.into()),
        ]))
    }
}

/// A connection to a node's API. Answers the node's pings and introduces itself again when the
/// node forgets it (`close`), so it can be kept for as long as the program runs.
pub struct Client {
    shared: Arc<Shared>,
    next_id: AtomicU64,
    timeout: Duration,
    /// Sent with every request to a UDP API (`ApiAddr::find_token`).
    token: Option<String>,
    info: InitInfo,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Connects to the node at `addr` as `name` (shown in the node's log). For a UDP API it
    /// finds the token itself ([`ApiAddr::find_token`]); without it only reading works.
    pub async fn connect(addr: ApiAddr, name: &str) -> Result<Client, Error> {
        // a unix socket: an abstract address first (Linux; see transport.rs), which a node
        // older than 4.2.1 leaves unanswered: then a file
        if cfg!(any(target_os = "linux", target_os = "android")) && matches!(addr, ApiAddr::Unix(_)) {
            match Self::connect_on(&addr, name, true, Duration::from_millis(1500)).await {
                Err(Error::Timeout) => {}
                r => return r,
            }
        }
        Self::connect_on(&addr, name, false, DEFAULT_TIMEOUT).await
    }

    async fn connect_on(addr: &ApiAddr, name: &str, abstract_addr: bool, wait: Duration) -> Result<Client, Error> {
        let token = addr.find_token();
        let sock = Socket::open(addr, abstract_addr).await?;
        let (events, _) = broadcast::channel(256);
        let (typed, _) = broadcast::channel(256);
        let (net, _) = broadcast::channel(1024);
        let shared = Arc::new(Shared {
            sock,
            name: name.to_owned(),
            pending: Mutex::default(),
            init: Mutex::default(),
            events,
            typed,
            net,
            sub: Mutex::default(),
            routes: Mutex::default(),
        });
        let task = tokio::spawn(recv_loop(shared.clone()));
        let (tx, rx) = oneshot::channel();
        *shared.init.lock().await = Some(tx);
        shared.sock.send(&shared.init_msg()).await?;
        let answer = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => Err(Error::Timeout),
        };
        let info = match answer.and_then(from_value::<InitInfo>) {
            Ok(i) => i,
            Err(e) => {
                task.abort();
                return Err(e);
            }
        };
        Ok(Client { shared, next_id: AtomicU64::new(1), timeout: DEFAULT_TIMEOUT, token, info, task })
    }

    /// Uses `token` for a UDP API instead of the one found.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Whether a token for changes is at hand (always false on a unix socket, which needs none).
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// How long requests wait for their answers.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// The node, as it answered `init`.
    pub fn info(&self) -> &InitInfo {
        &self.info
    }

    /// Everything the node sends besides answers (`event`, `net`), as it comes.
    pub fn raw_events(&self) -> broadcast::Receiver<Value> {
        self.shared.events.subscribe()
    }

    /// The node's events (by default all kinds but `metrics`; see [`Client::subscribe`]). A slow
    /// receiver loses the oldest ones (`RecvError::Lagged`).
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.shared.typed.subscribe()
    }

    /// Chooses the events the node sends to this client. Kept when the client introduces itself
    /// again.
    pub async fn subscribe(&self, s: &Subscription) -> Result<(), Error> {
        let mut f = Vec::new();
        if !s.kinds.is_empty() {
            f.push(("events", Value::Array(s.kinds.iter().map(|k| Value::from(k.as_str())).collect())));
        }
        if let Some(secs) = s.metrics_secs {
            f.push(("metrics_secs", secs.into()));
        }
        if let Some(l) = s.log_level {
            f.push(("log_level", l.as_str().into()));
        }
        let again = self.message("sub", None, 0, f.clone());
        self.request("sub", None, f).await?;
        *self.shared.sub.lock().await = Some(again);
        Ok(())
    }

    // ---- API routes: a protocol of one's own over the network ----

    /// Takes API route `route` (32..=255): packets members send to it come to this client
    /// ([`Client::net_packets`]). Taken again by itself if the node restarts.
    pub async fn route_reg(&self, route: u8) -> Result<(), Error> {
        let f = vec![("route", Value::from(route))];
        let again = self.message("route", Some("reg"), 0, f.clone());
        self.request("route", Some("reg"), f).await?;
        self.shared.routes.lock().await.insert(route, again);
        Ok(())
    }

    /// Gives API route `route` back.
    pub async fn route_del(&self, route: u8) -> Result<(), Error> {
        self.shared.routes.lock().await.remove(&route);
        self.request("route", Some("del"), vec![("route", Value::from(route))]).await.map(|_| ())
    }

    /// The API routes this client holds, as the node sees it.
    pub async fn own_routes(&self) -> Result<Vec<u8>, Error> {
        from_value(self.request("route", Some("routes"), Vec::new()).await?)
    }

    /// Sends `data` on API route `route` to member `node` (key, prefix or name), straight or
    /// through relays. Like UDP: no answer, delivery not guaranteed; the route must be ours.
    pub async fn send_net(&self, route: u8, node: &str, data: &[u8]) -> Result<(), Error> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::PacketTooLarge { len: data.len(), max: MAX_PAYLOAD });
        }
        let m = map(vec![
            ("type", "net".into()),
            ("rou", route.into()),
            ("key", node.into()),
            ("pack", Value::Binary(data.to_vec())),
        ]);
        self.shared.sock.send(&encode(&m)).await.map_err(Error::from)
    }

    /// Packets members send to the routes this client holds.
    pub fn net_packets(&self) -> broadcast::Receiver<NetPacket> {
        self.shared.net.subscribe()
    }

    /// Any request: `{"type": kind, "req": req, ...fields}`; its `res`, or the node's error.
    pub async fn raw(&self, kind: &str, req: &str, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        self.request(kind, Some(req), fields).await
    }

    fn message(&self, kind: &str, req: Option<&str>, id: u64, fields: Vec<(&str, Value)>) -> Vec<u8> {
        let mut m = vec![("type", Value::from(kind)), ("id", Value::from(id))];
        if let Some(r) = req {
            m.push(("req", r.into()));
        }
        if let Some(t) = &self.token {
            m.push(("token", t.as_str().into()));
        }
        m.extend(fields);
        encode(&map(m))
    }

    async fn request(&self, kind: &str, req: Option<&str>, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = self.message(kind, req, id, fields);
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(id, tx);
        if let Err(e) = self.shared.sock.send(&msg).await {
            self.shared.pending.lock().await.remove(&id);
            return Err(e.into());
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => {
                self.shared.pending.lock().await.remove(&id);
                Err(Error::Timeout)
            }
        }
    }

    async fn get<T: DeserializeOwned>(&self, req: &str, fields: Vec<(&str, Value)>) -> Result<T, Error> {
        from_value(self.raw("get", req, fields).await?)
    }

    pub async fn status(&self) -> Result<Status, Error> {
        self.get("status", Vec::new()).await
    }

    pub async fn version(&self) -> Result<Version, Error> {
        self.get("version", Vec::new()).await
    }

    pub async fn neighbors(&self) -> Result<Vec<Neighbor>, Error> {
        self.list("neighbors").await
    }

    pub async fn routes(&self) -> Result<Routes, Error> {
        match self.get::<Routes>("routes", Vec::new()).await {
            Err(e) if e.code() == Some(&ErrorCode::TooLarge) => {
                let mut all: Option<Routes> = None;
                let mut offset = 0;
                loop {
                    let part: Routes = self.get("routes", page(offset)).await?;
                    let total = part.mesh_total.max(part.ckr_total).unwrap_or(0) as usize;
                    let got = part.mesh.len().max(part.ckr.len());
                    match &mut all {
                        None => all = Some(part),
                        Some(a) => {
                            a.mesh.extend(part.mesh);
                            a.ckr.extend(part.ckr);
                        }
                    }
                    offset += PAGE;
                    if got == 0 || offset >= total {
                        return Ok(all.expect("a page"));
                    }
                }
            }
            r => r,
        }
    }

    pub async fn metrics(&self) -> Result<Metrics, Error> {
        match self.get::<Metrics>("metrics", Vec::new()).await {
            Err(e) if e.code() == Some(&ErrorCode::TooLarge) => {
                let mut all: Metrics = self.get("metrics", page(0)).await?;
                let total = all.peers_total.unwrap_or(0) as usize;
                while all.peers.len() < total {
                    let part: Metrics = self.get("metrics", page(all.peers.len())).await?;
                    if part.peers.is_empty() {
                        break;
                    }
                    all.peers.extend(part.peers);
                }
                Ok(all)
            }
            r => r,
        }
    }

    /// A list request; too large for one datagram, it is fetched in parts.
    async fn list<T: DeserializeOwned>(&self, req: &str) -> Result<Vec<T>, Error> {
        match self.get::<Vec<T>>(req, Vec::new()).await {
            Err(e) if e.code() == Some(&ErrorCode::TooLarge) => {
                let mut all = Vec::new();
                loop {
                    let part: Vec<T> = self.get(req, page(all.len())).await?;
                    let n = part.len();
                    all.extend(part);
                    if n < PAGE {
                        return Ok(all);
                    }
                }
            }
            r => r,
        }
    }

    /// The hops to `node` (a key, key prefix or member name); None: no path now.
    pub async fn path(&self, node: &str) -> Result<Option<Vec<Hop>>, Error> {
        self.get("path", vec![("key", node.into())]).await
    }

    /// The round trip to `node` over our session with it; None: no answer within 2 s.
    pub async fn ping(&self, node: &str) -> Result<Option<Ping>, Error> {
        self.get("ping", vec![("key", node.into())]).await
    }

    pub async fn group(&self) -> Result<Group, Error> {
        self.get("group", Vec::new()).await
    }

    /// Everybody in the group, offline and revoked ones included, by name.
    pub async fn members(&self) -> Result<Vec<Member>, Error> {
        self.list("members").await
    }

    pub async fn exit(&self) -> Result<Exit, Error> {
        self.get("exit", Vec::new()).await
    }

    /// Changes `[exit]` (like `dvpn exit`); answers the new state.
    pub async fn set_exit(&self, u: &ExitUpdate) -> Result<Exit, Error> {
        let list = |l: &Vec<String>| Value::Array(l.iter().map(|s| Value::from(s.as_str())).collect());
        let mut f = Vec::new();
        if u.clear {
            f.push(("clear", Value::from(true)));
        }
        if let Some(l) = &u.v4 {
            f.push(("v4", list(l)));
        }
        if let Some(l) = &u.v6 {
            f.push(("v6", list(l)));
        }
        if let Some(k) = u.kill_switch {
            f.push(("kill_switch", k.map_or(Value::Nil, Value::from)));
        }
        if let Some(l) = &u.dns {
            f.push(("dns", list(l)));
        }
        if let Some(l) = &u.sources {
            f.push(("sources", list(l)));
        }
        if let Some(t) = u.table {
            f.push(("table", t.map_or(Value::Nil, Value::from)));
        }
        from_value(self.raw("set", "exit", f).await?)
    }

    pub async fn acl(&self) -> Result<Acl, Error> {
        self.get("acl", Vec::new()).await
    }

    /// The ports forwarded on this node, or what admins set for gateway `on`.
    pub async fn forwards(&self, on: Option<&str>) -> Result<Forwards, Error> {
        self.get("forward", on.map(|o| ("on", Value::from(o))).into_iter().collect()).await
    }

    /// Makes `rules` the ports forwarded on this node. With `on`: on that gateway, which needs
    /// `allow_remote`, and the node must hold the group secret. Answers the new state.
    pub async fn set_forwards(&self, on: Option<&str>, rules: &[ForwardRule]) -> Result<Forwards, Error> {
        let list = rules
            .iter()
            .map(|r| {
                Value::Map(vec![
                    ("proto".into(), r.proto.as_str().into()),
                    ("port".into(), r.port.into()),
                    ("to".into(), r.to.as_str().into()),
                    ("to_port".into(), r.to_port.into()),
                    ("keep_ip".into(), r.keep_ip.into()),
                ])
            })
            .collect();
        let mut f = vec![("rules", Value::Array(list))];
        f.extend(on.map(|o| ("on", Value::from(o))));
        from_value(self.raw("set", "forward", f).await?)
    }

    // ---- admin operations (the node must hold the group secret, else `ErrorCode::NotAdmin`) ----

    /// An invite for one new node.
    pub async fn invite(&self, r: &InviteRequest) -> Result<InviteMade, Error> {
        let mut f = vec![("name", Value::from(r.name.as_str())), ("relay", Value::from(r.relay))];
        if let Some(a) = &r.addr {
            f.push(("addr", a.as_str().into()));
        }
        if let Some(h) = r.ttl_hours {
            f.push(("ttl_hours", h.into()));
        }
        f.push(("statics", strings(&r.statics)));
        f.push(("routes", strings(&r.routes)));
        from_value(self.raw("set", "invite", f).await?)
    }

    /// Issues member `node` (key, key prefix or name) a new certificate with `ch` applied.
    pub async fn set_node(&self, node: &str, ch: &NodeChange) -> Result<NodeCert, Error> {
        let mut f = vec![("key", Value::from(node))];
        if let Some(n) = &ch.name {
            f.push(("name", n.as_str().into()));
        }
        if let Some(a) = &ch.addr {
            f.push(("addr", a.as_str().into()));
        }
        f.push(("add_routes", strings(&ch.add_routes)));
        f.push(("del_routes", strings(&ch.del_routes)));
        if let Some(r) = ch.relay {
            f.push(("relay", r.into()));
        }
        from_value(self.raw("set", "node", f).await?)
    }

    /// Excludes member `node` from the group; with `rotate_in` also changes the psk that many
    /// seconds later (so the revoked node cannot unmask headers any more; 120 is the CLI's
    /// default).
    pub async fn revoke(&self, node: &str, rotate_in: Option<u64>) -> Result<Revoked, Error> {
        let mut f = vec![("key", Value::from(node)), ("rotate", Value::from(rotate_in.is_some()))];
        if let Some(s) = rotate_in {
            f.push(("lead_secs", s.into()));
        }
        from_value(self.raw("set", "revoke", f).await?)
    }

    /// A new group psk in `lead_secs` seconds.
    pub async fn rotate(&self, lead_secs: u64) -> Result<Rotated, Error> {
        from_value(self.raw("set", "rotate", vec![("lead_secs", lead_secs.into())]).await?)
    }

    /// Makes `toml` (`doc/acl.md`) the group's access rules.
    pub async fn set_acl(&self, toml: &str) -> Result<Acl, Error> {
        from_value(self.raw("set", "acl", vec![("toml", toml.into())]).await?)
    }

    /// Removes the group's access rules.
    pub async fn clear_acl(&self) -> Result<Acl, Error> {
        from_value(self.raw("del", "acl", Vec::new()).await?)
    }

    /// Drops the current connection to `node`: it is made again from scratch.
    pub async fn reset_endpoint(&self, node: &str) -> Result<(), Error> {
        self.raw("del", "peer_endpoint", vec![("key", node.into())]).await.map(|_| ())
    }
}

/// Entries per part when an answer is too large for one datagram (a member is ~300 bytes).
const PAGE: usize = 100;

fn page(offset: usize) -> Vec<(&'static str, Value)> {
    vec![("offset", (offset as u64).into()), ("limit", (PAGE as u64).into())]
}

fn strings(l: &[String]) -> Value {
    Value::Array(l.iter().map(|s| Value::from(s.as_str())).collect())
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shared.sock.try_send(&encode(&map(vec![("type", "close".into())])));
        self.task.abort();
    }
}

async fn recv_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match shared.sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                // UDP: the node is not there (ICMP port unreachable); answers time out
                log::debug!("dvpn-client | recv: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Some(v) = decode(&buf[..n]) else { continue };
        match field_str(&v, "type") {
            Some("res") => {
                let Some(id) = field(&v, "id").and_then(Value::as_u64) else { continue };
                let Some(tx) = shared.pending.lock().await.remove(&id) else { continue };
                let reply = match field_str(&v, "err") {
                    Some(code) => Err(Error::Api {
                        code: ErrorCode::from(code),
                        msg: field_str(&v, "msg").unwrap_or_default().to_owned(),
                    }),
                    None => Ok(field(&v, "res").cloned().unwrap_or(Value::Nil)),
                };
                let _ = tx.send(reply);
            }
            Some("init") => {
                if let Some(tx) = shared.init.lock().await.take() {
                    let _ = tx.send(Ok(v));
                } else {
                    // introduced ourselves again: the node forgot our subscription and routes too
                    if let Some(sub) = shared.sub.lock().await.clone() {
                        let _ = shared.sock.send(&sub).await;
                    }
                    let again: Vec<Vec<u8>> = shared.routes.lock().await.values().cloned().collect();
                    for m in again {
                        let _ = shared.sock.send(&m).await;
                    }
                }
            }
            Some("net") => {
                let route = field(&v, "rou").and_then(Value::as_u64).and_then(|r| u8::try_from(r).ok());
                let key = field_str(&v, "key").map(str::to_owned);
                let data = field(&v, "pack").and_then(|p| p.as_slice()).map(<[u8]>::to_vec);
                if let (Some(route), Some(key), Some(data)) = (route, key, data) {
                    let _ = shared.net.send(NetPacket { route, key, data });
                }
                let _ = shared.events.send(v);
            }
            Some("event") => {
                if let Some(e) = field(&v, "event") {
                    match rmpv::ext::from_value::<Event>(e.clone()) {
                        Ok(e) => {
                            let _ = shared.typed.send(e);
                        }
                        Err(err) => log::debug!("dvpn-client | event not understood: {err}: {e}"),
                    }
                }
                let _ = shared.events.send(v);
            }
            Some("error") => {
                let code = field_str(&v, "err").unwrap_or_default();
                let msg = field_str(&v, "msg").unwrap_or_default().to_owned();
                if code == ErrorCode::VersionUnsupported.as_str() {
                    let num = |k| field(&v, k).and_then(Value::as_u64).unwrap_or_default();
                    if let Some(tx) = shared.init.lock().await.take() {
                        let _ = tx.send(Err(Error::VersionUnsupported { min: num("min"), max: num("max"), msg }));
                        continue;
                    }
                }
                log::warn!("dvpn-client | node: {msg} ({code})");
            }
            Some("ping") => {
                let _ = shared.sock.send(&encode(&map(vec![("type", "pong".into())]))).await;
            }
            Some("close") => {
                // the node forgot us (restarted, or we missed its pings): introduce ourselves again
                log::debug!("dvpn-client | the node closed the connection, init again");
                let _ = shared.sock.send(&shared.init_msg()).await;
            }
            _ => {
                let _ = shared.events.send(v);
            }
        }
    }
}
