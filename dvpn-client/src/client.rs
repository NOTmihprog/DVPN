use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rmpv::Value;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::pipe::{PIPE_QUEUE, Pipe, PipeSlot};
use crate::transport::Socket;
use crate::types::*;
use crate::wire::{decode, encode, field, field_str, from_value, map};
use crate::{API_VERSION, ApiAddr, Error, ErrorCode};

/// How long a request waits for its answer (`ping` waits up to 2 s for the member).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

type Reply = Result<Value, Error>;

/// How long the node may say nothing before the client asks whether it is still there.
pub const SILENCE: Duration = Duration::from_secs(10);
/// How often that is looked at.
const LIVENESS: Duration = Duration::from_secs(5);
/// How long a liveness probe may take, sending included.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long sending `init` to a new socket may wait for room.
const INIT_SEND: Duration = Duration::from_secs(1);
/// How soon a route the node still holds for our old address is asked for again.
#[cfg(not(test))]
const RESTORE_RETRY: Duration = Duration::from_secs(5);
#[cfg(test)]
const RESTORE_RETRY: Duration = Duration::from_millis(200);

pub(crate) struct Shared {
    /// Made again when the node went away and came back (see [`Shared::reopen`]).
    sock: std::sync::RwLock<Arc<Socket>>,
    addr: ApiAddr,
    abstract_addr: bool,
    /// When the node last sent anything.
    heard: std::sync::Mutex<std::time::Instant>,
    /// Asks the receive task to make the socket again.
    reopen: tokio::sync::Notify,
    /// Ids of the client's own requests: probes and restoring (apart from the user's).
    own_id: AtomicU64,
    name: String,
    /// Sent with every request to a UDP API (`ApiAddr::find_token`); read again when the client
    /// introduces itself again, since a restarted node makes a new one.
    token: std::sync::RwLock<Option<String>>,
    /// Given by [`Client::with_token`]: not read again.
    token_fixed: AtomicBool,
    /// Bumped by every restore (and by dropping the client): an older one stops.
    restoring: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    /// The answer to our `init`, while we wait for it.
    init: Mutex<Option<oneshot::Sender<Reply>>>,
    events: broadcast::Sender<Value>,
    typed: broadcast::Sender<Event>,
    net: broadcast::Sender<NetPacket>,
    /// The fields of the last `sub`, sent again when the node forgot us.
    sub: std::sync::Mutex<Option<Vec<(&'static str, Value)>>>,
    /// API routes this client holds: taken again when the node forgot us.
    pub(crate) routes: std::sync::Mutex<BTreeSet<u8>>,
    /// Routes with a [`Pipe`]: their packets go to it alone.
    pub(crate) pipes: std::sync::Mutex<HashMap<u8, PipeSlot>>,
}

impl Shared {
    /// The socket to the node as it is now.
    pub(crate) fn sock(&self) -> Arc<Socket> {
        self.sock.read().unwrap().clone()
    }

    /// `{"type": kind, "id": id, "req": req, "token": .., ...fields}`.
    pub(crate) fn message(&self, kind: &str, req: Option<&str>, id: u64, fields: Vec<(&str, Value)>) -> Vec<u8> {
        let mut m = vec![("type", Value::from(kind)), ("id", Value::from(id))];
        if let Some(r) = req {
            m.push(("req", r.into()));
        }
        if let Some(t) = &*self.token.read().unwrap() {
            m.push(("token", t.as_str().into()));
        }
        m.extend(fields);
        encode(&map(m))
    }

    /// Sends request `id` and waits for its answer, the sending within `wait` too: a node that
    /// stopped reading fills the socket, and the send would wait for it forever.
    async fn request(
        &self,
        id: u64,
        kind: &str,
        req: Option<&str>,
        fields: Vec<(&str, Value)>,
        wait: Duration,
    ) -> Result<Value, Error> {
        let msg = self.message(kind, req, id, fields);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let r = tokio::time::timeout(wait, async {
            self.sock().send(&msg).await?;
            rx.await.unwrap_or(Err(Error::Closed))
        })
        .await
        .unwrap_or(Err(Error::Timeout));
        if r.is_err() {
            self.pending.lock().await.remove(&id);
        }
        r
    }

    /// A request of the client's own.
    async fn own_request(&self, kind: &str, req: Option<&str>, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        let id = self.own_id.fetch_add(1, Ordering::Relaxed);
        self.request(id, kind, req, fields, DEFAULT_TIMEOUT).await
    }

    /// Asks the node something cheap; whether it answered in time (an error is an answer too).
    async fn probe(&self) -> bool {
        let id = self.own_id.fetch_add(1, Ordering::Relaxed);
        matches!(
            self.request(id, "get", Some("version"), Vec::new(), PROBE_TIMEOUT).await,
            Ok(_) | Err(Error::Api { .. })
        )
    }

    /// Reads the token again: a restarted UDP node made a new one.
    fn refresh_token(&self) {
        if self.token_fixed.load(Ordering::Relaxed) {
            return;
        }
        if let Some(t) = self.addr.find_token() {
            *self.token.write().unwrap() = Some(t);
        }
    }

    /// A new socket to the node and `init` again; its answer brings back the subscription and
    /// the routes (see `recv_loop`). A unix socket must be made again: one with an abstract
    /// address is connected to the old node's socket, and the kernel drops what the new node
    /// sends to it.
    async fn reopen_socket(&self) {
        match Socket::open(&self.addr, self.abstract_addr).await {
            Ok(s) => {
                // a node that was only paused still holds our routes for the old address: let
                // it go of them first (no waiting: the old socket may be full)
                let close = encode(&map(vec![("type", "close".into())]));
                let old = std::mem::replace(&mut *self.sock.write().unwrap(), Arc::new(s));
                let _ = old.try_send(&close);
                log::debug!("dvpn-client | the node did not answer: a new socket, init again");
                self.refresh_token();
                let _ = tokio::time::timeout(INIT_SEND, self.sock().send(&self.init_msg())).await;
            }
            Err(e) => log::debug!("dvpn-client | the node is not back yet: {e}"),
        }
    }

    fn init_msg(&self) -> Vec<u8> {
        let mut m = vec![("type", "init".into()), ("name", self.name.as_str().into()), ("version", API_VERSION.into())];
        // a UDP node with `[api] token = "all"` lets nobody in without it
        if let Some(t) = &*self.token.read().unwrap() {
            m.push(("token", t.as_str().into()));
        }
        encode(&map(m))
    }
}

/// A connection to a node's API. Answers the node's pings and introduces itself again when the
/// node forgets it (`close`); when the node is silent for [`SILENCE`] and does not answer two
/// probes (it was restarted, or killed and started again), the socket is made again and the
/// subscription and routes (pipes too) are taken again. So it can be kept for as long as the
/// program runs.
pub struct Client {
    shared: Arc<Shared>,
    next_id: AtomicU64,
    timeout: Duration,
    info: InitInfo,
    task: tokio::task::JoinHandle<()>,
    live: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Connects to the node at `addr` as `name` (shown in the node's log). For a UDP API it
    /// finds the token itself ([`ApiAddr::find_token`]); without it only reading works.
    pub async fn connect(addr: ApiAddr, name: &str) -> Result<Client, Error> {
        // a unix socket: an abstract address first (Linux; see transport.rs), which a node
        // older than 4.2.1 leaves unanswered: then a file
        if cfg!(any(target_os = "linux", target_os = "android")) && matches!(addr, ApiAddr::Unix(_)) {
            match Self::connect_on(&addr, name, None, true, Duration::from_millis(1500)).await {
                Err(Error::Timeout) => {}
                r => return r,
            }
        }
        Self::connect_on(&addr, name, None, false, DEFAULT_TIMEOUT).await
    }

    /// Like [`Client::connect`], with this token for a UDP API: where `[api] token = "all"` is set
    /// and the token is not in its usual place, [`Client::with_token`] would come too late.
    pub async fn connect_with_token(addr: ApiAddr, name: &str, token: &str) -> Result<Client, Error> {
        Self::connect_on(&addr, name, Some(token), false, DEFAULT_TIMEOUT).await
    }

    async fn connect_on(
        addr: &ApiAddr,
        name: &str,
        given: Option<&str>,
        abstract_addr: bool,
        wait: Duration,
    ) -> Result<Client, Error> {
        let token = given.map(str::to_owned).or_else(|| addr.find_token());
        let sock = Socket::open(addr, abstract_addr).await?;
        let (events, _) = broadcast::channel(256);
        let (typed, _) = broadcast::channel(256);
        let (net, _) = broadcast::channel(1024);
        let shared = Arc::new(Shared {
            sock: std::sync::RwLock::new(Arc::new(sock)),
            addr: addr.clone(),
            abstract_addr,
            heard: std::sync::Mutex::new(std::time::Instant::now()),
            reopen: tokio::sync::Notify::new(),
            own_id: AtomicU64::new(1 << 62),
            name: name.to_owned(),
            token: std::sync::RwLock::new(token),
            token_fixed: AtomicBool::new(given.is_some()),
            restoring: AtomicU64::new(0),
            pending: Mutex::default(),
            init: Mutex::default(),
            events,
            typed,
            net,
            sub: Default::default(),
            routes: Default::default(),
            pipes: Default::default(),
        });
        let task = tokio::spawn(recv_loop(shared.clone()));
        let live = tokio::spawn(liveness(Arc::downgrade(&shared)));
        let (tx, rx) = oneshot::channel();
        *shared.init.lock().await = Some(tx);
        shared.sock().send(&shared.init_msg()).await?;
        let answer = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => Err(Error::Timeout),
        };
        let info = match answer.and_then(from_value::<InitInfo>) {
            Ok(i) => i,
            Err(e) => {
                task.abort();
                live.abort();
                return Err(e);
            }
        };
        Ok(Client { shared, next_id: AtomicU64::new(1), timeout: DEFAULT_TIMEOUT, info, task, live })
    }

    /// Uses `token` for a UDP API instead of the one found (also after the node restarts).
    pub fn with_token(self, token: impl Into<String>) -> Self {
        *self.shared.token.write().unwrap() = Some(token.into());
        self.shared.token_fixed.store(true, Ordering::Relaxed);
        self
    }

    /// Whether a token for changes is at hand (always false on a unix socket, which needs none).
    pub fn has_token(&self) -> bool {
        self.shared.token.read().unwrap().is_some()
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
        self.request("sub", None, f.clone()).await?;
        *self.shared.sub.lock().unwrap() = Some(f);
        Ok(())
    }

    // ---- API routes: a protocol of one's own over the network ----

    /// Takes API route `route` (32..=255): packets members send to it come to this client
    /// ([`Client::net_packets`]). Taken again by itself if the node restarts.
    pub async fn route_reg(&self, route: u8) -> Result<(), Error> {
        self.request("route", Some("reg"), vec![("route", Value::from(route))]).await?;
        self.shared.routes.lock().unwrap().insert(route);
        Ok(())
    }

    /// Takes API route `route` as a [`Pipe`]: its packets go to the pipe alone, through a queue of
    /// [`PIPE_QUEUE`] packets (see [`Client::pipe_with_queue`]). Dropping the pipe gives the route
    /// back.
    pub async fn pipe(&self, route: u8) -> Result<Pipe, Error> {
        self.pipe_with_queue(route, PIPE_QUEUE).await
    }

    /// [`Client::pipe`] with a queue of `queue` packets: what comes while it is full is dropped
    /// and counted ([`PipeReceiver::dropped`]).
    pub async fn pipe_with_queue(&self, route: u8, queue: usize) -> Result<Pipe, Error> {
        let (tx, rx) = tokio::sync::mpsc::channel(queue.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        {
            let mut pipes = self.shared.pipes.lock().unwrap();
            if pipes.contains_key(&route) {
                return Err(Error::Api {
                    code: ErrorCode::RouteExist,
                    msg: format!("route {route}: this client has a pipe on it already"),
                });
            }
            pipes.insert(route, PipeSlot { tx, dropped: dropped.clone() });
        }
        if let Err(e) = self.route_reg(route).await {
            self.shared.pipes.lock().unwrap().remove(&route);
            return Err(e);
        }
        Ok(Pipe::new(self.shared.clone(), route, rx, dropped))
    }

    /// Gives API route `route` back.
    pub async fn route_del(&self, route: u8) -> Result<(), Error> {
        self.shared.routes.lock().unwrap().remove(&route);
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
        self.shared.sock().send(&encode(&m)).await.map_err(Error::from)
    }

    /// Packets members send to the routes this client holds, but for those with a [`Pipe`].
    pub fn net_packets(&self) -> broadcast::Receiver<NetPacket> {
        self.shared.net.subscribe()
    }

    /// Any request: `{"type": kind, "req": req, ...fields}`; its `res`, or the node's error.
    pub async fn raw(&self, kind: &str, req: &str, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        self.request(kind, Some(req), fields).await
    }

    async fn request(&self, kind: &str, req: Option<&str>, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.shared.request(id, kind, req, fields, self.timeout).await
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
        if let Some(o) = &u.only_file {
            f.push(("only_file", o.as_deref().map_or(Value::Nil, Value::from)));
        }
        if let Some(p) = u.pause {
            f.push((
                "pause",
                match p {
                    ExitPause::Off => false.into(),
                    ExitPause::On => true.into(),
                    ExitPause::Secs(s) => s.into(),
                },
            ));
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

    /// Replaces member `node`, which is lost for good: revokes it and makes an invite for a new
    /// node with its name, address, subnets and relay role. `ttl_hours`, `statics`: as in
    /// [`InviteRequest`]. Older nodes answer `ErrorCode::UnknownRequest`.
    pub async fn replace(&self, node: &str, ttl_hours: Option<u64>, statics: &[String]) -> Result<InviteMade, Error> {
        let mut f = vec![("key", Value::from(node)), ("statics", strings(statics))];
        f.extend(ttl_hours.map(|h| ("ttl_hours", h.into())));
        from_value(self.raw("set", "replace", f).await?)
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
        let _ = self.shared.sock().try_send(&encode(&map(vec![("type", "close".into())])));
        self.shared.restoring.fetch_add(1, Ordering::Relaxed);
        self.task.abort();
        self.live.abort();
        // pipes see the end
        self.shared.pipes.lock().unwrap().clear();
    }
}

/// Asks the node after a silence; two unanswered probes in a row make the socket again.
async fn liveness(shared: std::sync::Weak<Shared>) {
    let mut misses = 0;
    loop {
        tokio::time::sleep(LIVENESS).await;
        let Some(s) = shared.upgrade() else { return };
        if s.heard.lock().unwrap().elapsed() < SILENCE {
            misses = 0;
            continue;
        }
        if s.probe().await {
            misses = 0;
            continue;
        }
        misses += 1;
        if misses >= 2 {
            s.reopen.notify_one();
            misses = 0;
        }
    }
}

/// After `init` again: the subscription and the routes again. A route the node still holds for
/// our old address (it was only paused, and our `close` from there was lost) is asked for again
/// until the node lets it go: the old address is closed when it stops answering pings. Stops
/// when a newer restore starts or the client is gone.
async fn restore(shared: std::sync::Weak<Shared>) {
    let Some(s) = shared.upgrade() else { return };
    let generation = s.restoring.fetch_add(1, Ordering::Relaxed) + 1;
    let mut sub = s.sub.lock().unwrap().clone();
    let mut left: BTreeSet<u8> = s.routes.lock().unwrap().clone();
    drop(s);
    loop {
        let Some(s) = shared.upgrade() else { return };
        if s.restoring.load(Ordering::Relaxed) != generation {
            return;
        }
        if let Some(f) = &sub {
            match s.own_request("sub", None, f.clone()).await {
                Err(Error::Timeout) => {}
                Err(e) => {
                    log::warn!("dvpn-client | subscription not taken again: {e}");
                    sub = None;
                }
                Ok(_) => sub = None,
            }
        }
        // only what is still ours: a route given back meanwhile is not taken again
        left.retain(|r| s.routes.lock().unwrap().contains(r));
        for r in left.clone() {
            match s.own_request("route", Some("reg"), vec![("route", Value::from(r))]).await {
                Ok(_) => {
                    left.remove(&r);
                }
                Err(Error::Timeout) => {}
                Err(e) if e.code() == Some(&ErrorCode::RouteExist) => {
                    log::debug!("dvpn-client | route {r} still held for our old address, again later");
                }
                Err(e) => {
                    log::warn!("dvpn-client | route {r} not taken again: {e}");
                    left.remove(&r);
                }
            }
        }
        if sub.is_none() && left.is_empty() {
            return;
        }
        drop(s);
        tokio::time::sleep(RESTORE_RETRY).await;
    }
}

async fn recv_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let sock = shared.sock();
        let got = tokio::select! {
            r = sock.recv(&mut buf) => Some(r),
            _ = shared.reopen.notified() => None,
        };
        let Some(got) = got else {
            shared.reopen_socket().await;
            continue;
        };
        let n = match got {
            Ok(n) => {
                *shared.heard.lock().unwrap() = std::time::Instant::now();
                n
            }
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
                    // (asked in a task of its own: its answers come through this loop)
                    tokio::spawn(restore(Arc::downgrade(&shared)));
                }
            }
            Some("net") => {
                let route = field(&v, "rou").and_then(Value::as_u64).and_then(|r| u8::try_from(r).ok());
                let key = field_str(&v, "key").map(str::to_owned);
                let data = field(&v, "pack").and_then(|p| p.as_slice()).map(<[u8]>::to_vec);
                if let (Some(route), Some(key), Some(data)) = (route, key, data) {
                    let p = NetPacket { route, key, data };
                    if let Some(slot) = shared.pipes.lock().unwrap().get(&route) {
                        // a pipe's packets go to it alone: no copies, and a slow pipe holds up nobody
                        if slot.tx.try_send(p).is_err() {
                            slot.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    let _ = shared.net.send(p);
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
                if code == ErrorCode::NotPermitted.as_str()
                    && let Some(tx) = shared.init.lock().await.take()
                {
                    let _ = tx.send(Err(Error::Api { code: ErrorCode::NotPermitted, msg }));
                    continue;
                }
                if code == ErrorCode::VersionUnsupported.as_str() {
                    let num = |k| field(&v, k).and_then(Value::as_u64).unwrap_or_default();
                    if let Some(tx) = shared.init.lock().await.take() {
                        let _ = tx.send(Err(Error::VersionUnsupported { min: num("min"), max: num("max"), msg }));
                        continue;
                    }
                }
                log::warn!("dvpn-client | node: {msg} ({code})");
            }
            // no waiting to send in this loop: a node that stopped reading would stop it too
            Some("ping") => {
                let _ = shared.sock().try_send(&encode(&map(vec![("type", "pong".into())])));
            }
            Some("close") => {
                // the node forgot us (restarted, or we missed its pings): introduce ourselves
                // again, with its token as it is now
                log::debug!("dvpn-client | the node closed the connection, init again");
                shared.refresh_token();
                let _ = shared.sock().try_send(&shared.init_msg());
            }
            _ => {
                let _ = shared.events.send(v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    fn res(id: Option<&Value>, err: Option<&str>) -> Vec<u8> {
        let mut m = vec![("type", Value::from("res")), ("id", id.cloned().unwrap_or(Value::Nil))];
        match err {
            Some(e) => m.extend([("err", Value::from(e)), ("msg", Value::from(e))]),
            None => m.push(("res", Value::Nil)),
        }
        encode(&map(m))
    }

    /// A node on UDP that knows `init` and `route reg`: refuses a wrong token, answers
    /// `route_exist` once when told to, and reports the routes it gave (with the token used).
    async fn fake_node(
        sock: Arc<UdpSocket>,
        token: Arc<std::sync::Mutex<String>>,
        exist_once: Arc<AtomicBool>,
        client: Arc<std::sync::Mutex<Option<SocketAddr>>>,
        got: tokio::sync::mpsc::UnboundedSender<(u8, String)>,
    ) {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
            *client.lock().unwrap() = Some(from);
            let Some(v) = decode(&buf[..n]) else { continue };
            let reply = match field_str(&v, "type") {
                Some("init") => encode(&map(vec![
                    ("type", "init".into()),
                    ("version", API_VERSION.into()),
                    ("min_version", API_VERSION.into()),
                    ("key", "k".into()),
                    ("name", "fake".into()),
                    ("group", "g".into()),
                    ("group_name", "g".into()),
                    ("admin", false.into()),
                    ("node_version", "0".into()),
                ])),
                Some("route") => {
                    let given = field_str(&v, "token").unwrap_or_default().to_owned();
                    if given != *token.lock().unwrap() {
                        res(field(&v, "id"), Some("not_permitted"))
                    } else if exist_once.swap(false, Ordering::SeqCst) {
                        res(field(&v, "id"), Some("route_exist"))
                    } else {
                        let r = field(&v, "route").and_then(Value::as_u64).unwrap() as u8;
                        let _ = got.send((r, given));
                        res(field(&v, "id"), None)
                    }
                }
                _ => continue,
            };
            let _ = sock.send_to(&reply, from).await;
        }
    }

    /// The node restarts with a new token while it still holds our route: the client reads the
    /// token again and asks for the route until it is free.
    #[tokio::test]
    async fn routes_come_back_with_the_new_token_after_route_exist() {
        let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(|d| std::path::PathBuf::from(d).join("dvpn")) else {
            return;
        };
        if std::env::var_os(crate::addr::TOKEN_ENV).is_some() {
            return;
        }
        std::fs::create_dir_all(&dir).unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let file = dir.join(format!("api-{}.token", addr.port()));
        std::fs::write(&file, "first").unwrap();
        let token = Arc::new(std::sync::Mutex::new("first".to_owned()));
        let exist_once = Arc::new(AtomicBool::new(false));
        let client_at = Arc::new(std::sync::Mutex::new(None));
        let (tx, mut got) = tokio::sync::mpsc::unbounded_channel();
        let node = tokio::spawn(fake_node(sock.clone(), token.clone(), exist_once.clone(), client_at.clone(), tx));

        let c = Client::connect(ApiAddr::Udp(addr), "test").await.unwrap();
        c.route_reg(42).await.unwrap();
        assert_eq!(got.recv().await.unwrap(), (42, "first".to_owned()));

        // "restarted": a new token, our route still held for the old address, and we are forgotten
        std::fs::write(&file, "second").unwrap();
        *token.lock().unwrap() = "second".to_owned();
        exist_once.store(true, Ordering::SeqCst);
        let at = client_at.lock().unwrap().unwrap();
        sock.send_to(&encode(&map(vec![("type", "close".into())])), at).await.unwrap();

        let back = tokio::time::timeout(Duration::from_secs(10), got.recv()).await;
        let _ = std::fs::remove_file(&file);
        assert_eq!(back.expect("the route did not come back").unwrap(), (42, "second".to_owned()));
        assert!(!exist_once.load(Ordering::SeqCst), "route_exist was answered once");
        drop(c);
        node.abort();
    }
}
