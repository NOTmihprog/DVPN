use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use serde_json::{Map, Value};
use tokio::sync::broadcast;

use crate::group::Cert;
use crate::identity::NodeId;
use crate::logger::node;

#[derive(Clone, Debug)]
pub struct PeerRecord {
    /// The node key.
    pub peer_id: NodeId,
    pub name: Option<String>,
    pub addr: Option<Ipv4Addr>,
    pub sub_args: Option<Map<String, Value>>,
}

impl PeerRecord {
    pub fn new(peer_id: NodeId) -> Self {
        PeerRecord { peer_id, name: None, addr: None, sub_args: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// Neither a valid key nor a prefix of a known one.
    NotFound,
    /// The prefix matches this many known keys.
    Ambiguous(usize),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound => f.write_str("neither a valid node key nor a prefix of a known one"),
            ResolveError::Ambiguous(n) => write!(f, "prefix matches {n} known keys, give more characters"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Each field: `None` = leave unchanged, `Some(v)` = set to `v` (`Some(None)` clears).
#[derive(Default)]
pub struct PeerUpdate {
    pub name: Option<Option<String>>,
    pub addr: Option<Option<Ipv4Addr>>,
    pub endpoint: Option<Option<SocketAddr>>,
    pub sub_args: Option<Option<Map<String, Value>>>,
}

impl PeerUpdate {
    /// Name and address as the peer's (verified) membership certificate states them.
    pub fn from_cert(cert: &Cert) -> Self {
        PeerUpdate { name: Some(Some(cert.body.name.clone())), addr: Some(cert.body.ipv4()), ..Default::default() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Add,
    Update,
    Del,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Add => "add",
            Action::Update => "update",
            Action::Del => "del",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Peer { action: Action, record: PeerRecord, endpoint: Option<SocketAddr> },
    Server { addr: SocketAddr, connected: bool },
    Ping { peer_id: NodeId, ms: f64 },
}

/// Liveness of the direct link to a peer, reset whenever its endpoint changes.
#[derive(Clone, Copy)]
pub struct Link {
    pub since: Instant,
    pub last_seen: Option<Instant>,
    pub last_ping: Option<Instant>,
    pub rtt_ms: Option<f64>,
}

impl Link {
    fn new() -> Self {
        Link { since: Instant::now(), last_seen: None, last_ping: None, rtt_ms: None }
    }
}

struct Peer {
    rec: PeerRecord,
    endpoint: Option<SocketAddr>,
    link: Link,
}

impl Peer {
    fn new(rec: PeerRecord) -> Self {
        Peer { rec, endpoint: None, link: Link::new() }
    }
}

struct Inner {
    self_id: NodeId,
    order: Vec<NodeId>,
    peers: HashMap<NodeId, Peer>,
    by_endpoint: HashMap<SocketAddr, NodeId>,
    by_addr: HashMap<Ipv4Addr, NodeId>,
}

impl Inner {
    fn reindex_addr(&mut self) {
        self.by_addr.clear();
        for id in &self.order {
            if let Some(addr) = self.peers[id].rec.addr
                && let Some(other) = self.by_addr.insert(addr, *id)
            {
                log::warn!("PeerStorage | Peers {} and {} share addr {addr}, using {1}", node(other), node(*id));
            }
        }
    }

    fn set_endpoint(&mut self, id: NodeId, endpoint: Option<SocketAddr>) {
        let Some(p) = self.peers.get_mut(&id) else { return };
        if p.endpoint == endpoint {
            return;
        }
        if let Some(old) = p.endpoint.take() {
            self.by_endpoint.remove(&old);
        }
        p.endpoint = endpoint;
        p.link = Link::new();
        if let Some(ep) = endpoint {
            // An endpoint belongs to one peer only; a NAT may hand it over to another one.
            if let Some(prev) = self.by_endpoint.insert(ep, id)
                && prev != id
                && let Some(pp) = self.peers.get_mut(&prev)
            {
                pp.endpoint = None;
            }
        }
    }
}

/// A route to a peer, as needed by the packet path.
pub struct Route {
    pub peer_id: NodeId,
    pub endpoint: SocketAddr,
}

/// Everything the packet path reads, rebuilt (under the write lock) whenever peers,
/// addresses or endpoints change, so per-packet lookups take no lock.
#[derive(Default)]
struct PacketView {
    by_addr: HashMap<Ipv4Addr, Arc<Route>>,
    by_id: HashMap<NodeId, Arc<Route>>,
    /// LAN address of each peer, for checking the source of packets it sends us.
    addrs: HashMap<NodeId, Ipv4Addr>,
}

impl PacketView {
    fn build(inner: &Inner) -> Self {
        let by_id: HashMap<NodeId, Arc<Route>> = inner
            .peers
            .iter()
            .filter_map(|(id, p)| Some((*id, Arc::new(Route { peer_id: *id, endpoint: p.endpoint? }))))
            .collect();
        let by_addr = inner.by_addr.iter().filter_map(|(a, id)| Some((*a, by_id.get(id)?.clone()))).collect();
        let addrs = inner.peers.iter().filter_map(|(id, p)| Some((*id, p.rec.addr?))).collect();
        PacketView { by_addr, by_id, addrs }
    }
}

pub struct PeerStorage {
    inner: RwLock<Inner>,
    view: ArcSwap<PacketView>,
    events: broadcast::Sender<Event>,
}

impl PeerStorage {
    /// Peers live in memory only: they are learned from the tracker and from handshakes, each
    /// with its membership certificate (PLAN stage 3), so nothing needs to be kept on disk.
    pub fn new(self_id: NodeId) -> Self {
        let inner = Inner {
            self_id,
            order: vec![self_id],
            peers: HashMap::from([(self_id, Peer::new(PeerRecord::new(self_id)))]),
            by_endpoint: HashMap::new(),
            by_addr: HashMap::new(),
        };
        PeerStorage {
            view: ArcSwap::from_pointee(PacketView::build(&inner)),
            inner: RwLock::new(inner),
            events: broadcast::channel(1024).0,
        }
    }

    /// Call with the write lock held, after any change the packet path can see.
    fn publish(&self, inner: &Inner) {
        self.view.store(Arc::new(PacketView::build(inner)));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    pub fn self_id(&self) -> NodeId {
        self.inner.read().self_id
    }

    pub fn is_self(&self, id: &NodeId) -> bool {
        self.inner.read().self_id == *id
    }

    pub fn set_peer(&self, id: NodeId, u: PeerUpdate) {
        let event = {
            let mut inner = self.inner.write();
            let action = if inner.peers.contains_key(&id) {
                Action::Update
            } else {
                inner.order.push(id);
                inner.peers.insert(id, Peer::new(PeerRecord::new(id)));
                Action::Add
            };
            let p = inner.peers.get_mut(&id).unwrap();
            if let Some(name) = u.name {
                p.rec.name = name;
            }
            if let Some(sub_args) = u.sub_args {
                p.rec.sub_args = sub_args;
            }
            let addr_changed = u.addr.is_some_and(|a| a != p.rec.addr);
            if let Some(addr) = u.addr {
                p.rec.addr = addr;
            }
            if addr_changed {
                inner.reindex_addr();
            }
            if let Some(ep) = u.endpoint {
                inner.set_endpoint(id, ep);
            }
            self.publish(&inner);
            let p = &inner.peers[&id];
            Event::Peer { action, record: p.rec.clone(), endpoint: p.endpoint }
        };
        self.emit(event);
    }

    pub fn del_peer(&self, id: &NodeId) -> bool {
        let rec = {
            let mut inner = self.inner.write();
            inner.set_endpoint(*id, None);
            let Some(p) = inner.peers.remove(id) else { return false };
            inner.order.retain(|x| x != id);
            inner.reindex_addr();
            self.publish(&inner);
            p.rec
        };
        self.emit(Event::Peer { action: Action::Del, record: rec, endpoint: None });
        true
    }

    pub fn del_endpoint(&self, id: &NodeId) -> bool {
        let rec = {
            let mut inner = self.inner.write();
            if !inner.peers.contains_key(id) {
                return false;
            }
            inner.set_endpoint(*id, None);
            self.publish(&inner);
            inner.peers[id].rec.clone()
        };
        self.emit(Event::Peer { action: Action::Update, record: rec, endpoint: None });
        true
    }

    pub fn get(&self, id: &NodeId) -> Option<(PeerRecord, Option<SocketAddr>)> {
        let inner = self.inner.read();
        inner.peers.get(id).map(|p| (p.rec.clone(), p.endpoint))
    }

    pub fn list(&self) -> Vec<(PeerRecord, Option<SocketAddr>)> {
        let inner = self.inner.read();
        inner.order.iter().map(|id| (inner.peers[id].rec.clone(), inner.peers[id].endpoint)).collect()
    }

    pub fn ids(&self) -> Vec<NodeId> {
        self.inner.read().order.clone()
    }

    pub fn exists(&self, id: &NodeId) -> bool {
        self.inner.read().peers.contains_key(id)
    }

    pub fn name(&self, id: &NodeId) -> Option<String> {
        self.inner.read().peers.get(id).and_then(|p| p.rec.name.clone())
    }

    /// Like `name`, but gives up instead of waiting if the storage is locked (for the logger,
    /// which is called from inside storage methods that hold the write lock).
    pub fn name_if_unlocked(&self, id: &NodeId) -> Option<String> {
        self.inner.try_read()?.peers.get(id).and_then(|p| p.rec.name.clone())
    }

    pub fn endpoint(&self, id: &NodeId) -> Option<SocketAddr> {
        self.inner.read().peers.get(id).and_then(|p| p.endpoint)
    }

    /// A full node key (known or not), or a prefix that matches exactly one known key.
    /// The prefix may use the standard base64 alphabet (`+/`) too.
    pub fn resolve(&self, s: &str) -> Result<NodeId, ResolveError> {
        let s = s.trim();
        if let Ok(id) = s.parse() {
            return Ok(id);
        }
        if s.is_empty() {
            return Err(ResolveError::NotFound);
        }
        let prefix = s.replace('+', "-").replace('/', "_");
        let inner = self.inner.read();
        let mut hits = inner.order.iter().filter(|id| id.to_string().starts_with(&prefix));
        match (hits.next(), hits.count()) {
            (None, _) => Err(ResolveError::NotFound),
            (Some(id), 0) => Ok(*id),
            (Some(_), more) => Err(ResolveError::Ambiguous(more + 1)),
        }
    }

    /// Everyone except ourselves.
    pub fn others(&self) -> Vec<NodeId> {
        let inner = self.inner.read();
        inner.order.iter().filter(|id| **id != inner.self_id).copied().collect()
    }

    /// Peers with an endpoint and their link state (for the ping loop).
    pub fn links(&self) -> Vec<(NodeId, Link)> {
        let inner = self.inner.read();
        inner
            .order
            .iter()
            .filter(|id| **id != inner.self_id)
            .filter_map(|id| inner.peers[id].endpoint.map(|_| (*id, inner.peers[id].link)))
            .collect()
    }

    pub fn update_link(&self, id: &NodeId, f: impl FnOnce(&mut Link)) {
        if let Some(p) = self.inner.write().peers.get_mut(id)
            && p.endpoint.is_some()
        {
            f(&mut p.link);
        }
    }

    /// Whether we heard from the peer at its current endpoint within `within`.
    pub fn link_alive(&self, id: &NodeId, within: Duration) -> bool {
        let inner = self.inner.read();
        inner
            .peers
            .get(id)
            .is_some_and(|p| p.endpoint.is_some() && p.link.last_seen.is_some_and(|t| t.elapsed() < within))
    }

    pub fn rtt_ms(&self, id: &NodeId) -> Option<f64> {
        self.inner.read().peers.get(id).and_then(|p| p.endpoint.and(p.link.rtt_ms))
    }

    // ---- packet path ----

    pub fn route_by_addr(&self, dst: Ipv4Addr) -> Option<Arc<Route>> {
        self.view.load().by_addr.get(&dst).cloned()
    }

    pub fn route_by_id(&self, id: &NodeId) -> Option<Arc<Route>> {
        self.view.load().by_id.get(id).cloned()
    }

    /// The LAN address `id` may send from.
    pub fn peer_addr(&self, id: &NodeId) -> Option<Ipv4Addr> {
        self.view.load().addrs.get(id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_route() {
        let me = NodeId::random();
        let s = PeerStorage::new(me);
        let other = NodeId::random();
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        s.set_peer(other, PeerUpdate { addr: Some(Some(ip)), ..Default::default() });
        assert!(s.route_by_addr(ip).is_none(), "no endpoint yet");
        assert_eq!(s.peer_addr(&other), Some(ip), "the address is known without an endpoint");
        s.set_peer(other, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        let r = s.route_by_addr(ip).unwrap();
        assert_eq!((r.peer_id, r.endpoint), (other, ep));

        s.del_endpoint(&other);
        assert!(s.route_by_id(&other).is_none());
        assert_eq!(s.others(), vec![other]);
        assert!(s.del_peer(&other));
        assert!(s.route_by_addr(ip).is_none());
    }

    #[test]
    fn packet_view_follows_changes() {
        let me = NodeId::random();
        let s = PeerStorage::new(me);
        let other = NodeId::random();
        let (ip, ip2) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        s.set_peer(other, PeerUpdate { addr: Some(Some(ip)), endpoint: Some(Some(ep)), ..Default::default() });
        assert!(s.route_by_addr(ip).is_some());

        s.set_peer(other, PeerUpdate { addr: Some(Some(ip2)), ..Default::default() });
        assert!(s.route_by_addr(ip).is_none());
        assert_eq!(s.route_by_addr(ip2).unwrap().peer_id, other);
        assert_eq!(s.peer_addr(&other), Some(ip2));

        let ep2: SocketAddr = "5.6.7.8:9000".parse().unwrap();
        s.set_peer(other, PeerUpdate { endpoint: Some(Some(ep2)), ..Default::default() });
        assert_eq!(s.route_by_id(&other).unwrap().endpoint, ep2, "roaming reaches the view");
        s.del_endpoint(&other);
        assert!(s.route_by_id(&other).is_none() && s.route_by_addr(ip2).is_none());
    }

    #[test]
    fn resolve_full_key_and_unique_prefix() {
        let me = NodeId::random();
        let s = PeerStorage::new(me);
        let unknown = NodeId::random();
        assert_eq!(s.resolve(&unknown.to_string()), Ok(unknown), "full keys need not be known (set adds them)");
        assert_eq!(s.resolve(&format!(" {me}\n")), Ok(me));
        let text = me.to_string();
        assert_eq!(s.resolve(&text[..6]), Ok(me));
        // standard base64 alphabet in a prefix
        let std_prefix = text[..20].replace('-', "+").replace('_', "/");
        assert_eq!(s.resolve(&std_prefix), Ok(me));
        assert_eq!(s.resolve(""), Err(ResolveError::NotFound));
        assert_eq!(s.resolve("!!"), Err(ResolveError::NotFound));

        // Add keys until two share a first character, then that character is ambiguous.
        let mut by_first: HashMap<char, NodeId> = HashMap::from([(text.chars().next().unwrap(), me)]);
        let (a, b) = loop {
            let id = NodeId::random();
            s.set_peer(id, PeerUpdate::default());
            if let Some(prev) = by_first.insert(id.to_string().chars().next().unwrap(), id) {
                break (prev, id);
            }
        };
        let first = &a.to_string()[..1];
        assert_eq!(s.resolve(first), Err(ResolveError::Ambiguous(2)));
        let common = a.to_string().chars().zip(b.to_string().chars()).take_while(|(x, y)| x == y).count();
        assert_eq!(s.resolve(&a.to_string()[..common + 1]), Ok(a));
        assert_eq!(s.resolve(&b.to_string()[..common + 1]), Ok(b));
    }

    #[test]
    fn endpoint_moves_between_peers() {
        let s = PeerStorage::new(NodeId::random());
        let (a, b) = (NodeId::random(), NodeId::random());
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        s.set_peer(a, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        s.set_peer(b, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        assert_eq!(s.route_by_id(&b).unwrap().endpoint, ep);
        assert!(s.endpoint(&a).is_none() && s.route_by_id(&a).is_none());
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    fn populated(n: u8) -> (Arc<PeerStorage>, Vec<Ipv4Addr>, Vec<NodeId>) {
        let s = Arc::new(PeerStorage::new(NodeId::random()));
        let (mut ips, mut ids) = (Vec::new(), Vec::new());
        for i in 0..n {
            let ip = Ipv4Addr::new(10, 0, 0, i + 2);
            let ep: SocketAddr = format!("192.0.2.{}:{}", i + 1, 5000 + i as u16).parse().unwrap();
            let id = NodeId::random();
            s.set_peer(id, PeerUpdate { addr: Some(Some(ip)), endpoint: Some(Some(ep)), ..Default::default() });
            ips.push(ip);
            ids.push(id);
        }
        (s, ips, ids)
    }

    /// Hot-path lookups: `route_by_addr` (TUN -> net) and `peer_addr` (net -> TUN source check).
    /// Run: cargo test --release storage::bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_route_lookup() {
        const N: usize = 2_000_000;
        let (s, ips, ids) = populated(64);

        let t = std::time::Instant::now();
        for i in 0..N {
            assert!(s.route_by_addr(ips[i % ips.len()]).is_some());
        }
        let one = t.elapsed().as_secs_f64();
        println!("route_by_addr, 1 thread : {:6.1} ns/lookup", one * 1e9 / N as f64);

        let t = std::time::Instant::now();
        for i in 0..N {
            assert!(s.peer_addr(&ids[i % ids.len()]).is_some());
        }
        let inb = t.elapsed().as_secs_f64();
        println!("peer_addr,     1 thread : {:6.1} ns/lookup", inb * 1e9 / N as f64);

        // 4 readers while a writer keeps moving one endpoint (roaming / tracker updates).
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (s, stop) = (s.clone(), stop.clone());
            let id = s.others()[0];
            std::thread::spawn(move || {
                let mut port = 6000u16;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    port = port.wrapping_add(1).max(6000);
                    let ep = SocketAddr::from(([198, 51, 100, 1], port));
                    s.set_peer(id, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        };
        let t = std::time::Instant::now();
        let readers: Vec<_> = (0..4)
            .map(|k| {
                let (s, ips) = (s.clone(), ips.clone());
                std::thread::spawn(move || {
                    for i in 0..N {
                        std::hint::black_box(s.route_by_addr(ips[(i + k) % ips.len()]));
                    }
                })
            })
            .collect();
        for r in readers {
            r.join().unwrap();
        }
        let par = t.elapsed().as_secs_f64();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();
        println!("route_by_addr, 4 threads + writer: {:6.1} ns/lookup (wall, per thread)", par * 1e9 / N as f64);
    }
}
