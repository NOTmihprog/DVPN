use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::broadcast;

use crate::crypto::{PeerCipher, decode_key32, encode_b64};
use crate::peer_id::PeerId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    #[serde(alias = "id")]
    pub peer_id: PeerId,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub addr: Option<Ipv4Addr>,
    /// 32 bytes base64. Packets sent *to* this peer are encrypted with it.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_args: Option<Map<String, Value>>,
}

impl PeerRecord {
    pub fn new(peer_id: PeerId) -> Self {
        PeerRecord { peer_id, name: None, addr: None, key: None, sub_args: None }
    }
}

/// Validates and normalizes a base64 key to url-safe form.
pub fn normalize_key(key: &str) -> anyhow::Result<String> {
    Ok(encode_b64(&decode_key32(key)?))
}

/// Each field: `None` = leave unchanged, `Some(v)` = set to `v` (`Some(None)` clears).
#[derive(Default)]
pub struct PeerUpdate {
    pub name: Option<Option<String>>,
    pub addr: Option<Option<Ipv4Addr>>,
    pub key: Option<Option<String>>,
    pub endpoint: Option<Option<SocketAddr>>,
    pub sub_args: Option<Option<Map<String, Value>>>,
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
    Ping { peer_id: PeerId, ms: f64 },
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
    cipher: Option<PeerCipher>,
    endpoint: Option<SocketAddr>,
    link: Link,
    /// Freshest (session, seq) seen in the peer's control packets; survives endpoint changes.
    seq: Option<(u64, u64)>,
}

impl Peer {
    fn new(rec: PeerRecord) -> Self {
        let mut p = Peer { rec, cipher: None, endpoint: None, link: Link::new(), seq: None };
        p.load_cipher();
        p
    }

    fn load_cipher(&mut self) {
        self.cipher = match &self.rec.key {
            None => None,
            Some(k) => match decode_key32(k) {
                Ok(k) => Some(PeerCipher::new(&k)),
                Err(e) => {
                    log::warn!("PeerStorage | Peer {} key load error: {e}, encryption disabled", self.rec.peer_id);
                    None
                }
            },
        };
    }
}

struct Inner {
    self_id: PeerId,
    order: Vec<PeerId>,
    peers: HashMap<PeerId, Peer>,
    by_endpoint: HashMap<SocketAddr, PeerId>,
    by_addr: HashMap<Ipv4Addr, PeerId>,
}

impl Inner {
    fn reindex_addr(&mut self) {
        self.by_addr.clear();
        for id in &self.order {
            if let Some(addr) = self.peers[id].rec.addr
                && let Some(other) = self.by_addr.insert(addr, *id) {
                    log::warn!("PeerStorage | Peers {other} and {id} share addr {addr}, using {id}");
                }
        }
    }

    fn set_endpoint(&mut self, id: PeerId, endpoint: Option<SocketAddr>) {
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
                    && let Some(pp) = self.peers.get_mut(&prev) {
                        pp.endpoint = None;
                    }
        }
    }
}

/// A route to a peer, as needed by the packet path.
pub struct Route {
    pub peer_id: PeerId,
    pub endpoint: SocketAddr,
    pub cipher: Option<PeerCipher>,
}

pub struct Inbound {
    pub peer_id: PeerId,
    pub peer_addr: Option<Ipv4Addr>,
    pub own_cipher: Option<PeerCipher>,
}

pub struct PeerStorage {
    path: Option<PathBuf>,
    inner: RwLock<Inner>,
    write_lock: Mutex<()>,
    events: broadcast::Sender<Event>,
}

impl PeerStorage {
    /// Loads peers from `path` (JSON array); `None` keeps everything in memory.
    pub fn load(self_id: PeerId, path: Option<PathBuf>) -> anyhow::Result<Self> {
        let mut records: Vec<PeerRecord> = Vec::new();
        if let Some(p) = &path {
            match std::fs::read(p) {
                Ok(data) => records = serde_json::from_slice(&data).with_context(|| format!("parse {}", p.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => log::warn!("PeerStorage | read file({}) error: {e}", p.display()),
            }
        }
        let mut inner = Inner {
            self_id,
            order: vec![self_id],
            peers: HashMap::from([(self_id, Peer::new(PeerRecord::new(self_id)))]),
            by_endpoint: HashMap::new(),
            by_addr: HashMap::new(),
        };
        for rec in records {
            let id = rec.peer_id;
            if !inner.peers.contains_key(&id) {
                inner.order.push(id);
            }
            inner.peers.insert(id, Peer::new(rec));
        }
        inner.reindex_addr();
        Ok(PeerStorage {
            path,
            inner: RwLock::new(inner),
            write_lock: Mutex::new(()),
            events: broadcast::channel(1024).0,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let _guard = self.write_lock.lock();
        let records: Vec<PeerRecord> = {
            let inner = self.inner.read();
            inner.order.iter().map(|id| inner.peers[id].rec.clone()).collect()
        };
        let data = serde_json::to_vec_pretty(&records).expect("records serialize");
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path)) {
            log::warn!("PeerStorage | write file({}) error: {e}", path.display());
        }
    }

    pub fn self_id(&self) -> PeerId {
        self.inner.read().self_id
    }

    pub fn set_self_id(&self, id: PeerId) {
        let mut inner = self.inner.write();
        inner.self_id = id;
        if !inner.peers.contains_key(&id) {
            inner.order.push(id);
            inner.peers.insert(id, Peer::new(PeerRecord::new(id)));
        }
    }

    pub fn is_self(&self, id: &PeerId) -> bool {
        self.inner.read().self_id == *id
    }

    pub fn set_peer(&self, id: PeerId, u: PeerUpdate) {
        let persist = u.name.is_some() || u.addr.is_some() || u.key.is_some() || u.sub_args.is_some();
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
            if let Some(key) = u.key {
                p.rec.key = key;
                p.load_cipher();
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
            let p = &inner.peers[&id];
            Event::Peer { action, record: p.rec.clone(), endpoint: p.endpoint }
        };
        // A newly added peer is persisted even if only its endpoint was given.
        let added = matches!(event, Event::Peer { action: Action::Add, .. });
        self.emit(event);
        if persist || added {
            self.save();
        }
    }

    pub fn del_peer(&self, id: &PeerId) -> bool {
        let rec = {
            let mut inner = self.inner.write();
            inner.set_endpoint(*id, None);
            let Some(p) = inner.peers.remove(id) else { return false };
            inner.order.retain(|x| x != id);
            inner.reindex_addr();
            p.rec
        };
        self.emit(Event::Peer { action: Action::Del, record: rec, endpoint: None });
        self.save();
        true
    }

    pub fn del_endpoint(&self, id: &PeerId) -> bool {
        let rec = {
            let mut inner = self.inner.write();
            if !inner.peers.contains_key(id) {
                return false;
            }
            inner.set_endpoint(*id, None);
            inner.peers[id].rec.clone()
        };
        self.emit(Event::Peer { action: Action::Update, record: rec, endpoint: None });
        true
    }

    pub fn get(&self, id: &PeerId) -> Option<(PeerRecord, Option<SocketAddr>)> {
        let inner = self.inner.read();
        inner.peers.get(id).map(|p| (p.rec.clone(), p.endpoint))
    }

    pub fn list(&self) -> Vec<(PeerRecord, Option<SocketAddr>)> {
        let inner = self.inner.read();
        inner.order.iter().map(|id| (inner.peers[id].rec.clone(), inner.peers[id].endpoint)).collect()
    }

    pub fn ids(&self) -> Vec<PeerId> {
        self.inner.read().order.clone()
    }

    pub fn exists(&self, id: &PeerId) -> bool {
        self.inner.read().peers.contains_key(id)
    }

    pub fn name(&self, id: &PeerId) -> Option<String> {
        self.inner.read().peers.get(id).and_then(|p| p.rec.name.clone())
    }

    pub fn endpoint(&self, id: &PeerId) -> Option<SocketAddr> {
        self.inner.read().peers.get(id).and_then(|p| p.endpoint)
    }

    pub fn has_cipher(&self, id: &PeerId) -> bool {
        self.inner.read().peers.get(id).is_some_and(|p| p.cipher.is_some())
    }

    /// Resolves a (possibly shortened) peer id.
    pub fn find(&self, prefix: &str) -> Option<PeerId> {
        if prefix.is_empty() {
            return None;
        }
        self.inner.read().order.iter().find(|id| id.as_str().starts_with(prefix)).copied()
    }

    /// Everyone except ourselves.
    pub fn others(&self) -> Vec<PeerId> {
        let inner = self.inner.read();
        inner.order.iter().filter(|id| **id != inner.self_id).copied().collect()
    }

    /// Peers with an endpoint and their link state (for the ping loop).
    pub fn links(&self) -> Vec<(PeerId, Link)> {
        let inner = self.inner.read();
        inner
            .order
            .iter()
            .filter(|id| **id != inner.self_id)
            .filter_map(|id| inner.peers[id].endpoint.map(|_| (*id, inner.peers[id].link)))
            .collect()
    }

    pub fn update_link(&self, id: &PeerId, f: impl FnOnce(&mut Link)) {
        if let Some(p) = self.inner.write().peers.get_mut(id)
            && p.endpoint.is_some() {
                f(&mut p.link);
            }
    }

    /// Whether we heard from the peer at its current endpoint within `within`.
    pub fn link_alive(&self, id: &PeerId, within: Duration) -> bool {
        let inner = self.inner.read();
        inner.peers.get(id).is_some_and(|p| p.endpoint.is_some() && p.link.last_seen.is_some_and(|t| t.elapsed() < within))
    }

    /// Records a control packet's (session, seq); false if it is not newer than what we saw (replay).
    pub fn accept_seq(&self, id: &PeerId, session: u64, seq: u64) -> bool {
        let mut inner = self.inner.write();
        let Some(p) = inner.peers.get_mut(id) else { return false };
        let fresh = match p.seq {
            Some((s, n)) => s != session || seq > n,
            None => true,
        };
        if fresh {
            p.seq = Some((session, seq));
        }
        fresh
    }

    pub fn own_cipher(&self) -> Option<PeerCipher> {
        let inner = self.inner.read();
        inner.peers[&inner.self_id].cipher.clone()
    }

    pub fn rtt_ms(&self, id: &PeerId) -> Option<f64> {
        self.inner.read().peers.get(id).and_then(|p| p.endpoint.and(p.link.rtt_ms))
    }

    // ---- packet path ----

    pub fn route_by_addr(&self, dst: Ipv4Addr) -> Option<Route> {
        let inner = self.inner.read();
        let id = inner.by_addr.get(&dst)?;
        let p = &inner.peers[id];
        Some(Route { peer_id: *id, endpoint: p.endpoint?, cipher: p.cipher.clone() })
    }

    pub fn route_by_id(&self, id: &PeerId) -> Option<Route> {
        let inner = self.inner.read();
        let p = inner.peers.get(id)?;
        Some(Route { peer_id: *id, endpoint: p.endpoint?, cipher: p.cipher.clone() })
    }

    /// For a datagram from `from`: who sent it and our own cipher (if we require encryption).
    pub fn inbound(&self, from: &SocketAddr) -> Option<Inbound> {
        let inner = self.inner.read();
        let id = *inner.by_endpoint.get(from)?;
        Some(Inbound {
            peer_id: id,
            peer_addr: inner.peers[&id].rec.addr,
            own_cipher: inner.peers[&inner.self_id].cipher.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key;

    #[test]
    fn set_and_route() {
        let me = PeerId::generate();
        let s = PeerStorage::load(me, None).unwrap();
        let other = PeerId::generate();
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        s.set_peer(other, PeerUpdate { addr: Some(Some(ip)), key: Some(Some(generate_key())), ..Default::default() });
        assert!(s.route_by_addr(ip).is_none(), "no endpoint yet");
        s.set_peer(other, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        let r = s.route_by_addr(ip).unwrap();
        assert_eq!(r.peer_id, other);
        assert!(r.cipher.is_some());
        assert_eq!(s.inbound(&ep).unwrap().peer_id, other);

        s.del_endpoint(&other);
        assert!(s.inbound(&ep).is_none());
        assert_eq!(s.others(), vec![other]);
        assert!(s.del_peer(&other));
        assert!(s.route_by_addr(ip).is_none());
    }

    #[test]
    fn endpoint_moves_between_peers() {
        let s = PeerStorage::load(PeerId::generate(), None).unwrap();
        let (a, b) = (PeerId::generate(), PeerId::generate());
        let ep: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        s.set_peer(a, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        s.set_peer(b, PeerUpdate { endpoint: Some(Some(ep)), ..Default::default() });
        assert_eq!(s.inbound(&ep).unwrap().peer_id, b);
        assert!(s.endpoint(&a).is_none());
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::crypto::generate_key;
    use std::sync::Arc;

    fn populated(n: u8) -> (Arc<PeerStorage>, Vec<Ipv4Addr>, Vec<SocketAddr>) {
        let s = Arc::new(PeerStorage::load(PeerId::generate(), None).unwrap());
        let (mut ips, mut eps) = (Vec::new(), Vec::new());
        for i in 0..n {
            let ip = Ipv4Addr::new(10, 0, 0, i + 2);
            let ep: SocketAddr = format!("192.0.2.{}:{}", i + 1, 5000 + i as u16).parse().unwrap();
            s.set_peer(
                PeerId::generate(),
                PeerUpdate { addr: Some(Some(ip)), key: Some(Some(generate_key())), endpoint: Some(Some(ep)), ..Default::default() },
            );
            ips.push(ip);
            eps.push(ep);
        }
        (s, ips, eps)
    }

    /// Hot-path lookups: `route_by_addr` (TUN -> net) and `inbound` (net -> TUN).
    /// Run: cargo test --release storage::bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_route_lookup() {
        const N: usize = 2_000_000;
        let (s, ips, eps) = populated(64);

        let t = std::time::Instant::now();
        for i in 0..N {
            assert!(s.route_by_addr(ips[i % ips.len()]).is_some());
        }
        let one = t.elapsed().as_secs_f64();
        println!("route_by_addr, 1 thread : {:6.1} ns/lookup", one * 1e9 / N as f64);

        let t = std::time::Instant::now();
        for i in 0..N {
            assert!(s.inbound(&eps[i % eps.len()]).is_some());
        }
        let inb = t.elapsed().as_secs_f64();
        println!("inbound,       1 thread : {:6.1} ns/lookup", inb * 1e9 / N as f64);

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
