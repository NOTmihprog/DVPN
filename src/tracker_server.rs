//! The tracker (PLAN §11): introduces members of a group to each other and relays the group
//! records. Sessions are masked like node-to-node sessions (`tunnel.rs`) and found by their
//! index, not the client's address, so a client whose NAT mapping changed keeps its session.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::group::{Cert, GroupId};
use crate::identity::{Identity, NodeId};
use crate::link::Session;
use crate::logger::node as show;
use crate::noise::{TAG_LEN, Tai64n};
use crate::obfs::MAX_PAD;
use crate::proto::{DATA, DATA_HDR, HS_INIT, MAX_ANNOUNCE_CERTS, MAX_CANDIDATES, MAX_DATAGRAM, TrackerMsg};
use crate::state::{Entry, Membership, StateStore, SyncMsg, record_key};
use crate::transport::{bind_udp, normalize, wire_addr};
use crate::tunnel::{self, MAX_SKEW, TrackerKeys};

/// A client that sent nothing for this long is dropped.
const TIMEOUT: Duration = Duration::from_secs(45);

struct Client {
    /// Where its last authenticated packet came from.
    addr: SocketAddr,
    /// The session we send on, and a newer one waiting for the client's first packet on it.
    current: Option<Arc<Session>>,
    next: Option<Arc<Session>>,
    /// Verified certificates, by group (empty until it announces).
    certs: HashMap<GroupId, Cert>,
    /// Its own addresses as announced (LAN, IPv6).
    candidates: Vec<SocketAddr>,
    announced: bool,
    last_seen: Instant,
}

type Out = Vec<(Vec<u8>, SocketAddr)>;

pub struct Server {
    identity: Identity,
    keys: TrackerKeys,
    clients: HashMap<NodeId, Client>,
    by_idx: HashMap<u32, (NodeId, Arc<Session>)>,
    /// Newest handshake timestamp per client key; older or equal ones are replays. Kept after a
    /// client leaves, until it is older than `MAX_SKEW` (then the freshness check covers it).
    last_ts: HashMap<NodeId, (Tai64n, Instant)>,
    /// Online members of each group.
    groups: HashMap<GroupId, HashSet<NodeId>>,
    /// Group records (revocations, issued certificates, psk epochs), replicated from members;
    /// memory only, members push them again after a restart.
    store: StateStore,
    /// Join key -> the first node that enrolled with it: an invite works for one node only.
    joins: HashMap<NodeId, NodeId>,
}

impl Server {
    pub fn new(identity: Identity) -> Self {
        Server {
            keys: TrackerKeys::new(identity.id()),
            identity,
            clients: HashMap::new(),
            by_idx: HashMap::new(),
            last_ts: HashMap::new(),
            groups: HashMap::new(),
            store: StateStore::memory(),
            joins: HashMap::new(),
        }
    }

    pub fn id(&self) -> NodeId {
        self.identity.id()
    }

    fn fresh_idx(&self) -> u32 {
        loop {
            let i = rand::random();
            if !self.by_idx.contains_key(&i) {
                return i;
            }
        }
    }

    fn send(&self, out: &mut Out, to: &NodeId, msg: &TrackerMsg) {
        let Some(c) = self.clients.get(to) else { return };
        let Some(s) = c.current.as_ref().or(c.next.as_ref()) else { return };
        let body = msg.encode();
        let mut buf = vec![0u8; DATA_HDR + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR..DATA_HDR + body.len()].copy_from_slice(&body);
        if let Some(n) = s.seal(&mut buf, body.len()) {
            buf.truncate(n);
            out.push((buf, c.addr));
        }
    }

    fn unindex(&mut self, node: NodeId, groups: impl IntoIterator<Item = GroupId>) {
        for g in groups {
            if let Some(members) = self.groups.get_mut(&g) {
                members.remove(&node);
                if members.is_empty() {
                    self.groups.remove(&g);
                }
            }
        }
    }

    fn drop_client(&mut self, out: &mut Out, node: NodeId, send_close: bool) {
        if send_close {
            self.send(out, &node, &TrackerMsg::Close);
        }
        let Some(c) = self.clients.remove(&node) else { return };
        for s in [c.current, c.next].into_iter().flatten() {
            self.by_idx.remove(&s.local_idx);
        }
        self.unindex(node, c.certs.into_keys());
        log::info!("Server | node {:#} {} dropped", show(node), c.addr);
    }

    /// What to tell others about the online member `node` of `group`.
    fn member(&self, group: &GroupId, node: &NodeId) -> Option<TrackerMsg> {
        let c = self.clients.get(node)?;
        let cert = Box::new(c.certs.get(group)?.clone());
        Some(TrackerMsg::Found { cert, addr: c.addr, candidates: c.candidates.clone() })
    }

    /// Tells the other online members of `node`'s groups where it is.
    fn notify_members(&self, out: &mut Out, node: NodeId) {
        let Some(c) = self.clients.get(&node) else { return };
        for g in c.certs.keys() {
            let Some(found) = self.member(g, &node) else { continue };
            for m in self.groups.get(g).into_iter().flatten().filter(|m| **m != node) {
                self.send(out, m, &found);
            }
        }
    }

    fn handshake(&mut self, out: &mut Out, packet: &[u8], wire_len: usize, from: SocketAddr) {
        let Some(acc) = tunnel::server_read(&self.identity, packet) else { return };
        let node = acc.node;
        // anti-probing: stale or replayed handshakes get no answer at all
        if !tunnel::fresh(acc.timestamp) || self.last_ts.get(&node).is_some_and(|(t, _)| acc.timestamp <= *t) {
            log::debug!("Server | stale or replayed handshake from {from} ignored");
            return;
        }
        self.last_ts.insert(node, (acc.timestamp, Instant::now()));
        let idx = self.fresh_idx();
        let Some((session, reply)) = acc.reply(&self.keys, idx, wire_len) else { return };
        let session = Arc::new(session);
        self.by_idx.insert(idx, (node, session.clone()));
        let new = !self.clients.contains_key(&node);
        let c = self.clients.entry(node).or_insert_with(|| Client {
            addr: from,
            current: None,
            next: None,
            certs: HashMap::new(),
            candidates: Vec::new(),
            announced: false,
            last_seen: Instant::now(),
        });
        if let Some(old) = c.next.replace(session) {
            self.by_idx.remove(&old.local_idx);
        }
        if new {
            log::info!("Server | New session from {from} node: {:#}", show(node));
        }
        out.push((reply, from));
    }

    fn data(&mut self, out: &mut Out, packet: &mut [u8], from: SocketAddr) {
        let Some(idx) = packet.get(3..7).map(|b| u32::from_le_bytes(b.try_into().unwrap())) else { return };
        let Some((node, session)) = self.by_idx.get(&idx).cloned() else { return };
        if !session.usable() {
            return;
        }
        let Some(plain) = session.open(packet) else { return };
        let Some(c) = self.clients.get_mut(&node) else { return };
        c.last_seen = Instant::now();
        if c.next.as_ref().is_some_and(|n| Arc::ptr_eq(n, &session)) {
            // the client uses its new session: switch to it
            if let Some(old) = c.current.replace(c.next.take().unwrap()) {
                self.by_idx.remove(&old.local_idx);
            }
        }
        let moved = c.addr != from;
        if moved {
            // authenticated packet from a new address: the client's NAT mapping changed
            log::info!("Server | node {:#} moved {} -> {from}", show(node), c.addr);
            c.addr = from;
        }
        let announced = c.announced;
        if moved && announced {
            self.notify_members(out, node);
        }
        match TrackerMsg::decode(&packet[plain]) {
            Some(TrackerMsg::Announce { certs, candidates }) => self.announce(out, node, certs, candidates),
            Some(TrackerMsg::Sync(msg)) => self.sync(out, node, msg),
            Some(TrackerMsg::Close) => self.drop_client(out, node, false),
            Some(TrackerMsg::Found { .. }) => {}
            None => log::info!("Server | {from} decode error"),
        }
    }

    fn announce(&mut self, out: &mut Out, node: NodeId, certs: Vec<Cert>, candidates: Vec<SocketAddr>) {
        let mut candidates: Vec<SocketAddr> = candidates
            .into_iter()
            .map(normalize)
            .filter(|a| a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast())
            .take(MAX_CANDIDATES)
            .collect();
        candidates.dedup();
        let now = crate::clock::trusted_unix();
        let mut valid: HashMap<GroupId, Cert> = HashMap::new();
        for c in certs.into_iter().take(MAX_ANNOUNCE_CERTS) {
            let group = c.body.group;
            match c.verify(&group, now) {
                Ok(()) if c.body.node != node => {
                    log::info!("Server | {:#}: certificate of another node ignored", show(node))
                }
                Ok(()) if !Membership::of(&self.store, &group).admits(&c) => {
                    log::info!("Server | {:#}: revoked in group {}", show(node), group.short())
                }
                Ok(()) => {
                    if let Some(jk) = c.join_key() {
                        let first = *self.joins.entry(jk).or_insert(node);
                        if first != node {
                            log::info!("Server | {:#}: invite already used by {:#}", show(node), show(first));
                            continue;
                        }
                    }
                    valid.insert(group, c);
                }
                Err(e) => log::info!("Server | {:#}: {e}", show(node)),
            }
        }
        let Some(c) = self.clients.get_mut(&node) else { return };
        let changed = !c.announced || c.certs != valid || c.candidates != candidates;
        c.candidates = candidates;
        let left: Vec<GroupId> = c.certs.keys().filter(|g| !valid.contains_key(g)).copied().collect();
        c.announced = true;
        c.certs = valid;
        self.unindex(node, left);

        let groups: Vec<GroupId> = self.clients[&node].certs.keys().copied().collect();
        for g in groups {
            let members = self.groups.entry(g).or_default();
            if members.insert(node) {
                log::info!("Server | node {:#} joined group {}", show(node), g.short());
            }
            let members: Vec<NodeId> = members.iter().copied().collect();
            let mine = self.member(&g, &node).expect("just indexed");
            // Every announce refreshes the announcer's view of its groups (its own address
            // included); the others hear about it when it is new or its certificate or
            // candidates changed.
            for m in members {
                let Some(found) = self.member(&g, &m) else { continue };
                self.send(out, &node, &found);
                if changed && m != node {
                    self.send(out, &m, &mine);
                }
            }
        }
    }

    /// Group records from a member: answer, store, pass new ones on to the other online members,
    /// and drop members that the new records revoked.
    fn sync(&mut self, out: &mut Out, node: NodeId, msg: SyncMsg) {
        let Some(groups) = self.clients.get(&node).map(|c| c.certs.keys().copied().collect::<HashSet<_>>()) else {
            return;
        };
        let (replies, changed) = msg.handle(&self.store, |g| groups.contains(g));
        for r in replies {
            self.send(out, &node, &TrackerMsg::Sync(r));
        }
        let mut by_group: HashMap<GroupId, Vec<Entry>> = HashMap::new();
        for e in changed {
            by_group.entry(e.group).or_default().push(e);
        }
        for (g, entries) in by_group {
            let keys: Vec<_> = entries.iter().map(|e| record_key(&g, &e.id)).collect();
            let records = self.store.get(&g, &keys);
            let membership = Membership::of(&self.store, &g);
            let members: Vec<NodeId> = self.groups.get(&g).map(|m| m.iter().copied().collect()).unwrap_or_default();
            for m in members {
                let Some(TrackerMsg::Found { cert, .. }) = self.member(&g, &m) else { continue };
                // a revoked member gets the records too, so it knows why nobody answers
                if m != node {
                    for msg in SyncMsg::records(records.clone()) {
                        self.send(out, &m, &TrackerMsg::Sync(msg));
                    }
                }
                if !membership.admits(&cert) {
                    log::info!("Server | node {:#} revoked in group {}", show(m), g.short());
                    if let Some(c) = self.clients.get_mut(&m) {
                        c.certs.remove(&g);
                    }
                    self.unindex(m, [g]);
                }
            }
        }
    }

    /// Handles one datagram; returns the datagrams to send. Anything that is not an
    /// authenticated packet of a session, or a fresh handshake, gets no answer.
    pub fn handle(&mut self, packet: &[u8], from: SocketAddr) -> Out {
        let mut out = Out::new();
        let mut p = packet.to_vec();
        let Some(len) = self.keys.obfs.open(&mut p) else { return out };
        let p = &mut p[..len];
        match p[0] {
            HS_INIT => self.handshake(&mut out, p, packet.len(), from),
            DATA => self.data(&mut out, p, from),
            _ => {}
        }
        out
    }

    /// Drops silent clients and expired sessions. Call every few seconds.
    pub fn collect_garbage(&mut self) -> Out {
        let mut out = Out::new();
        let silent: Vec<NodeId> =
            self.clients.iter().filter(|(_, c)| c.last_seen.elapsed() > TIMEOUT).map(|(n, _)| *n).collect();
        for n in silent {
            self.drop_client(&mut out, n, true);
        }
        let dead: Vec<u32> = self.by_idx.iter().filter(|(_, (_, s))| !s.usable()).map(|(i, _)| *i).collect();
        for i in dead {
            if let Some((node, s)) = self.by_idx.remove(&i)
                && let Some(c) = self.clients.get_mut(&node)
            {
                for slot in [&mut c.current, &mut c.next] {
                    if slot.as_ref().is_some_and(|x| Arc::ptr_eq(x, &s)) {
                        *slot = None;
                    }
                }
            }
        }
        self.last_ts.retain(|_, (_, at)| at.elapsed() < MAX_SKEW * 2);
        out
    }
}

/// Serves on `addr:port` (`::` = IPv6 and IPv4 on one socket).
pub async fn run(addr: std::net::IpAddr, port: u16, identity: Identity) -> std::io::Result<()> {
    let (sock, families) = bind_udp(addr, port)?;
    log::info!("Server started listen: {}", std::net::SocketAddr::new(addr, port));
    let sock: Arc<UdpSocket> = Arc::new(sock);
    let server = Arc::new(Mutex::new(Server::new(identity)));

    let gc = {
        let (sock, server) = (sock.clone(), server.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let out = server.lock().collect_garbage();
                for (p, a) in out {
                    if let Some(a) = wire_addr(families, a) {
                        let _ = sock.send_to(&p, a).await;
                    }
                }
            }
        })
    };

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                log::debug!("Server | recv error: {e}");
                continue;
            }
        };
        let out = server.lock().handle(&buf[..n], normalize(from));
        for (p, a) in out {
            let Some(to) = wire_addr(families, a) else { continue };
            if let Err(e) = sock.send_to(&p, to).await {
                log::info!("Server | send to {a} error: {e}");
            }
        }
        if gc.is_finished() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{CertBody, GroupSecret};
    use crate::state::Body;
    use crate::tunnel::{client_finish, client_hello};

    struct Client {
        id: Identity,
        addr: SocketAddr,
        keys: TrackerKeys,
        session: Session,
    }

    fn unmask(keys: &TrackerKeys, p: &[u8]) -> Vec<u8> {
        let mut p = p.to_vec();
        let n = keys.obfs.open(&mut p).unwrap();
        p.truncate(n);
        p
    }

    fn connect_as(st: &mut Server, id: Identity, addr: &str) -> Client {
        let addr = addr.parse().unwrap();
        let keys = TrackerKeys::new(st.id());
        let (packets, hello) = client_hello(&keys, &id, rand::random()).unwrap();
        let out = st.handle(packets.last().unwrap(), addr);
        let session = client_finish(&keys, &hello, &unmask(&keys, &out[0].0)).unwrap();
        Client { id, addr, keys, session }
    }

    fn connect(st: &mut Server, addr: &str) -> Client {
        connect_as(st, Identity::generate(), addr)
    }

    fn seal(c: &Client, msg: &TrackerMsg) -> Vec<u8> {
        let body = msg.encode();
        let mut buf = vec![0u8; DATA_HDR + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR..DATA_HDR + body.len()].copy_from_slice(&body);
        let n = c.session.seal(&mut buf, body.len()).unwrap();
        buf.truncate(n);
        buf
    }

    fn open(c: &Client, p: &[u8]) -> TrackerMsg {
        let mut p = unmask(&c.keys, p);
        let r = c.session.open(&mut p).unwrap();
        TrackerMsg::decode(&p[r]).unwrap()
    }

    /// Sends `msg` from `c`, returns the replies addressed to `c`.
    fn send(st: &mut Server, c: &Client, msg: &TrackerMsg) -> Vec<TrackerMsg> {
        let out = st.handle(&seal(c, msg), c.addr);
        out.into_iter().filter(|(_, to)| *to == c.addr).map(|(p, _)| open(c, &p)).collect()
    }

    fn cert(g: &GroupSecret, c: &Client) -> Cert {
        g.issue(CertBody::new(c.id.id(), "n", vec![]))
    }

    fn found(msgs: &[TrackerMsg]) -> Vec<(NodeId, SocketAddr)> {
        let mut v: Vec<_> = msgs
            .iter()
            .filter_map(|m| match m {
                TrackerMsg::Found { cert, addr, .. } => Some((cert.body.node, *addr)),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    fn server() -> Server {
        Server::new(Identity::generate())
    }

    #[test]
    fn announce_accepted() {
        let mut st = server();
        let g = GroupSecret::generate();
        let c = connect(&mut st, "198.51.100.1:4000");
        let replies = send(&mut st, &c, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &c)] });
        assert_eq!(found(&replies), vec![(c.id.id(), c.addr)]);
        assert!(st.groups[&g.id()].contains(&c.id.id()));
    }

    #[test]
    fn probes_and_replays_get_no_answer() {
        let mut st = server();
        let from: SocketAddr = "203.0.113.66:4000".parse().unwrap();
        for len in [0, 1, 40, 200, 1400] {
            let junk: Vec<u8> = (0..len).map(|_| rand::random()).collect();
            assert!(st.handle(&junk, from).is_empty(), "answered {len} random bytes");
        }
        let id = Identity::generate();
        let keys = TrackerKeys::new(st.id());
        let (packets, _) = client_hello(&keys, &id, 1).unwrap();
        let init = packets.last().unwrap();
        for junk in &packets[..packets.len() - 1] {
            assert!(st.handle(junk, from).is_empty());
        }
        let out = st.handle(init, from);
        assert_eq!(out.len(), 1);
        assert!(out[0].0.len() <= init.len(), "answer larger than the request");
        assert!(st.handle(init, from).is_empty(), "replayed handshake answered");
        assert!(st.handle(init, "198.51.100.9:1".parse().unwrap()).is_empty(), "replay from elsewhere answered");
        // a handshake for another tracker
        let other = TrackerKeys::new(Identity::generate().id());
        let (packets, _) = client_hello(&other, &id, 2).unwrap();
        assert!(st.handle(packets.last().unwrap(), from).is_empty());
    }

    #[test]
    fn session_survives_address_change() {
        let mut st = server();
        let g = GroupSecret::generate();
        let a = connect(&mut st, "198.51.100.1:4000");
        let mut b = connect(&mut st, "198.51.100.2:4000");
        send(&mut st, &a, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &a)] });
        send(&mut st, &b, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &b)] });
        // b's NAT gives it a new address: the same session goes on, a learns the new address
        b.addr = "198.51.100.22:5000".parse().unwrap();
        let out = st.handle(&seal(&b, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &b)] }), b.addr);
        let to_a: Vec<_> = out.iter().filter(|(_, t)| *t == a.addr).map(|(p, _)| open(&a, p)).collect();
        assert!(found(&to_a).contains(&(b.id.id(), b.addr)), "a told about b's new address");
        assert_eq!(st.clients[&b.id.id()].addr, b.addr);
    }

    #[test]
    fn candidates_passed_on() {
        let mut st = server();
        let g = GroupSecret::generate();
        let a = connect(&mut st, "198.51.100.1:4000");
        let b = connect(&mut st, "198.51.100.2:4000");
        let cands: Vec<SocketAddr> = vec!["192.168.1.5:4000".parse().unwrap(), "[2001:db8::5]:4000".parse().unwrap()];
        let junk: Vec<SocketAddr> = vec!["0.0.0.0:1".parse().unwrap(), "10.0.0.1:0".parse().unwrap()];
        let all = [cands.clone(), junk, vec!["[::ffff:10.1.1.1]:4000".parse().unwrap()]].concat();
        send(&mut st, &a, &TrackerMsg::Announce { certs: vec![cert(&g, &a)], candidates: all });
        let replies = send(&mut st, &b, &TrackerMsg::Announce { certs: vec![cert(&g, &b)], candidates: vec![] });
        let got = replies.iter().find_map(|m| match m {
            TrackerMsg::Found { cert, candidates, .. } if cert.body.node == a.id.id() => Some(candidates.clone()),
            _ => None,
        });
        let mut want = cands;
        want.push("10.1.1.1:4000".parse().unwrap());
        assert_eq!(got, Some(want), "unspecified and port-0 candidates dropped, mapped ones normalized");
    }

    #[test]
    fn members_find_each_other_without_search() {
        let mut st = server();
        let (g, other) = (GroupSecret::generate(), GroupSecret::generate());
        let a = connect(&mut st, "198.51.100.1:4000");
        let b = connect(&mut st, "198.51.100.2:4000");
        let x = connect(&mut st, "198.51.100.3:4000");
        send(&mut st, &a, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &a)] });
        send(&mut st, &x, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&other, &x)] });

        // b comes online: it learns a (and itself), and a learns b in the same step
        let b_cert = cert(&g, &b);
        let out =
            st.handle(&seal(&b, &TrackerMsg::Announce { candidates: vec![], certs: vec![b_cert.clone()] }), b.addr);
        let to = |c: &Client| -> Vec<TrackerMsg> {
            out.iter().filter(|(_, t)| *t == c.addr).map(|(p, _)| open(c, p)).collect()
        };
        let mut want = vec![(a.id.id(), a.addr), (b.id.id(), b.addr)];
        want.sort();
        assert_eq!(found(&to(&b)), want);
        assert_eq!(found(&to(&a)), vec![(b.id.id(), b.addr)]);
        assert!(to(&x).is_empty(), "another group hears nothing");

        // a later announce refreshes b's view but does not notify a again
        let out = st.handle(&seal(&b, &TrackerMsg::Announce { candidates: vec![], certs: vec![b_cert] }), b.addr);
        assert!(out.iter().all(|(_, t)| *t == b.addr));
        assert_eq!(out.len(), 2);

        // b leaves: it disappears from the group index
        send(&mut st, &b, &TrackerMsg::Close);
        assert_eq!(st.groups[&g.id()].len(), 1);
    }

    #[test]
    fn invalid_certificates_not_indexed() {
        let mut st = server();
        let g = GroupSecret::generate();
        let c = connect(&mut st, "198.51.100.9:4000");
        let mut expired = CertBody::new(c.id.id(), "n", vec![]);
        expired.not_after = 1;
        let mut forged = cert(&g, &c);
        forged.body.name = "admin".into();
        let someone_else = g.issue(CertBody::new(Identity::generate().id(), "n", vec![]));
        for bad in [g.issue(expired), someone_else, forged] {
            assert!(
                found(&send(&mut st, &c, &TrackerMsg::Announce { candidates: vec![], certs: vec![bad] })).is_empty()
            );
            assert!(st.groups.is_empty());
        }
    }

    #[test]
    fn invite_works_for_one_node_only() {
        let mut st = server();
        let g = GroupSecret::generate();
        let join = g.grant_join(CertBody::new(Identity::generate().id(), "n", vec![]), u64::MAX);
        let a = connect(&mut st, "198.51.100.1:4000");
        assert_eq!(
            found(&send(
                &mut st,
                &a,
                &TrackerMsg::Announce { candidates: vec![], certs: vec![join.enroll(a.id.id())] }
            ))
            .len(),
            1
        );
        let b = connect(&mut st, "198.51.100.2:4000");
        let m = TrackerMsg::Announce { candidates: vec![], certs: vec![join.enroll(b.id.id())] };
        assert!(found(&send(&mut st, &b, &m)).is_empty(), "second use of the invite");
        assert_eq!(st.groups[&g.id()].len(), 1);
    }

    #[test]
    fn revocation_spreads_and_unindexes() {
        let mut st = server();
        let g = GroupSecret::generate();
        let a = connect(&mut st, "198.51.100.1:4000");
        let b = connect(&mut st, "198.51.100.2:4000");
        send(&mut st, &a, &TrackerMsg::Announce { candidates: vec![], certs: vec![cert(&g, &a)] });
        let b_cert = cert(&g, &b);
        send(&mut st, &b, &TrackerMsg::Announce { candidates: vec![], certs: vec![b_cert.clone()] });

        // a (an admin's node) pushes a revocation of b
        let admin = StateStore::memory();
        admin.add(&g, Body::Revoke { key: b.id.id() }, false);
        let keys: Vec<_> = admin.summary(&g.id()).iter().map(|(k, _)| *k).collect();
        send(&mut st, &a, &TrackerMsg::Sync(SyncMsg::Records { records: admin.get(&g.id(), &keys) }));
        assert!(!st.groups[&g.id()].contains(&b.id.id()), "b left the index");
        assert!(st.store.revoked(&g.id()).contains(&b.id.id()));
        // and b cannot come back
        assert!(
            found(&send(&mut st, &b, &TrackerMsg::Announce { candidates: vec![], certs: vec![b_cert] })).is_empty()
        );

        // records of a group the sender is not in are refused
        let h = GroupSecret::generate();
        admin.add(&h, Body::Revoke { key: a.id.id() }, false);
        let keys: Vec<_> = admin.summary(&h.id()).iter().map(|(k, _)| *k).collect();
        send(&mut st, &a, &TrackerMsg::Sync(SyncMsg::Records { records: admin.get(&h.id(), &keys) }));
        assert!(st.store.revoked(&h.id()).is_empty());
    }
}
