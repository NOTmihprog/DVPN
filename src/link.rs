//! Neighbour sessions (PLAN §4.2): Noise handshakes in the wire format of `proto.rs`, session
//! indices, key confirmation, rekeying and replay protection.
//!
//! Per peer there is a `current` session (used for sending), the `previous` one (still accepted
//! for packets in flight after a rekey) and, on the responder side, a `next` one that becomes
//! current once the initiator has sent something on it (key confirmation, as in WireGuard).
//! Incoming packets find their session by the receiver index alone, never by source address.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use blake2::{Blake2s256, Digest};
use parking_lot::{Mutex, RwLock};
use rand::RngExt;

use crate::elligator;
use crate::identity::{Identity, NodeId};
use crate::noise::{self, HandshakePayload, Initiator, Responder, TAG_LEN, Tai64n};
use crate::proto::{DATA, DATA_HDR, HS_INIT, HS_INIT_HDR, HS_RESP, HS_RESP_HDR};
use crate::replay::ReplayWindow;

/// The initiator starts a new handshake after this long (minus jitter, so peers don't rekey
/// in lockstep).
pub const REKEY_AFTER: Duration = Duration::from_secs(120);
const REKEY_JITTER: Duration = Duration::from_secs(10);
/// The responder rekeys too, later than the initiator would. Needed when both sides handshook at
/// once and each ended up sending on the session the *other* initiated.
const RESPONDER_REKEY_DELAY: Duration = Duration::from_secs(30);
/// Sessions older than this are dropped, so every key is replaced eventually.
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
/// Counters are nonces; stop well before they could wrap.
const REJECT_AFTER_MESSAGES: u64 = 1 << 60;
/// An unanswered handshake is forgotten after this long.
const PENDING_TIMEOUT: Duration = Duration::from_secs(5);
/// Lookups of unknown initiator keys rebuild the key map at most this often.
const MEMBER_REFRESH: Duration = Duration::from_secs(1);

/// Group parameters set by hand until real groups arrive (stage 3).
#[derive(Clone)]
pub struct Group {
    pub psk: [u8; 32],
    pub id: [u8; 32],
}

impl Group {
    /// The group id is derived from the psk for now; stage 3 derives both from the group secret.
    pub fn from_psk(psk: [u8; 32]) -> Self {
        let id = Blake2s256::new().chain_update(b"dvpn/4 group id").chain_update(psk).finalize().into();
        Group { psk, id }
    }
}

pub struct Session {
    pub peer: NodeId,
    pub local_idx: u32,
    remote_idx: u32,
    transport: noise::Transport,
    counter: AtomicU64,
    replay: Mutex<ReplayWindow>,
    created: Instant,
    rekey_after: Duration,
    /// The peer has proven it holds the keys (always true for sessions we initiated).
    confirmed: AtomicBool,
}

impl Session {
    fn new(peer: NodeId, local_idx: u32, remote_idx: u32, transport: noise::Transport, initiator: bool) -> Self {
        let jitter = rand::rng().random_range(Duration::ZERO..REKEY_JITTER);
        Session {
            peer,
            local_idx,
            remote_idx,
            transport,
            counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::default()),
            created: Instant::now(),
            rekey_after: REKEY_AFTER - jitter + if initiator { Duration::ZERO } else { RESPONDER_REKEY_DELAY },
            confirmed: AtomicBool::new(initiator),
        }
    }

    /// Builds a DATA packet in `buf`: the plaintext must already be at
    /// `buf[DATA_HDR..DATA_HDR + plain_len]` and `buf` must have `TAG_LEN` more bytes after it.
    /// Returns the packet length, or `None` once the session has used up its counters.
    pub fn seal(&self, buf: &mut [u8], plain_len: usize) -> Option<usize> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        if n >= REJECT_AFTER_MESSAGES {
            return None;
        }
        buf[0] = DATA;
        buf[1..5].copy_from_slice(&self.remote_idx.to_le_bytes());
        buf[5..DATA_HDR].copy_from_slice(&n.to_le_bytes());
        let (hdr, rest) = buf.split_at_mut(DATA_HDR);
        let tag = self.transport.seal(n, hdr, &mut rest[..plain_len]);
        rest[plain_len..plain_len + TAG_LEN].copy_from_slice(&tag);
        Some(DATA_HDR + plain_len + TAG_LEN)
    }

    /// Decrypts a DATA packet for this session in place; returns the plaintext range.
    pub fn open(&self, packet: &mut [u8]) -> Option<Range<usize>> {
        if packet.len() < DATA_HDR + TAG_LEN {
            return None;
        }
        let n = u64::from_le_bytes(packet[5..DATA_HDR].try_into().unwrap());
        if n >= REJECT_AFTER_MESSAGES || !self.replay.lock().check(n) {
            return None;
        }
        let end = packet.len() - TAG_LEN;
        let tag: [u8; TAG_LEN] = packet[end..].try_into().unwrap();
        let (hdr, rest) = packet.split_at_mut(DATA_HDR);
        if !self.transport.open(n, hdr, &mut rest[..end - DATA_HDR], &tag) {
            return None;
        }
        // Accept only after authentication, so forged packets cannot move the window.
        let mut w = self.replay.lock();
        if !w.check(n) {
            return None;
        }
        w.accept(n);
        Some(DATA_HDR..end)
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    fn usable(&self) -> bool {
        self.age() < REJECT_AFTER && self.counter.load(Ordering::Relaxed) < REJECT_AFTER_MESSAGES
    }

    fn needs_rekey(&self) -> bool {
        self.age() >= self.rekey_after
    }
}

/// A Noise message whose leading ephemeral is an Elligator2 representative on the wire, with the
/// representative replaced by the public key it stands for.
fn with_decoded_ephemeral(msg: &[u8]) -> Option<Vec<u8>> {
    let repr: [u8; 32] = msg.get(..32)?.try_into().unwrap();
    let mut out = msg.to_vec();
    out[..32].copy_from_slice(&elligator::public(&repr));
    Some(out)
}

/// Receiver index of a DATA packet.
pub fn data_receiver_idx(packet: &[u8]) -> Option<u32> {
    packet.get(1..5).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

struct Pending {
    peer: NodeId,
    initiator: Initiator,
    sent: Instant,
}

#[derive(Default)]
struct PeerSessions {
    current: Option<Arc<Session>>,
    previous: Option<Arc<Session>>,
    next: Option<Arc<Session>>,
    last_init_sent: Option<Instant>,
    /// Newest handshake timestamp seen from this peer; older or equal ones are replays.
    last_init_ts: Option<Tai64n>,
}

#[derive(Default)]
struct Inner {
    by_idx: HashMap<u32, Arc<Session>>,
    pending: HashMap<u32, Pending>,
    peers: HashMap<NodeId, PeerSessions>,
    by_x25519: HashMap<[u8; 32], NodeId>,
    members_refreshed: Option<Instant>,
}

impl Inner {
    fn fresh_idx(&self) -> u32 {
        loop {
            let i = rand::random();
            if !self.by_idx.contains_key(&i) && !self.pending.contains_key(&i) {
                return i;
            }
        }
    }

    fn forget(&mut self, s: Option<Arc<Session>>) {
        if let Some(s) = s {
            self.by_idx.remove(&s.local_idx);
        }
    }

    /// Adds a session: a confirmed one becomes current (the old current stays as previous for
    /// packets in flight), an unconfirmed responder session waits as next.
    fn install(&mut self, s: Arc<Session>) {
        self.by_idx.insert(s.local_idx, s.clone());
        let st = self.peers.entry(s.peer).or_default();
        let dropped = if s.confirmed.load(Ordering::Relaxed) {
            if st.next.as_ref().is_some_and(|n| Arc::ptr_eq(n, &s)) {
                st.next = None;
            }
            let old_previous = st.previous.take();
            st.previous = st.current.replace(s);
            old_previous
        } else {
            st.next.replace(s)
        };
        self.forget(dropped);
    }
}

/// What a received packet turned out to be.
pub enum Received {
    /// A handshake completed or answered; `reply` (if any) goes back to the sender.
    Handshake { peer: NodeId, reply: Option<Vec<u8>> },
    /// Decrypted DATA: `plain` is the range of the packet holding `[kind][body]`.
    Data { session: Arc<Session>, plain: Range<usize> },
}

pub struct Links {
    identity: Arc<Identity>,
    group: Group,
    inner: RwLock<Inner>,
}

impl Links {
    pub fn new(identity: Arc<Identity>, group: Group) -> Self {
        Links { identity, group, inner: RwLock::new(Inner::default()) }
    }

    fn payload(&self) -> Vec<u8> {
        HandshakePayload::new(0, self.group.id).encode()
    }

    /// A HS_INIT packet to `peer`, unless one was sent less than `min_interval` ago.
    pub fn initiate(&self, peer: NodeId, min_interval: Duration) -> Option<Vec<u8>> {
        if peer == self.identity.id() {
            return None;
        }
        let mut inner = self.inner.write();
        let st = inner.peers.entry(peer).or_default();
        if st.last_init_sent.is_some_and(|t| t.elapsed() < min_interval) {
            return None;
        }
        st.last_init_sent = Some(Instant::now());
        let idx = inner.fresh_idx();
        let mut out = Vec::with_capacity(HS_INIT_HDR + noise::INIT_OVERHEAD + 64);
        out.push(HS_INIT);
        out.extend_from_slice(&idx.to_le_bytes());
        let remote = peer.x25519_public().to_bytes();
        let (e, repr) = elligator::ephemeral();
        let ini =
            Initiator::start(self.identity.x25519_secret(), &remote, &self.group.psk, e, &self.payload(), &mut out)
                .ok()?;
        out[HS_INIT_HDR..HS_INIT_HDR + 32].copy_from_slice(&repr);
        inner.pending.insert(idx, Pending { peer, initiator: ini, sent: Instant::now() });
        Some(out)
    }

    fn lookup_member(&self, x25519: &[u8; 32], members: impl FnOnce() -> Vec<NodeId>) -> Option<NodeId> {
        if let Some(id) = self.inner.read().by_x25519.get(x25519) {
            return Some(*id);
        }
        let mut inner = self.inner.write();
        if inner.members_refreshed.is_some_and(|t| t.elapsed() < MEMBER_REFRESH) {
            return None;
        }
        inner.members_refreshed = Some(Instant::now());
        inner.by_x25519 = members().into_iter().map(|id| (id.x25519_public().to_bytes(), id)).collect();
        inner.by_x25519.get(x25519).copied()
    }

    fn handle_init(&self, packet: &[u8], members: impl FnOnce() -> Vec<NodeId>) -> Option<Received> {
        let sender_idx = u32::from_le_bytes(packet.get(1..HS_INIT_HDR)?.try_into().unwrap());
        let msg = with_decoded_ephemeral(&packet[HS_INIT_HDR..])?;
        let (resp, rs, payload) = Responder::read(self.identity.x25519_secret(), &msg).ok()?;
        let peer = self.lookup_member(&rs, members)?;
        let p = HandshakePayload::decode(&payload).ok()?;
        if p.group_id != self.group.id || peer == self.identity.id() {
            return None;
        }
        let mut inner = self.inner.write();
        let st = inner.peers.entry(peer).or_default();
        if st.last_init_ts.is_some_and(|t| p.timestamp <= t) {
            log::debug!("Link | replayed handshake from {} dropped", crate::logger::node(peer));
            return None;
        }
        st.last_init_ts = Some(p.timestamp);
        let idx = inner.fresh_idx();
        let mut out = Vec::with_capacity(HS_RESP_HDR + noise::RESP_OVERHEAD + 64);
        out.push(HS_RESP);
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&sender_idx.to_le_bytes());
        let (e, repr) = elligator::ephemeral();
        let transport = resp.reply(&self.group.psk, e, &self.payload(), &mut out).ok()?;
        out[HS_RESP_HDR..HS_RESP_HDR + 32].copy_from_slice(&repr);
        inner.install(Arc::new(Session::new(peer, idx, sender_idx, transport, false)));
        Some(Received::Handshake { peer, reply: Some(out) })
    }

    fn handle_resp(&self, packet: &[u8]) -> Option<Received> {
        let sender_idx = u32::from_le_bytes(packet.get(1..5)?.try_into().unwrap());
        let receiver_idx = u32::from_le_bytes(packet.get(5..HS_RESP_HDR)?.try_into().unwrap());
        // Verify before removing the pending handshake: the index travels in clear, so a forged
        // HS_RESP must not be able to cancel it.
        let (peer, ini) = {
            let inner = self.inner.read();
            let p = inner.pending.get(&receiver_idx)?;
            (p.peer, p.initiator.clone())
        };
        let (transport, payload) = ini.finish(&with_decoded_ephemeral(&packet[HS_RESP_HDR..])?).ok()?;
        let p = HandshakePayload::decode(&payload).ok()?;
        if p.group_id != self.group.id {
            return None;
        }
        let mut inner = self.inner.write();
        inner.pending.remove(&receiver_idx)?;
        inner.install(Arc::new(Session::new(peer, receiver_idx, sender_idx, transport, true)));
        Some(Received::Handshake { peer, reply: None })
    }

    fn handle_data(&self, packet: &mut [u8]) -> Option<Received> {
        let idx = data_receiver_idx(packet)?;
        let session = self.inner.read().by_idx.get(&idx)?.clone();
        if !session.usable() {
            return None;
        }
        let plain = session.open(packet)?;
        if !session.confirmed.swap(true, Ordering::Relaxed) {
            // the initiator used the session: it holds the keys, switch to it
            self.inner.write().install(session.clone());
        }
        Some(Received::Data { session, plain })
    }

    /// Handles a HS_INIT, HS_RESP or DATA packet. `members` lists the nodes allowed to connect
    /// (called only when an unknown initiator key shows up). Packets that do not authenticate
    /// give `None`.
    pub fn receive(&self, packet: &mut [u8], members: impl FnOnce() -> Vec<NodeId>) -> Option<Received> {
        match *packet.first()? {
            HS_INIT => self.handle_init(packet, members),
            HS_RESP => self.handle_resp(packet),
            DATA => self.handle_data(packet),
            _ => None,
        }
    }

    /// The session to send on, if any.
    pub fn current(&self, peer: &NodeId) -> Option<Arc<Session>> {
        self.inner.read().peers.get(peer)?.current.clone().filter(|s| s.usable())
    }

    /// Whether `peer` needs a (new) handshake: no usable session, or ours is due for rekeying.
    pub fn needs_handshake(&self, peer: &NodeId) -> bool {
        self.current(peer).is_none_or(|s| s.needs_rekey())
    }

    /// Drops expired sessions and stale pending handshakes. Call about once a second.
    pub fn expire(&self) {
        let mut inner = self.inner.write();
        inner.pending.retain(|_, p| p.sent.elapsed() < PENDING_TIMEOUT);
        let mut dead = Vec::new();
        for st in inner.peers.values_mut() {
            for slot in [&mut st.current, &mut st.previous, &mut st.next] {
                if slot.as_ref().is_some_and(|s| !s.usable()) {
                    dead.push(slot.take().unwrap().local_idx);
                }
            }
        }
        for idx in dead {
            inner.by_idx.remove(&idx);
        }
    }

    /// Forgets every session with `peer` (link timeout, peer removed).
    pub fn drop_peer(&self, peer: &NodeId) {
        let mut inner = self.inner.write();
        if let Some(st) = inner.peers.remove(peer) {
            for s in [st.current, st.previous, st.next].into_iter().flatten() {
                inner.by_idx.remove(&s.local_idx);
            }
        }
        inner.pending.retain(|_, p| p.peer != *peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::KIND_IP;

    struct Side {
        id: NodeId,
        links: Links,
    }

    fn side(psk: [u8; 32]) -> Side {
        let identity = Arc::new(Identity::generate());
        Side { id: identity.id(), links: Links::new(identity, Group::from_psk(psk)) }
    }

    fn pair() -> (Side, Side) {
        let psk = crate::crypto::random_bytes();
        (side(psk), side(psk))
    }

    /// A -> B handshake; returns whether both ends completed it.
    fn handshake(a: &Side, b: &Side) -> bool {
        let Some(mut init) = a.links.initiate(b.id, Duration::ZERO) else { return false };
        let Some(Received::Handshake { peer, reply: Some(mut resp) }) = b.links.receive(&mut init, || vec![a.id])
        else {
            return false;
        };
        assert_eq!(peer, a.id);
        matches!(a.links.receive(&mut resp, Vec::new), Some(Received::Handshake { peer, reply: None }) if peer == b.id)
    }

    fn data(from: &Side, to: &NodeId, body: &[u8]) -> Option<Vec<u8>> {
        let s = from.links.current(to)?;
        let mut buf = vec![0u8; DATA_HDR + 1 + body.len() + TAG_LEN];
        buf[DATA_HDR] = KIND_IP;
        buf[DATA_HDR + 1..DATA_HDR + 1 + body.len()].copy_from_slice(body);
        let n = s.seal(&mut buf, 1 + body.len())?;
        buf.truncate(n);
        Some(buf)
    }

    fn deliver(to: &Side, mut packet: Vec<u8>) -> Option<(NodeId, Vec<u8>)> {
        match to.links.receive(&mut packet, Vec::new)? {
            Received::Data { session, plain } => Some((session.peer, packet[plain].to_vec())),
            _ => None,
        }
    }

    #[test]
    fn handshake_then_data_both_ways() {
        let (a, b) = pair();
        assert!(handshake(&a, &b));
        assert!(b.links.current(&a.id).is_none(), "responder waits for key confirmation");
        let p = data(&a, &b.id, b"hello").unwrap();
        assert_eq!(deliver(&b, p), Some((a.id, [&[KIND_IP][..], b"hello"].concat())));
        assert!(b.links.current(&a.id).is_some(), "confirmed by the first packet");
        let p = data(&b, &a.id, b"back").unwrap();
        assert_eq!(deliver(&a, p).unwrap().0, b.id);
    }

    #[test]
    fn different_psk_no_session() {
        let (a, b) = (side([1; 32]), side([2; 32]));
        assert!(!handshake(&a, &b), "group ids differ: no reply");
        assert!(a.links.current(&b.id).is_none() && b.links.current(&a.id).is_none());
    }

    #[test]
    fn same_group_id_wrong_psk_no_session() {
        let (a, mut b) = pair();
        b.links.group.psk = [9; 32]; // as if a node knew the group id but not the psk
        assert!(!handshake(&a, &b));
        assert!(a.links.current(&b.id).is_none());
    }

    #[test]
    fn unknown_initiator_rejected() {
        let (a, b) = pair();
        let mut init = a.links.initiate(b.id, Duration::ZERO).unwrap();
        assert!(b.links.receive(&mut init, Vec::new).is_none(), "a is not a member of b's network");
    }

    #[test]
    fn replayed_init_gets_no_reply() {
        let (a, b) = pair();
        let init = a.links.initiate(b.id, Duration::ZERO).unwrap();
        assert!(b.links.receive(&mut init.clone(), || vec![a.id]).is_some());
        assert!(b.links.receive(&mut init.clone(), || vec![a.id]).is_none(), "same TAI64N timestamp");
    }

    #[test]
    fn replayed_and_tampered_data_rejected() {
        let (a, b) = pair();
        assert!(handshake(&a, &b));
        let p = data(&a, &b.id, b"x").unwrap();
        assert!(deliver(&b, p.clone()).is_some());
        assert!(deliver(&b, p).is_none(), "replay");
        let mut t = data(&a, &b.id, b"y").unwrap();
        t[3] ^= 1; // header is authenticated too
        assert!(deliver(&b, t).is_none());
        let mut t = data(&a, &b.id, b"z").unwrap();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(deliver(&b, t).is_none());
    }

    #[test]
    fn forged_resp_does_not_cancel_pending_handshake() {
        let (a, b) = pair();
        let mut init = a.links.initiate(b.id, Duration::ZERO).unwrap();
        let Some(Received::Handshake { reply: Some(resp), .. }) = b.links.receive(&mut init, || vec![a.id]) else {
            panic!()
        };
        let mut forged = resp.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(a.links.receive(&mut forged, Vec::new).is_none());
        assert!(a.links.receive(&mut resp.clone(), Vec::new).is_some(), "genuine reply still accepted");
    }

    #[test]
    fn rekey_keeps_old_session_for_packets_in_flight() {
        let (a, b) = pair();
        assert!(handshake(&a, &b));
        assert!(deliver(&b, data(&a, &b.id, b"confirm").unwrap()).is_some());
        let in_flight = data(&a, &b.id, b"old").unwrap();
        assert!(handshake(&a, &b), "rekey");
        let fresh = data(&a, &b.id, b"new").unwrap();
        assert_eq!(deliver(&b, fresh).unwrap().1[1..], *b"new");
        assert_eq!(deliver(&b, in_flight).unwrap().1[1..], *b"old", "previous session still accepted");
    }

    #[test]
    fn simultaneous_handshakes_both_work() {
        let (a, b) = pair();
        let mut ia = a.links.initiate(b.id, Duration::ZERO).unwrap();
        let mut ib = b.links.initiate(a.id, Duration::ZERO).unwrap();
        let Some(Received::Handshake { reply: Some(mut ra), .. }) = b.links.receive(&mut ia, || vec![a.id]) else {
            panic!()
        };
        let Some(Received::Handshake { reply: Some(mut rb), .. }) = a.links.receive(&mut ib, || vec![b.id]) else {
            panic!()
        };
        assert!(a.links.receive(&mut ra, Vec::new).is_some());
        assert!(b.links.receive(&mut rb, Vec::new).is_some());
        for _ in 0..3 {
            assert!(deliver(&b, data(&a, &b.id, b"ab").unwrap()).is_some());
            assert!(deliver(&a, data(&b, &a.id, b"ba").unwrap()).is_some());
        }
    }

    #[test]
    fn initiate_rate_limited_and_drop_peer() {
        let (a, b) = pair();
        assert!(a.links.initiate(b.id, Duration::from_secs(1)).is_some());
        assert!(a.links.initiate(b.id, Duration::from_secs(1)).is_none());
        assert!(handshake(&a, &b));
        assert!(!a.links.needs_handshake(&b.id));
        a.links.drop_peer(&b.id);
        assert!(a.links.current(&b.id).is_none() && a.links.needs_handshake(&b.id));
        assert!(a.links.inner.read().by_idx.is_empty());
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::crypto::random_bytes;

    /// Session seal + open of a 1400-byte packet, same workload as the v3 `bench_peer_cipher`
    /// (84.6k pkt/s, 0.95 Gbit/s on the dev machine).
    /// Run: cargo test --release link::bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_session() {
        let psk = random_bytes();
        let (ia, ib) = (Arc::new(Identity::generate()), Arc::new(Identity::generate()));
        let (a, b) = (Links::new(ia.clone(), Group::from_psk(psk)), Links::new(ib.clone(), Group::from_psk(psk)));
        let mut init = a.initiate(ib.id(), Duration::ZERO).unwrap();
        let Some(Received::Handshake { reply: Some(mut resp), .. }) = b.receive(&mut init, || vec![ia.id()]) else {
            panic!()
        };
        a.receive(&mut resp, Vec::new).unwrap();
        let tx = a.current(&ib.id()).unwrap();
        let mut buf = vec![0u8; 2048];
        let n = 100_000;
        let t = Instant::now();
        for _ in 0..n {
            let len = tx.seal(&mut buf, 1400).unwrap();
            match b.receive(&mut buf[..len], Vec::new) {
                Some(Received::Data { .. }) => {}
                _ => panic!("decrypt failed"),
            }
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "noise session: {:.0} pkt/s encrypt+decrypt, {:.2} Gbit/s",
            n as f64 / dt,
            n as f64 * 1400.0 * 8.0 / dt / 1e9
        );
    }
}
