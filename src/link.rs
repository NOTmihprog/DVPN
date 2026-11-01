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

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use rand::RngExt;

use crate::elligator;
use crate::group::{Cert, GroupId, now_unix};
use crate::identity::{Identity, NodeId};
use crate::noise::{self, HandshakePayload, Initiator, Responder, TAG_LEN, Tai64n};
use crate::obfs::{MAX_PAD, Obfs, Profile};
use crate::proto::{DATA, DATA_HDR, HS_INIT, HS_INIT_HDR, HS_RESP, HS_RESP_HDR};
use crate::replay::ReplayWindow;
use crate::state::Membership;

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
/// What sessions need to know about the group (PLAN §5).
#[derive(Clone)]
pub struct Group {
    pub id: GroupId,
    pub psk: [u8; 32],
    pub obfs: Profile,
    /// Our membership certificate, sent in every handshake. The peer's one is checked against
    /// the group id: membership is proven by the certificate, not by a list of known keys.
    pub cert: Cert,
}

pub struct Session {
    pub peer: NodeId,
    pub local_idx: u32,
    remote_idx: u32,
    transport: noise::Transport,
    obfs: Arc<Obfs>,
    counter: AtomicU64,
    replay: Mutex<ReplayWindow>,
    created: Instant,
    rekey_after: Duration,
    /// The peer has proven it holds the keys (always true for sessions we initiated).
    confirmed: AtomicBool,
}

impl Session {
    fn new(
        peer: NodeId,
        local_idx: u32,
        remote_idx: u32,
        transport: noise::Transport,
        obfs: Arc<Obfs>,
        initiator: bool,
    ) -> Self {
        let jitter = rand::rng().random_range(Duration::ZERO..REKEY_JITTER);
        Session {
            peer,
            local_idx,
            remote_idx,
            transport,
            obfs,
            counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::default()),
            created: Instant::now(),
            rekey_after: REKEY_AFTER - jitter + if initiator { Duration::ZERO } else { RESPONDER_REKEY_DELAY },
            confirmed: AtomicBool::new(initiator),
        }
    }

    /// Builds a wire DATA packet in `buf`: the plaintext must already be at
    /// `buf[DATA_HDR..DATA_HDR + plain_len]`; `buf` needs `TAG_LEN` more bytes after it, plus up to
    /// `MAX_PAD` for padding (less room just means less padding). Returns the wire length, or
    /// `None` once the session has used up its counters.
    pub fn seal(&self, buf: &mut [u8], plain_len: usize) -> Option<usize> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        if n >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let len = DATA_HDR + plain_len + TAG_LEN;
        let pad = self.obfs.pad_len(DATA, len, buf.len() - len);
        buf[0] = DATA;
        buf[1..3].copy_from_slice(&pad.to_le_bytes());
        buf[3..7].copy_from_slice(&self.remote_idx.to_le_bytes());
        buf[7..DATA_HDR].copy_from_slice(&n.to_le_bytes());
        let (hdr, rest) = buf.split_at_mut(DATA_HDR);
        let tag = self.transport.seal(n, hdr, &mut rest[..plain_len]);
        rest[plain_len..plain_len + TAG_LEN].copy_from_slice(&tag);
        Some(self.obfs.finish(buf, len, pad))
    }

    /// Decrypts an unmasked DATA packet (padding removed) in place; returns the plaintext range.
    fn open(&self, packet: &mut [u8]) -> Option<Range<usize>> {
        if packet.len() < DATA_HDR + TAG_LEN {
            return None;
        }
        let n = u64::from_le_bytes(packet[7..DATA_HDR].try_into().unwrap());
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

/// Receiver index of an unmasked DATA packet.
fn data_receiver_idx(packet: &[u8]) -> Option<u32> {
    packet.get(3..7).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

struct Pending {
    peer: NodeId,
    initiator: Initiator,
    key: Arc<Key>,
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
    /// A handshake completed or answered; `reply` (if any) goes back to the sender. `cert` is
    /// the peer's verified membership certificate (its name and addresses).
    Handshake { peer: NodeId, cert: Box<Cert>, reply: Option<Vec<u8>> },
    /// Decrypted DATA: `plain` is the range of the packet holding `[kind][body]`.
    Data { session: Arc<Session>, plain: Range<usize> },
}

/// One psk of the group and the header protection derived from it. Sessions remember the key
/// their handshake used (through its `Obfs`).
pub struct Key {
    pub epoch: u32,
    psk: [u8; 32],
    obfs: Arc<Obfs>,
}

/// The psk to send with, and all psks accepted (the send one first). Two during a psk epoch
/// change (PLAN §4.4): before the switch we send with the old one and accept both, after it we
/// send with the new one and still accept the old one for a while.
struct Keys {
    send: Arc<Key>,
    accept: Vec<Arc<Key>>,
}

pub struct Links {
    identity: Arc<Identity>,
    group: Group,
    /// Our certificate as currently sent (renewed at runtime; `group.cert` is the initial one).
    cert: RwLock<Cert>,
    /// Revocations from the group records.
    membership: RwLock<Membership>,
    keys: ArcSwap<Keys>,
    inner: RwLock<Inner>,
}

impl Links {
    pub fn new(identity: Arc<Identity>, group: Group) -> Self {
        let key = Arc::new(Key { epoch: 0, psk: group.psk, obfs: Arc::new(Obfs::new(&group.psk, group.obfs.clone())) });
        Links {
            identity,
            cert: RwLock::new(group.cert.clone()),
            group,
            membership: RwLock::new(Membership::default()),
            keys: ArcSwap::from_pointee(Keys { send: key.clone(), accept: vec![key] }),
            inner: RwLock::new(Inner::default()),
        }
    }

    /// Sets the psk to send with (`send`) and an extra accepted one (`also`), as (epoch, psk).
    /// Keys already in use are kept, so their sessions go on.
    pub fn set_psks(&self, send: (u32, [u8; 32]), also: Option<(u32, [u8; 32])>) {
        let cur = self.keys.load();
        let make = |(epoch, psk): (u32, [u8; 32])| {
            cur.accept.iter().find(|k| k.psk == psk).cloned().unwrap_or_else(|| {
                Arc::new(Key { epoch, psk, obfs: Arc::new(Obfs::new(&psk, self.group.obfs.clone())) })
            })
        };
        let send = make(send);
        let mut accept = vec![send.clone()];
        if let Some(a) = also.filter(|a| a.1 != send.psk) {
            accept.push(make(a));
        }
        if cur.send.psk == send.psk && cur.accept.len() == accept.len() {
            return;
        }
        log::info!(
            "Link | sending with psk epoch {}, accepting {:?}",
            send.epoch,
            accept.iter().map(|k| k.epoch).collect::<Vec<_>>()
        );
        self.keys.store(Arc::new(Keys { send, accept }));
    }

    /// The psk epoch handshakes are sent with.
    pub fn send_epoch(&self) -> u32 {
        self.keys.load().send.epoch
    }

    /// Sends this certificate in handshakes from now on.
    pub fn set_cert(&self, cert: Cert) {
        *self.cert.write() = cert;
    }

    /// New handshakes are checked against this; existing sessions of revoked nodes are dropped
    /// by the caller (`drop_peer`).
    pub fn set_membership(&self, m: Membership) {
        *self.membership.write() = m;
    }

    /// Pads and masks a finished handshake packet in `out` (header with a zero pad field).
    fn finish_handshake(&self, key: &Key, ty: u8, mut out: Vec<u8>) -> Vec<u8> {
        let len = out.len();
        let pad = key.obfs.pad_len(ty, len, MAX_PAD);
        out[1..3].copy_from_slice(&pad.to_le_bytes());
        out.resize(len + pad as usize, 0);
        let n = key.obfs.finish(&mut out, len, pad);
        out.truncate(n);
        out
    }

    fn payload(&self) -> Vec<u8> {
        let mut p = HandshakePayload::new(0, *self.group.id.as_bytes());
        p.cert = self.cert.read().encode();
        p.encode()
    }

    /// The peer's certificate from a decrypted handshake payload, if it is a valid member of
    /// our group (and not us).
    fn member_cert(&self, payload: &[u8]) -> Option<Cert> {
        let p = HandshakePayload::decode(payload).ok()?;
        if p.group_id != *self.group.id.as_bytes() {
            return None;
        }
        let cert = Cert::decode(&p.cert)?;
        if let Err(e) = cert.verify(&self.group.id, Some(now_unix())) {
            log::debug!("Link | handshake from {} with {e}", crate::logger::node(cert.body.node));
            return None;
        }
        if !self.membership.read().admits(&cert) {
            log::debug!("Link | handshake from revoked {}", crate::logger::node(cert.body.node));
            return None;
        }
        (cert.body.node != self.identity.id()).then_some(cert)
    }

    /// Packets that start a handshake with `peer`, in sending order: the profile's signature and
    /// junk packets, then HS_INIT. `None` if one was sent less than `min_interval` ago.
    pub fn initiate(&self, peer: NodeId, min_interval: Duration) -> Option<Vec<Vec<u8>>> {
        if peer == self.identity.id() {
            return None;
        }
        let mut inner = self.inner.write();
        let st = inner.peers.entry(peer).or_default();
        if st.last_init_sent.is_some_and(|t| t.elapsed() < min_interval) {
            return None;
        }
        let key = self.keys.load().send.clone();
        st.last_init_sent = Some(Instant::now());
        let idx = inner.fresh_idx();
        let mut out = Vec::with_capacity(HS_INIT_HDR + noise::INIT_OVERHEAD + 64 + MAX_PAD);
        out.extend_from_slice(&[HS_INIT, 0, 0]);
        out.extend_from_slice(&idx.to_le_bytes());
        let remote = peer.x25519_public().to_bytes();
        let (e, repr) = elligator::ephemeral();
        let ini =
            Initiator::start(self.identity.x25519_secret(), &remote, &key.psk, e, &self.payload(), &mut out).ok()?;
        out[HS_INIT_HDR..HS_INIT_HDR + 32].copy_from_slice(&repr);
        inner.pending.insert(idx, Pending { peer, initiator: ini, key: key.clone(), sent: Instant::now() });
        drop(inner);
        let mut packets = key.obfs.prelude();
        packets.push(self.finish_handshake(&key, HS_INIT, out));
        Some(packets)
    }

    fn handle_init(&self, key: &Key, packet: &[u8]) -> Option<Received> {
        let sender_idx = u32::from_le_bytes(packet.get(3..HS_INIT_HDR)?.try_into().unwrap());
        let msg = with_decoded_ephemeral(&packet[HS_INIT_HDR..])?;
        let (resp, rs, payload) = Responder::read(self.identity.x25519_secret(), &msg).ok()?;
        let cert = self.member_cert(&payload)?;
        let peer = cert.body.node;
        // the certificate must be for the key that did the handshake
        if peer.x25519_public().to_bytes() != rs {
            return None;
        }
        let p = HandshakePayload::decode(&payload).ok()?;
        let mut inner = self.inner.write();
        let st = inner.peers.entry(peer).or_default();
        if st.last_init_ts.is_some_and(|t| p.timestamp <= t) {
            log::debug!("Link | replayed handshake from {} dropped", crate::logger::node(peer));
            return None;
        }
        st.last_init_ts = Some(p.timestamp);
        let idx = inner.fresh_idx();
        let mut out = Vec::with_capacity(HS_RESP_HDR + noise::RESP_OVERHEAD + 64 + MAX_PAD);
        out.extend_from_slice(&[HS_RESP, 0, 0]);
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&sender_idx.to_le_bytes());
        let (e, repr) = elligator::ephemeral();
        // answer with the psk the initiator masked its packet with
        let transport = resp.reply(&key.psk, e, &self.payload(), &mut out).ok()?;
        out[HS_RESP_HDR..HS_RESP_HDR + 32].copy_from_slice(&repr);
        inner.install(Arc::new(Session::new(peer, idx, sender_idx, transport, key.obfs.clone(), false)));
        drop(inner);
        Some(Received::Handshake { peer, cert: Box::new(cert), reply: Some(self.finish_handshake(key, HS_RESP, out)) })
    }

    fn handle_resp(&self, key: &Arc<Key>, packet: &[u8]) -> Option<Received> {
        let sender_idx = u32::from_le_bytes(packet.get(3..7)?.try_into().unwrap());
        let receiver_idx = u32::from_le_bytes(packet.get(7..HS_RESP_HDR)?.try_into().unwrap());
        // Verify before removing the pending handshake: the index travels in clear, so a forged
        // HS_RESP must not be able to cancel it.
        let (peer, ini) = {
            let inner = self.inner.read();
            let p = inner.pending.get(&receiver_idx).filter(|p| Arc::ptr_eq(&p.key, key))?;
            (p.peer, p.initiator.clone())
        };
        let (transport, payload) = ini.finish(&with_decoded_ephemeral(&packet[HS_RESP_HDR..])?).ok()?;
        // IK: the responder's key is the one we initiated to; its certificate must match it
        let cert = self.member_cert(&payload).filter(|c| c.body.node == peer)?;
        let mut inner = self.inner.write();
        inner.pending.remove(&receiver_idx)?;
        inner.install(Arc::new(Session::new(peer, receiver_idx, sender_idx, transport, key.obfs.clone(), true)));
        Some(Received::Handshake { peer, cert: Box::new(cert), reply: None })
    }

    fn handle_data(&self, key: &Key, packet: &mut [u8]) -> Option<Received> {
        let idx = data_receiver_idx(packet)?;
        let session = self.inner.read().by_idx.get(&idx)?.clone();
        if !session.usable() || !Arc::ptr_eq(&session.obfs, &key.obfs) {
            return None;
        }
        let plain = session.open(packet)?;
        if !session.confirmed.swap(true, Ordering::Relaxed) {
            // the initiator used the session: it holds the keys, switch to it
            self.inner.write().install(session.clone());
        }
        Some(Received::Data { session, plain })
    }

    /// Handles a wire packet from a peer: unmasks it, then processes the HS_INIT, HS_RESP or DATA
    /// inside. Packets that do not authenticate give `None`. `Data::plain` indexes into `packet`.
    pub fn receive(&self, packet: &mut [u8]) -> Option<Received> {
        let keys = self.keys.load();
        if let [key] = keys.accept.as_slice() {
            return self.receive_with(key, packet);
        }
        // During a psk change: unmasking is in place, so each further key starts from a copy.
        let orig = packet.to_vec();
        for (i, key) in keys.accept.iter().enumerate() {
            if i > 0 {
                packet.copy_from_slice(&orig);
            }
            if let Some(r) = self.receive_with(key, packet) {
                return Some(r);
            }
        }
        None
    }

    fn receive_with(&self, key: &Arc<Key>, packet: &mut [u8]) -> Option<Received> {
        let len = key.obfs.open(packet)?;
        let packet = &mut packet[..len];
        match packet[0] {
            HS_INIT => self.handle_init(key, packet),
            HS_RESP => self.handle_resp(key, packet),
            DATA => self.handle_data(key, packet),
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
    use crate::group::{CertBody, GroupSecret};
    use crate::proto::KIND_IP;

    struct Side {
        id: NodeId,
        links: Links,
    }

    fn member(secret: &GroupSecret, identity: &Identity) -> Group {
        let cert = secret.issue(CertBody::new(identity.id(), "n", vec![]));
        Group { id: secret.id(), psk: secret.psk(0), obfs: Profile::default(), cert }
    }

    fn side_with(identity: Identity, group: Group) -> Side {
        Side { id: identity.id(), links: Links::new(Arc::new(identity), group) }
    }

    fn side(secret: &GroupSecret) -> Side {
        let identity = Identity::generate();
        let g = member(secret, &identity);
        side_with(identity, g)
    }

    fn pair() -> (Side, Side) {
        let secret = GroupSecret::generate();
        (side(&secret), side(&secret))
    }

    /// A -> B handshake; returns whether both ends completed it.
    fn handshake(a: &Side, b: &Side) -> bool {
        let Some(mut init) = a.links.initiate(b.id, Duration::ZERO).and_then(|mut p| p.pop()) else { return false };
        let Some(Received::Handshake { peer, cert, reply: Some(mut resp) }) = b.links.receive(&mut init) else {
            return false;
        };
        assert_eq!((peer, cert.body.node), (a.id, a.id));
        matches!(a.links.receive(&mut resp), Some(Received::Handshake { peer, cert, reply: None }) if peer == b.id && cert.body.node == b.id)
    }

    fn data(from: &Side, to: &NodeId, body: &[u8]) -> Option<Vec<u8>> {
        let s = from.links.current(to)?;
        let mut buf = vec![0u8; DATA_HDR + 1 + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR] = KIND_IP;
        buf[DATA_HDR + 1..DATA_HDR + 1 + body.len()].copy_from_slice(body);
        let n = s.seal(&mut buf, 1 + body.len())?;
        buf.truncate(n);
        Some(buf)
    }

    fn deliver(to: &Side, mut packet: Vec<u8>) -> Option<(NodeId, Vec<u8>)> {
        match to.links.receive(&mut packet)? {
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
    fn different_group_no_session() {
        let (a, b) = (side(&GroupSecret::generate()), side(&GroupSecret::generate()));
        assert!(!handshake(&a, &b), "other psk and group id: no reply");
        assert!(a.links.current(&b.id).is_none() && b.links.current(&a.id).is_none());
    }

    #[test]
    fn revoked_member_no_session() {
        let (a, b) = pair();
        assert!(handshake(&a, &b));
        let m = Membership { revoked: [a.id].into(), ..Default::default() };
        b.links.set_membership(m.clone());
        std::thread::sleep(Duration::from_millis(40)); // next handshake timestamp
        assert!(!handshake(&a, &b), "b refuses revoked a");
        a.links.set_membership(Membership { revoked: [b.id].into(), ..Default::default() });
        b.links.set_membership(Membership::default());
        assert!(!handshake(&b, &a) && !handshake(&a, &b), "a refuses revoked b, also as initiator");
    }

    #[test]
    fn psk_change_with_overlap() {
        let (a, b) = pair();
        let (p0, p1) = (a.links.group.psk, [7u8; 32]);
        assert!(handshake(&a, &b));
        let old = data(&a, &b.id, b"old").unwrap();
        // a has switched to epoch 1 already, b has the record but not reached the switch time
        a.links.set_psks((1, p1), Some((0, p0)));
        b.links.set_psks((0, p0), Some((1, p1)));
        assert_eq!(deliver(&b, old).unwrap().1[1..], *b"old", "session from before the change goes on");
        std::thread::sleep(Duration::from_millis(40));
        assert!(handshake(&a, &b), "a sends with the new psk, b accepts it");
        assert!(deliver(&b, data(&a, &b.id, b"x").unwrap()).is_some());
        assert!(deliver(&a, data(&b, &a.id, b"y").unwrap()).is_some());
        std::thread::sleep(Duration::from_millis(40));
        assert!(handshake(&b, &a), "b still sends with the old psk, a still accepts it");
        assert!(deliver(&a, data(&b, &a.id, b"z").unwrap()).is_some());
        // after the grace period only the new psk counts
        a.links.set_psks((1, p1), None);
        b.links.set_psks((0, p0), None);
        std::thread::sleep(Duration::from_millis(40));
        assert!(!handshake(&a, &b) && !handshake(&b, &a), "different psks, no overlap: no session");
        assert_eq!(a.links.send_epoch(), 1);
    }

    #[test]
    fn same_group_id_wrong_psk_no_session() {
        let secret = GroupSecret::generate();
        let a = side(&secret);
        let ib = Identity::generate();
        let mut g = member(&secret, &ib);
        g.psk = [9; 32]; // as if a node had a valid certificate but not the psk
        let b = side_with(ib, g);
        assert!(!handshake(&a, &b));
        assert!(a.links.current(&b.id).is_none());
    }

    /// The psk alone is not enough: the initiator must present a valid certificate for its own key.
    #[test]
    fn certificate_required() {
        let secret = GroupSecret::generate();
        let b = side(&secret);
        type MakeCert<'a> = Box<dyn Fn(&Identity) -> Cert + 'a>;
        let bad_certs: [MakeCert; 3] = [
            // signed by another group
            Box::new(|i| GroupSecret::generate().issue(CertBody::new(i.id(), "x", vec![]))),
            // expired
            Box::new(|i| {
                let mut body = CertBody::new(i.id(), "x", vec![]);
                body.not_after = 1;
                secret.issue(body)
            }),
            // valid, but for somebody else's key
            Box::new(|_| secret.issue(CertBody::new(Identity::generate().id(), "x", vec![]))),
        ];
        for (i, make) in bad_certs.iter().enumerate() {
            let ia = Identity::generate();
            let mut g = member(&secret, &ia);
            g.cert = make(&ia);
            let a = side_with(ia, g);
            assert!(!handshake(&a, &b), "bad cert {i} accepted");
            // and as a responder
            assert!(!handshake(&b, &a), "bad cert {i} accepted from the responder");
        }
    }

    #[test]
    fn replayed_init_gets_no_reply() {
        let (a, b) = pair();
        let init = a.links.initiate(b.id, Duration::ZERO).unwrap().pop().unwrap();
        assert!(b.links.receive(&mut init.clone()).is_some());
        assert!(b.links.receive(&mut init.clone()).is_none(), "same TAI64N timestamp");
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
        t[DATA_HDR + 1 + 1 + TAG_LEN - 1] ^= 1; // last tag byte; padding follows
        assert!(deliver(&b, t).is_none());
        let mut t = data(&a, &b.id, b"padded").unwrap();
        let pad_start = DATA_HDR + 1 + 6 + TAG_LEN;
        if t.len() > pad_start {
            t[pad_start] ^= 1; // padding is not authenticated, but carries nothing either
            assert!(deliver(&b, t).is_some());
        }
    }

    #[test]
    fn forged_resp_does_not_cancel_pending_handshake() {
        let (a, b) = pair();
        let mut init = a.links.initiate(b.id, Duration::ZERO).unwrap().pop().unwrap();
        let Some(Received::Handshake { reply: Some(resp), .. }) = b.links.receive(&mut init) else { panic!() };
        let mut forged = resp.clone();
        forged[60] ^= 1; // inside the encrypted payload (the tail may be padding)
        assert!(a.links.receive(&mut forged).is_none());
        assert!(a.links.receive(&mut resp.clone()).is_some(), "genuine reply still accepted");
    }

    #[test]
    fn rekey_keeps_old_session_for_packets_in_flight() {
        let (a, b) = pair();
        assert!(handshake(&a, &b));
        assert!(deliver(&b, data(&a, &b.id, b"confirm").unwrap()).is_some());
        let in_flight = data(&a, &b.id, b"old").unwrap();
        // handshake timestamps are whitened to ~16.7 ms; a second init inside the same window
        // carries the same timestamp and is (rightly) treated as a replay
        std::thread::sleep(Duration::from_millis(40));
        assert!(handshake(&a, &b), "rekey");
        let fresh = data(&a, &b.id, b"new").unwrap();
        assert_eq!(deliver(&b, fresh).unwrap().1[1..], *b"new");
        assert_eq!(deliver(&b, in_flight).unwrap().1[1..], *b"old", "previous session still accepted");
    }

    #[test]
    fn simultaneous_handshakes_both_work() {
        let (a, b) = pair();
        let mut ia = a.links.initiate(b.id, Duration::ZERO).unwrap().pop().unwrap();
        let mut ib = b.links.initiate(a.id, Duration::ZERO).unwrap().pop().unwrap();
        let Some(Received::Handshake { reply: Some(mut ra), .. }) = b.links.receive(&mut ia) else { panic!() };
        let Some(Received::Handshake { reply: Some(mut rb), .. }) = a.links.receive(&mut ib) else { panic!() };
        assert!(a.links.receive(&mut ra).is_some());
        assert!(b.links.receive(&mut rb).is_some());
        for _ in 0..3 {
            assert!(deliver(&b, data(&a, &b.id, b"ab").unwrap()).is_some());
            assert!(deliver(&a, data(&b, &a.id, b"ba").unwrap()).is_some());
        }
    }

    #[test]
    fn junk_and_signatures_precede_init_and_are_ignored() {
        let secret = GroupSecret::generate();
        let (ia, ib) = (Identity::generate(), Identity::generate());
        let (mut ga, mut gb) = (member(&secret, &ia), member(&secret, &ib));
        ga.obfs.signatures = vec!["<b 0x16030301> <r 40>".parse().unwrap()];
        gb.obfs = ga.obfs.clone();
        let (ia, ib) = (Arc::new(ia), Arc::new(ib));
        let (a, b) = (Links::new(ia.clone(), ga), Links::new(ib.clone(), gb));
        let packets = a.initiate(ib.id(), Duration::ZERO).unwrap();
        assert!((1 + 4 + 1..=1 + 8 + 1).contains(&packets.len()), "signature, 4-8 junk, init");
        assert_eq!(packets[0][..4], [0x16, 0x03, 0x03, 0x01]);
        let (init, prelude) = packets.split_last().unwrap();
        for p in prelude {
            assert!(b.receive(&mut p.clone()).is_none());
        }
        assert!(b.receive(&mut init.clone()).is_some());
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

    /// Session seal + open of a 1400-byte packet, same workload as the v3 `bench_peer_cipher`
    /// (84.6k pkt/s, 0.95 Gbit/s on the dev machine).
    /// Run: cargo test --release link::bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_session() {
        let secret = crate::group::GroupSecret::generate();
        let group = |i: &Identity| Group {
            id: secret.id(),
            psk: secret.psk(0),
            obfs: Profile::default(),
            cert: secret.issue(crate::group::CertBody::new(i.id(), "n", vec![])),
        };
        let (ia, ib) = (Arc::new(Identity::generate()), Arc::new(Identity::generate()));
        let (a, b) = (Links::new(ia.clone(), group(&ia)), Links::new(ib.clone(), group(&ib)));
        let mut init = a.initiate(ib.id(), Duration::ZERO).unwrap().pop().unwrap();
        let Some(Received::Handshake { reply: Some(mut resp), .. }) = b.receive(&mut init) else { panic!() };
        a.receive(&mut resp).unwrap();
        let tx = a.current(&ib.id()).unwrap();
        let mut buf = vec![0u8; 2048];
        let n = 100_000;
        let t = Instant::now();
        for _ in 0..n {
            let len = tx.seal(&mut buf, 1400).unwrap();
            match b.receive(&mut buf[..len]) {
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
