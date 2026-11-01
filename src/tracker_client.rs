//! The client side of a tracker session (PLAN §11): a masked Noise session (`tunnel.rs`),
//! announces with our certificates, the members the tracker reports, and group record sync.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use parking_lot::Mutex;
use rand::RngExt;

use crate::group::{Cert, now_unix};
use crate::identity::{Identity, NodeId};
use crate::link::Session;
use crate::logger::node;
use crate::noise::TAG_LEN;
use crate::obfs::MAX_PAD;
use crate::proto::{DATA, DATA_HDR, HS_RESP, TrackerMsg};
use crate::state::{Entry, Membership, StateStore, SyncMsg};
use crate::storage::{PeerStorage, PeerUpdate};
use crate::tunnel::{self, ClientHello, TrackerKeys};

/// Each announce also refreshes the members list (and their current addresses) from the server.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15);
/// Group records are compared with the server this often (and right after connecting); new
/// records reach us sooner, the server forwards them as they arrive.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(45);
/// A link that answered within this time is not replaced by a tracker-reported endpoint.
const LIVE_LINK: Duration = Duration::from_secs(20);
/// New session keys this often (sessions are dropped after `link::REJECT_AFTER`).
const REKEY: std::ops::Range<Duration> = Duration::from_secs(100)..Duration::from_secs(120);
/// Handshake retries while not connected back off from 1 s to this.
const MAX_RETRY: Duration = Duration::from_secs(16);
/// A rekey handshake that got no answer is repeated after this.
const REKEY_RETRY: Duration = Duration::from_secs(5);

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

struct State {
    hello: Option<(ClientHello, Instant)>,
    retry: Duration,
    /// The session we send on, and the one before it (packets in flight after a rekey).
    session: Option<Arc<Session>>,
    previous: Option<Arc<Session>>,
    rekey_after: Duration,
    connected: bool,
    last_announce: Option<Instant>,
    last_sync: Option<Instant>,
    last_response: Option<Instant>,
    // Wall-clock copies, reported through the API.
    announce_ts: f64,
    response_ts: f64,
}

impl Default for State {
    fn default() -> Self {
        State {
            hello: None,
            retry: Duration::from_secs(1),
            session: None,
            previous: None,
            rekey_after: REKEY.start,
            connected: false,
            last_announce: None,
            last_sync: None,
            last_response: None,
            announce_ts: 0.0,
            response_ts: 0.0,
        }
    }
}

/// Packets to send to the server, an optional connection status change, and what the node
/// should act on: group members the server reported, records that changed our state.
#[derive(Default)]
pub struct Output {
    pub packets: Vec<Vec<u8>>,
    /// Send `packets` to every address of the tracker, not just the current one: a handshake
    /// while not connected goes to all of them at once (IPv6 and IPv4), the first to answer wins.
    pub to_all: bool,
    pub status: Option<bool>,
    pub members: Vec<Cert>,
    /// Address candidates of members, as the tracker reported them.
    pub candidates: Vec<(NodeId, Vec<SocketAddr>)>,
    pub changed: Vec<Entry>,
}

pub struct TrackerClient {
    /// All addresses of the tracker (IPv6 first); `cur` is the one the session runs over.
    addrs: Vec<SocketAddr>,
    cur: std::sync::atomic::AtomicUsize,
    pub key: VerifyingKey,
    keys: TrackerKeys,
    identity: Arc<Identity>,
    /// Our membership certificates, one per group.
    certs: Mutex<Vec<Cert>>,
    store: Arc<StateStore>,
    state: Mutex<State>,
    log_prefix: String,
}

impl State {
    fn send(&mut self, out: &mut Output, msg: &TrackerMsg) {
        let Some(s) = self.session.as_ref().filter(|_| self.connected) else { return };
        let body = msg.encode();
        let mut buf = vec![0u8; DATA_HDR + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR..DATA_HDR + body.len()].copy_from_slice(&body);
        if let Some(n) = s.seal(&mut buf, body.len()) {
            buf.truncate(n);
            out.packets.push(buf);
        }
    }

    fn disconnect(&mut self) {
        let (announce_ts, response_ts) = (self.announce_ts, self.response_ts);
        *self = State { announce_ts, response_ts, ..State::default() };
    }
}

impl TrackerClient {
    pub fn new(
        name: String,
        addrs: Vec<SocketAddr>,
        key: VerifyingKey,
        identity: Arc<Identity>,
        certs: Vec<Cert>,
        store: Arc<StateStore>,
    ) -> Self {
        let log_prefix = format!("Client {name} |");
        log::info!("{log_prefix} Connection status initiated");
        TrackerClient {
            addrs,
            cur: Default::default(),
            key,
            keys: TrackerKeys::new(NodeId::from(key)),
            identity,
            certs: Mutex::new(certs),
            store,
            state: Mutex::new(State::default()),
            log_prefix,
        }
    }

    /// Replaces our certificates (renewed by an admin); announced from the next announce on.
    pub fn set_certs(&self, certs: Vec<Cert>) {
        *self.certs.lock() = certs;
        self.state.lock().last_announce = None;
    }

    /// The address the session runs over (or the next to try).
    pub fn addr(&self) -> SocketAddr {
        self.addrs[self.cur.load(std::sync::atomic::Ordering::Relaxed) % self.addrs.len()]
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    fn in_group(&self, g: &crate::group::GroupId) -> bool {
        self.certs.lock().iter().any(|c| &c.body.group == g)
    }

    /// Sends sync messages (e.g. records just created here) if connected.
    pub fn sync(&self, msgs: Vec<SyncMsg>) -> Output {
        let mut out = Output::default();
        let mut s = self.state.lock();
        for m in msgs {
            s.send(&mut out, &TrackerMsg::Sync(m));
        }
        out
    }

    pub fn is_connected(&self) -> bool {
        self.state.lock().connected
    }

    /// (last announce, last search, last response) as unix timestamps, 0 = never. Members are
    /// looked up by every announce now, so the search time is the announce time.
    pub fn timestamps(&self) -> (f64, f64, f64) {
        let s = self.state.lock();
        (s.announce_ts, s.announce_ts, s.response_ts)
    }

    /// Called once per second, with our address candidates to announce.
    pub fn tick(&self, candidates: &[SocketAddr]) -> Output {
        let mut out = Output::default();
        let mut s = self.state.lock();

        if s.connected && s.last_response.is_some_and(|t| t.elapsed() >= RESPONSE_TIMEOUT) {
            log::info!("{} Connection status disconnected", self.log_prefix);
            s.send(&mut out, &TrackerMsg::Close);
            s.disconnect();
            out.status = Some(false);
        }

        let rekey_after = s.rekey_after;
        let need = s.session.as_ref().is_none_or(|x| x.age() >= rekey_after || !x.usable());
        let wait = if s.connected { REKEY_RETRY } else { s.retry };
        if need
            && s.hello.as_ref().is_none_or(|(_, t)| t.elapsed() >= wait)
            && let Some((packets, hello)) = tunnel::client_hello(&self.keys, &self.identity, rand::random())
        {
            out.packets.extend(packets);
            out.to_all = !s.connected;
            s.hello = Some((hello, Instant::now()));
            if !s.connected {
                log::debug!("{} Connection status connecting", self.log_prefix);
                s.retry = (s.retry * 2).min(MAX_RETRY);
            }
        }
        if !s.connected {
            return out;
        }
        // a rekey handshake goes to the current address only
        let mut rest = Output::default();

        if s.last_announce.is_none_or(|t| t.elapsed() >= ANNOUNCE_INTERVAL) {
            log::debug!("{} Send announce", self.log_prefix);
            let msg = TrackerMsg::Announce { certs: self.certs.lock().clone(), candidates: candidates.to_vec() };
            s.send(&mut rest, &msg);
            s.last_announce = Some(Instant::now());
            s.announce_ts = unix_now();
        }

        if s.last_sync.is_none_or(|t| t.elapsed() >= SYNC_INTERVAL) {
            let groups: Vec<_> = self.certs.lock().iter().map(|c| c.body.group).collect();
            for g in groups {
                for m in SyncMsg::summaries(&self.store, &g) {
                    s.send(&mut rest, &TrackerMsg::Sync(m));
                }
            }
            s.last_sync = Some(Instant::now());
        }
        out.packets.extend(rest.packets);
        out
    }

    pub fn handle(&self, packet: &[u8], from: SocketAddr, storage: &PeerStorage) -> Output {
        let mut out = Output::default();
        let mut p = packet.to_vec();
        let Some(len) = self.keys.obfs.open(&mut p) else { return out };
        let p = &mut p[..len];
        let mut s = self.state.lock();
        match p[0] {
            HS_RESP => {
                let Some((hello, _)) = s.hello.as_ref().filter(|(h, _)| tunnel::resp_receiver_idx(p) == Some(h.idx))
                else {
                    return out;
                };
                let Some(session) = tunnel::client_finish(&self.keys, hello, p) else {
                    log::info!("{} handshake reply does not verify", self.log_prefix);
                    return out;
                };
                s.hello = None;
                if let Some(i) = self.addrs.iter().position(|a| *a == from) {
                    self.cur.store(i, std::sync::atomic::Ordering::Relaxed);
                }
                s.previous = s.session.replace(Arc::new(session));
                s.rekey_after = rand::rng().random_range(REKEY);
                s.last_response = Some(Instant::now());
                s.response_ts = unix_now();
                if !s.connected {
                    log::info!("{} Connection status connected via {from}", self.log_prefix);
                    s.connected = true;
                    s.retry = Duration::from_secs(1);
                    s.last_announce = None;
                    s.last_sync = None;
                    out.status = Some(true);
                }
                // confirms the new session to the server (it switches to it on our first packet)
                s.send(&mut out, &TrackerMsg::Sync(SyncMsg::Records { records: Vec::new() }));
            }
            DATA => {
                let Some(idx) = p.get(3..7).map(|b| u32::from_le_bytes(b.try_into().unwrap())) else { return out };
                let Some(session) =
                    [&s.session, &s.previous].into_iter().flatten().find(|x| x.local_idx == idx).cloned()
                else {
                    return out;
                };
                let Some(plain) = session.open(p) else { return out };
                s.last_response = Some(Instant::now());
                s.response_ts = unix_now();
                match TrackerMsg::decode(&p[plain]) {
                    Some(TrackerMsg::Found { cert, addr, candidates }) => {
                        drop(s);
                        if self.found(&cert, addr, storage) {
                            out.candidates.push((cert.body.node, candidates));
                            out.members.push(*cert);
                        }
                    }
                    Some(TrackerMsg::Sync(msg)) => {
                        let (replies, changed) = msg.handle(&self.store, |g| self.in_group(g));
                        for r in replies {
                            s.send(&mut out, &TrackerMsg::Sync(r));
                        }
                        out.changed = changed;
                    }
                    Some(TrackerMsg::Close) => {
                        log::info!("{} Connection closed from server", self.log_prefix);
                        s.disconnect();
                        out.status = Some(false);
                    }
                    Some(TrackerMsg::Announce { .. }) => {}
                    None => log::info!("{} Received packet | decode error", self.log_prefix),
                }
            }
            _ => {}
        }
        out
    }

    /// A member of one of our groups is at `addr`. The certificate is checked here too: the
    /// tracker is not trusted with membership. Returns whether it is a valid member other than us.
    fn found(&self, cert: &Cert, addr: SocketAddr, storage: &PeerStorage) -> bool {
        let peer = cert.body.node;
        if !self.in_group(&cert.body.group) {
            return false;
        }
        if let Err(e) = cert.verify(&cert.body.group, Some(now_unix())) {
            log::info!("{} Peer {} from the server: {e}", self.log_prefix, node(peer));
            return false;
        }
        if storage.is_self(&peer) {
            if storage.endpoint(&peer) != Some(addr) {
                log::info!("{} New self endpoint {addr}", self.log_prefix);
                storage.set_peer(peer, PeerUpdate { endpoint: Some(Some(addr)), ..Default::default() });
            }
            return false;
        }
        if !Membership::of(&self.store, &cert.body.group).admits(cert) {
            log::debug!("{} Peer {} from the server is revoked", self.log_prefix, node(peer));
            return false;
        }
        let mut update = PeerUpdate::from_cert(cert);
        if let Some((r, _)) = storage.get(&peer)
            && Some(r.name) == update.name
            && Some(r.addr) == update.addr
        {
            // nothing new: no update event for API clients every announce
            update.name = None;
            update.addr = None;
        }
        if storage.endpoint(&peer) == Some(addr) {
            log::debug!("{} Peer {} receive endpoint {addr}", self.log_prefix, node(peer));
        } else if storage.link_alive(&peer, LIVE_LINK) {
            // The direct link works; behind some NATs the peer's real port differs from what the
            // tracker sees, so don't break a working link.
            log::debug!("{} Peer {} endpoint {addr} ignored, link alive", self.log_prefix, node(peer));
        } else {
            log::info!("{} Peer {} new endpoint {addr}", self.log_prefix, node(peer));
            update.endpoint = Some(Some(addr));
        }
        if update.name.is_some() || update.endpoint.is_some() {
            storage.set_peer(peer, update);
        }
        true
    }

    /// Best-effort goodbye on shutdown.
    pub fn close(&self) -> Option<Vec<u8>> {
        let mut s = self.state.lock();
        let mut out = Output::default();
        s.send(&mut out, &TrackerMsg::Close);
        s.disconnect();
        out.packets.pop()
    }
}
