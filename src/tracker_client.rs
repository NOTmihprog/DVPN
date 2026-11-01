use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use parking_lot::Mutex;

use crate::crypto::{ClientHandshake, TrackerSession};
use crate::group::{Cert, now_unix};
use crate::identity::Identity;
use crate::logger::node;
use crate::proto::{HELLO_ACK, TRACKER, TrackerMsg};
use crate::storage::{PeerStorage, PeerUpdate};

/// Each announce also refreshes the members list (and their current addresses) from the server.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(45);
/// A link that answered within this time is not replaced by a tracker-reported endpoint.
const LIVE_LINK: Duration = Duration::from_secs(20);

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

#[derive(Default)]
struct State {
    handshake: Option<ClientHandshake>,
    session: Option<TrackerSession>,
    last_announce: Option<Instant>,
    last_response: Option<Instant>,
    // Wall-clock copies of the above, reported through the API.
    announce_ts: f64,
    response_ts: f64,
}

/// Packets to send to the server plus an optional connection status change.
#[derive(Default)]
pub struct Output {
    pub packets: Vec<Vec<u8>>,
    pub status: Option<bool>,
}

pub struct TrackerClient {
    pub addr: SocketAddr,
    pub key: VerifyingKey,
    identity: Arc<Identity>,
    /// Our membership certificates, one per group.
    certs: Vec<Cert>,
    state: Mutex<State>,
    log_prefix: String,
}

impl State {
    fn send(&mut self, out: &mut Output, msg: &TrackerMsg) {
        if let Some(s) = &mut self.session {
            out.packets.push(s.seal(&msg.encode()));
        }
    }

    fn drop_session(&mut self) {
        *self = State::default();
    }
}

impl TrackerClient {
    pub fn new(name: String, addr: SocketAddr, key: VerifyingKey, identity: Arc<Identity>, certs: Vec<Cert>) -> Self {
        let log_prefix = format!("Client {name} {addr} |");
        log::info!("{log_prefix} Connection status initiated");
        TrackerClient { addr, key, identity, certs, state: Mutex::new(State::default()), log_prefix }
    }

    pub fn is_connected(&self) -> bool {
        self.state.lock().session.is_some()
    }

    /// (last announce, last search, last response) as unix timestamps, 0 = never. Members are
    /// looked up by every announce now, so the search time is the announce time.
    pub fn timestamps(&self) -> (f64, f64, f64) {
        let s = self.state.lock();
        (s.announce_ts, s.announce_ts, s.response_ts)
    }

    /// Called once per second.
    pub fn tick(&self) -> Output {
        let mut out = Output::default();
        let mut s = self.state.lock();
        if s.session.is_none() {
            let hs = ClientHandshake::new();
            out.packets.push(hs.hello());
            s.handshake = Some(hs);
            log::debug!("{} Connection status connecting", self.log_prefix);
            return out;
        }

        if s.last_response.is_some_and(|t| t.elapsed() >= RESPONSE_TIMEOUT) {
            log::info!("{} Connection status disconnected", self.log_prefix);
            s.send(&mut out, &TrackerMsg::Close);
            s.drop_session();
            out.status = Some(false);
            return out;
        }

        if s.last_announce.is_none_or(|t| t.elapsed() >= ANNOUNCE_INTERVAL) {
            log::debug!("{} Send announce", self.log_prefix);
            let sig = self.identity.sign(s.session.as_ref().expect("checked above").announce_msg());
            let msg = TrackerMsg::Announce { node: self.identity.id(), certs: self.certs.clone(), sig };
            s.send(&mut out, &msg);
            s.last_announce = Some(Instant::now());
            s.announce_ts = unix_now();
        }
        out
    }

    pub fn handle(&self, packet: &[u8], storage: &PeerStorage) -> Output {
        let mut out = Output::default();
        let mut s = self.state.lock();
        match packet.first() {
            Some(&HELLO_ACK) => {
                let Some(hs) = s.handshake.take() else { return out };
                let Some(session) = hs.finish(packet, &self.key) else {
                    log::info!("{} Reg session Invalid Signature", self.log_prefix);
                    return out;
                };
                let was_connected = s.session.is_some();
                s.session = Some(session);
                s.last_response = Some(Instant::now());
                s.response_ts = unix_now();
                s.last_announce = None;
                if !was_connected {
                    log::info!("{} Connection status connected", self.log_prefix);
                    out.status = Some(true);
                }
            }
            Some(&TRACKER) => {
                let Some(session) = &mut s.session else { return out };
                let Some(plain) = session.open(packet) else {
                    log::info!("{} Received packet | Invalid Data", self.log_prefix);
                    return out;
                };
                match TrackerMsg::decode(&plain) {
                    Some(TrackerMsg::Found { cert, addr }) => {
                        s.last_response = Some(Instant::now());
                        s.response_ts = unix_now();
                        drop(s);
                        self.found(&cert, addr, storage);
                    }
                    Some(TrackerMsg::Close) => {
                        log::info!("{} Connection closed from server", self.log_prefix);
                        s.drop_session();
                        out.status = Some(false);
                    }
                    Some(_) => {}
                    None => log::info!("{} Received packet | decode error", self.log_prefix),
                }
            }
            _ => {}
        }
        out
    }

    /// A member of one of our groups is at `addr`. The certificate is checked here too: the
    /// tracker is not trusted with membership.
    fn found(&self, cert: &Cert, addr: SocketAddr, storage: &PeerStorage) {
        let peer = cert.body.node;
        if !self.certs.iter().any(|c| c.body.group == cert.body.group) {
            return;
        }
        if let Err(e) = cert.verify(&cert.body.group, Some(now_unix())) {
            log::info!("{} Peer {} from the server: {e}", self.log_prefix, node(peer));
            return;
        }
        if storage.is_self(&peer) {
            if storage.endpoint(&peer) != Some(addr) {
                log::info!("{} New self endpoint {addr}", self.log_prefix);
                storage.set_peer(peer, PeerUpdate { endpoint: Some(Some(addr)), ..Default::default() });
            }
            return;
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
    }

    /// Best-effort goodbye on shutdown.
    pub fn close(&self) -> Option<Vec<u8>> {
        let mut s = self.state.lock();
        let mut out = Output::default();
        s.send(&mut out, &TrackerMsg::Close);
        s.drop_session();
        out.packets.pop()
    }
}
