use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::crypto::{TrackerSession, server_accept};
use crate::peer_id::PeerId;
use crate::proto::{HELLO, MAX_DATAGRAM, SEARCH_BATCH, TRACKER, TrackerMsg};

const TIMEOUT: Duration = Duration::from_secs(45);
/// Bound on how many different peers a single peer may search for.
const MAX_SEARCHES: usize = 4096;

struct Session {
    crypto: TrackerSession,
    peer_id: Option<PeerId>,
    last_announce: Instant,
}

#[derive(Default)]
struct State {
    sessions: HashMap<SocketAddr, Session>,
    by_peer: HashMap<PeerId, SocketAddr>,
    searches: HashMap<PeerId, HashSet<PeerId>>,
}

type Out = Vec<(Vec<u8>, SocketAddr)>;

impl State {
    fn send(&mut self, out: &mut Out, to: SocketAddr, msg: &TrackerMsg) {
        if let Some(s) = self.sessions.get_mut(&to) {
            out.push((s.crypto.seal(&msg.encode()), to));
        }
    }

    fn drop_session(&mut self, out: &mut Out, addr: SocketAddr, send_close: bool) {
        if send_close {
            self.send(out, addr, &TrackerMsg::Close);
        }
        let Some(s) = self.sessions.remove(&addr) else { return };
        if let Some(id) = s.peer_id
            && self.by_peer.get(&id) == Some(&addr) {
                self.by_peer.remove(&id);
                self.searches.remove(&id);
            }
        log::info!("Server | {addr} Session dropped");
    }

    fn announce(&mut self, out: &mut Out, addr: SocketAddr, peer_id: PeerId) {
        let s = self.sessions.get_mut(&addr).unwrap();
        s.last_announce = Instant::now();
        match s.peer_id {
            Some(prev) if prev != peer_id => {
                self.drop_session(out, addr, true);
                return;
            }
            Some(_) => {}
            None => {
                s.peer_id = Some(peer_id);
                // The newest address wins: the peer probably restarted or its NAT mapping changed.
                if let Some(old) = self.by_peer.insert(peer_id, addr)
                    && old != addr {
                        self.drop_session(out, old, true);
                        self.by_peer.insert(peer_id, addr);
                    }
                log::info!("Server | Session {addr} peer_id: {peer_id}");
            }
        }
        self.send(out, addr, &TrackerMsg::Found { peer_id, addr });
    }

    fn search(&mut self, out: &mut Out, addr: SocketAddr, peers: Vec<PeerId>) {
        let Some(me) = self.sessions.get(&addr).and_then(|s| s.peer_id) else { return };
        for target in peers.into_iter().take(SEARCH_BATCH) {
            if target == me {
                continue;
            }
            let mine = self.searches.entry(me).or_default();
            if mine.len() < MAX_SEARCHES && mine.insert(target) {
                log::info!("Server | peer_id: {me} new search {target}");
            }
            let mutual = self.searches.get(&target).is_some_and(|s| s.contains(&me));
            if !mutual {
                continue;
            }
            let Some(&target_addr) = self.by_peer.get(&target) else { continue };
            // Tell both sides at once so they start punching through their NATs simultaneously.
            self.send(out, addr, &TrackerMsg::Found { peer_id: target, addr: target_addr });
            self.send(out, target_addr, &TrackerMsg::Found { peer_id: me, addr });
            log::debug!("Server | peer_id: {me} <-> {target} matched");
        }
    }

    fn handle(&mut self, identity: &SigningKey, packet: &[u8], from: SocketAddr) -> Out {
        let mut out = Out::new();
        match packet.first() {
            Some(&HELLO) => {
                let Some((ack, crypto)) = server_accept(packet, identity) else {
                    log::info!("Server | Invalid hello from {from}");
                    return out;
                };
                if self.sessions.contains_key(&from) {
                    self.drop_session(&mut out, from, false);
                }
                self.sessions.insert(from, Session { crypto, peer_id: None, last_announce: Instant::now() });
                out.push((ack, from));
                log::info!("Server | New session from {from}");
            }
            Some(&TRACKER) => {
                let Some(s) = self.sessions.get_mut(&from) else { return out };
                let Some(plain) = s.crypto.open(packet) else {
                    log::info!("Server | Packet from {from} Invalid Data");
                    return out;
                };
                match TrackerMsg::decode(&plain) {
                    Some(TrackerMsg::Announce { peer_id }) => self.announce(&mut out, from, peer_id),
                    Some(TrackerMsg::Search { peers }) => self.search(&mut out, from, peers),
                    Some(TrackerMsg::Close) => {
                        self.drop_session(&mut out, from, false);
                        log::info!("Server | connection close from {from}");
                    }
                    Some(TrackerMsg::Found { .. }) => {}
                    None => {
                        log::info!("Server | Packet from {from} decode error");
                        self.drop_session(&mut out, from, true);
                    }
                }
            }
            _ => {}
        }
        out
    }

    fn collect_garbage(&mut self) -> Out {
        let mut out = Out::new();
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.last_announce.elapsed() > TIMEOUT)
            .map(|(a, _)| *a)
            .collect();
        for addr in expired {
            self.drop_session(&mut out, addr, true);
        }
        out
    }
}

pub async fn run(sock: UdpSocket, identity: SigningKey) {
    let sock = Arc::new(sock);
    let state = Arc::new(Mutex::new(State::default()));

    let gc = {
        let (sock, state) = (sock.clone(), state.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TIMEOUT / 3);
            loop {
                tick.tick().await;
                let out = state.lock().collect_garbage();
                for (p, a) in out {
                    let _ = sock.send_to(&p, a).await;
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
        let out = state.lock().handle(&identity, &buf[..n], from);
        for (p, a) in out {
            if let Err(e) = sock.send_to(&p, a).await {
                log::info!("Server | send to {a} error: {e}");
            }
        }
        if gc.is_finished() {
            break;
        }
    }
}
