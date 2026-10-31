use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, SigningKey};
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::crypto::{TrackerSession, server_accept};
use crate::identity::NodeId;
use crate::logger::node;
use crate::proto::{HELLO, MAX_DATAGRAM, SEARCH_BATCH, TRACKER, TrackerMsg};

const TIMEOUT: Duration = Duration::from_secs(45);
/// Bound on how many different peers a single peer may search for.
const MAX_SEARCHES: usize = 4096;

struct Session {
    crypto: TrackerSession,
    peer_id: Option<NodeId>,
    last_announce: Instant,
}

#[derive(Default)]
struct State {
    sessions: HashMap<SocketAddr, Session>,
    by_peer: HashMap<NodeId, SocketAddr>,
    searches: HashMap<NodeId, HashSet<NodeId>>,
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
            && self.by_peer.get(&id) == Some(&addr)
        {
            self.by_peer.remove(&id);
            self.searches.remove(&id);
        }
        log::info!("Server | {addr} Session dropped");
    }

    fn announce(&mut self, out: &mut Out, addr: SocketAddr, peer_id: NodeId, sig: Signature) {
        let s = self.sessions.get_mut(&addr).unwrap();
        // Only the key owner can sign this session's transcript: no announcing someone else's key,
        // and a signature captured from another session does not verify here.
        if peer_id.verifying_key().verify_strict(s.crypto.announce_msg(), &sig).is_err() {
            log::info!("Server | {addr} announce of {:#} with an invalid signature ignored", node(peer_id));
            return;
        }
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
                    && old != addr
                {
                    self.drop_session(out, old, true);
                    self.by_peer.insert(peer_id, addr);
                }
                log::info!("Server | Session {addr} node: {:#}", node(peer_id));
            }
        }
        self.send(out, addr, &TrackerMsg::Found { peer_id, addr });
    }

    fn search(&mut self, out: &mut Out, addr: SocketAddr, peers: Vec<NodeId>) {
        let Some(me) = self.sessions.get(&addr).and_then(|s| s.peer_id) else { return };
        for target in peers.into_iter().take(SEARCH_BATCH) {
            if target == me {
                continue;
            }
            let mine = self.searches.entry(me).or_default();
            if mine.len() < MAX_SEARCHES && mine.insert(target) {
                log::info!("Server | node {:#} new search {:#}", node(me), node(target));
            }
            let mutual = self.searches.get(&target).is_some_and(|s| s.contains(&me));
            if !mutual {
                continue;
            }
            let Some(&target_addr) = self.by_peer.get(&target) else { continue };
            // Tell both sides at once so they start punching through their NATs simultaneously.
            self.send(out, addr, &TrackerMsg::Found { peer_id: target, addr: target_addr });
            self.send(out, target_addr, &TrackerMsg::Found { peer_id: me, addr });
            log::debug!("Server | node {:#} <-> {:#} matched", node(me), node(target));
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
                    Some(TrackerMsg::Announce { peer_id, sig }) => self.announce(&mut out, from, peer_id, sig),
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
        let expired: Vec<_> =
            self.sessions.iter().filter(|(_, s)| s.last_announce.elapsed() > TIMEOUT).map(|(a, _)| *a).collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ClientHandshake, random_bytes};
    use crate::identity::Identity;

    struct Client {
        addr: SocketAddr,
        session: TrackerSession,
    }

    fn connect(st: &mut State, server: &SigningKey, addr: &str) -> Client {
        let addr = addr.parse().unwrap();
        let hs = ClientHandshake::new();
        let out = st.handle(server, &hs.hello(), addr);
        let session = hs.finish(&out[0].0, &server.verifying_key()).unwrap();
        Client { addr, session }
    }

    /// Sends `msg` from `c`, returns the replies addressed to `c`.
    fn send(st: &mut State, server: &SigningKey, c: &mut Client, msg: &TrackerMsg) -> Vec<TrackerMsg> {
        let packet = c.session.seal(&msg.encode());
        st.handle(server, &packet, c.addr)
            .into_iter()
            .filter(|(_, to)| *to == c.addr)
            .map(|(p, _)| TrackerMsg::decode(&c.session.open(&p).unwrap()).unwrap())
            .collect()
    }

    fn announce(id: &Identity, signed_in: &TrackerSession) -> TrackerMsg {
        TrackerMsg::Announce { peer_id: id.id(), sig: id.sign(signed_in.announce_msg()) }
    }

    #[test]
    fn own_key_announce_accepted() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let me = Identity::generate();
        let mut c = connect(&mut st, &server, "198.51.100.1:4000");
        let msg = announce(&me, &c.session);
        let replies = send(&mut st, &server, &mut c, &msg);
        assert!(
            matches!(replies.as_slice(), [TrackerMsg::Found { peer_id, addr }] if *peer_id == me.id() && *addr == c.addr)
        );
        assert_eq!(st.by_peer.get(&me.id()), Some(&c.addr));
    }

    #[test]
    fn foreign_key_announce_rejected() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (victim, attacker) = (Identity::generate(), Identity::generate());
        let mut c = connect(&mut st, &server, "198.51.100.2:4000");
        // The victim's key, signed with the attacker's own key.
        let msg = TrackerMsg::Announce { peer_id: victim.id(), sig: attacker.sign(c.session.announce_msg()) };
        assert!(send(&mut st, &server, &mut c, &msg).is_empty());
        assert!(!st.by_peer.contains_key(&victim.id()));
        assert_eq!(st.sessions[&c.addr].peer_id, None);
    }

    #[test]
    fn announce_signature_bound_to_session() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let victim = Identity::generate();
        let mut v = connect(&mut st, &server, "198.51.100.3:4000");
        let genuine = announce(&victim, &v.session);
        assert_eq!(send(&mut st, &server, &mut v, &genuine).len(), 1);

        // An attacker who captured the victim's (decrypted) announce replays it in its own session
        // to steal the victim's endpoint.
        let mut a = connect(&mut st, &server, "203.0.113.66:4000");
        assert!(send(&mut st, &server, &mut a, &genuine).is_empty());
        assert_eq!(st.by_peer.get(&victim.id()), Some(&v.addr), "endpoint not hijacked");
        assert_eq!(st.sessions[&a.addr].peer_id, None);
    }
}
