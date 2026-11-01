use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, SigningKey};
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::crypto::{TrackerSession, server_accept};
use crate::group::{Cert, GroupId, now_unix};
use crate::identity::NodeId;
use crate::logger::node as show;
use crate::proto::{HELLO, MAX_ANNOUNCE_CERTS, MAX_DATAGRAM, TRACKER, TrackerMsg};

const TIMEOUT: Duration = Duration::from_secs(45);

struct Session {
    crypto: TrackerSession,
    node: Option<NodeId>,
    /// Verified certificates of the announced node, by group.
    certs: HashMap<GroupId, Cert>,
    last_announce: Instant,
}

#[derive(Default)]
struct State {
    sessions: HashMap<SocketAddr, Session>,
    by_node: HashMap<NodeId, SocketAddr>,
    /// Online members of each group (PLAN §11).
    groups: HashMap<GroupId, HashSet<NodeId>>,
}

type Out = Vec<(Vec<u8>, SocketAddr)>;

impl State {
    fn send(&mut self, out: &mut Out, to: SocketAddr, msg: &TrackerMsg) {
        if let Some(s) = self.sessions.get_mut(&to) {
            out.push((s.crypto.seal(&msg.encode()), to));
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

    fn drop_session(&mut self, out: &mut Out, addr: SocketAddr, send_close: bool) {
        if send_close {
            self.send(out, addr, &TrackerMsg::Close);
        }
        let Some(s) = self.sessions.remove(&addr) else { return };
        if let Some(id) = s.node
            && self.by_node.get(&id) == Some(&addr)
        {
            self.by_node.remove(&id);
            self.unindex(id, s.certs.into_keys());
        }
        log::info!("Server | {addr} Session dropped");
    }

    /// The online member `node` of `group`: its certificate and address.
    fn member(&self, group: &GroupId, node: &NodeId) -> Option<(Cert, SocketAddr)> {
        let addr = *self.by_node.get(node)?;
        Some((self.sessions.get(&addr)?.certs.get(group)?.clone(), addr))
    }

    fn announce(&mut self, out: &mut Out, addr: SocketAddr, node: NodeId, certs: Vec<Cert>, sig: Signature) {
        let s = self.sessions.get_mut(&addr).unwrap();
        // Only the key owner can sign this session's transcript: no announcing someone else's key,
        // and a signature captured from another session does not verify here.
        if node.verifying_key().verify_strict(s.crypto.announce_msg(), &sig).is_err() {
            log::info!("Server | {addr} announce of {:#} with an invalid signature ignored", show(node));
            return;
        }
        if s.node.is_some_and(|prev| prev != node) {
            self.drop_session(out, addr, true);
            return;
        }
        s.last_announce = Instant::now();
        let now = now_unix();
        let mut valid: HashMap<GroupId, Cert> = HashMap::new();
        for c in certs.into_iter().take(MAX_ANNOUNCE_CERTS) {
            let group = c.body.group;
            match c.verify(&group, Some(now)) {
                Ok(()) if c.body.node == node => {
                    valid.insert(group, c);
                }
                Ok(()) => log::info!("Server | {addr} certificate of another node ignored"),
                Err(e) => log::info!("Server | {addr} {:#}: {e}", show(node)),
            }
        }

        let first = s.node.is_none();
        let changed = first || s.certs != valid;
        let left: Vec<GroupId> = s.certs.keys().filter(|g| !valid.contains_key(g)).copied().collect();
        s.node = Some(node);
        s.certs = valid;
        if first {
            // The newest address wins: the node probably restarted or its NAT mapping changed.
            if let Some(old) = self.by_node.insert(node, addr)
                && old != addr
            {
                self.drop_session(out, old, true);
                self.by_node.insert(node, addr);
            }
            log::info!("Server | Session {addr} node: {:#}", show(node));
        }
        self.unindex(node, left);

        let groups: Vec<GroupId> = self.sessions[&addr].certs.keys().copied().collect();
        for g in groups {
            let members = self.groups.entry(g).or_default();
            if members.insert(node) {
                log::info!("Server | node {:#} joined group {}", show(node), g.short());
            }
            let members: Vec<NodeId> = members.iter().copied().collect();
            let (mine, _) = self.member(&g, &node).expect("just indexed");
            // Every announce refreshes the announcer's view of its groups (its own address
            // included); the others hear about it when it is new or its certificate changed.
            for m in members {
                let Some((cert, m_addr)) = self.member(&g, &m) else { continue };
                self.send(out, addr, &TrackerMsg::Found { cert: Box::new(cert), addr: m_addr });
                if changed && m != node {
                    self.send(out, m_addr, &TrackerMsg::Found { cert: Box::new(mine.clone()), addr });
                }
            }
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
                self.sessions
                    .insert(from, Session { crypto, node: None, certs: HashMap::new(), last_announce: Instant::now() });
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
                    Some(TrackerMsg::Announce { node, certs, sig }) => self.announce(&mut out, from, node, certs, sig),
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
    use crate::group::{CertBody, GroupSecret};
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

    fn announce(id: &Identity, certs: Vec<Cert>, signed_in: &TrackerSession) -> TrackerMsg {
        TrackerMsg::Announce { node: id.id(), certs, sig: id.sign(signed_in.announce_msg()) }
    }

    fn cert(g: &GroupSecret, id: &Identity) -> Cert {
        g.issue(CertBody::new(id.id(), "n", vec![]))
    }

    fn found(msgs: &[TrackerMsg]) -> Vec<(NodeId, SocketAddr)> {
        let mut v: Vec<_> = msgs
            .iter()
            .filter_map(|m| match m {
                TrackerMsg::Found { cert, addr } => Some((cert.body.node, *addr)),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn own_key_announce_accepted() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (me, g) = (Identity::generate(), GroupSecret::generate());
        let mut c = connect(&mut st, &server, "198.51.100.1:4000");
        let msg = announce(&me, vec![cert(&g, &me)], &c.session);
        let replies = send(&mut st, &server, &mut c, &msg);
        assert_eq!(found(&replies), vec![(me.id(), c.addr)]);
        assert_eq!(st.by_node.get(&me.id()), Some(&c.addr));
        assert!(st.groups[&g.id()].contains(&me.id()));
    }

    #[test]
    fn members_find_each_other_without_search() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (g, other) = (GroupSecret::generate(), GroupSecret::generate());
        let (a, b, x) = (Identity::generate(), Identity::generate(), Identity::generate());
        let mut ca = connect(&mut st, &server, "198.51.100.1:4000");
        let mut cb = connect(&mut st, &server, "198.51.100.2:4000");
        let mut cx = connect(&mut st, &server, "198.51.100.3:4000");
        let m = announce(&a, vec![cert(&g, &a)], &ca.session);
        send(&mut st, &server, &mut ca, &m);
        let m = announce(&x, vec![cert(&other, &x)], &cx.session);
        send(&mut st, &server, &mut cx, &m);

        // b comes online: it learns a (and itself), and a learns b in the same step
        let b_cert = cert(&g, &b);
        let m = announce(&b, vec![b_cert.clone()], &cb.session);
        let packet = cb.session.seal(&m.encode());
        let out = st.handle(&server, &packet, cb.addr);
        let to = |c: &mut Client| -> Vec<TrackerMsg> {
            out.iter()
                .filter(|(_, t)| *t == c.addr)
                .map(|(p, _)| TrackerMsg::decode(&c.session.open(p).unwrap()).unwrap())
                .collect()
        };
        let mut want = vec![(a.id(), ca.addr), (b.id(), cb.addr)];
        want.sort();
        assert_eq!(found(&to(&mut cb)), want);
        assert_eq!(found(&to(&mut ca)), vec![(b.id(), cb.addr)]);
        assert!(to(&mut cx).is_empty(), "another group hears nothing");

        // a later announce refreshes b's view but does not notify a again
        let m = announce(&b, vec![b_cert], &cb.session);
        let packet = cb.session.seal(&m.encode());
        let out = st.handle(&server, &packet, cb.addr);
        assert!(out.iter().all(|(_, t)| *t == cb.addr));
        assert_eq!(out.len(), 2);

        // b leaves: it disappears from the group index
        let m = TrackerMsg::Close;
        send(&mut st, &server, &mut cb, &m);
        assert_eq!(st.groups[&g.id()].len(), 1);
    }

    #[test]
    fn invalid_certificates_not_indexed() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (g, me, other) = (GroupSecret::generate(), Identity::generate(), Identity::generate());
        let mut expired = CertBody::new(me.id(), "n", vec![]);
        expired.not_after = 1;
        let mut forged = cert(&g, &me);
        forged.body.name = "admin".into();
        for bad in [g.issue(expired), cert(&g, &other), forged] {
            let mut c = connect(&mut st, &server, "198.51.100.9:4000");
            let msg = announce(&me, vec![bad], &c.session);
            assert!(found(&send(&mut st, &server, &mut c, &msg)).is_empty());
            assert!(st.groups.is_empty());
        }
    }

    #[test]
    fn foreign_key_announce_rejected() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (victim, attacker) = (Identity::generate(), Identity::generate());
        let mut c = connect(&mut st, &server, "198.51.100.2:4000");
        // The victim's key, signed with the attacker's own key.
        let msg =
            TrackerMsg::Announce { node: victim.id(), certs: vec![], sig: attacker.sign(c.session.announce_msg()) };
        assert!(send(&mut st, &server, &mut c, &msg).is_empty());
        assert!(!st.by_node.contains_key(&victim.id()));
        assert_eq!(st.sessions[&c.addr].node, None);
    }

    #[test]
    fn announce_signature_bound_to_session() {
        let (mut st, server) = (State::default(), SigningKey::from_bytes(&random_bytes()));
        let (victim, g) = (Identity::generate(), GroupSecret::generate());
        let mut v = connect(&mut st, &server, "198.51.100.3:4000");
        let genuine = announce(&victim, vec![cert(&g, &victim)], &v.session);
        assert_eq!(send(&mut st, &server, &mut v, &genuine).len(), 1);

        // An attacker who captured the victim's (decrypted) announce replays it in its own session
        // to steal the victim's endpoint.
        let mut a = connect(&mut st, &server, "203.0.113.66:4000");
        assert!(send(&mut st, &server, &mut a, &genuine).is_empty());
        assert_eq!(st.by_node.get(&victim.id()), Some(&v.addr), "endpoint not hijacked");
        assert_eq!(st.sessions[&a.addr].node, None);
    }
}
