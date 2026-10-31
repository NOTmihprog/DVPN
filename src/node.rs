use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::identity::NodeId;
use crate::link::{Links, Received};
use crate::logger::node;
use crate::noise::TAG_LEN;
use crate::obfs::MAX_PAD;
use crate::packet::{self, IpInfo};
use crate::proto::{
    CONTROL_LEN, CONTROL_PING, CONTROL_PONG, DATA_HDR, KIND_API_MIN, KIND_CONTROL, KIND_IP, MAX_DATAGRAM,
};
use crate::storage::{Event, PeerStorage, PeerUpdate};
use crate::tracker_client::{Output, TrackerClient};
use crate::transport::Transport;

/// While there is no session, a handshake is sent this often (it also punches NATs).
const PUNCH_INTERVAL: Duration = Duration::from_secs(1);
/// Retry interval for a rekey handshake while the old session still works.
const REKEY_RETRY: Duration = Duration::from_secs(5);
/// Keepalive pings go out at a random point of this range, so they have no fixed period (§4.4).
const KEEPALIVE: std::ops::Range<Duration> = Duration::from_secs(12)..Duration::from_secs(18);
/// The link loop runs at random intervals around a second, for the same reason.
const LINK_TICK: std::ops::Range<Duration> = Duration::from_millis(700)..Duration::from_millis(1300);
const LINK_TIMEOUT: Duration = Duration::from_secs(45);

/// A packet for an API client: (route, from peer, payload).
pub type ApiPacket = (u8, NodeId, Vec<u8>);

pub struct Node {
    pub storage: Arc<PeerStorage>,
    pub transport: Arc<Transport>,
    pub links: Links,
    pub clients: Vec<Arc<TrackerClient>>,
    clients_by_addr: HashMap<SocketAddr, Arc<TrackerClient>>,
    tun: Option<Arc<AsyncDevice>>,
    self_addr: Option<Ipv4Addr>,
    api_tx: OnceLock<mpsc::Sender<ApiPacket>>,
    epoch: Instant,
}

impl Node {
    pub fn new(
        storage: Arc<PeerStorage>,
        transport: Arc<Transport>,
        links: Links,
        clients: Vec<TrackerClient>,
        tun: Option<AsyncDevice>,
        self_addr: Option<Ipv4Addr>,
    ) -> Arc<Self> {
        let clients: Vec<_> = clients.into_iter().map(Arc::new).collect();
        let clients_by_addr = clients.iter().map(|c| (c.addr, c.clone())).collect();
        Arc::new(Node {
            storage,
            transport,
            links,
            clients,
            clients_by_addr,
            tun: tun.map(Arc::new),
            self_addr,
            api_tx: OnceLock::new(),
            epoch: Instant::now(),
        })
    }

    pub fn set_api_sink(&self, tx: mpsc::Sender<ApiPacket>) {
        let _ = self.api_tx.set(tx);
    }

    pub fn client(&self, addr: &SocketAddr) -> Option<&Arc<TrackerClient>> {
        self.clients_by_addr.get(addr)
    }

    pub fn start(self: &Arc<Self>) {
        tokio::spawn(self.clone().udp_loop());
        tokio::spawn(self.clone().link_loop());
        tokio::spawn(self.clone().tracker_loop());
        if self.tun.is_some() {
            tokio::spawn(self.clone().tun_loop());
        }
    }

    /// Sends a handshake to `peer`'s endpoint unless one went out less than `min_interval` ago.
    async fn handshake(&self, peer: NodeId, min_interval: Duration) {
        let Some(route) = self.storage.route_by_id(&peer) else { return };
        if let Some(packets) = self.links.initiate(peer, min_interval) {
            log::debug!("Link | handshake to {}", node(peer));
            for p in &packets {
                self.transport.send_to(p, route.endpoint).await;
            }
        }
    }

    /// Sends `[kind][body]` to `peer` over its session. Not for the TUN hot path.
    pub async fn send_kind(&self, peer: &NodeId, kind: u8, body: &[u8]) -> bool {
        let Some(route) = self.storage.route_by_id(peer) else { return false };
        let Some(session) = self.links.current(peer) else {
            self.handshake(*peer, PUNCH_INTERVAL).await;
            return false;
        };
        let mut buf = vec![0u8; DATA_HDR + 1 + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR] = kind;
        buf[DATA_HDR + 1..DATA_HDR + 1 + body.len()].copy_from_slice(body);
        let Some(len) = session.seal(&mut buf, 1 + body.len()) else { return false };
        self.transport.send_to(&buf[..len], route.endpoint).await;
        true
    }

    /// For API clients: `payload` on API route `route` (32..=255).
    pub async fn send_routed(&self, peer: &NodeId, route: u8, payload: &[u8]) -> bool {
        self.send_kind(peer, route, payload).await
    }

    async fn send_tracker(&self, client: &TrackerClient, out: Output) {
        for p in &out.packets {
            self.transport.send_to(p, client.addr).await;
        }
        if let Some(connected) = out.status {
            self.storage.emit(Event::Server { addr: client.addr, connected });
            if !connected && self.transport.can_change_port() && self.clients.iter().all(|c| !c.is_connected()) {
                self.transport.change_port().await;
            }
        }
    }

    async fn tracker_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            for c in &self.clients {
                let out = c.tick(&self.storage);
                self.send_tracker(c, out).await;
            }
        }
    }

    /// Control body (after the kind byte): `[PING|PONG][echo_ts u64][random padding]`.
    fn control(sub: u8, echo_ts: u64) -> Vec<u8> {
        // Random padding so keepalives don't all have the same size on the wire.
        let pad = rand::rng().random_range(16..96);
        let len = CONTROL_LEN - 1;
        let mut p = Vec::with_capacity(len + pad);
        p.push(sub);
        p.extend_from_slice(&echo_ts.to_le_bytes());
        p.resize(len + pad, 0);
        rand::fill(&mut p[len..]);
        p
    }

    async fn send_ping(&self, peer: NodeId) {
        let ts = self.epoch.elapsed().as_nanos() as u64;
        if self.send_kind(&peer, KIND_CONTROL, &Self::control(CONTROL_PING, ts)).await {
            self.storage.update_link(&peer, |l| l.last_ping = Some(Instant::now()));
            log::debug!("Ping | send ping to peer {}", node(peer));
        }
    }

    /// Once a second: link timeouts, handshakes (first contact, NAT punching, rekeying) and
    /// keepalive pings that also measure RTT.
    async fn link_loop(self: Arc<Self>) {
        loop {
            let tick = rand::rng().random_range(LINK_TICK); // ThreadRng must not live across .await
            tokio::time::sleep(tick).await;
            self.links.expire();
            for (id, link) in self.storage.links() {
                if link.last_seen.unwrap_or(link.since).elapsed() > LINK_TIMEOUT {
                    log::info!("Link | peer {} timed out, endpoint dropped", node(id));
                    self.storage.del_endpoint(&id);
                    self.links.drop_peer(&id);
                    continue;
                }
                let has_session = self.links.current(&id).is_some();
                if self.links.needs_handshake(&id) {
                    self.handshake(id, if has_session { REKEY_RETRY } else { PUNCH_INTERVAL }).await;
                }
                let keepalive = rand::rng().random_range(KEEPALIVE);
                if has_session && link.last_ping.is_none_or(|t| t.elapsed() >= keepalive) {
                    self.send_ping(id).await;
                }
            }
        }
    }

    async fn handle_control(&self, peer: NodeId, c: &[u8]) {
        if c.len() < CONTROL_LEN - 1 {
            return;
        }
        let echo_ts = u64::from_le_bytes(c[1..9].try_into().unwrap());
        self.storage.update_link(&peer, |l| l.last_seen = Some(Instant::now()));
        match c[0] {
            CONTROL_PING => {
                self.send_kind(&peer, KIND_CONTROL, &Self::control(CONTROL_PONG, echo_ts)).await;
                log::debug!("Ping | receive ping from {}", node(peer));
            }
            CONTROL_PONG => {
                let now = self.epoch.elapsed().as_nanos() as u64;
                let Some(rtt) = now.checked_sub(echo_ts) else { return };
                let ms = rtt as f64 / 1e6;
                self.storage.update_link(&peer, |l| l.rtt_ms = Some(ms));
                self.storage.emit(Event::Ping { peer_id: peer, ms });
                log::debug!("Ping | receive pong from {} ping: {ms:.3}", node(peer));
            }
            _ => {}
        }
    }

    async fn udp_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, from) = self.transport.recv_from(&mut buf).await;
            if n == 0 {
                continue;
            }
            // Peer packets have no readable type byte, so trackers are told apart by address.
            match self.clients_by_addr.get(&from) {
                Some(c) => {
                    let out = c.handle(&buf[..n], &self.storage);
                    self.send_tracker(c, out).await;
                }
                None => self.handle_peer_packet(&mut buf[..n], from).await,
            }
        }
    }

    /// The peer proved its identity with a packet from `from`: that is where it is now
    /// (roaming, NAT port change). Unauthenticated packets never move an endpoint.
    fn roam(&self, peer: NodeId, from: SocketAddr) {
        if self.storage.route_by_id(&peer).map(|r| r.endpoint) != Some(from) {
            log::info!("Link | peer {} at new endpoint {from}", node(peer));
            self.storage.set_peer(peer, PeerUpdate { endpoint: Some(Some(from)), ..Default::default() });
        }
    }

    async fn handle_peer_packet(&self, packet: &mut [u8], from: SocketAddr) {
        let storage = &self.storage;
        match self.links.receive(packet, || storage.others()) {
            None => {}
            Some(Received::Handshake { peer, reply }) => {
                self.roam(peer, from);
                storage.update_link(&peer, |l| l.last_seen = Some(Instant::now()));
                match reply {
                    Some(r) => self.transport.send_to(&r, from).await,
                    None => {
                        log::debug!("Link | session with {} established", node(peer));
                        // confirms the session to the responder and measures RTT
                        self.send_ping(peer).await;
                    }
                }
            }
            Some(Received::Data { session, plain }) => {
                let peer = session.peer;
                self.roam(peer, from);
                let Some((&kind, body)) = packet[plain].split_first() else { return };
                match kind {
                    KIND_IP => {
                        let Some(tun) = &self.tun else { return };
                        // A peer may only inject packets from its own LAN address.
                        let own = matches!(
                            packet::parse(body),
                            Some(IpInfo { src: IpAddr::V4(src), .. }) if storage.peer_addr(&peer) == Some(src)
                        );
                        if !own {
                            log::debug!("Link | packet from {} with foreign source dropped", node(peer));
                            return;
                        }
                        if let Err(e) = tun.send(body).await {
                            log::warn!("TUN | write error: {e}");
                        }
                    }
                    KIND_CONTROL => self.handle_control(peer, body).await,
                    k if k >= KIND_API_MIN => {
                        if let Some(tx) = self.api_tx.get() {
                            let _ = tx.try_send((k, peer, body.to_vec()));
                        }
                    }
                    k => log::debug!("Link | unknown kind {k} from {}", node(peer)),
                }
            }
        }
    }

    async fn tun_loop(self: Arc<Self>) {
        let tun = self.tun.clone().unwrap();
        let Some(self_addr) = self.self_addr else { return };
        // Layout: [DATA header][KIND_IP][ip packet][tag]; the IP packet is read in place.
        const OFF: usize = DATA_HDR + 1;
        let mut buf = vec![0u8; OFF + MAX_DATAGRAM + TAG_LEN + MAX_PAD];
        log::info!("TUN | Thread receiver - started");
        loop {
            let n = match tun.recv(&mut buf[OFF..OFF + MAX_DATAGRAM - 64]).await {
                Ok(n) => n,
                Err(e) => {
                    log::error!("TUN | read error: {e}");
                    break;
                }
            };
            // IPv4 only until the IPv6 overlay (PLAN stage 4).
            let Some(IpInfo { src: IpAddr::V4(src), dst: IpAddr::V4(dst), .. }) = packet::parse(&buf[OFF..OFF + n])
            else {
                continue;
            };
            if src != self_addr {
                continue;
            }
            let Some(route) = self.storage.route_by_addr(dst) else {
                log::trace!("TUN | Packet to {dst} peer not found");
                continue;
            };
            let Some(session) = self.links.current(&route.peer_id) else {
                self.handshake(route.peer_id, PUNCH_INTERVAL).await;
                continue;
            };
            buf[DATA_HDR] = KIND_IP;
            if let Some(len) = session.seal(&mut buf, n + 1) {
                self.transport.send_to(&buf[..len], route.endpoint).await;
            }
        }
        log::info!("TUN | Thread receiver - stopped");
    }

    pub async fn shutdown(&self) {
        for c in &self.clients {
            if let Some(p) = c.close() {
                self.transport.send_to(&p, c.addr).await;
            }
        }
    }
}
