use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::crypto::{SEALED_HDR, TAG_LEN};
use crate::peer_id::PeerId;
use crate::proto::{
    CONTROL_LEN, CONTROL_PING, CONTROL_PONG, HELLO_ACK, MAX_DATAGRAM, PLAIN, ROAM_MAX_LEN, ROUTE_API_MIN,
    ROUTE_CONTROL, ROUTE_NET, SEALED, TRACKER,
};
use crate::storage::{Event, PeerStorage, PeerUpdate, Route};
use crate::tracker_client::{Output, TrackerClient};
use crate::transport::Transport;

const PUNCH_INTERVAL: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const LINK_TIMEOUT: Duration = Duration::from_secs(45);

struct Control {
    kind: u8,
    echo_ts: u64,
    session: u64,
    seq: u64,
    sender: PeerId,
}

impl Control {
    fn parse(p: &[u8]) -> Option<Self> {
        if p.len() < CONTROL_LEN {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(p[i..i + 8].try_into().unwrap());
        Some(Control {
            kind: p[0],
            echo_ts: u64_at(1),
            session: u64_at(9),
            seq: u64_at(17),
            sender: PeerId::try_from(&p[25..CONTROL_LEN]).ok()?,
        })
    }
}

/// A packet for an API client: (route, from peer, payload).
pub type ApiPacket = (u8, PeerId, Vec<u8>);

pub struct Node {
    pub storage: Arc<PeerStorage>,
    pub transport: Arc<Transport>,
    pub clients: Vec<Arc<TrackerClient>>,
    clients_by_addr: HashMap<SocketAddr, Arc<TrackerClient>>,
    tun: Option<Arc<AsyncDevice>>,
    self_id: PeerId,
    self_addr: Option<Ipv4Addr>,
    api_tx: OnceLock<mpsc::Sender<ApiPacket>>,
    epoch: Instant,
    /// Identifies this run in control packets; with `seq` it makes them replay-detectable.
    session: u64,
    seq: AtomicU64,
}

/// Frames `buf[SEALED_HDR..SEALED_HDR + plain_len]` (route byte + payload) for `route`,
/// returning the range of `buf` to put on the wire.
fn frame(buf: &mut [u8], plain_len: usize, route: &Route) -> std::ops::Range<usize> {
    match &route.cipher {
        Some(c) => 0..c.seal(buf, plain_len, &route.peer_id),
        None => {
            buf[SEALED_HDR - 1] = PLAIN;
            SEALED_HDR - 1..SEALED_HDR + plain_len
        }
    }
}

impl Node {
    pub fn new(
        storage: Arc<PeerStorage>,
        transport: Arc<Transport>,
        clients: Vec<TrackerClient>,
        tun: Option<AsyncDevice>,
        self_addr: Option<Ipv4Addr>,
    ) -> Arc<Self> {
        let clients: Vec<_> = clients.into_iter().map(Arc::new).collect();
        let clients_by_addr = clients.iter().map(|c| (c.addr, c.clone())).collect();
        Arc::new(Node {
            self_id: storage.self_id(),
            storage,
            transport,
            clients,
            clients_by_addr,
            tun: tun.map(Arc::new),
            self_addr,
            api_tx: OnceLock::new(),
            epoch: Instant::now(),
            session: rand::random(),
            seq: AtomicU64::new(1),
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
        tokio::spawn(self.clone().ping_loop());
        tokio::spawn(self.clone().tracker_loop());
        if self.tun.is_some() {
            tokio::spawn(self.clone().tun_loop());
        }
    }

    /// Sends `payload` on `route` to a peer with a known endpoint. Not for the TUN hot path.
    pub async fn send_routed(&self, peer_id: &PeerId, route: u8, payload: &[u8]) -> bool {
        let Some(r) = self.storage.route_by_id(peer_id) else { return false };
        let mut buf = vec![0u8; SEALED_HDR + 1 + payload.len() + TAG_LEN];
        buf[SEALED_HDR] = route;
        buf[SEALED_HDR + 1..SEALED_HDR + 1 + payload.len()].copy_from_slice(payload);
        let range = frame(&mut buf, 1 + payload.len(), &r);
        self.transport.send_to(&buf[range], r.endpoint).await;
        true
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

    fn control_payload(&self, kind: u8, echo_ts: u64) -> Vec<u8> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        // Random padding so keepalives don't all have the same size on the wire.
        let pad = rand::rng().random_range(16..96);
        let mut p = Vec::with_capacity(CONTROL_LEN + pad);
        p.push(kind);
        p.extend_from_slice(&echo_ts.to_le_bytes());
        p.extend_from_slice(&self.session.to_le_bytes());
        p.extend_from_slice(&seq.to_le_bytes());
        p.extend_from_slice(self.self_id.as_bytes());
        p.resize(CONTROL_LEN + pad, 0);
        rand::fill(&mut p[CONTROL_LEN..]);
        p
    }

    async fn ping_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            for (id, link) in self.storage.links() {
                if link.last_seen.unwrap_or(link.since).elapsed() > LINK_TIMEOUT {
                    log::info!("Ping | peer {id} link timeout, endpoint dropped");
                    self.storage.del_endpoint(&id);
                    continue;
                }
                // Until the first reply we are punching through NATs, so ping often.
                let interval = if link.last_seen.is_some() { KEEPALIVE_INTERVAL } else { PUNCH_INTERVAL };
                if link.last_ping.is_some_and(|t| t.elapsed() < interval) {
                    continue;
                }
                let ts = self.epoch.elapsed().as_nanos() as u64;
                if self.send_routed(&id, ROUTE_CONTROL, &self.control_payload(CONTROL_PING, ts)).await {
                    self.storage.update_link(&id, |l| l.last_ping = Some(Instant::now()));
                    log::debug!("Ping | send ping to peer {id}");
                }
            }
        }
    }

    async fn handle_control(&self, peer: PeerId, c: Control) {
        match c.kind {
            CONTROL_PING => {
                self.storage.update_link(&peer, |l| l.last_seen = Some(Instant::now()));
                self.send_routed(&peer, ROUTE_CONTROL, &self.control_payload(CONTROL_PONG, c.echo_ts)).await;
                log::debug!("Ping | receive ping from {peer}");
            }
            CONTROL_PONG => {
                let now = self.epoch.elapsed().as_nanos() as u64;
                let Some(rtt) = now.checked_sub(c.echo_ts) else { return };
                let ms = rtt as f64 / 1e6;
                self.storage.update_link(&peer, |l| {
                    l.last_seen = Some(Instant::now());
                    l.rtt_ms = Some(ms);
                });
                self.storage.emit(Event::Ping { peer_id: peer, ms });
                log::debug!("Ping | receive pong from {peer} ping: {ms:.3}");
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
            match buf[0] {
                HELLO_ACK | TRACKER => {
                    if let Some(c) = self.clients_by_addr.get(&from) {
                        let out = c.handle(&buf[..n], &self.storage);
                        self.send_tracker(c, out).await;
                    }
                }
                SEALED | PLAIN => self.handle_peer_packet(&mut buf[..n], from).await,
                _ => {}
            }
        }
    }

    async fn handle_peer_packet(&self, packet: &mut [u8], from: SocketAddr) {
        let known = self.storage.inbound(&from);
        let own_cipher = match &known {
            Some(inb) => inb.own_cipher.clone(),
            // Unknown address: maybe a peer whose NAT gave it a new port. Only small (control)
            // packets are worth a decryption attempt.
            None if packet.len() <= ROAM_MAX_LEN => self.storage.own_cipher(),
            None => return,
        };
        let range = match (&own_cipher, packet[0]) {
            (Some(c), SEALED) => match c.open(packet, &self.self_id) {
                Some(r) => r,
                None => {
                    if known.is_some() {
                        log::debug!("Peer | packet from {from} decrypt error");
                    }
                    return;
                }
            },
            (None, PLAIN) => 1..packet.len(),
            _ => {
                log::debug!("Peer | packet from {from} encryption mismatch");
                return;
            }
        };
        if range.is_empty() {
            return;
        }
        let route = packet[range.start];
        let payload = &packet[range.start + 1..range.end];

        let Some(inb) = known else {
            let Some(c) = Control::parse(payload).filter(|_| route == ROUTE_CONTROL) else { return };
            if c.sender == self.self_id || !self.storage.exists(&c.sender) {
                return;
            }
            if !self.storage.accept_seq(&c.sender, c.session, c.seq) {
                log::debug!("Peer | replayed control packet from {from} dropped");
                return;
            }
            log::info!("Peer | Peer {} new endpoint {from} (roaming)", c.sender);
            self.storage.set_peer(c.sender, PeerUpdate { endpoint: Some(Some(from)), ..Default::default() });
            self.handle_control(c.sender, c).await;
            return;
        };

        match route {
            ROUTE_NET => {
                let Some(tun) = &self.tun else { return };
                // A peer may only inject packets from its own LAN address.
                if payload.len() < 20
                    || payload[0] >> 4 != 4
                    || inb.peer_addr.is_none_or(|a| payload[12..16] != a.octets())
                {
                    log::debug!("Peer | packet from {} with foreign source dropped", inb.peer_id);
                    return;
                }
                if let Err(e) = tun.send(payload).await {
                    log::warn!("TUN | write error: {e}");
                }
            }
            ROUTE_CONTROL => {
                let Some(c) = Control::parse(payload) else { return };
                if c.sender != inb.peer_id || !self.storage.accept_seq(&c.sender, c.session, c.seq) {
                    return;
                }
                self.handle_control(inb.peer_id, c).await;
            }
            route if route >= ROUTE_API_MIN => {
                if let Some(tx) = self.api_tx.get() {
                    let _ = tx.try_send((route, inb.peer_id, payload.to_vec()));
                }
            }
            route => log::debug!("Peer | route {route} from {} not found", inb.peer_id),
        }
    }

    async fn tun_loop(self: Arc<Self>) {
        let tun = self.tun.clone().unwrap();
        let Some(self_addr) = self.self_addr else { return };
        // Layout: [SEALED][nonce][ROUTE_NET][ip packet][tag]; the IP packet is read in place.
        const OFF: usize = SEALED_HDR + 1;
        let mut buf = vec![0u8; OFF + MAX_DATAGRAM + TAG_LEN];
        log::info!("TUN | Thread receiver - started");
        loop {
            let n = match tun.recv(&mut buf[OFF..OFF + MAX_DATAGRAM - 64]).await {
                Ok(n) => n,
                Err(e) => {
                    log::error!("TUN | read error: {e}");
                    break;
                }
            };
            let ip = &buf[OFF..OFF + n];
            if n < 20 || ip[0] >> 4 != 4 || ip[12..16] != self_addr.octets() {
                continue;
            }
            let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            let Some(route) = self.storage.route_by_addr(dst) else {
                log::trace!("TUN | Packet to {dst} peer not found");
                continue;
            };
            buf[SEALED_HDR] = ROUTE_NET;
            let range = frame(&mut buf, n + 1, &route);
            self.transport.send_to(&buf[range], route.endpoint).await;
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
