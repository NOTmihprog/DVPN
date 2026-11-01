use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::ckr::CkrTable;
use crate::group::{CERT_TTL_SECS, Cert, GroupId, GroupSecret, now_unix};
use crate::identity::NodeId;
use crate::link::{Links, Received};
use crate::logger::node;
use crate::noise::TAG_LEN;
use crate::obfs::MAX_PAD;
use crate::packet::{self, IpInfo};
use crate::proto::{
    CONTROL_LEN, CONTROL_PING, CONTROL_PONG, DATA_HDR, FORWARD_HDR, KIND_API_MIN, KIND_CONTROL, KIND_FORWARD, KIND_IP,
    KIND_REPORT, KIND_ROUTING, KIND_STATE, MAX_DATAGRAM, MAX_HOPS, REPORT_LEN,
};
use crate::router::{LSA_REFRESH, Lsa, LsaBody, Lsdb, MAX_LSA_NEIGHBORS, RouteTable, RoutingMsg, ShortId, short_id};
use crate::state::{Body, Entry, Membership, StateStore, SyncMsg, record_key};
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
/// A neighbour silent this long (keepalives answer every 12-18 s) is no longer announced as a
/// link nor used as a first hop, so routes move to another relay quickly.
const NEIGHBOR_ALIVE: Duration = Duration::from_secs(25);
/// Group records are compared with each neighbour this often (and when a session comes up).
const PEER_SYNC: Duration = Duration::from_secs(60);
/// Admins renew certificates that expire sooner than this.
const RENEW_BEFORE: u64 = 10 * 24 * 3600;
/// Attempts to reach a static peer without a session back off from 1 s to this.
const STATIC_MAX_BACKOFF: Duration = Duration::from_secs(60);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// After a psk epoch switch the old psk is still accepted this long, for nodes that learned
/// about the switch late (PLAN §4.4). Longer than a session lives, so no session is cut short.
const EPOCH_GRACE_MS: u64 = 10 * 60 * 1000;

/// The node's group: its records, our certificate, and the secret if we are an admin.
pub struct GroupCtx {
    pub id: GroupId,
    pub secret: Option<GroupSecret>,
    pub cert: Cert,
    pub store: Arc<StateStore>,
    /// The psk epoch we are in (from the config) and its psk.
    pub epoch: u32,
    pub psk: [u8; 32],
    pub identity: Arc<crate::identity::Identity>,
    /// Called with our certificate when an admin renewed it, to persist it.
    pub on_cert: Box<dyn Fn(&Cert) + Send + Sync>,
    /// Called with (epoch, psk) once a new psk epoch is active, to persist it.
    pub on_epoch: Box<dyn Fn(u32, [u8; 32]) + Send + Sync>,
    /// `[[static_peers]]`: connected to directly, without a tracker (PLAN §10).
    pub statics: Vec<crate::group::StaticRef>,
    /// `[ckr.remote_subnets]`: manual routes on top of the members' certificates (PLAN §7).
    pub routes: Vec<crate::ckr::Route>,
}

type EpochPsk = (u32, [u8; 32]);

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
    group: GroupCtx,
    cert: parking_lot::RwLock<Cert>,
    /// The verified certificates of peers we have seen, for re-checking them when records change.
    peer_certs: parking_lot::Mutex<HashMap<NodeId, Cert>>,
    /// Destination -> node, from `peer_certs` and the manual routes (rebuilt when they change).
    ckr: arc_swap::ArcSwap<CkrTable>,
    /// System routes for the CKR table, with the prefixes already on the TUN interface.
    sys_routes: parking_lot::Mutex<Option<(crate::sysroute::SysRoutes, Vec<ipnet::IpNet>)>>,
    /// Mesh (PLAN §6): end-to-end sessions carried in `FORWARD`, the link-state database, the
    /// routes computed from it, and what we last announced.
    pub e2e: Links,
    lsdb: parking_lot::Mutex<Lsdb>,
    routes: arc_swap::ArcSwap<RouteTable>,
    my_lsa: parking_lot::Mutex<(Vec<NodeId>, Option<Instant>, u64)>,
    last_routing_sync: parking_lot::Mutex<HashMap<NodeId, Instant>>,
    /// Packets sent with a TTL within the hop limit (traceroute probes), by probe id: what an
    /// ICMP Time Exceeded quotes when a relay reports the probe ran out (PLAN §6.4).
    probes: parking_lot::Mutex<HashMap<u16, (Vec<u8>, Instant)>>,
    /// Reports sent in the current second (rate limit).
    reports: parking_lot::Mutex<(Instant, u32)>,
    /// Further addresses to try for peers without a session (PLAN §9.1): the candidates they
    /// announced to the tracker, or all addresses of a static peer.
    candidates: parking_lot::Mutex<HashMap<NodeId, Vec<SocketAddr>>>,
    last_peer_sync: parking_lot::Mutex<HashMap<NodeId, Instant>>,
    /// The psk epoch we are in, and the previous one while it is still accepted (until unix ms).
    psk: parking_lot::Mutex<(EpochPsk, Option<(EpochPsk, u64)>)>,
    /// Last psk epoch we warned about not having a key for.
    epoch_warned: std::sync::atomic::AtomicU32,
}

impl Node {
    pub fn new(
        storage: Arc<PeerStorage>,
        transport: Arc<Transport>,
        // direct link sessions, and end-to-end sessions through the mesh
        (links, e2e): (Links, Links),
        clients: Vec<TrackerClient>,
        tun: Option<AsyncDevice>,
        self_addr: Option<Ipv4Addr>,
        group: GroupCtx,
    ) -> Arc<Self> {
        let group_id = group.id;
        let clients: Vec<_> = clients.into_iter().map(Arc::new).collect();
        let clients_by_addr = clients.iter().flat_map(|c| c.addrs().iter().map(move |a| (*a, c.clone()))).collect();
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
            cert: parking_lot::RwLock::new(group.cert.clone()),
            psk: parking_lot::Mutex::new(((group.epoch, group.psk), None)),
            epoch_warned: std::sync::atomic::AtomicU32::new(0),
            group,
            peer_certs: parking_lot::Mutex::new(HashMap::new()),
            ckr: arc_swap::ArcSwap::from_pointee(CkrTable::default()),
            sys_routes: parking_lot::Mutex::new(None),
            e2e,
            lsdb: parking_lot::Mutex::new(Lsdb::new(group_id)),
            routes: arc_swap::ArcSwap::from_pointee(RouteTable::default()),
            my_lsa: parking_lot::Mutex::new((Vec::new(), None, 0)),
            last_routing_sync: parking_lot::Mutex::new(HashMap::new()),
            probes: parking_lot::Mutex::new(HashMap::new()),
            reports: parking_lot::Mutex::new((Instant::now(), 0)),
            candidates: parking_lot::Mutex::new(HashMap::new()),
            last_peer_sync: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    pub fn group_id(&self) -> GroupId {
        self.group.id
    }

    /// The CKR table now in use.
    pub fn ckr(&self) -> Arc<CkrTable> {
        self.ckr.load_full()
    }

    /// Rebuilds the CKR table: every member's certificate prefixes and IPv6 ULA (sorted by key,
    /// so conflicts resolve the same way everywhere), then the manual routes over them.
    fn rebuild_ckr(&self) {
        let certs = self.peer_certs.lock();
        let mut peers: Vec<&Cert> = certs.values().collect();
        peers.sort_by_key(|c| c.body.node);
        let mut routes = Vec::new();
        for c in peers {
            let target = crate::ckr::Target::Node(c.body.node);
            for net in &c.body.prefixes {
                routes.push(crate::ckr::Route { net: net.trunc(), target, system: true });
            }
            let ula = crate::ckr::ula_addr(&self.group.id, &c.body.node);
            routes.push(crate::ckr::Route { net: ipnet::IpNet::from(IpAddr::V6(ula)), target, system: false });
        }
        drop(certs);
        routes.extend(self.group.routes.iter().copied());
        let table = CkrTable::new(routes);
        if let Some((sys, connected)) = self.sys_routes.lock().as_mut() {
            let wanted = crate::sysroute::wanted(table.routes(), connected);
            tokio::task::block_in_place(|| sys.apply(&wanted));
        }
        self.ckr.store(Arc::new(table));
    }

    /// Manage system routes for the overlay on the TUN interface `tun` (whose own prefixes
    /// are `connected`). Call before `start`.
    pub fn manage_routes(&self, tun: &str, connected: Vec<ipnet::IpNet>) {
        *self.sys_routes.lock() = Some((crate::sysroute::SysRoutes::new(tun), connected));
    }

    pub fn store(&self) -> &StateStore {
        &self.group.store
    }

    // ---- group records ----

    /// Acts on changed records: saves them, applies revocations to sessions and peers, and picks
    /// up a renewed certificate of ours.
    fn apply(&self, changed: &[Entry]) {
        if changed.is_empty() {
            return;
        }
        let store = &self.group.store;
        store.save();
        let m = Membership::of(store, &self.group.id);
        self.links.set_membership(m.clone());
        self.e2e.set_membership(m.clone());
        let gone: Vec<NodeId> =
            self.peer_certs.lock().iter().filter(|(_, c)| !m.admits(c)).map(|(id, _)| *id).collect();
        for id in gone {
            log::info!("Group | {} revoked, dropped", node(id));
            self.peer_certs.lock().remove(&id);
            self.rebuild_ckr();
            self.links.drop_peer(&id);
            self.e2e.drop_peer(&id);
            self.storage.del_peer(&id);
        }
        self.update_psks();
        let me = self.storage.self_id();
        if m.revoked.contains(&me) {
            log::error!("Group | this node is revoked from the group");
        }
        if let Some(c) = store.cert(&self.group.id, &me)
            && c.body.not_after > self.cert.read().body.not_after
            && c.verify(&self.group.id, crate::clock::trusted_unix()).is_ok()
        {
            log::info!(
                "Group | new certificate from an admin, valid {} more days",
                (c.body.not_after - now_unix()) / 86400
            );
            *self.cert.write() = c.clone();
            self.links.set_cert(c.clone());
            self.e2e.set_cert(c.clone());
            for client in &self.clients {
                client.set_certs(vec![c.clone()]);
            }
            self.storage.set_peer(me, PeerUpdate::from_cert(&c));
            (self.group.on_cert)(&c);
        }
    }

    /// Sends records we just learned or made to trackers and neighbours.
    async fn spread(&self, changed: &[Entry]) {
        if changed.is_empty() {
            return;
        }
        let keys: Vec<_> = changed.iter().map(|e| record_key(&e.group, &e.id)).collect();
        let records = self.group.store.get(&self.group.id, &keys);
        for c in &self.clients {
            let out = c.sync(SyncMsg::records(records.clone()));
            self.send_tracker(c, out).await;
        }
        for peer in self.storage.others() {
            if self.links.current(&peer).is_some() {
                for m in SyncMsg::records(records.clone()) {
                    self.send_kind(&peer, KIND_STATE, &m.encode()).await;
                }
            }
        }
    }

    /// A member's certificate seen in a handshake or from a tracker. Admins turn invite
    /// certificates into regular ones (revoking the join key, so the invite is used up) and
    /// renew certificates that expire soon.
    async fn member_seen(&self, cert: &Cert) {
        let id = cert.body.node;
        if id != self.storage.self_id() {
            let changed = {
                let mut certs = self.peer_certs.lock();
                match certs.get(&id) {
                    Some(old) if old == cert || old.body.not_after > cert.body.not_after => false,
                    _ => {
                        certs.insert(id, cert.clone());
                        true
                    }
                }
            };
            if changed {
                self.rebuild_ckr();
            }
        }
        let Some(secret) = &self.group.secret else { return };
        if !crate::clock::trusted() {
            return; // records signed with a wrong clock would win or lose LWW races wrongly
        }
        let store = &self.group.store;
        let g = self.group.id;
        if !Membership::of(store, &g).admits(cert) {
            return;
        }
        let mut changed = Vec::new();
        let renew = cert.grant.is_some() || cert.body.not_after < now_unix() + RENEW_BEFORE;
        let issued = store.cert(&g, &id).is_some_and(|c| c.body.not_after > cert.body.not_after);
        if renew && !issued {
            let mut body = cert.body.clone();
            body.not_after = now_unix() + CERT_TTL_SECS;
            body.serial = rand::random();
            changed.push(store.add(secret, Body::Cert(Box::new(secret.issue(body))), false));
            if let Some(jk) = cert.join_key() {
                changed.push(store.add(secret, Body::Revoke { key: jk }, false));
                log::info!("Group | {} joined by invite: regular certificate issued, invite used up", node(id));
            } else {
                log::info!("Group | certificate of {} renewed", node(id));
            }
        }
        // a member that joined after the last psk change needs that epoch's psk too
        if let Some((n, _)) = store.epoch(&g)
            && !store.has_epoch_key(&g, &id, n)
        {
            changed.push(store.add(secret, crate::state::seal_psk(&g, &id, n, &secret.psk(n)), false));
        }
        if changed.is_empty() {
            return;
        }
        self.apply(&changed);
        self.spread(&changed).await;
    }

    /// Follows the psk epoch records: accept a new psk as soon as we have it, send with it from
    /// its switch time on, keep accepting the old one for a while after.
    fn update_psks(&self) {
        let g = &self.group;
        let now = crate::state::now_ms();
        let mut st = self.psk.lock();
        let (cur, _) = *st;
        let mut next = None;
        if let Some((n, at)) = g.store.epoch(&g.id)
            && n > cur.0
        {
            let psk = match &g.secret {
                Some(secret) => Some(secret.psk(n)),
                None => g.store.epoch_psk(&g.id, &g.identity, n),
            };
            match psk {
                Some(psk) if now >= at => {
                    log::info!("Group | psk epoch {n} active");
                    *st = ((n, psk), Some((cur, at + EPOCH_GRACE_MS)));
                    (g.on_epoch)(n, psk);
                }
                Some(psk) => next = Some((n, psk)),
                None => {
                    let warned = &self.epoch_warned;
                    if now >= at && warned.swap(n, std::sync::atomic::Ordering::Relaxed) != n {
                        log::warn!("Group | psk epoch {n} is active but there is no key for this node");
                    }
                }
            }
        }
        let (cur, prev) = *st;
        let prev = prev.filter(|(_, until)| now < *until).map(|(p, _)| p);
        if st.1.is_some() && prev.is_none() {
            st.1 = None;
        }
        drop(st);
        self.links.set_psks(cur, next.or(prev));
        self.e2e.set_psks(cur, next.or(prev));
    }

    async fn sync_peer(&self, peer: NodeId) {
        self.last_peer_sync.lock().insert(peer, Instant::now());
        for m in SyncMsg::summaries(&self.group.store, &self.group.id) {
            self.send_kind(&peer, KIND_STATE, &m.encode()).await;
        }
    }

    async fn handle_state(&self, peer: NodeId, body: &[u8]) {
        let Some(msg) = SyncMsg::decode(body) else { return };
        let (replies, changed) = msg.handle(&self.group.store, |g| *g == self.group.id);
        for r in replies {
            self.send_kind(&peer, KIND_STATE, &r.encode()).await;
        }
        self.apply(&changed);
    }

    pub fn set_api_sink(&self, tx: mpsc::Sender<ApiPacket>) {
        let _ = self.api_tx.set(tx);
    }

    pub fn client(&self, addr: &SocketAddr) -> Option<&Arc<TrackerClient>> {
        self.clients_by_addr.get(addr)
    }

    pub fn start(self: &Arc<Self>) {
        self.rebuild_ckr();
        self.links.set_membership(Membership::of(&self.group.store, &self.group.id));
        self.e2e.set_membership(Membership::of(&self.group.store, &self.group.id));
        self.update_psks();
        {
            let me = self.clone();
            tokio::spawn(async move {
                // an admin renews its own certificate too
                let own = me.cert.read().clone();
                me.member_seen(&own).await;
            });
        }
        tokio::spawn(self.clone().udp_loop());
        tokio::spawn(self.clone().link_loop());
        tokio::spawn(self.clone().tracker_loop());
        if self.tun.is_some() {
            tokio::spawn(self.clone().tun_loop());
        }
        if !self.group.statics.is_empty() {
            tokio::spawn(self.clone().static_loop());
        }
    }

    /// Sends a handshake to `peer`'s endpoint unless one went out less than `min_interval` ago.
    /// The same handshake goes to the peer's endpoint and, while there is no session, to all its
    /// candidate addresses at once (happy eyeballs, IPv6 first): the first that answers becomes
    /// the endpoint (`roam`), copies arriving elsewhere are dropped as replays.
    async fn handshake(&self, peer: NodeId, min_interval: Duration) {
        let mut targets: Vec<SocketAddr> = self.storage.route_by_id(&peer).map(|r| r.endpoint).into_iter().collect();
        if self.links.current(&peer).is_none() {
            let fam = self.transport.families();
            for c in self.candidates.lock().get(&peer).into_iter().flatten() {
                if fam.reaches(c) && !targets.contains(c) {
                    targets.push(*c);
                }
            }
        }
        if targets.is_empty() {
            return;
        }
        if let Some(packets) = self.links.initiate(peer, min_interval) {
            log::debug!("Link | handshake to {} at {targets:?}", node(peer));
            for t in &targets {
                for p in &packets {
                    self.transport.send_to(p, *t).await;
                }
            }
        }
    }

    /// Our own address candidates for the tracker: interface addresses with our port, not the
    /// overlay address.
    fn own_candidates(&self) -> Vec<SocketAddr> {
        let Ok(local) = self.transport.local_addr() else { return Vec::new() };
        let mut c = crate::transport::local_candidates(local.port(), self.transport.families(), None);
        c.retain(|a| Some(a.ip()) != self.self_addr.map(IpAddr::V4) && !self.in_overlay(a));
        c.truncate(crate::proto::MAX_CANDIDATES);
        c
    }

    /// Whether an address belongs to the overlay itself (the group ULA, or anything the CKR
    /// routes into the tunnel): a "direct" link to it would run inside the tunnel.
    fn in_overlay(&self, a: &SocketAddr) -> bool {
        let ip = a.ip();
        ipnet::IpNet::V6(crate::ckr::ula_prefix(&self.group.id)).contains(&ip)
            || self.self_addr.is_some_and(|s| IpAddr::V4(s) == ip)
            || self.ckr.load().lookup(ip).is_some()
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
        let to: Vec<SocketAddr> = if out.to_all { client.addrs().to_vec() } else { vec![client.addr()] };
        for a in &to {
            for p in &out.packets {
                self.transport.send_to(p, *a).await;
            }
        }
        if !out.candidates.is_empty() {
            let mut cands = self.candidates.lock();
            for (peer, c) in out.candidates.iter().cloned() {
                cands.insert(peer, c.into_iter().filter(|a| !self.in_overlay(a)).collect());
            }
        }
        for cert in &out.members {
            Box::pin(self.member_seen(cert)).await;
        }
        self.apply(&out.changed);
        if let Some(connected) = out.status {
            self.storage.emit(Event::Server { addr: client.addr(), connected });
            if !connected && self.transport.can_change_port() && self.clients.iter().all(|c| !c.is_connected()) {
                self.transport.change_port().await;
            }
        }
    }

    async fn tracker_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut cands = Vec::new();
        let mut cands_at: Option<Instant> = None;
        loop {
            tick.tick().await;
            // interfaces change rarely; look again every 15 s
            if cands_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(15)) {
                cands = self.own_candidates();
                cands_at = Some(Instant::now());
            }
            for c in &self.clients {
                let out = c.tick(&cands);
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
            self.e2e.expire();
            self.mesh_tick().await;
            // records written by the CLI (e.g. dvpn group revoke)
            let changed = self.group.store.reload();
            self.apply(&changed);
            self.spread(&changed).await;
            self.update_psks();
            for (id, link) in self.storage.links() {
                if link.last_seen.unwrap_or(link.since).elapsed() > LINK_TIMEOUT {
                    log::info!("Link | peer {} timed out, endpoint dropped", node(id));
                    self.storage.del_endpoint(&id);
                    self.links.drop_peer(&id);
                    continue;
                }
                let has_session = self.links.current(&id).is_some();
                // static peers without a session are tried by static_loop, with backoff
                let static_pending = !has_session && self.group.statics.iter().any(|s| s.key == id);
                if self.links.needs_handshake(&id) && !static_pending {
                    self.handshake(id, if has_session { REKEY_RETRY } else { PUNCH_INTERVAL }).await;
                }
                let keepalive = rand::rng().random_range(KEEPALIVE);
                if has_session && link.last_ping.is_none_or(|t| t.elapsed() >= keepalive) {
                    self.send_ping(id).await;
                }
                let synced = self.last_peer_sync.lock().get(&id).copied();
                if has_session && synced.is_none_or(|t| t.elapsed() >= PEER_SYNC) {
                    self.sync_peer(id).await;
                }
                let routed = self.last_routing_sync.lock().get(&id).copied();
                if has_session && routed.is_none_or(|t| t.elapsed() >= LSA_REFRESH) {
                    self.last_routing_sync.lock().insert(id, Instant::now());
                    let msgs = RoutingMsg::summaries(&self.lsdb.lock());
                    for m in msgs {
                        self.send_kind(&id, KIND_ROUTING, &m.encode()).await;
                    }
                }
            }
        }
    }

    /// Connects to static peers on our own: no tracker needed. Each attempt takes the next
    /// endpoint (DNS names are resolved every time, so a changed address is found), and the
    /// pause between attempts doubles up to a minute while the peer does not answer.
    async fn static_loop(self: Arc<Self>) {
        struct Try {
            next: Instant,
            backoff: Duration,
        }
        let mut tries: HashMap<NodeId, Try> = HashMap::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            for sp in &self.group.statics {
                let t = tries.entry(sp.key).or_insert(Try { next: Instant::now(), backoff: Duration::from_secs(1) });
                if self.links.current(&sp.key).is_some() {
                    t.backoff = Duration::from_secs(1);
                    t.next = Instant::now();
                    continue;
                }
                if Instant::now() < t.next {
                    continue;
                }
                let jitter = Duration::from_millis(rand::rng().random_range(0..500));
                t.next = Instant::now() + t.backoff + jitter;
                t.backoff = (t.backoff * 2).min(STATIC_MAX_BACKOFF);
                // every endpoint, every resolved address of it: tried at once, IPv6 first
                let fam = self.transport.families();
                let mut addrs: Vec<SocketAddr> = Vec::new();
                for ep in &sp.endpoints {
                    match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(ep.as_str())).await {
                        Ok(Ok(r)) => addrs.extend(r.map(crate::transport::normalize).filter(|a| fam.reaches(a))),
                        Ok(Err(e)) => log::debug!("Static | {ep}: {e}"),
                        Err(_) => log::debug!("Static | {ep}: DNS timeout"),
                    }
                }
                addrs.sort_by_key(|a| a.is_ipv4());
                addrs.dedup();
                let Some(&first) = addrs.first() else {
                    log::debug!("Static | {}: no reachable address", node(sp.key));
                    continue;
                };
                if self.storage.endpoint(&sp.key).is_none_or(|e| !addrs.contains(&e)) {
                    self.storage.set_peer(sp.key, PeerUpdate { endpoint: Some(Some(first)), ..Default::default() });
                }
                self.candidates.lock().insert(sp.key, addrs);
                self.handshake(sp.key, Duration::ZERO).await;
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
                    let out = c.handle(&buf[..n], from, &self.storage);
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
        match self.links.receive(packet) {
            None => {}
            Some(Received::Handshake { peer, cert, reply }) => {
                // name and address as the certificate states them (also for peers that did not
                // come through the tracker, e.g. static ones)
                let update = PeerUpdate::from_cert(&cert);
                if storage.get(&peer).is_none_or(|(r, _)| Some(r.name) != update.name || Some(r.addr) != update.addr) {
                    storage.set_peer(peer, update);
                }
                self.roam(peer, from);
                self.member_seen(&cert).await;
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
                    KIND_IP => self.deliver_ip(peer, body).await,
                    KIND_CONTROL => self.handle_control(peer, body).await,
                    KIND_STATE => self.handle_state(peer, body).await,
                    KIND_ROUTING => self.handle_routing(peer, body).await,
                    KIND_FORWARD => Box::pin(self.handle_forward(peer, body)).await,
                    KIND_REPORT => self.handle_report(peer, body).await,
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

    /// An IP packet from `peer` (directly or end to end) for the TUN device. Reverse path
    /// (PLAN §7.2): the source must route back to the sender, so a peer injects only from its own
    /// addresses and subnets (its certificate), or from the internet if it is our exit.
    async fn deliver_ip(&self, peer: NodeId, body: &[u8]) {
        let Some(tun) = &self.tun else { return };
        let own = packet::parse(body).is_some_and(|i| self.ckr.load().lookup(i.src) == Some(peer));
        if !own {
            log::debug!("Link | packet from {} with foreign source dropped", node(peer));
            return;
        }
        if let Err(e) = tun.send(body).await {
            log::warn!("TUN | write error: {e}");
        }
    }

    // ---- mesh (PLAN §6) ----

    /// Whether we relay for others: the relay role in our certificate.
    fn is_relay(&self) -> bool {
        self.cert.read().body.roles.has(crate::group::Roles::RELAY)
    }

    /// Our direct links for the LSA: neighbours with a live session, cost = RTT in ms.
    fn neighbors(&self) -> Vec<(NodeId, u32)> {
        let mut v: Vec<(NodeId, u32)> = self
            .storage
            .others()
            .into_iter()
            .filter(|p| self.link_alive(p))
            .map(|p| (p, self.storage.rtt_ms(&p).map_or(100, |r| r.ceil() as u32 + 1)))
            .collect();
        v.sort_by_key(|(p, c)| (*c, *p));
        v.truncate(MAX_LSA_NEIGHBORS);
        v
    }

    /// A direct session that answered recently.
    fn link_alive(&self, p: &NodeId) -> bool {
        self.links.current(p).is_some() && self.storage.link_alive(p, NEIGHBOR_ALIVE)
    }

    fn recompute_routes(&self) {
        let me = self.storage.self_id();
        let certs = self.peer_certs.lock();
        let relay = |n: &NodeId| certs.get(n).is_some_and(|c| c.body.roles.has(crate::group::Roles::RELAY));
        let table = RouteTable::compute(me, &self.lsdb.lock(), &relay, &self.routes.load());
        drop(certs);
        self.routes.store(Arc::new(table));
    }

    /// Floods LSAs to all neighbours but `except`.
    async fn flood(&self, lsas: Vec<Lsa>, except: Option<NodeId>) {
        let msgs: Vec<Vec<u8>> = RoutingMsg::lsas(lsas).iter().map(|m| m.encode()).collect();
        for n in self.storage.others() {
            if Some(n) != except && self.links.current(&n).is_some() {
                for m in &msgs {
                    self.send_kind(&n, KIND_ROUTING, m).await;
                }
            }
        }
    }

    /// Once a second: announce our links when they changed (or every `LSA_REFRESH`), expire old
    /// LSAs, recompute routes.
    async fn mesh_tick(&self) {
        let revoked = Membership::of(&self.group.store, &self.group.id).revoked;
        let expired = self.lsdb.lock().expire(&revoked);
        let neighbors = self.neighbors();
        let ids: Vec<NodeId> = neighbors.iter().map(|(n, _)| *n).collect();
        let due = {
            let (last, at, _) = &*self.my_lsa.lock();
            *last != ids || at.is_none_or(|t| t.elapsed() >= LSA_REFRESH)
        };
        if due {
            let seq = {
                let mut m = self.my_lsa.lock();
                m.2 = crate::clock::now_ms().max(m.2 + 1);
                m.0 = ids;
                m.1 = Some(Instant::now());
                m.2
            };
            let body = LsaBody { origin: self.storage.self_id(), group: self.group.id, seq, neighbors };
            let lsa = Lsa::sign(&self.group.identity, &body);
            self.lsdb.lock().insert(lsa.clone(), &HashSet::new());
            self.flood(vec![lsa], None).await;
        }
        if due || expired {
            self.recompute_routes();
        }
    }

    async fn handle_routing(&self, peer: NodeId, body: &[u8]) {
        let Some(msg) = RoutingMsg::decode(body) else { return };
        match msg {
            RoutingMsg::Summary(theirs) => {
                let (give, want) = self.lsdb.lock().diff(&theirs);
                for m in RoutingMsg::lsas(give) {
                    self.send_kind(&peer, KIND_ROUTING, &m.encode()).await;
                }
                if !want.is_empty() {
                    self.send_kind(&peer, KIND_ROUTING, &RoutingMsg::Want(want).encode()).await;
                }
            }
            RoutingMsg::Want(origins) => {
                let lsas = self.lsdb.lock().get(&origins);
                for m in RoutingMsg::lsas(lsas) {
                    self.send_kind(&peer, KIND_ROUTING, &m.encode()).await;
                }
            }
            RoutingMsg::Lsas(lsas) => {
                let revoked = Membership::of(&self.group.store, &self.group.id).revoked;
                let me = self.storage.self_id();
                let new: Vec<Lsa> = {
                    let mut db = self.lsdb.lock();
                    // our own LSA comes back from neighbours: ignore older copies of it
                    lsas.into_iter()
                        .filter(|l| l.open().is_some_and(|b| b.origin != me) && db.insert(l.clone(), &revoked))
                        .collect()
                };
                if !new.is_empty() {
                    self.recompute_routes();
                    self.flood(new, Some(peer)).await;
                }
            }
        }
    }

    /// Sends `inner` (a packet of the end-to-end session with the node `dst`) towards `dst`.
    async fn send_forward(&self, next: NodeId, hdr: [u8; 4], dst: ShortId, src: ShortId, inner: &[u8]) -> bool {
        let mut body = Vec::with_capacity(FORWARD_HDR + inner.len());
        body.extend_from_slice(&hdr);
        body.extend_from_slice(&dst);
        body.extend_from_slice(&src);
        body.extend_from_slice(inner);
        self.send_kind(&next, KIND_FORWARD, &body).await
    }

    /// The neighbour to send `dst`'s packets to: `dst` itself over a direct session, else the
    /// first hop of the mesh route.
    fn next_hop(&self, dst: &NodeId) -> Option<NodeId> {
        if self.links.current(dst).is_some() {
            return Some(*dst);
        }
        self.routes.load().next_hop(dst).filter(|n| self.link_alive(n))
    }

    /// End-to-end handshake with `dst` through the mesh (rate limited like direct ones).
    async fn e2e_handshake(&self, dst: NodeId, min_interval: Duration) {
        let Some(next) = self.next_hop(&dst) else { return };
        if let Some(packets) = self.e2e.initiate(dst, min_interval) {
            log::debug!("Mesh | handshake to {} via {}", node(dst), node(next));
            let (d, s) = (short_id(&dst), short_id(&self.storage.self_id()));
            for p in packets {
                self.send_forward(next, [MAX_HOPS, 0, 0, 0], d, s, &p).await;
            }
        }
    }

    /// `[kind][body]` to `dst` over the end-to-end session, through the mesh. Starts the
    /// session if there is none (the packet is dropped meanwhile, like a direct first contact).
    pub async fn send_e2e(&self, dst: NodeId, kind: u8, body: &[u8], limit: u8, probe: u16) -> bool {
        let Some(next) = self.next_hop(&dst) else { return false };
        let Some(session) = self.e2e.current(&dst) else {
            self.e2e_handshake(dst, PUNCH_INTERVAL).await;
            return false;
        };
        if self.e2e.needs_handshake(&dst) {
            self.e2e_handshake(dst, REKEY_RETRY).await;
        }
        let mut buf = vec![0u8; DATA_HDR + 1 + body.len() + TAG_LEN + MAX_PAD];
        buf[DATA_HDR] = kind;
        buf[DATA_HDR + 1..DATA_HDR + 1 + body.len()].copy_from_slice(body);
        let Some(len) = session.seal(&mut buf, 1 + body.len()) else { return false };
        let (d, s) = (short_id(&dst), short_id(&self.storage.self_id()));
        let p = probe.to_le_bytes();
        self.send_forward(next, [limit, 0, p[0], p[1]], d, s, &buf[..len]).await
    }

    /// Remembers a probe (an IP packet with a small TTL) for a later ICMP Time Exceeded.
    fn new_probe(&self, packet: &[u8]) -> u16 {
        let mut probes = self.probes.lock();
        probes.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(10));
        if probes.len() >= 256 {
            return 0; // no more room: the probe just gets no ICMP answer
        }
        let id = loop {
            let id: u16 = rand::random();
            if id != 0 && !probes.contains_key(&id) {
                break id;
            }
        };
        probes.insert(id, (packet::quote(packet), Instant::now()));
        id
    }

    /// Reports to the source that its probe ran out of hops here (rate limited).
    async fn send_report(&self, src: ShortId, probe: u16) {
        {
            let mut r = self.reports.lock();
            if r.0.elapsed() >= Duration::from_secs(1) {
                *r = (Instant::now(), 0);
            }
            r.1 += 1;
            if r.1 > 50 {
                return;
            }
        }
        let Some(src_id) = self.routes.load().resolve(&src) else { return };
        let Some(next) = self.next_hop(&src_id) else { return };
        let mut b = Vec::with_capacity(REPORT_LEN);
        b.extend_from_slice(&src);
        b.extend_from_slice(&probe.to_le_bytes());
        b.extend_from_slice(self.storage.self_id().as_bytes());
        b.push(0); // time exceeded
        self.send_kind(&next, KIND_REPORT, &b).await;
    }

    /// A report on the way back to a probe's source: ours (answer traceroute with an ICMP Time
    /// Exceeded from the reporter's overlay address) or one to pass on.
    async fn handle_report(&self, from: NodeId, body: &[u8]) {
        if body.len() < REPORT_LEN {
            return;
        }
        let dst: ShortId = body[..8].try_into().unwrap();
        let probe = u16::from_le_bytes([body[8], body[9]]);
        let Ok(reporter) = NodeId::try_from(&body[10..42]) else { return };
        if dst != short_id(&self.storage.self_id()) {
            let Some(dst_id) = self.routes.load().resolve(&dst) else { return };
            if let Some(next) = self.next_hop(&dst_id).filter(|n| *n != from) {
                self.send_kind(&next, KIND_REPORT, body).await;
            }
            return;
        }
        let Some((quoted, _)) = self.probes.lock().remove(&probe) else { return };
        let addr = match packet::version(&quoted) {
            Some(4) => self.peer_certs.lock().get(&reporter).and_then(|c| c.body.ipv4()).map(IpAddr::V4),
            _ => Some(IpAddr::V6(crate::ckr::ula_addr(&self.group.id, &reporter))),
        };
        let (Some(addr), Some(tun)) = (addr, &self.tun) else { return };
        if let Some(icmp) = packet::icmp_time_exceeded(addr, &quoted) {
            let _ = tun.send(&icmp).await;
        }
    }

    /// A `FORWARD` from neighbour `from`: ours (open the end-to-end packet) or one to pass on.
    async fn handle_forward(&self, from: NodeId, body: &[u8]) {
        if body.len() < FORWARD_HDR {
            return;
        }
        let (limit, hops) = (body[0], body[1]);
        let dst: ShortId = body[4..12].try_into().unwrap();
        let src: ShortId = body[12..20].try_into().unwrap();
        let inner = &body[FORWARD_HDR..];
        let me = self.storage.self_id();
        if dst == short_id(&me) {
            return self.handle_e2e(from, inner, hops).await;
        }
        if !self.is_relay() {
            log::debug!("Mesh | FORWARD from {} dropped: not a relay", node(from));
            return;
        }
        let hops = hops.saturating_add(1);
        if hops >= limit {
            log::debug!("Mesh | FORWARD from {} dropped: hop limit", node(from));
            let probe = u16::from_le_bytes([body[2], body[3]]);
            if probe != 0 {
                self.send_report(src, probe).await;
            }
            return;
        }
        let routes = self.routes.load();
        let Some(dst_id) = routes.resolve(&dst) else { return };
        let Some(next) = self.next_hop(&dst_id) else { return };
        if next == from {
            return; // routes not converged yet: do not bounce
        }
        let hdr = [limit, hops, body[2], body[3]];
        self.send_forward(next, hdr, dst, src, inner).await;
    }

    /// An end-to-end packet that reached us after `hops` relays.
    async fn handle_e2e(&self, from: NodeId, inner: &[u8], hops: u8) {
        let mut packet = inner.to_vec();
        match self.e2e.receive(&mut packet) {
            None => {}
            Some(Received::Handshake { peer, cert, reply }) => {
                let update = PeerUpdate::from_cert(&cert);
                if self
                    .storage
                    .get(&peer)
                    .is_none_or(|(r, _)| Some(r.name) != update.name || Some(r.addr) != update.addr)
                {
                    self.storage.set_peer(peer, update);
                }
                Box::pin(self.member_seen(&cert)).await;
                if let Some(r) = reply {
                    // back the way it came if we have no route of our own yet
                    let next = self.next_hop(&peer).unwrap_or(from);
                    let (d, s) = (short_id(&peer), short_id(&self.storage.self_id()));
                    self.send_forward(next, [MAX_HOPS, 0, 0, 0], d, s, &r).await;
                } else {
                    log::info!("Mesh | end-to-end session with {} via {}", node(peer), node(from));
                }
            }
            Some(Received::Data { session, plain }) => {
                let peer = session.peer;
                let Some((&kind, body)) = packet[plain].split_first() else { return };
                match kind {
                    KIND_IP => {
                        // relays do not see the IP header: the TTL drops here, by the hops
                        let mut ip = body.to_vec();
                        if packet::decrement_ttl(&mut ip, hops) {
                            self.deliver_ip(peer, &ip).await;
                        }
                    }
                    k if k >= KIND_API_MIN => {
                        if let Some(tx) = self.api_tx.get() {
                            let _ = tx.try_send((k, peer, body.to_vec()));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    async fn tun_loop(self: Arc<Self>) {
        let tun = self.tun.clone().unwrap();
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
            let Some(IpInfo { dst, ttl, .. }) = packet::parse(&buf[OFF..OFF + n]) else { continue };
            // Any source: our own address, a LAN host behind us (site-to-site), or the internet
            // if we are an exit; the receiver checks it by the reverse path.
            let Some(peer) = self.ckr.load().lookup(dst) else {
                log::trace!("TUN | no route to {dst}");
                continue;
            };
            let (Some(session), Some(route)) = (self.links.current(&peer), self.storage.route_by_id(&peer)) else {
                // no direct session: through the mesh if there is a route (link_loop keeps
                // trying the direct path meanwhile), else first contact
                let ip = &buf[OFF..OFF + n];
                // TTL into the hop limit (PLAN §6.4): small TTLs are traceroute probes
                let (limit, probe) = if ttl <= MAX_HOPS { (ttl.max(1), self.new_probe(ip)) } else { (MAX_HOPS, 0) };
                if !self.send_e2e(peer, KIND_IP, ip, limit, probe).await && self.routes.load().next_hop(&peer).is_none()
                {
                    self.handshake(peer, PUNCH_INTERVAL).await;
                }
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
        if let Some((sys, _)) = self.sys_routes.lock().as_mut() {
            tokio::task::block_in_place(|| sys.clear());
        }
        for c in &self.clients {
            if let Some(p) = c.close() {
                self.transport.send_to(&p, c.addr()).await;
            }
        }
    }
}
