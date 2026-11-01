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
use crate::router::{
    Insert, LSA_MIN_SEND, LSA_REFRESH, Lsa, LsaBody, Lsdb, MAX_LSA_NEIGHBORS, RouteTable, RoutingMsg, Scores, ShortId,
    short_id,
};
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
/// The largest IP packet a direct session carries within `obfs::MAX_WIRE`: DATA header, kind
/// and tag; through relays the end-to-end layer and the FORWARD header come on top.
const DIRECT_MTU: usize = crate::obfs::MAX_WIRE - (DATA_HDR + 1 + TAG_LEN);
const RELAY_MTU: usize = DIRECT_MTU - (FORWARD_HDR + DATA_HDR + 1 + TAG_LEN);
/// How long `ping` waits for the answer.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

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

/// A neighbour with a direct session, for diagnostics.
pub struct DirectLink {
    pub peer: NodeId,
    pub endpoint: Option<SocketAddr>,
    pub rtt_ms: Option<f64>,
    pub alive: bool,
    pub age: Duration,
}

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
    /// Prefix length of the group network on the TUN (`[net] mask`).
    pub tun_prefix: u8,
    /// The group's local name and the DNS zone of members' names (`[dns]`), if served.
    pub group_name: String,
    pub dns: Option<(String, Arc<arc_swap::ArcSwap<crate::dns::Zone>>)>,
    /// Where the DNS server forwards other names (`[exit] dns` while a gateway is active).
    pub dns_upstream: crate::dns::Upstream,
    /// Change systemd-resolved (split DNS, all names through the gateway): the TUN name.
    pub resolved_tun: Option<String>,
    /// `[exit]` as at start; the node follows later changes in `config_path`.
    pub exits: crate::config::Exits,
    pub config_path: std::path::PathBuf,
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
    /// Our IPv4 address in the group (it follows our certificate).
    self_addr: parking_lot::RwLock<Option<Ipv4Addr>>,
    api_tx: OnceLock<mpsc::Sender<ApiPacket>>,
    epoch: Instant,
    group: GroupCtx,
    cert: parking_lot::RwLock<Cert>,
    /// The verified certificates of peers we have seen, for re-checking them when records change.
    peer_certs: parking_lot::Mutex<HashMap<NodeId, Cert>>,
    /// Destination -> node, from `peer_certs` and the manual routes (rebuilt when they change).
    ckr: arc_swap::ArcSwap<CkrTable>,
    /// The plan in place now (`plan.rs`), and the system it is applied to (`apply.rs`).
    plan: parking_lot::Mutex<crate::plan::Plan>,
    system: parking_lot::Mutex<crate::apply::System>,
    /// Mesh (PLAN §6): end-to-end sessions carried in `FORWARD`, the link-state database, the
    /// routes computed from it, and what we last announced.
    pub e2e: Links,
    lsdb: parking_lot::Mutex<Lsdb>,
    routes: arc_swap::ArcSwap<RouteTable>,
    my_lsa: parking_lot::Mutex<(Vec<NodeId>, Option<Instant>, u64)>,
    last_routing_sync: parking_lot::Mutex<HashMap<NodeId, Instant>>,
    /// Misbehaving neighbours: their ROUTING and STATE messages are ignored for a while.
    scores: parking_lot::Mutex<Scores>,
    /// Traffic and drop counters (`dvpn metrics`).
    pub metrics: crate::metrics::Metrics,
    /// Packets sent with a TTL within the hop limit (traceroute probes), by probe id: what an
    /// ICMP Time Exceeded quotes when a relay reports the probe ran out (PLAN §6.4).
    probes: parking_lot::Mutex<HashMap<u16, (Vec<u8>, Instant)>>,
    /// `dvpn ping` waiting for answers, by the echoed timestamp.
    pings: parking_lot::Mutex<HashMap<u64, tokio::sync::oneshot::Sender<f64>>>,
    /// Reports sent in the current second (rate limit).
    reports: parking_lot::Mutex<(Instant, u32)>,
    /// `[exit]` and the config file's mtime it was read at; the chosen IPv4 / IPv6 gateways.
    exits: parking_lot::Mutex<(crate::config::Exits, Option<std::time::SystemTime>)>,
    exit4: parking_lot::Mutex<crate::exit::ExitChooser>,
    exit6: parking_lot::Mutex<crate::exit::ExitChooser>,
    /// Kill switch on for IPv4 / IPv6: gateways configured, none alive.
    kill: parking_lot::Mutex<(bool, bool)>,
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
        let exits = (group.exits.clone(), std::fs::metadata(&group.config_path).and_then(|m| m.modified()).ok());
        let clients: Vec<_> = clients.into_iter().map(Arc::new).collect();
        let clients_by_addr = clients.iter().flat_map(|c| c.addrs().iter().map(move |a| (*a, c.clone()))).collect();
        let tun = tun.map(Arc::new);
        let mut system = crate::apply::System::new(tun.clone());
        if let (Some(_), Some((domain, _))) = (&group.resolved_tun, &group.dns) {
            system.manage_resolved(domain);
        }
        // what the TUN starts with: the first plan only adds the rest
        let plan = crate::plan::Plan {
            addrs: crate::plan::own_addrs(&group.cert, &group.id, group.tun_prefix),
            ..Default::default()
        };
        Arc::new(Node {
            storage,
            transport,
            links,
            clients,
            clients_by_addr,
            tun,
            self_addr: parking_lot::RwLock::new(self_addr),
            api_tx: OnceLock::new(),
            epoch: Instant::now(),
            cert: parking_lot::RwLock::new(group.cert.clone()),
            psk: parking_lot::Mutex::new(((group.epoch, group.psk), None)),
            epoch_warned: std::sync::atomic::AtomicU32::new(0),
            group,
            peer_certs: parking_lot::Mutex::new(HashMap::new()),
            ckr: arc_swap::ArcSwap::from_pointee(CkrTable::default()),
            plan: parking_lot::Mutex::new(plan),
            system: parking_lot::Mutex::new(system),
            e2e,
            lsdb: parking_lot::Mutex::new(Lsdb::new(group_id)),
            routes: arc_swap::ArcSwap::from_pointee(RouteTable::default()),
            my_lsa: parking_lot::Mutex::new((Vec::new(), None, 0)),
            last_routing_sync: parking_lot::Mutex::new(HashMap::new()),
            scores: parking_lot::Mutex::new(Scores::default()),
            metrics: crate::metrics::Metrics::default(),
            probes: parking_lot::Mutex::new(HashMap::new()),
            reports: parking_lot::Mutex::new((Instant::now(), 0)),
            pings: parking_lot::Mutex::new(HashMap::new()),
            exits: parking_lot::Mutex::new(exits),
            exit4: parking_lot::Mutex::new(Default::default()),
            exit6: parking_lot::Mutex::new(Default::default()),
            kill: parking_lot::Mutex::new((false, false)),
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

    /// Recomputes the node's plan (`plan.rs`: CKR, our addresses, ACL, DNS) from what it knows
    /// now and applies what changed (`apply.rs`). Called whenever an input changes: certificates,
    /// records, gateways, the kill switch, `[exit]`.
    fn replan(&self) {
        // every member's newest certificate: from handshakes and trackers, or from the records
        // (an admin changed its addresses or subnets: `dvpn node set`), revoked ones left out
        let me = self.storage.self_id();
        let m = Membership::of(&self.group.store, &self.group.id);
        let mut newest: HashMap<NodeId, Cert> = HashMap::new();
        for c in self.peer_certs.lock().values().cloned().chain(self.group.store.certs(&self.group.id)) {
            let n = c.body.node;
            if n == me || !m.admits(&c) {
                continue;
            }
            if newest.get(&n).is_none_or(|old| old.body.not_after < c.body.not_after) {
                newest.insert(n, c);
            }
        }
        let own = self.cert.read().clone();
        let acl = self.group.store.acl(&self.group.id);
        let (dns_forward, exit_table, exit_sources) = {
            let e = &self.exits.lock().0;
            (e.dns.clone(), e.table, e.sources())
        };
        let plan = crate::plan::compute(&crate::plan::Inputs {
            me,
            group: self.group.id,
            group_name: &self.group.group_name,
            own: &own,
            members: &newest,
            tun_prefix: self.group.tun_prefix,
            exit4: self.exit4.lock().current,
            exit6: self.exit6.lock().current,
            kill: *self.kill.lock(),
            exit_table,
            exit_sources: &exit_sources,
            manual: &self.group.routes,
            acl: acl.as_ref(),
            dns_domain: self.group.dns.as_ref().map(|(d, _)| d.as_str()),
            dns_forward: &dns_forward,
        });
        // one replan at a time, so the system follows the plans in order
        let mut current = self.plan.lock();
        if *current == plan {
            return;
        }
        // in-process state first: packets route by the new table at once
        self.ckr.store(Arc::new(CkrTable::new(plan.ckr.clone())));
        *self.self_addr.write() = plan.ipv4();
        if let Some((_, zone)) = &self.group.dns {
            zone.store(Arc::new(plan.zone.clone()));
        }
        if current.dns_upstream != plan.dns_upstream {
            if !plan.dns_upstream.is_empty() {
                log::info!("DNS | other names through the gateway to {:?}", plan.dns_upstream);
            }
            self.group.dns_upstream.store(Arc::new(plan.dns_upstream.clone()));
        }
        tokio::task::block_in_place(|| self.system.lock().apply(&me, &current, &plan));
        *current = plan;
    }

    /// An mDNS query the system sent into the TUN (`<member>.local`): the response, from the
    /// member's address (our own would be a martian source on arrival), to the mDNS group.
    fn mdns_reply(&self, ip: &[u8]) -> Option<Vec<u8>> {
        use crate::dns::{MDNS_PORT, MDNS_V4, MDNS_V6};
        let (domain, zone) = self.group.dns.as_ref()?;
        let (_, dport, data) = packet::udp(ip)?;
        if dport != MDNS_PORT {
            return None;
        }
        let (msg, addrs) = crate::dns::mdns_answer(data, &zone.load(), domain)?;
        let v6 = packet::parse(ip)?.src.is_ipv6();
        let src = addrs.iter().find(|a| a.is_ipv6() == v6).copied()?;
        let group = if v6 { IpAddr::V6(MDNS_V6) } else { IpAddr::V4(MDNS_V4) };
        packet::udp_packet(src, group, MDNS_PORT, MDNS_PORT, &msg, 255)
    }

    /// Act as a gateway (`[gateway]`). Call before `start`.
    pub fn set_gateway(&self, gw: crate::gateway::Gateway) {
        self.system.lock().set_gateway(gw);
    }

    /// Manage system routes for the overlay on the TUN interface. Call before `start`.
    pub fn manage_routes(&self) {
        self.system.lock().manage_routes();
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
            self.metrics.remove(&id);
            self.peer_certs.lock().remove(&id);
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
            self.links.set_cert(c.clone());
            self.e2e.set_cert(c.clone());
            for client in &self.clients {
                client.set_certs(vec![c.clone()]);
            }
            self.storage.set_peer(me, PeerUpdate::from_cert(&c));
            // our addresses on the TUN follow it in the replan below
            *self.cert.write() = c.clone();
            (self.group.on_cert)(&c);
        }
        // members' certificates in the records carry their current addresses and subnets
        self.replan();
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
                self.replan();
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

    /// Counts bad messages from a neighbour; logs when that gets it ignored.
    fn penalize(&self, peer: NodeId, points: u32, what: &str) {
        if self.scores.lock().penalize(peer, points) {
            log::warn!("Mesh | {} sends too many bad {what} messages: ignored for a while", node(peer));
        }
    }

    async fn handle_state(&self, peer: NodeId, body: &[u8]) {
        if self.scores.lock().banned(&peer) {
            return;
        }
        let Some(msg) = SyncMsg::decode(body) else {
            return self.penalize(peer, 10, "record");
        };
        if let SyncMsg::Records { records } = &msg {
            let bad = records.iter().filter(|r| r.open().map_or(true, |e| e.group != self.group.id)).count();
            self.penalize(peer, 5 * bad as u32, "record");
        }
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
        self.replan();
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
        c.retain(|a| Some(a.ip()) != self.self_addr.read().map(IpAddr::V4) && !self.in_overlay(a));
        c.truncate(crate::proto::MAX_CANDIDATES);
        c
    }

    /// Whether an address belongs to the overlay itself (the group ULA, or anything the CKR
    /// routes into the tunnel): a "direct" link to it would run inside the tunnel.
    fn in_overlay(&self, a: &SocketAddr) -> bool {
        let ip = a.ip();
        ipnet::IpNet::V6(crate::ckr::ula_prefix(&self.group.id)).contains(&ip)
            || self.self_addr.read().is_some_and(|s| IpAddr::V4(s) == ip)
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
        self.metrics.peer(peer).wire_tx.add(len);
        true
    }

    /// For API clients: `payload` on API route `route` (32..=255), directly or end to end
    /// through relays.
    pub async fn send_routed(&self, peer: &NodeId, route: u8, payload: &[u8]) -> bool {
        if self.links.current(peer).is_some() {
            self.send_kind(peer, route, payload).await
        } else {
            self.send_e2e(*peer, route, payload, MAX_HOPS, 0).await
        }
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

    /// `dvpn ping`: the round trip to `peer` over our session with it (direct or end to end
    /// through relays): (milliseconds, through relays). `None` if no answer came.
    pub async fn ping(&self, peer: NodeId) -> Option<(f64, bool)> {
        let ts = loop {
            let ts = self.epoch.elapsed().as_nanos() as u64;
            if !self.pings.lock().contains_key(&ts) {
                break ts;
            }
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pings.lock().insert(ts, tx);
        let body = Self::control(CONTROL_PING, ts);
        let mesh = self.links.current(&peer).is_none();
        let sent = if mesh {
            // a first end-to-end packet only starts the session: give it a moment
            self.send_e2e(peer, KIND_CONTROL, &body, MAX_HOPS, 0).await || {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.send_e2e(peer, KIND_CONTROL, &body, MAX_HOPS, 0).await
            }
        } else {
            self.send_kind(&peer, KIND_CONTROL, &body).await
        };
        let r = if sent { tokio::time::timeout(PING_TIMEOUT, rx).await.ok().and_then(Result::ok) } else { None };
        self.pings.lock().remove(&ts);
        r.map(|ms| (ms, mesh))
    }

    /// A pong for `dvpn ping`.
    fn ping_answered(&self, echo_ts: u64) -> Option<f64> {
        let ms = self.epoch.elapsed().as_nanos().checked_sub(u128::from(echo_ts))? as f64 / 1e6;
        if let Some(tx) = self.pings.lock().remove(&echo_ts) {
            let _ = tx.send(ms);
        }
        Some(ms)
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
                let Some(ms) = self.ping_answered(echo_ts) else { return };
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
        let len = packet.len();
        match self.links.receive(packet) {
            None => self.metrics.dropped(crate::metrics::Drop::Unreadable),
            Some(Received::Handshake { peer, cert, reply }) => {
                self.metrics.handshake();
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
                self.metrics.peer(&peer).wire_rx.add(len);
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
            self.metrics.dropped(crate::metrics::Drop::ForeignSource);
            log::debug!("Link | packet from {} with foreign source dropped", node(peer));
            return;
        }
        match tun.send(body).await {
            Ok(_) => self.metrics.peer(&peer).ip_rx.add(body.len()),
            Err(e) => log::warn!("TUN | write error: {e}"),
        }
    }

    // ---- mesh (PLAN §6) ----

    /// Whether we relay for others: the relay role in our certificate.
    fn is_relay(&self) -> bool {
        self.cert.read().body.roles.has(crate::group::Roles::RELAY)
    }

    /// Our direct links for the LSA: neighbours with a live session, cost = RTT in ms.
    fn lsa_neighbors(&self) -> Vec<(NodeId, u32)> {
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
        let neighbors = self.lsa_neighbors();
        let ids: Vec<NodeId> = neighbors.iter().map(|(n, _)| *n).collect();
        let due = {
            // changed links are announced at once, but not more often than LSA_MIN_SEND
            let (last, at, _) = &*self.my_lsa.lock();
            at.is_none_or(|t| t.elapsed() >= LSA_REFRESH || (*last != ids && t.elapsed() >= LSA_MIN_SEND))
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
        self.exit_tick();
    }

    // ---- diagnostics (dvpn status / neighbors / routes / path) ----

    /// Peers with a direct session.
    pub fn direct_links(&self) -> Vec<DirectLink> {
        self.storage
            .others()
            .into_iter()
            .filter_map(|p| {
                let s = self.links.current(&p)?;
                Some(DirectLink {
                    peer: p,
                    endpoint: self.storage.endpoint(&p),
                    rtt_ms: self.storage.rtt_ms(&p),
                    alive: self.link_alive(&p),
                    age: s.age(),
                })
            })
            .collect()
    }

    /// Mesh routes: (destination, first hop, cost).
    pub fn mesh_routes(&self) -> Vec<(NodeId, NodeId, u32)> {
        let mut v: Vec<_> = self.routes.load().next.iter().map(|(d, (f, c))| (*d, *f, *c)).collect();
        v.sort_by_key(|(d, _, c)| (*c, *d));
        v
    }

    /// The hops to `dst` as the mesh would take them: every hop's choice recomputed from the
    /// LSDB (without its hysteresis). `None` if there is no route.
    pub fn path(&self, dst: &NodeId) -> Option<Vec<NodeId>> {
        if self.link_alive(dst) {
            return Some(vec![*dst]);
        }
        let lsdb = self.lsdb.lock();
        let certs = self.peer_certs.lock();
        let relay = |n: &NodeId| certs.get(n).is_some_and(|c| c.body.roles.has(crate::group::Roles::RELAY));
        let mut hops = vec![self.next_hop(dst)?];
        while hops.last() != Some(dst) && hops.len() < usize::from(MAX_HOPS) {
            let at = *hops.last().unwrap();
            let t = RouteTable::compute(at, &lsdb, &relay, &RouteTable::default());
            hops.push(t.next_hop(dst)?);
        }
        Some(hops)
    }

    /// The gateways in use (IPv4, IPv6) and whether the kill switch is on.
    pub fn exit_state(&self) -> (Option<NodeId>, Option<NodeId>, bool) {
        let k = *self.kill.lock();
        (self.exit4.lock().current, self.exit6.lock().current, k.0 || k.1)
    }

    /// Our certificate as now in use.
    pub fn own_cert(&self) -> Cert {
        self.cert.read().clone()
    }

    /// A gateway from `[exit]`: a member name or a node key.
    fn resolve_member(&self, s: &str) -> Option<NodeId> {
        if let Ok(k) = s.parse::<NodeId>() {
            return Some(k);
        }
        self.peer_certs.lock().values().find(|c| c.body.name == s).map(|c| c.body.node)
    }

    /// Follows `[exit]` changes in the config, picks the gateways (first alive by priority, see
    /// `exit.rs`) and moves the internet routes when they change.
    fn exit_tick(&self) {
        let path = &self.group.config_path;
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let mut config_changed = false;
        let exits = {
            let mut e = self.exits.lock();
            if mtime != e.1 {
                e.1 = mtime;
                match crate::config::read_exits(path) {
                    Ok(new) if new != e.0 => {
                        log::info!("Exit | gateways from config: IPv4 {:?}, IPv6 {:?}", new.v4, new.v6);
                        e.0 = new;
                        config_changed = true;
                    }
                    Ok(_) => {}
                    Err(err) => log::warn!("Exit | [exit] in {}: {err:#}", path.display()),
                }
            }
            e.0.clone()
        };
        let me = self.storage.self_id();
        let resolve = |l: &[String]| -> Vec<NodeId> {
            l.iter().filter_map(|s| self.resolve_member(s)).filter(|g| *g != me).collect()
        };
        let (p4, p6) = (resolve(&exits.v4), resolve(&exits.v6));
        let now = Instant::now();
        let alive = |g: &NodeId| self.next_hop(g).is_some();
        // `[exit] dns` may have changed: the plan forwards names accordingly
        let mut changed = config_changed;
        for (chooser, prio, fam) in [(&self.exit4, &p4, "IPv4"), (&self.exit6, &p6, "IPv6")] {
            let mut ch = chooser.lock();
            let old = ch.current;
            let new = ch.choose(prio, alive, now);
            if new != old {
                changed = true;
                match new {
                    Some(g) => log::info!("Exit | {fam} via {}", node(g)),
                    None if !prio.is_empty() || old.is_some() => {
                        log::warn!("Exit | {fam}: no gateway alive, internet goes direct")
                    }
                    None => {}
                }
            }
        }
        let kill = (
            !p4.is_empty() && exits.kill_switch() && self.exit4.lock().current.is_none(),
            !p6.is_empty() && exits.kill_switch() && self.exit6.lock().current.is_none(),
        );
        {
            let mut k = self.kill.lock();
            if *k != kill {
                if kill.0 || kill.1 {
                    log::warn!("Exit | kill switch on: no gateway alive, internet blocked");
                } else if k.0 || k.1 {
                    log::info!("Exit | kill switch off");
                }
                *k = kill;
                changed = true;
            }
        }
        if changed {
            self.replan();
        }
    }

    async fn handle_routing(&self, peer: NodeId, body: &[u8]) {
        if self.scores.lock().banned(&peer) {
            return;
        }
        let Some(msg) = RoutingMsg::decode(body) else {
            return self.penalize(peer, 10, "routing");
        };
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
                let mut bad = 0;
                let new: Vec<Lsa> = {
                    let mut db = self.lsdb.lock();
                    let mut new = Vec::new();
                    for l in lsas {
                        // our own LSA comes back from neighbours: ignore older copies of it
                        if l.open().is_some_and(|b| b.origin == me) {
                            continue;
                        }
                        match db.insert_checked(l.clone(), &revoked) {
                            Insert::New => new.push(l),
                            Insert::Known => {}
                            Insert::Invalid => bad += 5,
                            Insert::TooSoon => bad += 1,
                        }
                    }
                    new
                };
                self.penalize(peer, bad, "routing");
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
    /// `code`: 0 the hop limit ran out, 1 no way on from here.
    async fn send_report(&self, src: ShortId, probe: u16, code: u8) {
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
        b.push(code);
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
        let kind = if body[42] == 1 { packet::IcmpError::HostUnreachable } else { packet::IcmpError::TimeExceeded };
        if let Some(icmp) = packet::icmp_error(kind, addr, &quoted) {
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
            self.metrics.dropped(crate::metrics::Drop::NotRelay);
            log::debug!("Mesh | FORWARD from {} dropped: not a relay", node(from));
            return;
        }
        let hops = hops.saturating_add(1);
        if hops >= limit {
            self.metrics.dropped(crate::metrics::Drop::HopLimit);
            log::debug!("Mesh | FORWARD from {} dropped: hop limit", node(from));
            let probe = u16::from_le_bytes([body[2], body[3]]);
            if probe != 0 {
                self.send_report(src, probe, 0).await;
            }
            return;
        }
        let routes = self.routes.load();
        let probe = u16::from_le_bytes([body[2], body[3]]);
        let Some(next) = routes.resolve(&dst).and_then(|d| self.next_hop(&d)) else {
            // no way on: a traceroute probe learns it (!H), other packets are just dropped
            self.metrics.dropped(crate::metrics::Drop::NoWayOn);
            if probe != 0 {
                self.send_report(src, probe, 1).await;
            }
            return;
        };
        if next == from {
            return; // routes not converged yet: do not bounce
        }
        let hdr = [limit, hops, body[2], body[3]];
        if self.send_forward(next, hdr, dst, src, inner).await {
            self.metrics.relayed.add(inner.len());
        }
    }

    /// An end-to-end packet that reached us after `hops` relays.
    async fn handle_e2e(&self, from: NodeId, inner: &[u8], hops: u8) {
        let mut packet = inner.to_vec();
        match self.e2e.receive(&mut packet) {
            None => {}
            Some(Received::Handshake { peer, cert, reply }) => {
                self.metrics.handshake();
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
                    KIND_CONTROL if body.len() >= CONTROL_LEN - 1 => {
                        let echo_ts = u64::from_le_bytes(body[1..9].try_into().unwrap());
                        match body[0] {
                            CONTROL_PING => {
                                self.send_e2e(peer, KIND_CONTROL, &Self::control(CONTROL_PONG, echo_ts), MAX_HOPS, 0)
                                    .await;
                            }
                            CONTROL_PONG => {
                                self.ping_answered(echo_ts);
                            }
                            _ => {}
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

    /// An ICMP error about `ip` (a packet from the TUN) back into the TUN, from its destination
    /// address (our own address would be dropped as a martian source).
    async fn icmp_back(&self, kind: packet::IcmpError, ip: &[u8]) {
        self.icmp_from(kind, ip, None).await;
    }

    /// Like `icmp_back`, from `from` if given.
    async fn icmp_from(&self, kind: packet::IcmpError, ip: &[u8], from: Option<IpAddr>) {
        let (Some(tun), Some(info)) = (&self.tun, packet::parse(ip)) else { return };
        if let Some(icmp) = packet::icmp_error(kind, from.unwrap_or(info.dst), &packet::quote(ip)) {
            let _ = tun.send(&icmp).await;
        }
    }

    /// A member's address in the group: its IPv4 from the certificate, or its ULA.
    fn overlay_addr(&self, n: &NodeId, v6: bool) -> Option<IpAddr> {
        if v6 {
            Some(IpAddr::V6(crate::ckr::ula_addr(&self.group.id, n)))
        } else {
            self.peer_certs.lock().get(n).and_then(|c| c.body.ipv4()).map(IpAddr::V4)
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
            if dst == IpAddr::V4(crate::dns::MDNS_V4) || dst == IpAddr::V6(crate::dns::MDNS_V6) {
                // names of members as <name>.local, answered right here
                if let Some(r) = self.mdns_reply(&buf[OFF..OFF + n]) {
                    let _ = tun.send(&r).await;
                }
                continue;
            }
            // Any source: our own address, a LAN host behind us (site-to-site), or the internet
            // if we are an exit; the receiver checks it by the reverse path.
            let table = self.ckr.load();
            let peer = match table.target(dst) {
                Some(crate::ckr::Target::Node(p)) => p,
                Some(crate::ckr::Target::Blackhole) => {
                    // kill switch: tell the application at once instead of a silent timeout
                    self.metrics.dropped(crate::metrics::Drop::KillSwitch);
                    self.icmp_back(packet::IcmpError::Prohibited, &buf[OFF..OFF + n]).await;
                    continue;
                }
                _ => {
                    self.metrics.dropped(crate::metrics::Drop::NoRoute);
                    log::trace!("TUN | no route to {dst}");
                    continue;
                }
            };
            let direct = self.links.current(&peer).is_some();
            let mtu = if direct { DIRECT_MTU } else { RELAY_MTU };
            if n > mtu && packet::dont_fragment(&buf[OFF..OFF + n]) {
                // does not fit the path: the sender lowers its packet size (path MTU discovery);
                // through relays the path narrows at the first one, so the error comes from it
                let ip = buf[OFF..OFF + n].to_vec();
                let relay = (!direct).then(|| self.routes.load().next_hop(&peer)).flatten();
                let from = relay.and_then(|r| self.overlay_addr(&r, dst.is_ipv6()));
                self.metrics.dropped(crate::metrics::Drop::TooBig);
                self.icmp_from(packet::IcmpError::TooBig(mtu as u16), &ip, from).await;
                continue;
            }
            let (Some(session), Some(route)) = (self.links.current(&peer), self.storage.route_by_id(&peer)) else {
                // no direct session: through the mesh if there is a route (link_loop keeps
                // trying the direct path meanwhile), else first contact
                let ip = &buf[OFF..OFF + n];
                // TTL into the hop limit (PLAN §6.4): small TTLs are traceroute probes
                let (limit, probe) = if ttl <= MAX_HOPS { (ttl.max(1), self.new_probe(ip)) } else { (MAX_HOPS, 0) };
                if self.send_e2e(peer, KIND_IP, ip, limit, probe).await {
                    self.metrics.peer(&peer).ip_tx.add(n);
                } else if self.routes.load().next_hop(&peer).is_none() {
                    let nothing_to_try = self.storage.route_by_id(&peer).is_none()
                        && self.candidates.lock().get(&peer).is_none_or(|c| c.is_empty());
                    if nothing_to_try {
                        // no address, no relay: unreachable for now, say so at once
                        self.metrics.dropped(crate::metrics::Drop::Unreachable);
                        let ip = buf[OFF..OFF + n].to_vec();
                        self.icmp_back(packet::IcmpError::HostUnreachable, &ip).await;
                    } else {
                        self.metrics.dropped(crate::metrics::Drop::NoSession);
                        self.handshake(peer, PUNCH_INTERVAL).await;
                    }
                } else {
                    // a route through relays, the end-to-end session is being set up
                    self.metrics.dropped(crate::metrics::Drop::NoSession);
                }
                continue;
            };
            buf[DATA_HDR] = KIND_IP;
            if let Some(len) = session.seal(&mut buf, n + 1) {
                self.transport.send_to(&buf[..len], route.endpoint).await;
                let c = self.metrics.peer(&peer);
                c.ip_tx.add(n);
                c.wire_tx.add(len);
            }
        }
        log::info!("TUN | Thread receiver - stopped");
    }

    pub async fn shutdown(&self) {
        tokio::task::block_in_place(|| self.system.lock().clear());
        for c in &self.clients {
            if let Some(p) = c.close() {
                self.transport.send_to(&p, c.addr()).await;
            }
        }
    }
}
