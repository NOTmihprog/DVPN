//! Mesh routing (PLAN §6): link-state, like OSPF / EasyTier. Every node announces its direct
//! links (neighbours with a live session, cost = RTT) in an LSA signed with its node key; LSAs
//! flood between neighbours, and every node computes shortest paths with Dijkstra, remembering
//! the first hop. Packets to a node without a direct link go to that first hop in a `FORWARD`.
//!
//! - An edge counts only if both ends announce it (nobody can draw an edge to itself).
//! - Only nodes with the `relay` role carry transit traffic.
//! - A new path replaces the current one only if it is better by 10 % and 5 ms (no flapping).
//! - LSAs live `LSA_TTL` after they were received; their `seq` (milliseconds) orders them.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::group::GroupId;
use crate::identity::{Identity, NodeId};

/// An LSA is dropped this long after it was received unless a newer one came.
pub const LSA_TTL: Duration = Duration::from_secs(120);
/// Nodes announce themselves this often (and when their links change).
pub const LSA_REFRESH: Duration = Duration::from_secs(30);
/// LSAs of one origin are accepted at most this often (a member flooding LSAs with an ever
/// growing seq gets nowhere, PLAN §6.3a); nodes send their own at most every `LSA_MIN_SEND`.
pub const LSA_MIN_INTERVAL: Duration = Duration::from_secs(2);
pub const LSA_MIN_SEND: Duration = Duration::from_secs(4);
/// At most this many neighbours per LSA (the cheapest), so it fits a datagram.
pub const MAX_LSA_NEIGHBORS: usize = 28;
const LSA_CTX: &[u8] = b"dvpn/4 lsa\0";
/// Hysteresis (PLAN §6.2): a new first hop must be at least this much better.
const SWITCH_RATIO: f64 = 0.9;
const SWITCH_MIN_MS: u32 = 5;

/// The first 8 bytes of a node key: how `FORWARD` names nodes (unambiguous within a group).
pub type ShortId = [u8; 8];

pub fn short_id(n: &NodeId) -> ShortId {
    n.as_bytes()[..8].try_into().unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LsaBody {
    pub origin: NodeId,
    pub group: GroupId,
    /// Milliseconds; newer LSAs of the same origin have a larger seq.
    pub seq: u64,
    /// Neighbours with a live direct session, and the cost (ms) to each.
    pub neighbors: Vec<(NodeId, u32)>,
}

/// A signed LSA as it travels: the signature covers the exact payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsa {
    pub payload: Vec<u8>,
    pub sig: Signature,
}

impl Lsa {
    pub fn sign(identity: &Identity, body: &LsaBody) -> Self {
        let payload = postcard::to_stdvec(body).expect("lsa serializes");
        Lsa { sig: identity.sign(&[LSA_CTX, &payload].concat()), payload }
    }

    pub fn open(&self) -> Option<LsaBody> {
        if self.payload.len() > 1400 {
            return None;
        }
        let b: LsaBody = postcard::from_bytes(&self.payload).ok()?;
        b.origin.verifying_key().verify_strict(&[LSA_CTX, &self.payload].concat(), &self.sig).ok()?;
        (b.neighbors.len() <= MAX_LSA_NEIGHBORS).then_some(b)
    }
}

/// Link-state database: the newest LSA of every origin.
pub struct Lsdb {
    group: GroupId,
    entries: HashMap<NodeId, (LsaBody, Lsa, Instant)>,
    pub(crate) min_interval: Duration,
}

/// What became of an LSA offered to the database.
#[derive(Debug, PartialEq, Eq)]
pub enum Insert {
    New,
    /// The same or an older one is known: nothing to do.
    Known,
    /// Bad signature, another group, or a revoked origin.
    Invalid,
    /// Newer, but its origin sent one less than `LSA_MIN_INTERVAL` ago.
    TooSoon,
}

impl Lsdb {
    pub fn new(group: GroupId) -> Self {
        Lsdb { group, entries: HashMap::new(), min_interval: LSA_MIN_INTERVAL }
    }

    /// Stores a verified LSA if it is newer and not too soon after the last one of its origin;
    /// `revoked` origins are refused.
    pub fn insert_checked(&mut self, lsa: Lsa, revoked: &HashSet<NodeId>) -> Insert {
        let Some(b) = lsa.open() else { return Insert::Invalid };
        if b.group != self.group || revoked.contains(&b.origin) {
            return Insert::Invalid;
        }
        if let Some((old, _, until)) = self.entries.get(&b.origin) {
            if old.seq >= b.seq {
                return Insert::Known;
            }
            let received = *until - LSA_TTL;
            if received.elapsed() < self.min_interval {
                return Insert::TooSoon;
            }
        }
        self.entries.insert(b.origin, (b, lsa, Instant::now() + LSA_TTL));
        Insert::New
    }

    /// Like `insert_checked`; whether it changed the database (then it is flooded on).
    pub fn insert(&mut self, lsa: Lsa, revoked: &HashSet<NodeId>) -> bool {
        self.insert_checked(lsa, revoked) == Insert::New
    }

    /// Drops expired LSAs and those of `revoked` origins; returns whether anything went.
    pub fn expire(&mut self, revoked: &HashSet<NodeId>) -> bool {
        let n = self.entries.len();
        let now = Instant::now();
        self.entries.retain(|o, (_, _, until)| *until > now && !revoked.contains(o));
        n != self.entries.len()
    }

    pub fn summary(&self) -> Vec<(NodeId, u64)> {
        self.entries.iter().map(|(o, (b, _, _))| (*o, b.seq)).collect()
    }

    /// The LSAs the other side lacks or has older, and the origins it has newer.
    pub fn diff(&self, theirs: &[(NodeId, u64)]) -> (Vec<Lsa>, Vec<NodeId>) {
        let theirs: HashMap<NodeId, u64> = theirs.iter().copied().collect();
        let give = self
            .entries
            .iter()
            .filter(|(o, (b, _, _))| theirs.get(o).is_none_or(|s| *s < b.seq))
            .map(|(_, (_, l, _))| l.clone())
            .collect();
        let want = theirs
            .iter()
            .filter(|(o, s)| self.entries.get(o).is_none_or(|(b, _, _)| b.seq < **s))
            .map(|(o, _)| *o)
            .collect();
        (give, want)
    }

    pub fn get(&self, origins: &[NodeId]) -> Vec<Lsa> {
        origins.iter().filter_map(|o| self.entries.get(o)).map(|(_, l, _)| l.clone()).collect()
    }

    pub fn seq(&self, origin: &NodeId) -> Option<u64> {
        self.entries.get(origin).map(|(b, _, _)| b.seq)
    }

    pub fn bodies(&self) -> impl Iterator<Item = &LsaBody> {
        self.entries.values().map(|(b, _, _)| b)
    }
}

/// Routing messages between neighbours (kind ROUTING).
#[derive(Debug, Serialize, Deserialize)]
pub enum RoutingMsg {
    Summary(Vec<(NodeId, u64)>),
    Want(Vec<NodeId>),
    Lsas(Vec<Lsa>),
}

impl RoutingMsg {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("routing message serializes")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// LSAs packed into datagram-sized messages.
    pub fn lsas(lsas: Vec<Lsa>) -> Vec<RoutingMsg> {
        let mut out = Vec::new();
        let (mut cur, mut size) = (Vec::new(), 0);
        for l in lsas {
            let n = l.payload.len() + 72;
            if !cur.is_empty() && size + n > 1100 {
                out.push(RoutingMsg::Lsas(std::mem::take(&mut cur)));
                size = 0;
            }
            size += n;
            cur.push(l);
        }
        if !cur.is_empty() {
            out.push(RoutingMsg::Lsas(cur));
        }
        out
    }

    pub fn summaries(lsdb: &Lsdb) -> Vec<RoutingMsg> {
        let s = lsdb.summary();
        if s.is_empty() {
            return vec![RoutingMsg::Summary(s)];
        }
        s.chunks(30).map(|c| RoutingMsg::Summary(c.to_vec())).collect()
    }
}

/// Misbehaving neighbours (gossipsub v1.1 peer scoring, PLAN §6.3a): each one's bad routing and
/// record messages are counted in a window; past the limit its ROUTING and STATE messages are
/// ignored for a while. Weights: undecodable 10, invalid (signature, group, revoked) 5, too
/// frequent 1.
#[derive(Default)]
pub struct Scores {
    peers: HashMap<NodeId, (Instant, u32, Option<Instant>)>,
}

pub const SCORE_WINDOW: Duration = Duration::from_secs(60);
pub const SCORE_LIMIT: u32 = 50;
pub const SCORE_BAN: Duration = Duration::from_secs(300);

impl Scores {
    /// Whether `peer` is being ignored now.
    pub fn banned(&mut self, peer: &NodeId) -> bool {
        match self.peers.get_mut(peer) {
            Some((_, _, Some(until))) if *until > Instant::now() => true,
            Some(e @ (_, _, Some(_))) => {
                *e = (Instant::now(), 0, None);
                false
            }
            _ => false,
        }
    }

    /// Adds `points` against `peer`; returns true when this got it banned.
    pub fn penalize(&mut self, peer: NodeId, points: u32) -> bool {
        if points == 0 {
            return false;
        }
        let now = Instant::now();
        let e = self.peers.entry(peer).or_insert((now, 0, None));
        if e.2.is_some() {
            return false;
        }
        if now.duration_since(e.0) >= SCORE_WINDOW {
            *e = (now, 0, None);
        }
        e.1 += points;
        if e.1 >= SCORE_LIMIT {
            e.2 = Some(now + SCORE_BAN);
            return true;
        }
        false
    }
}

/// The undirected graph of confirmed edges: (u, v) with cost max(u's, v's view).
fn graph(lsdb: &Lsdb) -> HashMap<NodeId, Vec<(NodeId, u32)>> {
    let said: HashMap<NodeId, HashMap<NodeId, u32>> =
        lsdb.bodies().map(|b| (b.origin, b.neighbors.iter().copied().collect())).collect();
    let mut g: HashMap<NodeId, Vec<(NodeId, u32)>> = HashMap::new();
    for (u, ns) in &said {
        for (v, c) in ns {
            if u == v {
                continue;
            }
            if let Some(back) = said.get(v).and_then(|m| m.get(u)) {
                g.entry(*u).or_default().push((*v, (*c).max(*back).max(1)));
            }
        }
    }
    g
}

/// Shortest distances from `from` (excluding `avoid`); only `transit` nodes are passed through.
fn dijkstra(
    g: &HashMap<NodeId, Vec<(NodeId, u32)>>,
    from: NodeId,
    avoid: NodeId,
    transit: &dyn Fn(&NodeId) -> bool,
) -> HashMap<NodeId, u32> {
    let mut dist: HashMap<NodeId, u32> = HashMap::from([(from, 0)]);
    let mut heap = BinaryHeap::from([std::cmp::Reverse((0u32, from))]);
    while let Some(std::cmp::Reverse((d, u))) = heap.pop() {
        if dist.get(&u).is_some_and(|best| *best < d) {
            continue;
        }
        if u != from && !transit(&u) {
            continue; // reachable, but no further through it
        }
        for (v, c) in g.get(&u).into_iter().flatten() {
            if *v == avoid {
                continue;
            }
            let nd = d.saturating_add(*c);
            if dist.get(v).is_none_or(|old| nd < *old) {
                dist.insert(*v, nd);
                heap.push(std::cmp::Reverse((nd, *v)));
            }
        }
    }
    dist
}

/// Where to send packets for each reachable node.
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    /// dst -> (first hop, path cost)
    pub next: HashMap<NodeId, (NodeId, u32)>,
    by_short: HashMap<ShortId, NodeId>,
}

impl RouteTable {
    /// Computes routes from `me`. `transit` says which nodes may relay (the relay role);
    /// `prev` gives the current first hops for hysteresis.
    pub fn compute(me: NodeId, lsdb: &Lsdb, transit: &dyn Fn(&NodeId) -> bool, prev: &RouteTable) -> Self {
        let g = graph(lsdb);
        // per first hop: cost to every destination through it
        let mut via: HashMap<NodeId, HashMap<NodeId, u32>> = HashMap::new();
        for (n, c) in g.get(&me).into_iter().flatten() {
            // the first hop is itself a transit node, unless it is the destination
            let d = if transit(n) { dijkstra(&g, *n, me, transit) } else { HashMap::from([(*n, 0)]) };
            via.insert(*n, d.into_iter().map(|(dst, x)| (dst, x.saturating_add(*c))).collect());
        }
        let mut next: HashMap<NodeId, (NodeId, u32)> = HashMap::new();
        for (fh, costs) in &via {
            for (dst, cost) in costs {
                if *dst == me {
                    continue;
                }
                let better = next.get(dst).is_none_or(|(bf, bc)| (*cost, *fh) < (*bc, *bf));
                if better {
                    next.insert(*dst, (*fh, *cost));
                }
            }
        }
        // hysteresis: keep the old first hop unless the new one is clearly better
        for (dst, (fh, cost)) in next.iter_mut() {
            let Some((old_fh, _)) = prev.next.get(dst) else { continue };
            if old_fh == fh {
                continue;
            }
            if let Some(old_cost) = via.get(old_fh).and_then(|c| c.get(dst)) {
                let clearly = (*cost as f64) <= (*old_cost as f64) * SWITCH_RATIO && old_cost - *cost >= SWITCH_MIN_MS;
                if !clearly {
                    (*fh, *cost) = (*old_fh, *old_cost);
                }
            }
        }
        let mut by_short = HashMap::new();
        for o in lsdb.bodies().map(|b| b.origin).chain(next.keys().copied()) {
            by_short.insert(short_id(&o), o);
        }
        RouteTable { next, by_short }
    }

    pub fn next_hop(&self, dst: &NodeId) -> Option<NodeId> {
        self.next.get(dst).map(|(f, _)| *f)
    }

    /// The node a `FORWARD` short id names, among the nodes we know routes for.
    pub fn resolve(&self, s: &ShortId) -> Option<NodeId> {
        self.by_short.get(s).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ids(n: usize) -> Vec<Identity> {
        (0..n).map(|i| Identity::from_seed(&[i as u8 + 1; 32])).collect()
    }

    fn group() -> GroupId {
        Identity::from_seed(&[99; 32]).id()
    }

    /// An LSDB from undirected edges (a, b, cost), both ends announcing them.
    fn lsdb(nodes: &[Identity], edges: &[(usize, usize, u32)]) -> Lsdb {
        let mut db = Lsdb::new(group());
        for (i, n) in nodes.iter().enumerate() {
            let neighbors: Vec<(NodeId, u32)> = edges
                .iter()
                .filter_map(|&(a, b, c)| match (a == i, b == i) {
                    (true, _) => Some((nodes[b].id(), c)),
                    (_, true) => Some((nodes[a].id(), c)),
                    _ => None,
                })
                .collect();
            let body = LsaBody { origin: n.id(), group: group(), seq: 1, neighbors };
            assert!(db.insert(Lsa::sign(n, &body), &HashSet::new()));
        }
        db
    }

    #[test]
    fn lsa_rate_limit_and_scores() {
        let n = ids(2);
        let mut db = Lsdb::new(group());
        let lsa = |seq| Lsa::sign(&n[0], &LsaBody { origin: n[0].id(), group: group(), seq, neighbors: vec![] });
        assert_eq!(db.insert_checked(lsa(1), &HashSet::new()), Insert::New);
        assert_eq!(db.insert_checked(lsa(2), &HashSet::new()), Insert::TooSoon, "newer, but right away");
        assert_eq!(db.insert_checked(lsa(1), &HashSet::new()), Insert::Known);
        let forged = Lsa { sig: lsa(3).sig, payload: lsa(4).payload };
        assert_eq!(db.insert_checked(forged, &HashSet::new()), Insert::Invalid);

        let mut s = Scores::default();
        let p = n[1].id();
        assert!(!s.banned(&p));
        for _ in 0..9 {
            assert!(!s.penalize(p, 5));
        }
        assert!(s.penalize(p, 5), "the 10th invalid message bans");
        assert!(s.banned(&p));
        assert!(!s.penalize(p, 5), "no double counting while banned");
    }

    #[test]
    fn lsa_signature_and_ordering() {
        let n = ids(2);
        let body = LsaBody { origin: n[0].id(), group: group(), seq: 5, neighbors: vec![(n[1].id(), 3)] };
        let lsa = Lsa::sign(&n[0], &body);
        assert_eq!(lsa.open(), Some(body.clone()));
        let forged = Lsa::sign(&n[1], &body);
        assert_eq!(forged.open(), None, "signed by somebody else");
        let mut db = Lsdb::new(group());
        db.min_interval = Duration::ZERO;
        assert!(db.insert(lsa.clone(), &HashSet::new()));
        assert!(!db.insert(lsa, &HashSet::new()), "same seq");
        let older = LsaBody { seq: 4, ..body.clone() };
        assert!(!db.insert(Lsa::sign(&n[0], &older), &HashSet::new()));
        let other_group = LsaBody { seq: 9, group: n[1].id(), ..body.clone() };
        assert!(!db.insert(Lsa::sign(&n[0], &other_group), &HashSet::new()));
        let newer = LsaBody { seq: 6, ..body };
        assert!(!db.insert(Lsa::sign(&n[0], &newer), &HashSet::from([n[0].id()])), "revoked");
        assert!(db.insert(Lsa::sign(&n[0], &newer), &HashSet::new()));
    }

    #[test]
    fn relay_path_and_transit_role() {
        // a - b - c, a and c do not see each other
        let n = ids(3);
        let db = lsdb(&n, &[(0, 1, 10), (1, 2, 10)]);
        let all = |_: &NodeId| true;
        let t = RouteTable::compute(n[0].id(), &db, &all, &RouteTable::default());
        assert_eq!(t.next_hop(&n[2].id()), Some(n[1].id()));
        assert_eq!(t.next[&n[2].id()].1, 20);
        assert_eq!(t.resolve(&short_id(&n[2].id())), Some(n[2].id()));
        // b may not relay: c unreachable, b itself still is
        let b = n[1].id();
        let not_b = move |x: &NodeId| *x != b;
        let t = RouteTable::compute(n[0].id(), &db, &not_b, &RouteTable::default());
        assert_eq!(t.next_hop(&n[2].id()), None);
        assert_eq!(t.next_hop(&b), Some(b));
    }

    #[test]
    fn one_sided_edges_ignored() {
        let n = ids(3);
        let mut db = lsdb(&n, &[(0, 1, 10)]);
        // c claims an edge to a that a does not confirm
        let body = LsaBody { origin: n[2].id(), group: group(), seq: 2, neighbors: vec![(n[0].id(), 1)] };
        db.insert(Lsa::sign(&n[2], &body), &HashSet::new());
        let t = RouteTable::compute(n[1].id(), &db, &|_| true, &RouteTable::default());
        assert_eq!(t.next_hop(&n[2].id()), None);
    }

    #[test]
    fn hysteresis_and_switch() {
        // a has two relays to d: b (cost 10+10) and c (10+12)
        let n = ids(4);
        let db = lsdb(&n, &[(0, 1, 10), (1, 3, 10), (0, 2, 10), (2, 3, 12)]);
        let all = |_: &NodeId| true;
        let t1 = RouteTable::compute(n[0].id(), &db, &all, &RouteTable::default());
        assert_eq!(t1.next_hop(&n[3].id()), Some(n[1].id()));
        // c gets slightly better (21 vs 20... now 10+9=19 vs 20): not enough to switch
        let db2 = lsdb(&n, &[(0, 1, 10), (1, 3, 10), (0, 2, 10), (2, 3, 9)]);
        let t2 = RouteTable::compute(n[0].id(), &db2, &all, &t1);
        assert_eq!(t2.next_hop(&n[3].id()), Some(n[1].id()), "within hysteresis");
        // c gets much better: switch
        let db3 = lsdb(&n, &[(0, 1, 10), (1, 3, 10), (0, 2, 5), (2, 3, 5)]);
        let t3 = RouteTable::compute(n[0].id(), &db3, &all, &t2);
        assert_eq!(t3.next_hop(&n[3].id()), Some(n[2].id()));
        // b disappears: c at once, whatever the hysteresis
        let db4 = lsdb(&n, &[(0, 2, 10), (2, 3, 12)]);
        let t4 = RouteTable::compute(n[0].id(), &db4, &all, &t1);
        assert_eq!(t4.next_hop(&n[3].id()), Some(n[2].id()));
    }

    #[test]
    fn sync_by_summaries() {
        let n = ids(3);
        let full = lsdb(&n, &[(0, 1, 1), (1, 2, 1)]);
        let mut empty = Lsdb::new(group());
        let (give, want) = full.diff(&empty.summary());
        assert_eq!((give.len(), want.len()), (3, 0));
        for m in RoutingMsg::lsas(give) {
            let RoutingMsg::Lsas(ls) = RoutingMsg::decode(&m.encode()).unwrap() else { panic!() };
            for l in ls {
                empty.insert(l, &HashSet::new());
            }
        }
        assert_eq!(empty.diff(&full.summary()), (vec![], vec![]));
    }

    proptest! {
        /// Following first hops from any node always reaches the destination, in as many
        /// steps as there are nodes at most: no loops, whatever the graph.
        #[test]
        fn next_hops_never_loop(
            edges in proptest::collection::vec((0usize..7, 0usize..7, 1u32..50), 0..20),
            relays in proptest::collection::vec(any::<bool>(), 7),
        ) {
            let n = ids(7);
            let edges: Vec<_> = edges.into_iter().filter(|(a, b, _)| a != b).collect();
            let db = lsdb(&n, &edges);
            let relay_set: HashSet<NodeId> = n.iter().zip(&relays).filter(|(_, r)| **r).map(|(i, _)| i.id()).collect();
            let transit = |x: &NodeId| relay_set.contains(x);
            let tables: HashMap<NodeId, RouteTable> = n
                .iter()
                .map(|i| (i.id(), RouteTable::compute(i.id(), &db, &transit, &RouteTable::default())))
                .collect();
            for src in &n {
                for dst in &n {
                    let (src, dst) = (src.id(), dst.id());
                    if src == dst || tables[&src].next_hop(&dst).is_none() {
                        continue;
                    }
                    let mut at = src;
                    let mut steps = 0;
                    while at != dst {
                        let nh = tables[&at].next_hop(&dst);
                        prop_assert!(nh.is_some(), "route breaks at a hop");
                        at = nh.unwrap();
                        steps += 1;
                        prop_assert!(steps <= 7, "loop");
                        if at != dst {
                            prop_assert!(relay_set.contains(&at), "transit through a non-relay");
                        }
                    }
                }
            }
        }
    }
}
