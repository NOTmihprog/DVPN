//! Counters (PLAN §14a): what the node carries and what it drops, read through the API
//! (`get metrics`, `dvpn metrics`, the traffic columns of `dvpn neighbors`).
//!
//! - per member: IP packets and bytes exchanged with it, directly or end to end through relays;
//! - per neighbour: data packets and bytes of the direct session with it, as the network sees
//!   them (everything: IP, records, routing, keepalives, packets relayed through it; handshakes
//!   are not counted);
//! - node-wide: packets relayed for others, sessions established, dropped packets by reason.
//!
//! Counters are atomics, counted from the start of the process; a member's counters stay while
//! it reconnects.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use parking_lot::RwLock;

use crate::identity::NodeId;

/// Packets and bytes.
#[derive(Default)]
pub struct Pair {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl Pair {
    pub fn add(&self, bytes: usize) {
        self.packets.fetch_add(1, Relaxed);
        self.bytes.fetch_add(bytes as u64, Relaxed);
    }

    /// (packets, bytes)
    pub fn get(&self) -> (u64, u64) {
        (self.packets.load(Relaxed), self.bytes.load(Relaxed))
    }
}

/// Counters of one member.
#[derive(Default)]
pub struct PeerCounters {
    /// IP packets to / from the member (the TUN side), whatever the path.
    pub ip_tx: Pair,
    pub ip_rx: Pair,
    /// Data packets of the direct session with the member (the wire side).
    pub wire_tx: Pair,
    pub wire_rx: Pair,
}

/// Why a packet was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    /// From the TUN: no member has the destination.
    NoRoute,
    /// From the TUN: no session with the member yet (a handshake is under way).
    NoSession,
    /// From the TUN: the member is unreachable (no address, no relay); ICMP sent.
    Unreachable,
    /// From the TUN: larger than the path, DF set; ICMP sent.
    TooBig,
    /// From the TUN: kill switch, no gateway alive; ICMP sent.
    KillSwitch,
    /// From a member: its source address is not its own (reverse path check).
    ForeignSource,
    /// From the network: not a packet of any session (junk before handshakes, probes, replays,
    /// another group).
    Unreadable,
    /// To relay: this node has no relay role.
    NotRelay,
    /// To relay: the hop limit ran out.
    HopLimit,
    /// To relay: no way on to the destination.
    NoWayOn,
    /// From a member: the ACL does not let it reach this node (filtered by the node itself
    /// where there is no nftables).
    Acl,
}

impl Drop {
    pub const ALL: [Drop; 11] = [
        Drop::NoRoute,
        Drop::NoSession,
        Drop::Unreachable,
        Drop::TooBig,
        Drop::KillSwitch,
        Drop::ForeignSource,
        Drop::Unreadable,
        Drop::NotRelay,
        Drop::HopLimit,
        Drop::NoWayOn,
        Drop::Acl,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Drop::NoRoute => "no_route",
            Drop::NoSession => "no_session",
            Drop::Unreachable => "unreachable",
            Drop::TooBig => "too_big",
            Drop::KillSwitch => "kill_switch",
            Drop::ForeignSource => "foreign_source",
            Drop::Unreadable => "unreadable",
            Drop::NotRelay => "not_relay",
            Drop::HopLimit => "hop_limit",
            Drop::NoWayOn => "no_way_on",
            Drop::Acl => "acl",
        }
    }
}

pub struct Metrics {
    started: Instant,
    peers: RwLock<HashMap<NodeId, Arc<PeerCounters>>>,
    /// FORWARD packets passed on for other members (as a relay).
    pub relayed: Pair,
    /// Handshakes completed, as initiator or responder (direct and end to end, rekeys included).
    pub handshakes: AtomicU64,
    drops: [AtomicU64; Drop::ALL.len()],
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            started: Instant::now(),
            peers: RwLock::default(),
            relayed: Pair::default(),
            handshakes: AtomicU64::new(0),
            drops: Default::default(),
        }
    }
}

impl Metrics {
    /// The counters of `peer`, created on first use.
    pub fn peer(&self, peer: &NodeId) -> Arc<PeerCounters> {
        if let Some(c) = self.peers.read().get(peer) {
            return c.clone();
        }
        self.peers.write().entry(*peer).or_default().clone()
    }

    pub fn dropped(&self, why: Drop) {
        self.drops[why as usize].fetch_add(1, Relaxed);
    }

    pub fn drops(&self) -> Vec<(Drop, u64)> {
        Drop::ALL.iter().map(|d| (*d, self.drops[*d as usize].load(Relaxed))).collect()
    }

    pub fn handshake(&self) {
        self.handshakes.fetch_add(1, Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// All members with counters, in key order.
    pub fn peers(&self) -> Vec<(NodeId, Arc<PeerCounters>)> {
        let mut v: Vec<_> = self.peers.read().iter().map(|(k, c)| (*k, c.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    /// Forgets a member (revoked).
    pub fn remove(&self, peer: &NodeId) {
        self.peers.write().remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        let m = Metrics::default();
        let a = crate::identity::Identity::generate().id();
        m.peer(&a).ip_tx.add(100);
        m.peer(&a).ip_tx.add(50);
        m.peer(&a).wire_rx.add(10);
        assert_eq!(m.peer(&a).ip_tx.get(), (2, 150));
        assert_eq!(m.peer(&a).wire_rx.get(), (1, 10));
        m.dropped(Drop::HopLimit);
        m.dropped(Drop::HopLimit);
        m.dropped(Drop::NoRoute);
        let d: HashMap<&str, u64> = m.drops().into_iter().map(|(d, n)| (d.name(), n)).collect();
        assert_eq!((d["hop_limit"], d["no_route"], d["too_big"]), (2, 1, 0));
        assert_eq!(m.peers().len(), 1);
        m.remove(&a);
        assert!(m.peers().is_empty());
        for (i, d) in Drop::ALL.iter().enumerate() {
            assert_eq!(*d as usize, i, "ALL in declaration order");
        }
    }
}
