//! The ACL (`acl.rs`) enforced by the node itself, on packets from the tunnel before they reach
//! the TUN: for systems without nftables (Windows, Android, macOS). The same rules in the same
//! order, first match wins, as `Acl::render` gives nftables:
//!
//! - replies to our own connections always pass (`ct state established,related`): a table of
//!   flows seen going out ([`Flows`]), and ICMP errors;
//! - a source outside the group (the internet through an exit) is not ours to judge;
//! - then the rules whose `to` includes this node, then the default.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use parking_lot::Mutex;

use crate::acl::{Acl, Proto};
use crate::identity::NodeId;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMP6: u8 = 58;

/// What the filter looks at in a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct L4 {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    /// TCP/UDP: ports; ICMP: (identifier, type); otherwise zeros, and for later fragments too.
    sport: u16,
    dport: u16,
}

fn l4(p: &[u8]) -> Option<L4> {
    let info = crate::packet::parse(p)?;
    let (mut proto, mut off, mut first) = match p[0] >> 4 {
        4 => {
            let frag = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
            (p[9], usize::from(p[0] & 0x0f) * 4, frag == 0)
        }
        _ => (p[6], 40, true),
    };
    if p[0] >> 4 == 6 {
        // extension headers: hop-by-hop, routing, destination options, fragment
        for _ in 0..8 {
            match proto {
                0 | 43 | 60 if p.len() >= off + 2 => {
                    proto = p[off];
                    off += (usize::from(p[off + 1]) + 1) * 8;
                }
                44 if p.len() >= off + 8 => {
                    first = u16::from_be_bytes([p[off + 2], p[off + 3]]) >> 3 == 0;
                    proto = p[off];
                    off += 8;
                }
                _ => break,
            }
        }
    }
    let word = |i: usize| p.get(off + i..off + i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let (sport, dport) = match proto {
        TCP | UDP if first => (word(0)?, word(2)?),
        ICMP | ICMP6 if first => (word(4).unwrap_or(0), u16::from(*p.get(off)?)),
        _ => (0, 0),
    };
    Some(L4 { src: info.src, dst: info.dst, proto, sport, dport })
}

fn is_icmp_error(l: &L4) -> bool {
    match l.proto {
        ICMP => matches!(l.dport, 3 | 4 | 11 | 12),
        ICMP6 => matches!(l.dport, 1..=4),
        _ => false,
    }
}

/// A flow as seen going out: (protocol, our address, our port / ICMP id, their address, their port).
type FlowKey = (u8, IpAddr, u16, IpAddr, u16);

/// Flows this node started (packets from the TUN into the tunnel), so that their replies pass.
#[derive(Default)]
pub struct Flows {
    seen: Mutex<HashMap<FlowKey, Instant>>,
}

const MAX_FLOWS: usize = 65536;

fn timeout(proto: u8) -> Duration {
    Duration::from_secs(match proto {
        TCP => 3600,
        ICMP | ICMP6 => 30,
        _ => 180,
    })
}

impl Flows {
    fn key_out(l: &L4) -> Option<FlowKey> {
        match l.proto {
            // only echo requests start something an answer comes back to
            ICMP if l.dport == 8 => Some((ICMP, l.src, l.sport, l.dst, 0)),
            ICMP6 if l.dport == 128 => Some((ICMP6, l.src, l.sport, l.dst, 0)),
            ICMP | ICMP6 => None,
            _ => Some((l.proto, l.src, l.sport, l.dst, l.dport)),
        }
    }

    fn key_in(l: &L4) -> Option<FlowKey> {
        match l.proto {
            ICMP if l.dport == 0 => Some((ICMP, l.dst, l.sport, l.src, 0)),
            ICMP6 if l.dport == 129 => Some((ICMP6, l.dst, l.sport, l.src, 0)),
            ICMP | ICMP6 => None,
            _ => Some((l.proto, l.dst, l.dport, l.src, l.sport)),
        }
    }

    /// A packet leaving through the tunnel.
    pub fn outbound(&self, p: &[u8]) {
        let Some(k) = l4(p).as_ref().and_then(Self::key_out) else { return };
        let now = Instant::now();
        let mut seen = self.seen.lock();
        if seen.len() >= MAX_FLOWS && !seen.contains_key(&k) {
            seen.retain(|k, t| now.duration_since(*t) < timeout(k.0));
            if seen.len() >= MAX_FLOWS {
                return; // full of live flows: new ones are judged by the rules
            }
        }
        seen.insert(k, now);
    }

    fn established(&self, l: &L4) -> bool {
        let Some(k) = Self::key_in(l) else { return false };
        let mut seen = self.seen.lock();
        match seen.get_mut(&k) {
            Some(t) if t.elapsed() < timeout(k.0) => {
                *t = Instant::now();
                true
            }
            _ => false,
        }
    }
}

struct Rule {
    src: Vec<IpNet>,
    proto: Proto,
    ports: Vec<(u16, u16)>,
    allow: bool,
}

impl Rule {
    fn matches(&self, l: &L4) -> bool {
        if !self.src.iter().any(|n| n.contains(&l.src)) {
            return false;
        }
        match self.proto {
            Proto::Any => true,
            Proto::Icmp => l.proto == ICMP || l.proto == ICMP6,
            Proto::Tcp | Proto::Udp => {
                let want = if self.proto == Proto::Tcp { TCP } else { UDP };
                l.proto == want
                    && (self.ports.is_empty() || self.ports.iter().any(|(a, b)| (*a..=*b).contains(&l.dport)))
            }
        }
    }
}

/// The rules for this node, compiled.
pub struct Filter {
    rules: Vec<Rule>,
    default_deny: bool,
    /// Every member's addresses and subnets: other sources are not judged.
    members: Vec<IpNet>,
}

impl Filter {
    /// `None` when nothing restricts traffic to `me` (as `Acl::render`).
    pub fn new(acl: &Acl, me: &NodeId, prefixes: &HashMap<NodeId, Vec<IpNet>>) -> Option<Filter> {
        let mine: Vec<_> = acl.rules.iter().filter(|r| r.to.iter().any(|w| acl.covers(w, me))).collect();
        if mine.iter().all(|r| r.allow) && !acl.default_deny {
            return None;
        }
        let rules = mine
            .into_iter()
            .map(|r| Rule {
                src: prefixes
                    .iter()
                    .filter(|(n, _)| r.from.iter().any(|w| acl.covers(w, n)))
                    .flat_map(|(_, p)| p.iter().copied())
                    .collect(),
                proto: r.proto,
                ports: r.ports.clone(),
                allow: r.allow,
            })
            .collect();
        Some(Filter { rules, default_deny: acl.default_deny, members: prefixes.values().flatten().copied().collect() })
    }

    /// Whether a packet from the tunnel may reach the TUN.
    pub fn allows(&self, flows: &Flows, p: &[u8]) -> bool {
        let Some(l) = l4(p) else { return false };
        if is_icmp_error(&l) || flows.established(&l) || !self.members.iter().any(|n| n.contains(&l.src)) {
            return true;
        }
        match self.rules.iter().find(|r| r.matches(&l)) {
            Some(r) => r.allow,
            None => !self.default_deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> [NodeId; 3] {
        [1u8, 2, 3].map(|i| crate::identity::Identity::from_seed(&[i; 32]).id())
    }

    fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        if proto == ICMP {
            p[20] = dport as u8; // type
            p[24..26].copy_from_slice(&sport.to_be_bytes()); // identifier
        } else {
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&dport.to_be_bytes());
        }
        p
    }

    #[test]
    fn rules_in_order_and_replies() {
        let [me, a, b] = ids();
        let acl = Acl::parse(
            "default = \"deny\"\n[[rule]]\nfrom = [\"*\"]\nto = [\"*\"]\nproto = \"tcp\"\nports = [\"22\", \"80-443\"]\naction = \"allow\"\n[[rule]]\nfrom = [\"b\"]\nto = [\"*\"]\nproto = \"icmp\"\naction = \"allow\"\n",
            &|s| match s {
                "b" => Some(b),
                _ => None,
            },
        )
        .unwrap();
        let prefixes = HashMap::from([
            (me, vec!["10.0.0.1/32".parse().unwrap()]),
            (a, vec!["10.0.0.2/32".parse().unwrap()]),
            (b, vec!["10.0.0.3/32".parse().unwrap(), "192.168.5.0/24".parse().unwrap()]),
        ]);
        let f = Filter::new(&acl, &me, &prefixes).unwrap();
        let flows = Flows::default();
        let (me4, a4, b4) = ([10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]);
        assert!(f.allows(&flows, &v4(a4, me4, TCP, 40000, 22)), "ssh from anybody");
        assert!(f.allows(&flows, &v4(a4, me4, TCP, 40000, 443)), "range");
        assert!(!f.allows(&flows, &v4(a4, me4, TCP, 40000, 3389)), "default deny");
        assert!(!f.allows(&flows, &v4(a4, me4, UDP, 40000, 22)), "tcp only");
        assert!(!f.allows(&flows, &v4(a4, me4, ICMP, 7, 8)), "ping from a: denied");
        assert!(f.allows(&flows, &v4(b4, me4, ICMP, 7, 8)), "ping from b");
        assert!(f.allows(&flows, &v4([192, 168, 5, 9], me4, ICMP, 7, 8)), "b's subnet is b");
        assert!(f.allows(&flows, &v4([8, 8, 8, 8], me4, UDP, 53, 5353)), "not a member: not judged");
        // our own connection to a: its replies pass, others from a do not
        flows.outbound(&v4(me4, a4, TCP, 50000, 3389));
        assert!(f.allows(&flows, &v4(a4, me4, TCP, 3389, 50000)), "reply");
        assert!(!f.allows(&flows, &v4(a4, me4, TCP, 3389, 50001)), "another port");
        flows.outbound(&v4(me4, a4, ICMP, 99, 8));
        assert!(f.allows(&flows, &v4(a4, me4, ICMP, 99, 0)), "echo reply");
        assert!(!f.allows(&flows, &v4(a4, me4, ICMP, 98, 0)), "another echo id");
        assert!(f.allows(&flows, &v4(a4, me4, ICMP, 0, 3)), "ICMP errors are related");
    }

    #[test]
    fn nothing_to_enforce() {
        let [me, _, _] = ids();
        let acl = Acl::parse("default = \"allow\"\n", &|_| None).unwrap();
        assert!(Filter::new(&acl, &me, &HashMap::new()).is_none());
    }
}
