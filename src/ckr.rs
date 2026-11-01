//! CKR (PLAN §7): which node an overlay destination belongs to. A longest-prefix-match table
//! `IpNet -> node` for IPv4 and IPv6, built from the members' certificates (their address and
//! the subnets an admin gave them) and the manual `[ckr.remote_subnets]` on top.
//!
//! Entry syntax, compatible with Yggdrasil CKR:
//!
//! | entry                       | meaning                                                   |
//! |-----------------------------|-----------------------------------------------------------|
//! | `10.0.0.0/24`, `10.0.0.5`   | route (and a system route); no mask = /32 or /128         |
//! | `~10.0.0.0/8`               | CKR only, no system route                                 |
//! | `!192.168.1.0/24`           | not through the tunnel (a hole in a wider route)          |
//! | `inetv4`, `~inetv4`         | public IPv4: `0.0.0.0/0` with holes for private ranges    |
//! | `inetv6`, `~inetv6`         | `2000::/3`                                                |

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv6Net};

use crate::identity::NodeId;

/// Not public IPv4 space: holes in `inetv4`.
const PRIVATE_V4: [&str; 10] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Node(NodeId),
    /// `!prefix`: not through the tunnel.
    Exclude,
}

/// One parsed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub net: IpNet,
    pub target: Target,
    /// Whether a system route is wanted (`~` turns it off; holes always are).
    pub system: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SpecError(String);

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SpecError {}

fn net(s: &str) -> Result<IpNet, SpecError> {
    let n = match s.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => IpNet::from(s.parse::<IpAddr>().map_err(|_| SpecError(format!("{s}: not an address or prefix")))?),
    };
    Ok(n.trunc())
}

/// Parses one entry for `node`.
pub fn parse_spec(spec: &str, node: NodeId) -> Result<Vec<Route>, SpecError> {
    let spec = spec.trim();
    let (system, rest) = match spec.strip_prefix('~') {
        Some(r) => (false, r),
        None => (true, spec),
    };
    if let Some(r) = rest.strip_prefix('!') {
        return Ok(vec![Route { net: net(r)?, target: Target::Exclude, system: true }]);
    }
    let node = Target::Node(node);
    Ok(match rest {
        "inetv4" => {
            let mut v = vec![Route { net: net("0.0.0.0/0")?, target: node, system }];
            for p in PRIVATE_V4 {
                v.push(Route { net: net(p)?, target: Target::Exclude, system });
            }
            v
        }
        "inetv6" => vec![Route { net: net("2000::/3")?, target: node, system }],
        "" => return Err(SpecError("empty entry".into())),
        _ => vec![Route { net: net(rest)?, target: node, system }],
    })
}

/// Longest-prefix match: one hash map per prefix length, longest first. At most 33 / 129
/// lookups per packet, usually a handful (only the lengths in use are tried).
#[derive(Default, Clone)]
pub struct CkrTable {
    v4: Vec<(u8, HashMap<u32, Target>)>,
    v6: Vec<(u8, HashMap<u128, Target>)>,
    routes: Vec<Route>,
}

fn mask4(a: Ipv4Addr, len: u8) -> u32 {
    if len == 0 { 0 } else { u32::from(a) & (u32::MAX << (32 - len)) }
}

fn mask6(a: Ipv6Addr, len: u8) -> u128 {
    if len == 0 { 0 } else { u128::from(a) & (u128::MAX << (128 - len)) }
}

impl CkrTable {
    /// Later routes override earlier ones for the same prefix (manual after automatic).
    pub fn new(routes: impl IntoIterator<Item = Route>) -> Self {
        let mut t = CkrTable::default();
        let mut by_net: HashMap<IpNet, Route> = HashMap::new();
        let mut order = Vec::new();
        for r in routes {
            if by_net.insert(r.net, r).is_none() {
                order.push(r.net);
            }
        }
        for n in order {
            let r = by_net[&n];
            t.routes.push(r);
            match r.net {
                IpNet::V4(n) => {
                    Self::slot4(&mut t.v4, n.prefix_len()).insert(mask4(n.addr(), n.prefix_len()), r.target)
                }
                IpNet::V6(n) => {
                    Self::slot6(&mut t.v6, n.prefix_len()).insert(mask6(n.addr(), n.prefix_len()), r.target)
                }
            };
        }
        t.v4.sort_by_key(|e| std::cmp::Reverse(e.0));
        t.v6.sort_by_key(|e| std::cmp::Reverse(e.0));
        t
    }

    fn slot4(v: &mut Vec<(u8, HashMap<u32, Target>)>, len: u8) -> &mut HashMap<u32, Target> {
        let i = v.iter().position(|(l, _)| *l == len).unwrap_or_else(|| {
            v.push((len, HashMap::new()));
            v.len() - 1
        });
        &mut v[i].1
    }

    fn slot6(v: &mut Vec<(u8, HashMap<u128, Target>)>, len: u8) -> &mut HashMap<u128, Target> {
        let i = v.iter().position(|(l, _)| *l == len).unwrap_or_else(|| {
            v.push((len, HashMap::new()));
            v.len() - 1
        });
        &mut v[i].1
    }

    /// The most specific entry for `ip`.
    pub fn target(&self, ip: IpAddr) -> Option<Target> {
        match ip {
            IpAddr::V4(a) => self.v4.iter().find_map(|(len, m)| m.get(&mask4(a, *len)).copied()),
            IpAddr::V6(a) => self.v6.iter().find_map(|(len, m)| m.get(&mask6(a, *len)).copied()),
        }
    }

    /// The node `ip` is routed to, if any (a hole means none).
    pub fn lookup(&self, ip: IpAddr) -> Option<NodeId> {
        match self.target(ip)? {
            Target::Node(n) => Some(n),
            Target::Exclude => None,
        }
    }

    /// All entries, for system routes and display.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

/// The IPv6 ULA prefix of a group (RFC 4193, global ID from the group id) and a node's address
/// in it (PLAN §9.2): no allocation needed, collisions practically impossible, and the source
/// check is exact because the address follows from the key.
pub fn ula_prefix(group: &NodeId) -> Ipv6Net {
    let h = blake2_32(&[b"dvpn/4 ula", group.as_bytes()]);
    let mut b = [0u8; 16];
    b[0] = 0xfd;
    b[1..6].copy_from_slice(&h[..5]);
    Ipv6Net::new(Ipv6Addr::from(b), 48).expect("/48")
}

pub fn ula_addr(group: &NodeId, node: &NodeId) -> Ipv6Addr {
    let p = ula_prefix(group).addr().octets();
    let h = blake2_32(&[b"dvpn/4 ula node", node.as_bytes()]);
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&p[..6]);
    b[6..].copy_from_slice(&h[..10]);
    Ipv6Addr::from(b)
}

fn blake2_32(parts: &[&[u8]]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;
    use proptest::prelude::*;

    fn id(n: u8) -> NodeId {
        crate::identity::Identity::from_seed(&[n; 32]).id()
    }

    fn routes(specs: &[(&str, u8)]) -> Vec<Route> {
        specs.iter().flat_map(|(s, n)| parse_spec(s, id(*n)).unwrap()).collect()
    }

    #[test]
    fn syntax() {
        let r = parse_spec("10.0.0.5", id(1)).unwrap();
        assert_eq!(r, vec![Route { net: "10.0.0.5/32".parse().unwrap(), target: Target::Node(id(1)), system: true }]);
        assert!(!parse_spec("~10.0.0.0/8", id(1)).unwrap()[0].system);
        assert_eq!(parse_spec("!192.168.1.0/24", id(1)).unwrap()[0].target, Target::Exclude);
        assert_eq!(
            parse_spec("10.1.2.3/8", id(1)).unwrap()[0].net,
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "truncated"
        );
        assert_eq!(parse_spec("fd00::1", id(1)).unwrap()[0].net, "fd00::1/128".parse::<IpNet>().unwrap());
        assert_eq!(parse_spec("inetv6", id(1)).unwrap()[0].net, "2000::/3".parse::<IpNet>().unwrap());
        for bad in ["", "~", "!", "10.0.0.0/33", "host", "inetv5", "~!"] {
            assert!(parse_spec(bad, id(1)).is_err(), "{bad}");
        }
    }

    #[test]
    fn longest_match_holes_and_override() {
        let t = CkrTable::new(routes(&[
            ("10.10.33.2", 1),
            ("192.168.20.0/24", 1),
            ("inetv4", 2), // exit
            ("!203.0.113.0/24", 2),
            ("10.10.33.3", 3),
            ("10.10.33.3", 4), // manual overrides automatic
        ]));
        let l = |s: &str| t.lookup(s.parse().unwrap());
        assert_eq!(l("10.10.33.2"), Some(id(1)));
        assert_eq!(l("192.168.20.7"), Some(id(1)));
        assert_eq!(l("8.8.8.8"), Some(id(2)));
        assert_eq!(l("10.99.0.1"), None, "private, not public internet");
        assert_eq!(l("192.168.1.1"), None);
        assert_eq!(l("203.0.113.9"), None, "hole");
        assert_eq!(l("10.10.33.3"), Some(id(4)));
        assert_eq!(l("fd00::1"), None);
    }

    #[test]
    fn ula_is_stable_and_in_prefix() {
        let (g, n) = (id(9), id(1));
        let p = ula_prefix(&g);
        assert_eq!(p.addr().octets()[0], 0xfd);
        assert!(p.contains(&ula_addr(&g, &n)));
        assert_eq!(ula_addr(&g, &n), ula_addr(&g, &n));
        assert_ne!(ula_addr(&g, &n), ula_addr(&g, &id(2)));
        assert_ne!(ula_prefix(&g), ula_prefix(&id(8)));
    }

    /// Reference: the longest matching prefix by a linear scan.
    fn linear(rs: &[Route], ip: IpAddr) -> Option<Target> {
        let mut last: HashMap<IpNet, Target> = HashMap::new();
        for r in rs {
            last.insert(r.net, r.target);
        }
        last.iter().filter(|(n, _)| n.contains(&ip)).max_by_key(|(n, _)| n.prefix_len()).map(|(_, t)| *t)
    }

    proptest! {
        #[test]
        fn matches_linear_scan(
            entries in proptest::collection::vec((any::<u32>(), 0u8..=32, 0u8..4, any::<bool>()), 0..40),
            probes in proptest::collection::vec(any::<u32>(), 1..40),
        ) {
            let rs: Vec<Route> = entries.iter().map(|(a, l, n, hole)| Route {
                net: IpNet::V4(Ipv4Net::new(Ipv4Addr::from(*a), *l).unwrap().trunc()),
                target: if *hole { Target::Exclude } else { Target::Node(id(*n)) },
                system: true,
            }).collect();
            let t = CkrTable::new(rs.clone());
            // probe addresses inside the entries too, not only random ones
            let inside = entries.iter().map(|(a, _, _, _)| *a);
            for p in probes.into_iter().chain(inside) {
                let ip = IpAddr::V4(Ipv4Addr::from(p));
                prop_assert_eq!(t.target(ip), linear(&rs, ip), "{}", ip);
            }
        }

        #[test]
        fn matches_linear_scan_v6(
            entries in proptest::collection::vec((any::<u128>(), 0u8..=128, 0u8..4), 0..30),
            probes in proptest::collection::vec(any::<u128>(), 1..30),
        ) {
            let rs: Vec<Route> = entries.iter().map(|(a, l, n)| Route {
                net: IpNet::V6(Ipv6Net::new(Ipv6Addr::from(*a), *l).unwrap().trunc()),
                target: Target::Node(id(*n)),
                system: true,
            }).collect();
            let t = CkrTable::new(rs.clone());
            for p in probes.into_iter().chain(entries.iter().map(|e| e.0)) {
                let ip = IpAddr::V6(Ipv6Addr::from(p));
                prop_assert_eq!(t.target(ip), linear(&rs, ip));
            }
        }
    }
}
