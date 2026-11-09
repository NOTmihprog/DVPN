//! The node's wanted state (PLAN §8, 6.4): what the overlay should look like on this node,
//! computed as a pure function of what the node knows, without locks, I/O or system calls.
//! `apply.rs` then moves the system there (on Linux: addresses, `ip` routes and rules, nftables,
//! systemd-resolved), touching only what differs from the last plan.
//!
//! Splitting the two keeps the policy testable without root and leaves each platform only the
//! "apply" half: Windows (IP Helper, NRPT) and Android (`VpnService.Builder` takes the whole set
//! at once) get their own backend for the same `Plan`, and several groups (PLAN 3.5) merge plans.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::acl::Acl;
use crate::ckr::{Route, Target, parse_spec, ula_addr, ula_prefix};
use crate::dns::Zone;
use crate::group::{Cert, GroupId};
use crate::identity::NodeId;

/// Everything the plan depends on.
pub struct Inputs<'a> {
    pub me: NodeId,
    pub group: GroupId,
    /// Local name of the group (DNS: `<member>.<group>.<domain>`).
    pub group_name: &'a str,
    /// Our own certificate: our addresses.
    pub own: &'a Cert,
    /// The newest admitted certificate of every other member.
    pub members: &'a HashMap<NodeId, Cert>,
    /// Prefix length of the group network (`[net] mask`).
    pub tun_prefix: u8,
    /// The gateways in use (`exit.rs`) and whether the kill switch holds each family.
    pub exit4: Option<NodeId>,
    pub exit6: Option<NodeId>,
    pub kill: (bool, bool),
    /// `[exit] table` and `v4_sources`/`v6_sources`: the internet routes go to their own table
    /// (with `from <source>` rules), not to the whole node.
    pub exit_table: Option<u32>,
    pub exit_sources: &'a [IpNet],
    /// `[exit] only_file`, as read: only these destinations go through the gateway (and only
    /// they are blocked by the kill switch). `None`: the whole internet.
    pub exit_only: Option<&'a [IpNet]>,
    /// `[ckr.remote_subnets]`: over everything else.
    pub manual: &'a [Route],
    /// The group's access rules, if any.
    pub acl: Option<&'a Acl>,
    /// `[dns] domain` if the node serves names, and `[exit] dns`.
    pub dns_domain: Option<&'a str>,
    pub dns_forward: &'a [IpAddr],
    /// The ports forwarded on this gateway.
    pub forwards: &'a [crate::forward::Forward],
}

/// What should be in place on this node.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    /// Our addresses on the TUN: IPv4 in the group network, the group ULA (/48), public IPv6
    /// /128s an admin gave us.
    pub addrs: Vec<IpNet>,
    /// The networks of those addresses: on-link, never sent into the tunnel by system routes.
    pub connected: Vec<IpNet>,
    /// The CKR table (destination -> node), in order: members by key, gateways, manual routes.
    pub ckr: Vec<Route>,
    /// With `[exit] table` or sources: the internet routes (gateway or kill switch) for that
    /// table, kept out of the system routes of `ckr` (they are in `ckr` for DVPN itself), and
    /// the sources ruled into it.
    pub exit: Vec<Route>,
    pub exit_table: Option<u32>,
    pub exit_sources: Vec<IpNet>,
    /// Per family (IPv4, IPv6): internet destinations go into the tunnel by routes narrower
    /// than a default one (`[exit] only_file`). Where nothing like Linux's fwmark keeps DVPN's
    /// own packets out of the tunnel (Windows), its socket is then pinned to the physical
    /// interface, in case a listed destination is a peer's endpoint.
    pub exit_only: [bool; 2],
    /// The group's access rules and every member's addresses and subnets (whom they apply to).
    pub acl: Option<Acl>,
    pub members: BTreeMap<NodeId, Vec<IpNet>>,
    /// Members' prefixes from their certificates (a gateway answers NDP for their public IPv6).
    pub member_prefixes: Vec<IpNet>,
    /// Names of members for the DNS server, and where it forwards other names.
    pub zone: Zone,
    pub dns_upstream: Vec<IpAddr>,
    /// Forwarded ports whose member is known.
    pub forwards: Vec<crate::forward::Target>,
}

impl Plan {
    /// The internet routes are not for the whole node (`[exit] table` or sources).
    pub fn exit_split(&self) -> bool {
        self.exit_table.is_some() || !self.exit_sources.is_empty()
    }

    /// Our IPv4 address in the group.
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.addrs.iter().find_map(|a| match a {
            IpNet::V4(n) => Some(n.addr()),
            IpNet::V6(_) => None,
        })
    }
}

/// Our addresses on the TUN from our certificate (also what the TUN starts with).
pub fn own_addrs(own: &Cert, group: &GroupId, tun_prefix: u8) -> Vec<IpNet> {
    let mut v: Vec<IpNet> =
        own.body.ipv4().and_then(|a| ipnet::Ipv4Net::new(a, tun_prefix).ok()).map(IpNet::V4).into_iter().collect();
    let ula = ula_addr(group, &own.body.node);
    v.push(IpNet::V6(ipnet::Ipv6Net::new(ula, ula_prefix(group).prefix_len()).expect("/48")));
    v.extend(public_v6(own).map(|a| IpNet::V6(ipnet::Ipv6Net::from(a))));
    v
}

/// Public IPv6 addresses in a certificate: its /128 prefixes.
fn public_v6(c: &Cert) -> impl Iterator<Item = std::net::Ipv6Addr> + '_ {
    c.body.prefixes.iter().filter_map(|p| match p {
        IpNet::V6(n) if n.prefix_len() == 128 => Some(n.addr()),
        _ => None,
    })
}

/// The rules with the addresses of their members; the others wait for their member.
fn forward_targets(i: &Inputs) -> Vec<crate::forward::Target> {
    i.forwards
        .iter()
        .filter_map(|f| {
            let named = |c: &&Cert| c.body.name == f.to || c.body.node.to_string() == f.to;
            let c = i.members.values().filter(named).min_by_key(|c| c.body.node)?;
            let (proto, port, to_port, keep_ip) = (f.proto, f.port, f.to_port, f.keep_ip);
            Some(crate::forward::Target { proto, port, addr: c.body.ipv4()?, to_port, keep_ip })
        })
        .collect()
}

pub fn compute(i: &Inputs) -> Plan {
    let addrs = own_addrs(i.own, &i.group, i.tun_prefix);
    let connected = addrs.iter().map(IpNet::trunc).collect();

    // members sorted by key, so overlapping prefixes resolve the same way on every node
    let mut members: Vec<&Cert> = i.members.values().filter(|c| c.body.node != i.me).collect();
    members.sort_by_key(|c| c.body.node);
    let mut ckr = Vec::new();
    for c in &members {
        let target = Target::Node(c.body.node);
        for net in &c.body.prefixes {
            ckr.push(Route { net: net.trunc(), target, system: true });
        }
        let ula = ula_addr(&i.group, &c.body.node);
        ckr.push(Route { net: IpNet::from(IpAddr::V6(ula)), target, system: false });
    }
    // the chosen gateways get the internet (private ranges stay local), or only the listed
    // destinations of it
    let mut inet = Vec::new();
    let mut exit_only = [false; 2];
    for (fam6, gw, kill, spec) in [(false, i.exit4, i.kill.0, "inetv4"), (true, i.exit6, i.kill.1, "inetv6")] {
        let target = match (gw, kill) {
            (Some(gw), _) => Target::Node(gw),
            (None, true) => Target::Blackhole, // the internet stays in the tunnel, where nothing carries it
            (None, false) => continue,
        };
        match i.exit_only {
            Some(only) => {
                // a member's own prefix stays the member's (the table keeps the later of equal
                // prefixes; a narrower one wins anyway)
                let before = inet.len();
                inet.extend(
                    only.iter()
                        .filter(|n| {
                            matches!(n, IpNet::V6(_)) == fam6
                                && !members.iter().any(|c| c.body.prefixes.iter().any(|p| p.trunc() == **n))
                        })
                        .map(|n| Route { net: n.trunc(), target, system: true }),
                );
                exit_only[fam6 as usize] = inet.len() > before;
            }
            None => inet.extend(parse_spec(spec, gw.unwrap_or(i.me)).expect("valid spec").into_iter().map(|mut r| {
                if matches!(r.target, Target::Node(_)) {
                    r.target = target;
                }
                r
            })),
        }
    }
    let split = i.exit_table.is_some() || !i.exit_sources.is_empty();
    let exit = if split {
        // DVPN routes by them all the same; the system only for the sources, in their table
        ckr.extend(inet.iter().map(|r| Route { system: false, ..*r }));
        inet
    } else {
        ckr.extend(inet);
        Vec::new()
    };
    ckr.extend(i.manual.iter().copied());

    // whom the access rules talk about: members' subnets and their group ULA
    let acl_members = members
        .iter()
        .map(|c| {
            let mut v: Vec<IpNet> = c.body.prefixes.iter().map(IpNet::trunc).collect();
            v.push(IpNet::from(IpAddr::V6(ula_addr(&i.group, &c.body.node))));
            (c.body.node, v)
        })
        .collect();
    let member_prefixes = members.iter().flat_map(|c| c.body.prefixes.iter().copied()).collect();

    let zone = i.dns_domain.map(|d| zone(i, d, &members)).unwrap_or_default();
    // other names through the gateway while it carries our IPv4 internet
    // (not with a list of destinations: the rest of the internet, the resolvers too, is direct)
    let dns_upstream = if i.exit4.is_some() && i.exit_only.is_none() && i.dns_domain.is_some() {
        i.dns_forward.to_vec()
    } else {
        Vec::new()
    };

    Plan {
        forwards: forward_targets(i),
        addrs,
        connected,
        ckr,
        exit,
        exit_table: i.exit_table,
        exit_sources: i.exit_sources.to_vec(),
        exit_only,
        acl: i.acl.cloned(),
        members: acl_members,
        member_prefixes,
        zone,
        dns_upstream,
    }
}

/// Names of members and our own (PLAN §14a): `<name>.<domain>` and `<name>.<group>.<domain>`.
fn zone(i: &Inputs, domain: &str, members: &[&Cert]) -> Zone {
    let group = crate::dns::label(i.group_name);
    let mut z = Zone::new();
    // ourselves first, members in key order: on a clash of names the later one wins everywhere
    for c in std::iter::once(&i.own).chain(members.iter()) {
        let name = crate::dns::label(&c.body.name);
        if name.is_empty() {
            continue;
        }
        let mut addrs: Vec<IpAddr> = c.body.ipv4().map(IpAddr::V4).into_iter().collect();
        addrs.push(IpAddr::V6(ula_addr(&i.group, &c.body.node)));
        addrs.extend(public_v6(c).map(IpAddr::V6));
        z.insert(format!("{name}.{domain}"), addrs.clone());
        if !group.is_empty() {
            z.insert(format!("{name}.{group}.{domain}"), addrs);
        }
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{CertBody, GroupSecret};
    use crate::identity::Identity;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    struct World {
        secret: GroupSecret,
        me: Cert,
        members: HashMap<NodeId, Cert>,
    }

    fn cert(secret: &GroupSecret, name: &str, prefixes: &[&str]) -> Cert {
        let id = Identity::generate().id();
        secret.issue(CertBody::new(id, name, prefixes.iter().map(|p| net(p)).collect()))
    }

    fn world() -> World {
        let secret = GroupSecret::generate();
        let me = cert(&secret, "alice", &["10.10.33.1/32"]);
        let members = [
            cert(&secret, "bob", &["10.10.33.2/32", "2001:db8::50/128"]),
            cert(&secret, "office", &["10.10.33.3/32", "192.168.30.0/24"]),
        ]
        .into_iter()
        .map(|c| (c.body.node, c))
        .collect();
        World { secret, me, members }
    }

    fn inputs<'a>(w: &'a World) -> Inputs<'a> {
        Inputs {
            me: w.me.body.node,
            group: w.secret.id(),
            group_name: "home",
            own: &w.me,
            members: &w.members,
            tun_prefix: 24,
            exit4: None,
            exit6: None,
            kill: (false, false),
            exit_table: None,
            exit_sources: &[],
            exit_only: None,
            manual: &[],
            acl: None,
            dns_domain: Some("dvpn"),
            dns_forward: &[],
            forwards: &[],
        }
    }

    fn by_name(w: &World, name: &str) -> NodeId {
        w.members.values().find(|c| c.body.name == name).unwrap().body.node
    }

    fn target(p: &Plan, n: &str) -> Option<Target> {
        p.ckr.iter().rev().find(|r| r.net == net(n)).map(|r| r.target)
    }

    #[test]
    fn addresses_and_members() {
        let w = world();
        let p = compute(&inputs(&w));
        assert_eq!(p.ipv4(), Some("10.10.33.1".parse().unwrap()));
        assert_eq!(p.addrs.len(), 2, "IPv4 and ULA: {:?}", p.addrs);
        assert!(p.connected.contains(&net("10.10.33.0/24")));
        assert!(p.connected.contains(&IpNet::V6(ula_prefix(&w.secret.id()))));
        let office = by_name(&w, "office");
        assert_eq!(target(&p, "192.168.30.0/24"), Some(Target::Node(office)));
        assert!(p.ckr.iter().all(|r| r.target != Target::Node(w.me.body.node)), "no routes to ourselves");
        // the ULA of a member is routed inside DVPN only (the /48 is on-link)
        let ula = IpNet::from(IpAddr::V6(ula_addr(&w.secret.id(), &office)));
        assert!(p.ckr.iter().any(|r| r.net == ula && !r.system));
        assert_eq!(p.members.len(), 2);
        assert!(p.member_prefixes.contains(&net("2001:db8::50/128")));
        // deterministic: the same inputs give the same plan
        assert_eq!(p, compute(&inputs(&w)));
    }

    #[test]
    fn exits_and_kill_switch() {
        let w = world();
        let office = by_name(&w, "office");
        let mut i = inputs(&w);
        let p = compute(&i);
        assert_eq!(target(&p, "0.0.0.0/0"), None, "no gateway: the internet goes direct");
        i.exit4 = Some(office);
        let p = compute(&i);
        assert_eq!(target(&p, "0.0.0.0/0"), Some(Target::Node(office)));
        assert_eq!(target(&p, "192.168.0.0/16"), Some(Target::Exclude), "private ranges stay local");
        assert_eq!(target(&p, "2000::/3"), None, "IPv6 only with exit6");
        i.exit4 = None;
        i.kill = (true, false);
        let p = compute(&i);
        assert_eq!(target(&p, "0.0.0.0/0"), Some(Target::Blackhole), "kill switch");
        // manual routes come last and win
        let manual = [Route { net: net("0.0.0.0/0"), target: Target::Node(office), system: true }];
        i.manual = &manual;
        assert_eq!(target(&compute(&i), "0.0.0.0/0"), Some(Target::Node(office)));
    }

    #[test]
    fn exit_for_sources_only() {
        let w = world();
        let office = by_name(&w, "office");
        let mut i = inputs(&w);
        i.exit4 = Some(office);
        assert!(compute(&i).exit.is_empty(), "whole node: the internet routes are in ckr");
        let sources = [net("10.10.11.0/24")];
        i.exit_sources = &sources;
        let p = compute(&i);
        assert!(p.exit_split());
        // DVPN still sends the internet to the gateway and accepts it back from it ...
        assert_eq!(target(&p, "0.0.0.0/0"), Some(Target::Node(office)));
        // ... but the node's system routes do not carry it, the exit table does
        assert!(p.ckr.iter().filter(|r| r.net == net("0.0.0.0/0")).all(|r| !r.system));
        assert!(p.exit.iter().any(|r| r.net == net("0.0.0.0/0") && r.system && r.target == Target::Node(office)));
        assert!(p.exit.iter().any(|r| r.net == net("192.168.0.0/16") && r.target == Target::Exclude));
        assert_eq!(p.exit_sources, sources);
        // the kill switch is for the sources too
        i.exit4 = None;
        i.kill = (true, false);
        let p = compute(&i);
        assert!(p.exit.iter().any(|r| r.net == net("0.0.0.0/0") && r.target == Target::Blackhole));
        assert!(p.ckr.iter().filter(|r| r.net == net("0.0.0.0/0")).all(|r| !r.system));
        // a table alone (the system's rules steer into it) splits as well
        i.exit_sources = &[];
        i.exit_table = Some(445);
        let p = compute(&i);
        assert!(p.exit_split() && !p.exit.is_empty() && p.exit_sources.is_empty());
    }

    #[test]
    fn exit_for_listed_destinations_only() {
        let w = world();
        let office = by_name(&w, "office");
        let mut i = inputs(&w);
        let only = [net("1.1.1.1/32"), net("8.8.8.8/32"), net("9.9.9.0/24"), net("2001:db8:1::/48")];
        i.exit_only = Some(&only);
        assert!(compute(&i).ckr.iter().all(|r| !only.contains(&r.net)), "no gateway, no kill switch: all direct");
        assert_eq!(compute(&i).exit_only, [false, false]);
        i.exit4 = Some(office);
        let p = compute(&i);
        for n in ["1.1.1.1/32", "8.8.8.8/32", "9.9.9.0/24"] {
            assert_eq!(target(&p, n), Some(Target::Node(office)), "{n}");
            assert!(p.ckr.iter().any(|r| r.net == net(n) && r.system), "{n}: a system route");
        }
        assert_eq!(target(&p, "0.0.0.0/0"), None, "the rest of the internet goes direct");
        assert_eq!(target(&p, "192.168.0.0/16"), None, "no holes needed");
        assert_eq!(target(&p, "2001:db8:1::/48"), None, "IPv6 only with exit6");
        assert_eq!(p.exit_only, [true, false]);
        assert!(p.exit.is_empty() && !p.exit_split());
        // the kill switch blocks only the listed destinations
        i.exit4 = None;
        i.kill = (true, true);
        let p = compute(&i);
        assert_eq!(target(&p, "9.9.9.0/24"), Some(Target::Blackhole));
        assert_eq!(target(&p, "2001:db8:1::/48"), Some(Target::Blackhole));
        assert_eq!(target(&p, "0.0.0.0/0"), None);
        assert_eq!(target(&p, "::/0"), None);
        assert_eq!(p.exit_only, [true, true]);
        // a family the list has nothing of needs no pinning
        let v4 = [net("1.1.1.1/32")];
        i.exit_only = Some(&v4);
        assert_eq!(compute(&i).exit_only, [true, false]);
        // an empty list: nothing through the gateway (not the whole internet)
        i.exit_only = Some(&[]);
        i.exit4 = Some(office);
        let p = compute(&i);
        assert_eq!(target(&p, "0.0.0.0/0"), None);
        assert_eq!(p.exit_only, [false, false]);
        // a member's own subnet in the list stays the member's
        let bob = by_name(&w, "bob");
        let mixed = [net("192.168.30.0/24"), net("1.1.1.1/32")];
        i.exit_only = Some(&mixed);
        i.exit4 = Some(bob);
        let p = compute(&i);
        assert_eq!(target(&p, "192.168.30.0/24"), Some(Target::Node(office)));
        assert_eq!(target(&p, "1.1.1.1/32"), Some(Target::Node(bob)));
        // with sources: the listed destinations, in the exit table
        let sources = [net("10.10.11.0/24")];
        i.exit_sources = &sources;
        let p = compute(&i);
        assert!(p.exit_split());
        assert!(p.exit.iter().any(|r| r.net == net("1.1.1.1/32") && r.system && r.target == Target::Node(bob)));
        assert!(p.exit.iter().all(|r| r.net != net("0.0.0.0/0")));
        assert!(p.ckr.iter().filter(|r| r.net == net("1.1.1.1/32")).all(|r| !r.system));
    }

    #[test]
    fn dns_zone_and_upstream() {
        let w = world();
        let mut i = inputs(&w);
        let p = compute(&i);
        let bob = &p.zone["bob.dvpn"];
        assert!(bob.contains(&"10.10.33.2".parse().unwrap()));
        assert!(bob.contains(&"2001:db8::50".parse().unwrap()), "public IPv6 too");
        assert_eq!(p.zone["office.home.dvpn"].len(), 2, "IPv4 and ULA");
        assert!(p.zone.contains_key("alice.dvpn"), "ourselves too");
        let dns = ["1.1.1.1".parse().unwrap()];
        i.dns_forward = &dns;
        assert!(compute(&i).dns_upstream.is_empty(), "forwarding only while a gateway is in use");
        i.exit4 = Some(by_name(&w, "office"));
        assert_eq!(compute(&i).dns_upstream, dns);
        let only = [net("9.9.9.0/24")];
        i.exit_only = Some(&only);
        assert!(compute(&i).dns_upstream.is_empty(), "a list of destinations: names resolve directly");
        i.exit_only = None;
        i.dns_domain = None;
        let p = compute(&i);
        assert!(p.zone.is_empty() && p.dns_upstream.is_empty(), "no DNS server, nothing to serve");
    }

    #[test]
    fn new_address_moves_connected() {
        let mut w = world();
        let p = compute(&inputs(&w));
        let id = w.me.body.node;
        let mut body = CertBody::new(id, "alice", vec![net("10.20.0.1/32"), net("2001:db8::7/128")]);
        body.not_after = w.me.body.not_after + 1;
        w.me = w.secret.issue(body);
        let q = compute(&inputs(&w));
        assert_ne!(p.addrs, q.addrs);
        assert!(q.connected.contains(&net("10.20.0.0/24")) && !q.connected.contains(&net("10.10.33.0/24")));
        assert!(q.addrs.contains(&net("2001:db8::7/128")));
    }
}
