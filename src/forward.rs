//! Port forwarding on a gateway: a port of its WAN interfaces leads to a member. The rules come
//! from `[[gateway.forward]]`, and from an admin (the record `forward/<gateway>`) if the gateway
//! allows it (`allow_remote`). A member is named by name or key and found through its certificate,
//! so a rule follows the member when its address changes.
//!
//! The member has to answer through the gateway, and takes packets from outside the group only
//! from its own exit (`Node::deliver_ip`). So by default the gateway hides the client behind its
//! own group address; with `keep_ip` the member sees the client's address, which works only while
//! this gateway is the member's exit.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Both,
}

impl Proto {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            "both" => Some(Proto::Both),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Both => "both",
        }
    }

    pub fn overlaps(self, other: Proto) -> bool {
        self == other || self == Proto::Both || other == Proto::Both
    }

    fn names(self) -> &'static [&'static str] {
        match self {
            Proto::Tcp => &["tcp"],
            Proto::Udp => &["udp"],
            Proto::Both => &["tcp", "udp"],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forward {
    pub proto: Proto,
    /// The port on the gateway.
    pub port: u16,
    /// The member: name or key.
    pub to: String,
    pub to_port: u16,
    /// Let the member see the client's address.
    pub keep_ip: bool,
}

/// A rule with its member's address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub proto: Proto,
    pub port: u16,
    pub addr: Ipv4Addr,
    pub to_port: u16,
    pub keep_ip: bool,
}

/// Whether the rules make sense together; what is wrong with them otherwise.
pub fn check(rules: &[Forward]) -> Result<(), String> {
    for (i, r) in rules.iter().enumerate() {
        if r.port == 0 || r.to_port == 0 {
            return Err(format!("port {} to {}: ports start at 1", r.port, r.to_port));
        }
        if r.to.trim().is_empty() {
            return Err(format!("port {}: no member given", r.port));
        }
        if rules[..i].iter().any(|o| o.port == r.port && o.proto.overlaps(r.proto)) {
            return Err(format!("port {} is forwarded twice", r.port));
        }
    }
    Ok(())
}

/// The rules in force: this node's own, then an admin's for the ports that are left.
pub fn merge(local: &[Forward], remote: &[Forward]) -> Vec<Forward> {
    let free = |r: &&Forward| !local.iter().any(|l| l.port == r.port && l.proto.overlaps(r.proto));
    local.iter().chain(remote.iter().filter(free)).cloned().collect()
}

/// The nft script that makes `targets` the rules of `table` (chains `fwd_pre`, `fwd_post`), in
/// one transaction. `reserved`: the node's own UDP ports, never taken over: a rule from an admin
/// must not cut the gateway off.
pub fn script(table: &str, wan: &[String], tun: &str, reserved: (u16, u16), targets: &[Target]) -> String {
    let wan = wan.iter().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", ");
    let mut s = format!("flush chain inet {table} fwd_pre\nflush chain inet {table} fwd_post\n");
    for t in targets {
        for proto in t.proto.names() {
            if *proto == "udp" && (reserved.0..=reserved.1).contains(&t.port) {
                log::warn!("Gateway | port {} is this node's own, not forwarded", t.port);
                continue;
            }
            let (port, addr, to_port) = (t.port, t.addr, t.to_port);
            s.push_str(&format!(
                "add rule inet {table} fwd_pre iifname {{ {wan} }} meta nfproto ipv4 {proto} dport {port} dnat ip to {addr}:{to_port}\n"
            ));
            if !t.keep_ip {
                s.push_str(&format!(
                    "add rule inet {table} fwd_post oifname \"{tun}\" ip daddr {addr} {proto} dport {to_port} ct status dnat masquerade\n"
                ));
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(proto: Proto, port: u16, to: &str) -> Forward {
        Forward { proto, port, to: to.into(), to_port: port, keep_ip: false }
    }

    #[test]
    fn checks() {
        assert!(check(&[rule(Proto::Tcp, 80, "a"), rule(Proto::Udp, 80, "b"), rule(Proto::Both, 81, "a")]).is_ok());
        assert!(check(&[rule(Proto::Tcp, 80, "a"), rule(Proto::Both, 80, "b")]).is_err());
        assert!(check(&[rule(Proto::Tcp, 0, "a")]).is_err());
        assert!(check(&[Forward { to_port: 0, ..rule(Proto::Tcp, 80, "a") }]).is_err());
        assert!(check(&[rule(Proto::Tcp, 80, " ")]).is_err());
    }

    #[test]
    fn own_rules_win() {
        let local = [rule(Proto::Tcp, 80, "mine")];
        let remote = [rule(Proto::Both, 80, "theirs"), rule(Proto::Udp, 53, "theirs")];
        assert_eq!(merge(&local, &remote), vec![local[0].clone(), remote[1].clone()]);
    }

    #[test]
    fn nft_rules() {
        let t =
            |proto, port, keep_ip| Target { proto, port, addr: "10.10.33.5".parse().unwrap(), to_port: 80, keep_ip };
        let s = script(
            "gw",
            &["wan0".into()],
            "dnet",
            (7000, 7000),
            &[t(Proto::Tcp, 8080, false), t(Proto::Udp, 53, true)],
        );
        assert!(
            s.contains("fwd_pre iifname { \"wan0\" } meta nfproto ipv4 tcp dport 8080 dnat ip to 10.10.33.5:80\n"),
            "{s}"
        );
        assert!(
            s.contains("fwd_post oifname \"dnet\" ip daddr 10.10.33.5 tcp dport 80 ct status dnat masquerade\n"),
            "{s}"
        );
        assert!(s.contains("udp dport 53 dnat ip to"), "{s}");
        assert!(!s.contains("udp dport 80 ct status"), "keep_ip: no masquerade: {s}");
        // both protocols, the node's own UDP port left alone
        let s = script("gw", &["wan0".into()], "dnet", (7000, 7000), &[t(Proto::Both, 7000, false)]);
        assert!(s.contains("tcp dport 7000") && !s.contains("udp dport 7000"), "{s}");
    }
}
