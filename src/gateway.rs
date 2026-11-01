//! A gateway node (PLAN §8.3, `[gateway]`): members send their internet traffic through it
//! (`[exit]` on their side). Linux, with nftables, `ip` and sysctl:
//!
//! - forwarding on (IPv4 and IPv6; `accept_ra = 2` on the WAN interfaces first, so a gateway
//!   that gets its own IPv6 route from router advertisements keeps it);
//! - `table inet dvpn_gw`: traffic from the tunnel out of the WAN interfaces is masqueraded
//!   (IPv4, and IPv6 from the group ULA, which is not routable outside); TCP MSS clamped to the
//!   path MTU both ways, so TCP through the tunnel never needs fragments;
//! - public IPv6 for members (like `ndp_proxy` in yggmgr): an admin gives a member an address
//!   of the gateway's prefix in its certificate (`--route 2001:db8::50/128`); the gateway
//!   answers neighbour discovery for it on the WAN (`ip -6 neigh proxy`) and routes it into the
//!   tunnel (a /128 in the main table, so the on-link /64 does not win).
//!
//! Everything is removed again on exit (sysctls stay as they are).

use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::process::{Command, Stdio};

use ipnet::{IpNet, Ipv6Net};

const TABLE: &str = "dvpn_gw";

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            log::debug!("Gateway | {cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
            false
        }
        Err(e) => {
            log::warn!("Gateway | cannot run {cmd}: {e}");
            false
        }
    }
}

fn sysctl(key: &str, value: &str) {
    if !run("sysctl", &["-qw", &format!("{key}={value}")]) {
        log::warn!("Gateway | could not set {key}={value}");
    }
}

fn nft(script: &str) -> bool {
    let child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let Ok(mut child) = child else {
        log::warn!("Gateway | cannot run nft");
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(script.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            log::warn!("Gateway | nft: {}", String::from_utf8_lossy(&o.stderr).trim());
            false
        }
        Err(e) => {
            log::warn!("Gateway | nft: {e}");
            false
        }
    }
}

/// The global IPv6 prefixes on an interface (from `ip -6 -o addr`).
fn global_prefixes(dev: &str) -> Vec<Ipv6Net> {
    let Ok(o) = Command::new("ip").args(["-6", "-o", "addr", "show", "dev", dev, "scope", "global"]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().skip_while(|w| *w != "inet6").nth(1))
        .filter_map(|a| a.parse::<Ipv6Net>().ok())
        .map(|n| n.trunc())
        .collect()
}

pub struct Gateway {
    tun: String,
    wan: Vec<String>,
    ndp: Option<String>,
    proxied: BTreeSet<Ipv6Addr>,
}

impl Gateway {
    /// Sets the gateway up: sysctls (if `manage_sysctl`), NAT and MSS clamping.
    pub fn start(tun: &str, wan: &[String], ndp: Option<String>, ula: Ipv6Net, manage_sysctl: bool) -> Self {
        let g = Gateway { tun: tun.to_owned(), wan: wan.to_vec(), ndp, proxied: BTreeSet::new() };
        if !cfg!(target_os = "linux") {
            log::warn!("Gateway | [gateway] is supported on Linux only");
            return g;
        }
        if manage_sysctl {
            for w in g.wan.iter().chain(g.ndp.iter()) {
                sysctl(&format!("net.ipv6.conf.{w}.accept_ra"), "2");
            }
            sysctl("net.ipv4.ip_forward", "1");
            sysctl("net.ipv6.conf.all.forwarding", "1");
            if let Some(n) = &g.ndp {
                sysctl(&format!("net.ipv6.conf.{n}.proxy_ndp"), "1");
            }
        }
        let wan_set = g.wan.iter().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", ");
        let tun = &g.tun;
        g.remove_table();
        let ok = nft(&format!(
            "table inet {TABLE} {{
    chain post {{
        type nat hook postrouting priority 100;
        iifname \"{tun}\" oifname {{ {wan_set} }} meta nfproto ipv4 masquerade
        iifname \"{tun}\" oifname {{ {wan_set} }} ip6 saddr {ula} masquerade
    }}
    chain mss {{
        type filter hook forward priority -10;
        oifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu
        iifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu
    }}
}}"
        ));
        if ok {
            log::info!("Gateway | NAT from {tun} to {} on, MSS clamped", g.wan.join(", "));
        }
        g
    }

    fn remove_table(&self) {
        let _ = Command::new("nft").args(["delete", "table", "inet", TABLE]).stderr(Stdio::null()).status();
    }

    /// Members' public IPv6 addresses (/128 in their certificates) within the NDP interface's
    /// prefixes: answer neighbour discovery for them and route them into the tunnel.
    pub fn apply(&mut self, member_prefixes: &[IpNet]) {
        let Some(dev) = self.ndp.clone().filter(|_| cfg!(target_os = "linux")) else { return };
        let ours = global_prefixes(&dev);
        let wanted: BTreeSet<Ipv6Addr> = member_prefixes
            .iter()
            .filter_map(|p| match p {
                IpNet::V6(n) if n.prefix_len() == 128 && ours.iter().any(|o| o.contains(&n.addr())) => Some(n.addr()),
                _ => None,
            })
            .collect();
        for a in self.proxied.difference(&wanted).copied().collect::<Vec<_>>() {
            let a = a.to_string();
            run("ip", &["-6", "neigh", "del", "proxy", &a, "dev", &dev]);
            run("ip", &["-6", "route", "del", &format!("{a}/128"), "dev", &self.tun]);
        }
        for a in wanted.difference(&self.proxied.clone()) {
            let s = a.to_string();
            let ok = run("ip", &["-6", "neigh", "replace", "proxy", &s, "dev", &dev])
                && run("ip", &["-6", "route", "replace", &format!("{s}/128"), "dev", &self.tun]);
            if ok {
                log::info!("Gateway | public {s} of a member via {dev}");
            }
        }
        self.proxied = wanted;
    }

    /// Removes NAT, NDP proxies and their routes (on exit).
    pub fn stop(&mut self) {
        if !cfg!(target_os = "linux") {
            return;
        }
        self.apply(&[]);
        self.remove_table();
    }
}
