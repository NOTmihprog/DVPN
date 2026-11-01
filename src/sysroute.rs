//! System routes for the CKR table (PLAN §7.3), Linux for now. Like `wg-quick`:
//!
//! ```text
//! ip rule  priority 7346  lookup main suppress_prefixlength 0   (LAN and other specific routes win)
//! ip rule  priority 7347  not fwmark 0x7347 lookup 7347          (everything else: our table)
//! table 7347: <prefix> dev <tun>, throw <hole>
//! ```
//!
//! The node's own socket carries fwmark 0x7347 (`transport.rs`), so DVPN's own packets to
//! trackers, static peers and neighbours never enter the tunnel, whatever the table routes
//! (even a default route through an exit node): no per-address underlay exceptions are needed.
//! Routes are applied as a diff, and the rules and table are removed on exit and cleaned up on
//! start (after a crash). Uses the `ip` command (iproute2).

use std::collections::BTreeSet;
use std::process::Command;

use ipnet::IpNet;

pub const FWMARK: u32 = 0x7347;
pub const TABLE: u32 = 7347;
const PRIORITY: u32 = 7347;

/// A wanted route in our table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SysRoute {
    Dev(IpNet),
    /// A hole: lookups fall through to the next rule (the main table).
    Throw(IpNet),
}

impl SysRoute {
    fn net(&self) -> IpNet {
        match self {
            SysRoute::Dev(n) | SysRoute::Throw(n) => *n,
        }
    }
}

/// The system routes for a CKR table: every entry that wants one, except prefixes already on
/// the TUN interface (`connected`) and `~` entries.
pub fn wanted(routes: &[crate::ckr::Route], connected: &[IpNet]) -> BTreeSet<SysRoute> {
    routes
        .iter()
        .filter(|r| r.system && !connected.iter().any(|c| c.contains(&r.net)))
        .map(|r| match r.target {
            crate::ckr::Target::Node(_) | crate::ckr::Target::Blackhole => SysRoute::Dev(r.net),
            crate::ckr::Target::Exclude => SysRoute::Throw(r.net),
        })
        .collect()
}

fn family(n: &IpNet) -> &'static str {
    if matches!(n, IpNet::V4(_)) { "-4" } else { "-6" }
}

fn ip(args: &[String]) -> bool {
    match Command::new("ip").args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            log::debug!("Routes | ip {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
            false
        }
        Err(e) => {
            log::warn!("Routes | cannot run ip: {e}");
            false
        }
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Installs and removes our routes.
pub struct SysRoutes {
    tun: String,
    installed: BTreeSet<SysRoute>,
    rules: bool,
}

impl SysRoutes {
    pub fn new(tun: &str) -> Self {
        let s = SysRoutes { tun: tun.to_owned(), installed: BTreeSet::new(), rules: false };
        if cfg!(target_os = "linux") {
            s.remove_all(); // leftovers of a crashed run
        }
        s
    }

    fn rule(&self, add: bool, fam: &str) {
        let op = if add { "add" } else { "del" };
        let (p1, p2) = ((PRIORITY - 1).to_string(), PRIORITY.to_string());
        let mark = format!("{FWMARK:#x}");
        let table = TABLE.to_string();
        ip(&args(&[fam, "rule", op, "priority", &p1, "lookup", "main", "suppress_prefixlength", "0"]));
        ip(&args(&[fam, "rule", op, "priority", &p2, "not", "fwmark", &mark, "lookup", &table]));
    }

    fn remove_all(&self) {
        for fam in ["-4", "-6"] {
            // rules may have been added more than once by crashed runs
            for _ in 0..4 {
                self.rule(false, fam);
            }
            ip(&args(&[fam, "route", "flush", "table", &TABLE.to_string()]));
        }
    }

    /// Makes the table match `wanted`. Only Linux; elsewhere a warning once.
    pub fn apply(&mut self, wanted: &BTreeSet<SysRoute>) {
        if !cfg!(target_os = "linux") {
            if !wanted.is_empty() && !self.rules {
                log::warn!("Routes | system routes are not managed on this OS yet: add them by hand");
                self.rules = true;
            }
            return;
        }
        if !wanted.is_empty() && !self.rules {
            self.rule(true, "-4");
            self.rule(true, "-6");
            self.rules = true;
        }
        let table = TABLE.to_string();
        for r in self.installed.difference(wanted).copied().collect::<Vec<_>>() {
            let n = r.net().to_string();
            let a = match r {
                SysRoute::Dev(_) => args(&[family(&r.net()), "route", "del", &n, "dev", &self.tun, "table", &table]),
                SysRoute::Throw(_) => args(&[family(&r.net()), "route", "del", "throw", &n, "table", &table]),
            };
            ip(&a);
            self.installed.remove(&r);
        }
        for r in wanted.difference(&self.installed.clone()) {
            let n = r.net().to_string();
            let a = match r {
                SysRoute::Dev(_) => {
                    args(&[family(&r.net()), "route", "replace", &n, "dev", &self.tun, "table", &table])
                }
                SysRoute::Throw(_) => args(&[family(&r.net()), "route", "replace", "throw", &n, "table", &table]),
            };
            if ip(&a) {
                log::info!("Routes | {r:?} installed");
                self.installed.insert(*r);
            }
        }
    }

    /// Removes our rules and table (on exit).
    pub fn clear(&mut self) {
        if cfg!(target_os = "linux") && (self.rules || !self.installed.is_empty()) {
            self.remove_all();
        }
        self.installed.clear();
        self.rules = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckr::{CkrTable, parse_spec};

    #[test]
    fn wanted_routes() {
        let n = crate::identity::Identity::from_seed(&[1; 32]).id();
        let rs: Vec<_> = ["10.10.33.2", "192.168.20.0/24", "~10.99.0.0/16", "inetv4", "!203.0.113.0/24"]
            .iter()
            .flat_map(|s| parse_spec(s, n).unwrap())
            .collect();
        let t = CkrTable::new(rs);
        let connected: Vec<IpNet> = vec!["10.10.33.0/24".parse().unwrap()];
        let w = wanted(t.routes(), &connected);
        assert!(w.contains(&SysRoute::Dev("192.168.20.0/24".parse().unwrap())));
        assert!(w.contains(&SysRoute::Dev("0.0.0.0/0".parse().unwrap())));
        assert!(w.contains(&SysRoute::Throw("203.0.113.0/24".parse().unwrap())));
        assert!(w.contains(&SysRoute::Throw("10.0.0.0/8".parse().unwrap())), "inetv4 holes");
        assert!(!w.iter().any(|r| r.net() == "10.10.33.2/32".parse::<IpNet>().unwrap()), "on the TUN subnet already");
        assert!(!w.iter().any(|r| r.net() == "10.99.0.0/16".parse::<IpNet>().unwrap()), "~ entry");
    }
}
