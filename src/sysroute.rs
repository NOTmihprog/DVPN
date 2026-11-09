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
//!
//! With `[exit] v4_sources`/`v6_sources` or `table` the internet routes (gateway, kill switch)
//! are not in table 7347 but in the exit table (7348 or `table`), and only the sources look
//! there: `ip rule priority 7348 from <source> lookup <table>`, after ours, so the main table's
//! specific routes still win. With `table` and no sources DVPN adds no rule: the system's own
//! rules steer into it. Our routes carry `proto 73`, so in a table that is not ours only they are
//! removed. Routes are applied as a diff, and the rules and routes are removed on exit and
//! cleaned up on start (after a crash). Uses the `ip` command (iproute2).

use std::collections::BTreeSet;
#[cfg(not(windows))]
use std::process::Command;

use ipnet::IpNet;

pub const FWMARK: u32 = 0x7347;
pub const TABLE: u32 = 7347;
#[cfg(not(windows))]
const PRIORITY: u32 = 7347;
/// The table of the internet routes for `[exit] v4_sources` without `table`.
pub const EXIT_TABLE: u32 = 7348;
/// The `from <source>` rules: after ours (7346, 7347), before the main table.
#[cfg(not(windows))]
const EXIT_PRIORITY: u32 = 7348;
/// Marks our routes (`proto 73`), so that we only ever remove our own.
#[cfg(not(windows))]
const PROTO: &str = "73";

/// A wanted route in our table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SysRoute {
    Dev(IpNet),
    /// A hole: lookups fall through to the next rule (the main table).
    Throw(IpNet),
}

impl SysRoute {
    #[cfg_attr(windows, allow(dead_code))]
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

/// Everything a plan wants from the system routing: routes by table and `from` rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wanted {
    pub routes: BTreeSet<(u32, SysRoute)>,
    /// `from <source> lookup <table>`.
    pub sources: BTreeSet<(IpNet, u32)>,
    /// Per family: internet destinations in the tunnel by narrower routes than a default one
    /// (`Plan::exit_only`); Windows pins DVPN's socket then.
    pub exit_only: [bool; 2],
}

impl Wanted {
    pub fn of(plan: &crate::plan::Plan) -> Self {
        let exit_table = plan.exit_table.unwrap_or(EXIT_TABLE);
        let main = wanted(&plan.ckr, &plan.connected).into_iter().map(|r| (TABLE, r));
        let exit = wanted(&plan.exit, &plan.connected).into_iter().map(|r| (exit_table, r));
        Wanted {
            routes: main.chain(exit).collect(),
            sources: plan.exit_sources.iter().map(|s| (s.trunc(), exit_table)).collect(),
            exit_only: plan.exit_only,
        }
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.sources.is_empty()
    }
}

#[cfg(not(windows))]
fn family(n: &IpNet) -> &'static str {
    if matches!(n, IpNet::V4(_)) { "-4" } else { "-6" }
}

#[cfg(not(windows))]
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

/// More route changes than this at once go through one `ip -batch`.
#[cfg(not(windows))]
const BATCH_FROM: usize = 16;

/// Runs `lines` (`ip` commands without the `ip`) through `ip -force -batch -`, which goes on
/// after a failing line. Returns the indexes of the lines that failed (all, if `ip` did not run).
#[cfg(not(windows))]
fn ip_batch(lines: &[String]) -> std::collections::HashSet<usize> {
    use std::io::Write;
    let all = || (0..lines.len()).collect();
    let child = Command::new("ip")
        .args(["-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Routes | cannot run ip: {e}");
            return all();
        }
    };
    let mut input = lines.join("\n");
    input.push('\n');
    // written from another thread: `ip` may fill stderr before it read all of stdin
    let stdin = child.stdin.take();
    let writer = std::thread::spawn(move || stdin.map(|mut s| s.write_all(input.as_bytes())));
    let out = child.wait_with_output();
    let _ = writer.join();
    match out {
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let failed = batch_failures(&err, lines.len());
            if !failed.is_empty() {
                log::debug!("Routes | ip -batch: {}", err.trim());
            }
            failed
        }
        Err(e) => {
            log::warn!("Routes | ip -batch: {e}");
            all()
        }
    }
}

/// The failed lines (0-based) in `ip -batch -` output: `Command failed -:<line>`.
#[cfg(not(windows))]
fn batch_failures(stderr: &str, count: usize) -> std::collections::HashSet<usize> {
    stderr
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Command failed -:")?.trim().parse::<usize>().ok())
        .filter(|n| (1..=count).contains(n))
        .map(|n| n - 1)
        .collect()
}

#[cfg(not(windows))]
fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[cfg(windows)]
pub use crate::sysroute_win::SysRoutes;

/// Installs and removes our routes.
#[cfg(not(windows))]
pub struct SysRoutes {
    tun: String,
    installed: BTreeSet<(u32, SysRoute)>,
    sources: BTreeSet<(IpNet, u32)>,
    rules: bool,
}

#[cfg(not(windows))]
impl SysRoutes {
    pub fn new(tun: &str, _tun_index: u32) -> Self {
        let s = SysRoutes { tun: tun.to_owned(), installed: BTreeSet::new(), sources: BTreeSet::new(), rules: false };
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

    fn source_rule(&self, add: bool, (src, table): (IpNet, u32)) -> bool {
        let op = if add { "add" } else { "del" };
        let (fam, p, src, table) = (family(&src), EXIT_PRIORITY.to_string(), src.to_string(), table.to_string());
        ip(&args(&[fam, "rule", op, "priority", &p, "from", &src, "lookup", &table]))
    }

    /// `ip` arguments (after the family) to add or remove a route.
    fn route_args(&self, add: bool, (table, r): (u32, SysRoute)) -> Vec<String> {
        let (n, t) = (r.net().to_string(), table.to_string());
        let op = if add { "replace" } else { "del" };
        match r {
            SysRoute::Dev(_) => args(&["route", op, &n, "dev", &self.tun, "table", &t, "proto", PROTO]),
            SysRoute::Throw(_) => args(&["route", op, "throw", &n, "table", &t, "proto", PROTO]),
        }
    }

    fn route(&self, add: bool, r: (u32, SysRoute)) -> bool {
        let mut a = vec![family(&r.1.net()).to_owned()];
        a.extend(self.route_args(add, r));
        ip(&a)
    }

    /// Adds or removes `routes`, logging each, or with many (`[exit] only_file`) all through one
    /// `ip -batch` and a summary. Returns those that took.
    fn routes(&self, add: bool, routes: Vec<(u32, SysRoute)>) -> Vec<(u32, SysRoute)> {
        if routes.len() <= BATCH_FROM {
            return routes.into_iter().filter(|r| self.route(add, *r)).collect();
        }
        let lines: Vec<String> = routes.iter().map(|r| self.route_args(add, *r).join(" ")).collect();
        let failed = ip_batch(&lines);
        let ok: Vec<_> = routes.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, r)| r).collect();
        log::info!(
            "Routes | {} routes {}{}",
            ok.len(),
            if add { "installed" } else { "removed" },
            if failed.is_empty() { String::new() } else { format!(", {} failed", failed.len()) }
        );
        ok
    }

    fn remove_all(&self) {
        let (p, table) = (EXIT_PRIORITY.to_string(), TABLE.to_string());
        for fam in ["-4", "-6"] {
            // rules may have been added more than once by crashed runs
            for _ in 0..4 {
                self.rule(false, fam);
            }
            for _ in 0..64 {
                if !ip(&args(&[fam, "rule", "del", "priority", &p])) {
                    break;
                }
            }
            ip(&args(&[fam, "route", "flush", "table", &table]));
            // ours in any table (the exit table may be the system's own)
            ip(&args(&[fam, "route", "flush", "table", "all", "proto", PROTO]));
        }
    }

    /// Makes the routes and rules match `wanted`. Only Linux; elsewhere a warning once.
    pub fn apply(&mut self, wanted: &Wanted) {
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
        for s in self.sources.difference(&wanted.sources).copied().collect::<Vec<_>>() {
            self.source_rule(false, s);
            self.sources.remove(&s);
        }
        let gone: Vec<_> = self.installed.difference(&wanted.routes).copied().collect();
        // removed whether `ip` agreed or not (a route someone else deleted)
        self.routes(false, gone.clone());
        for r in gone {
            self.installed.remove(&r);
        }
        let new: Vec<_> = wanted.routes.difference(&self.installed).copied().collect();
        let few = new.len() <= BATCH_FROM;
        for r in self.routes(true, new) {
            if few {
                log::info!(
                    "Routes | {:?} installed{}",
                    r.1,
                    if r.0 == TABLE { String::new() } else { format!(" in table {}", r.0) }
                );
            }
            self.installed.insert(r);
        }
        for s in wanted.sources.difference(&self.sources.clone()) {
            if self.source_rule(true, *s) {
                log::info!("Routes | from {} through the exit table {}", s.0, s.1);
                self.sources.insert(*s);
            }
        }
    }

    /// Removes our rules and routes (on exit).
    pub fn clear(&mut self) {
        if cfg!(target_os = "linux") && (self.rules || !self.installed.is_empty() || !self.sources.is_empty()) {
            self.remove_all();
        }
        self.installed.clear();
        self.sources.clear();
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

    #[cfg(not(windows))]
    #[test]
    fn batch_failures_by_line() {
        let err = "Error: Nexthop has invalid gateway.\nCommand failed -:2\nRTNETLINK answers: No such process\nCommand failed -:5\nCommand failed -:99\n";
        assert_eq!(batch_failures(err, 5), [1, 4].into());
        assert!(batch_failures("", 5).is_empty());
    }

    #[test]
    fn exit_only_reaches_wanted() {
        let plan = crate::plan::Plan { exit_only: [true, false], ..Default::default() };
        assert_eq!(Wanted::of(&plan).exit_only, [true, false]);
    }

    #[test]
    fn exit_table_for_sources() {
        let gw = crate::identity::Identity::from_seed(&[2; 32]).id();
        let inet = parse_spec("inetv4", gw).unwrap();
        let mut plan = crate::plan::Plan {
            ckr: parse_spec("192.168.20.0/24", gw).unwrap(),
            exit: inet,
            exit_sources: vec!["10.10.11.7/24".parse().unwrap()],
            ..Default::default()
        };
        let w = Wanted::of(&plan);
        let default: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(w.routes.contains(&(TABLE, SysRoute::Dev("192.168.20.0/24".parse().unwrap()))));
        assert!(w.routes.contains(&(EXIT_TABLE, SysRoute::Dev(default))));
        assert!(!w.routes.contains(&(TABLE, SysRoute::Dev(default))), "not for the whole node");
        assert!(w.routes.contains(&(EXIT_TABLE, SysRoute::Throw("10.0.0.0/8".parse().unwrap()))));
        assert_eq!(w.sources, BTreeSet::from([("10.10.11.0/24".parse().unwrap(), EXIT_TABLE)]));
        // the system's own table, no rules of ours
        plan.exit_table = Some(445);
        plan.exit_sources.clear();
        let w = Wanted::of(&plan);
        assert!(w.routes.contains(&(445, SysRoute::Dev(default))));
        assert!(w.sources.is_empty());
    }
}
