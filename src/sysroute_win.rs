//! System routes on Windows (PLAN 4.5), for the same [`Wanted`] as on Linux, through the IP
//! Helper API (`winnet.rs`). Windows has no policy routing, so:
//!
//! - routes into the overlay go on the Wintun interface; a default route is split into two
//!   halves (`0.0.0.0/1` + `128.0.0.0/1`, `::/1` + `8000::/1`), which win over the system's
//!   default route whatever the metrics, and keep it in place for when DVPN is gone;
//! - a hole (`~` / `!`, Linux's `throw`) is a route through the physical network's gateway;
//!   it moves with the network ([`SysRoutes::underlay_changed`]);
//! - while the overlay takes a default route, DVPN's own socket is pinned to the physical
//!   interface (`IP_UNICAST_IF`), Linux's fwmark: see [`SysRoutes::pin`];
//! - an exit for some sources only (`[exit] v4_sources` / `table`) has no Windows counterpart:
//!   those routes are left out with a warning.
//!
//! All our routes carry the metric [`winnet::TAG_METRIC`]: for equal prefixes the system's own
//! routes win (as the main table does on Linux), and a crashed run's routes are found again.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::sysroute::{SysRoute, TABLE, Wanted};
use crate::winnet::{self, Route, TAG_METRIC};

/// The physical network's default route per family: interface and gateway.
pub type Underlay = [Option<(u32, Option<IpAddr>)>; 2];

pub struct SysRoutes {
    tun_index: u32,
    /// What each wanted route became (a default route is two).
    installed: BTreeMap<(u32, SysRoute), Vec<Route>>,
    wanted: BTreeSet<(u32, SysRoute)>,
    underlay: Underlay,
    warned: bool,
}

/// A default route as the two halves that win over it.
fn halves(n: IpNet) -> Vec<IpNet> {
    if n.prefix_len() != 0 {
        return vec![n];
    }
    let parse = |s: &str| s.parse::<IpNet>().expect("valid");
    match n {
        IpNet::V4(_) => vec![parse("0.0.0.0/1"), parse("128.0.0.0/1")],
        IpNet::V6(_) => vec![parse("::/1"), parse("8000::/1")],
    }
}

fn v6(n: &IpNet) -> bool {
    matches!(n, IpNet::V6(_))
}

impl SysRoutes {
    pub fn new(_tun: &str, tun_index: u32) -> Self {
        winnet::remove_tagged(); // leftovers of a crashed run
        let underlay = Self::current_underlay(tun_index);
        SysRoutes { tun_index, installed: BTreeMap::new(), wanted: BTreeSet::new(), underlay, warned: false }
    }

    fn current_underlay(tun_index: u32) -> Underlay {
        [winnet::default_route(false, tun_index), winnet::default_route(true, tun_index)]
    }

    /// The Windows routes for a wanted one: `None` while it cannot be had (a hole without a
    /// physical gateway of its family).
    fn concrete(&self, r: SysRoute) -> Option<Vec<Route>> {
        match r {
            SysRoute::Dev(n) => Some(
                halves(n)
                    .into_iter()
                    .map(|net| Route { net, if_index: self.tun_index, next_hop: None, metric: TAG_METRIC })
                    .collect(),
            ),
            SysRoute::Throw(n) => {
                let (if_index, next_hop) = self.underlay[v6(&n) as usize]?;
                Some(vec![Route { net: n, if_index, next_hop, metric: TAG_METRIC }])
            }
        }
    }

    fn install(&mut self, key: (u32, SysRoute)) {
        let Some(routes) = self.concrete(key.1) else {
            log::debug!("Routes | {:?}: no physical gateway for it now", key.1);
            return;
        };
        let mut done = Vec::new();
        for r in routes {
            match winnet::add_route(&r) {
                Ok(()) => done.push(r),
                Err(e) => log::warn!("Routes | {} on interface {}: {e}", r.net, r.if_index),
            }
        }
        if !done.is_empty() {
            log::info!("Routes | {:?} installed", key.1);
            self.installed.insert(key, done);
        }
    }

    fn uninstall(&mut self, key: &(u32, SysRoute)) {
        for r in self.installed.remove(key).unwrap_or_default() {
            if let Err(e) = winnet::del_route(&r) {
                log::debug!("Routes | remove {}: {e}", r.net);
            }
        }
    }

    /// Makes the routes match `wanted`.
    pub fn apply(&mut self, wanted: &Wanted) {
        let (ours, other): (BTreeSet<_>, BTreeSet<_>) = wanted.routes.iter().copied().partition(|(t, _)| *t == TABLE);
        if (!other.is_empty() || !wanted.sources.is_empty()) && !self.warned {
            log::warn!("Routes | an exit for some sources or in a table of its own is Linux only: not applied");
            self.warned = true;
        }
        for k in self.installed.keys().filter(|k| !ours.contains(k)).copied().collect::<Vec<_>>() {
            self.uninstall(&k);
        }
        for k in ours.iter().filter(|k| !self.installed.contains_key(k)).copied().collect::<Vec<_>>() {
            self.install(k);
        }
        self.wanted = ours;
    }

    /// Looks at the physical network again; when its default route moved, the holes follow it.
    /// Returns the interfaces DVPN's socket should be pinned to (see [`SysRoutes::pin`]).
    pub fn underlay_changed(&mut self) -> Option<[u32; 2]> {
        let now = Self::current_underlay(self.tun_index);
        if now != self.underlay {
            log::info!("Routes | physical network: IPv4 {:?}, IPv6 {:?}", now[0], now[1]);
            self.underlay = now;
            let holes: Vec<_> = self.wanted.iter().filter(|(_, r)| matches!(r, SysRoute::Throw(_))).copied().collect();
            for k in holes {
                self.uninstall(&k);
                self.install(k);
            }
        }
        Some(self.pin())
    }

    /// The interfaces DVPN's own socket goes out of, per family (0: as the routes say). Only
    /// while the overlay takes that family's default route: then nothing but the physical
    /// interface keeps our own packets out of the tunnel. Otherwise the socket stays free, so
    /// that peers behind other interfaces (a second LAN) are still reached.
    pub fn pin(&self) -> [u32; 2] {
        let takes_default = |fam6: bool| {
            self.installed.keys().any(|(_, r)| matches!(r, SysRoute::Dev(n) if n.prefix_len() == 0 && v6(n) == fam6))
        };
        [false, true].map(
            |fam6| {
                if takes_default(fam6) { self.underlay[fam6 as usize].map_or(0, |(i, _)| i) } else { 0 }
            },
        )
    }

    /// Removes our routes (on exit).
    pub fn clear(&mut self) {
        for k in self.installed.keys().copied().collect::<Vec<_>>() {
            self.uninstall(&k);
        }
        self.wanted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_routes_are_split() {
        let n = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(halves(n("0.0.0.0/0")), vec![n("0.0.0.0/1"), n("128.0.0.0/1")]);
        assert_eq!(halves(n("::/0")), vec![n("::/1"), n("8000::/1")]);
        assert_eq!(halves(n("10.1.0.0/16")), vec![n("10.1.0.0/16")]);
    }
}
