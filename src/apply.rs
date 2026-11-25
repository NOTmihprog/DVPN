//! Moves the system to a `Plan` (`plan.rs`, PLAN 6.4), touching only what differs from the last
//! one: addresses on the TUN, system routes (`sysroute.rs`), the ACL (`acl.rs`), a gateway's NDP
//! proxies (`gateway.rs`) and systemd-resolved. Linux for now; on other systems the parts that
//! are not supported warn once and do nothing. A Windows or Android backend replaces this for
//! the same `Plan`.

use std::sync::Arc;

use ipnet::IpNet;
use tun_rs::AsyncDevice;

use crate::identity::NodeId;
use crate::plan::Plan;

/// The system side of a node; every part is optional (no TUN, routes not managed, ...).
#[derive(Default)]
pub struct System {
    tun: Option<Arc<AsyncDevice>>,
    /// The TUN interface name, for routes, the ACL and systemd-resolved.
    tun_name: String,
    routes: Option<crate::sysroute::SysRoutes>,
    gateway: Option<crate::gateway::Gateway>,
    /// systemd-resolved is configured for the DNS domain (split DNS) and may route all names.
    resolved: Option<String>,
    /// The ACL chain installed now (rendered for nftables).
    acl: Option<String>,
    /// The ACL wanted could not be installed: to be tried again.
    acl_failed: bool,
}

impl System {
    pub fn new(tun: Option<Arc<AsyncDevice>>) -> Self {
        // on Android and iOS the VPN service owns the interface: no name, addresses or routes here
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let tun_name = tun.as_ref().and_then(|t| t.name().ok()).unwrap_or_default();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let (tun, tun_name) = {
            drop(tun);
            (None, String::new())
        };
        System { tun, tun_name, ..Default::default() }
    }

    /// Manage system routes on the TUN (`[net] manage_routes`).
    pub fn manage_routes(&mut self) {
        if self.tun.is_some() {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let index = self.tun.as_ref().and_then(|t| t.if_index().ok()).unwrap_or(0);
            // no TUN of ours there (`new`), so never reached
            #[cfg(any(target_os = "android", target_os = "ios"))]
            let index = 0;
            self.routes = Some(crate::sysroute::SysRoutes::new(&self.tun_name, index));
        }
    }

    /// Act as a gateway (`[gateway]`).
    pub fn set_gateway(&mut self, gw: crate::gateway::Gateway) {
        self.gateway = Some(gw);
    }

    /// systemd-resolved serves `domain` from us (`[dns] manage_resolved`).
    pub fn manage_resolved(&mut self, domain: &str) {
        if self.tun.is_some() {
            self.resolved = Some(domain.to_owned());
        }
    }

    /// Part of the last plan could not be applied: the same plan again may help.
    pub fn retry(&self) -> bool {
        self.acl_failed
    }

    /// From `old` to `new` for node `me`. Blocking (runs `ip`, `nft`, `resolvectl`).
    pub fn apply(&mut self, me: &NodeId, old: &Plan, new: &Plan) {
        self.addresses(&old.addrs, &new.addrs);
        if let Some(r) = self.routes.as_mut() {
            r.apply(&crate::sysroute::Wanted::of(new));
        }
        if let Some(gw) = self.gateway.as_mut() {
            // also when members did not change: the gateway's own prefix may have come since
            gw.apply(&new.member_prefixes);
            gw.forward(&new.forwards);
        }
        if self.tun.is_some() {
            let chain = new.acl.as_ref().and_then(|a| a.render(me, &new.members.clone().into_iter().collect()));
            self.acl_failed = chain != self.acl && !crate::acl::apply_nft(&self.tun_name, chain.as_deref());
            if !self.acl_failed {
                self.acl = chain;
            }
        }
        // all names through us only when the whole node goes through the gateway: with
        // `[exit] v4_sources` the node itself resolves directly, as it reaches the internet
        let all = |p: &Plan| !p.dns_upstream.is_empty() && !p.exit_split();
        if let Some(domain) = &self.resolved
            && all(old) != all(new)
        {
            crate::dns::resolved_route_all(&self.tun_name, domain, all(new));
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn addresses(&self, _: &[IpNet], _: &[IpNet]) {}

    /// Our addresses on the TUN follow our certificate (`dvpn node set --addr`, public IPv6).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn addresses(&self, old: &[IpNet], new: &[IpNet]) {
        let Some(tun) = &self.tun else { return };
        for a in new.iter().filter(|a| !old.contains(a)) {
            let r = match a {
                IpNet::V4(n) => tun.add_address_v4(n.addr(), n.prefix_len()),
                IpNet::V6(n) => tun.add_address_v6(n.addr(), n.prefix_len()),
            };
            match r {
                Ok(()) => log::info!("TUN | address {a}"),
                Err(e) => log::warn!("TUN | add {a}: {e}"),
            }
        }
        for a in old.iter().filter(|a| !new.contains(a)) {
            let _ = tun.remove_address(a.addr());
        }
    }

    /// Windows: the interfaces DVPN's own socket must use now (`sysroute_win.rs`); `None` when
    /// routes are not managed.
    #[cfg(windows)]
    pub fn pin(&self) -> Option<[u32; 2]> {
        self.routes.as_ref().map(|r| r.pin())
    }

    /// Windows: looks at the physical network again (holes move with its default route);
    /// returns the interfaces to pin DVPN's socket to.
    #[cfg(windows)]
    pub fn underlay_changed(&mut self) -> Option<[u32; 2]> {
        self.routes.as_mut().and_then(|r| r.underlay_changed())
    }

    /// Removes what was applied (on exit): routes and rules, the gateway, the ACL.
    pub fn clear(&mut self) {
        if let Some(r) = self.routes.as_mut() {
            r.clear();
        }
        if let Some(gw) = self.gateway.as_mut() {
            gw.stop();
        }
        if self.acl.take().is_some() {
            crate::acl::apply_nft(&self.tun_name, None);
        }
        // systemd-resolved forgets the TUN link with it; Windows' NRPT rules stay
        #[cfg(windows)]
        if self.resolved.is_some() {
            crate::dns::resolved_clear();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// An ACL that could not be installed is tried again: it is not the one in place.
    #[test]
    fn failed_acl_is_tried_again() {
        use std::os::unix::fs::PermissionsExt;
        const NAME: &str = "apply::tests::failed_acl_is_tried_again";
        let tag = crate::crypto::encode_b64(&crate::crypto::random_bytes::<9>());
        let dir = std::env::temp_dir().join(format!("dvpn-nft-{tag}"));
        // `nft` that fails to load rules while the file `fail` is next to it; found first in PATH
        let script =
            "#!/bin/sh\n[ \"$1\" = -f ] && [ -e \"${0%/*}/fail\" ] && exit 1\nPATH=${PATH#*:}\nexec nft \"$@\"\n";
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nft"), script).unwrap();
        std::fs::set_permissions(dir.join("nft"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = std::panic::catch_unwind(|| crate::testutil::in_netns(NAME, Some(&dir)));
        std::fs::remove_dir_all(&dir).unwrap();
        match r {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => std::panic::resume_unwind(e),
        }
        let path = std::env::var("PATH").unwrap();
        let fail = std::path::Path::new(path.split(':').next().unwrap()).join("fail");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _in_rt = rt.enter();
        let tun = tun_rs::DeviceBuilder::new().name("dvpntest").build_async().unwrap();
        let mut sys = System::new(Some(Arc::new(tun)));
        let me = crate::identity::Identity::generate().id();
        let acl = crate::acl::Acl { default_deny: true, ..Default::default() };
        let members = [(me, vec!["10.0.0.1/32".parse().unwrap()])].into();
        let plan = Plan { acl: Some(acl), members, ..Default::default() };
        let installed = || {
            let o = std::process::Command::new("nft").args(["list", "table", "inet", "dvpn_acl"]).output().unwrap();
            o.status.success()
        };
        std::fs::write(&fail, "").unwrap();
        sys.apply(&me, &Plan::default(), &plan);
        assert!(!installed() && sys.retry(), "nft failed");
        std::fs::remove_file(&fail).unwrap();
        sys.apply(&me, &plan, &plan);
        assert!(installed() && !sys.retry(), "never tried again: no rules until the ACL changes");
    }
}
