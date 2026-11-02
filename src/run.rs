//! Running a node (PLAN 6.4, 7): everything `dvpn` does between reading the config and Ctrl+C,
//! as a library, so that the CLI and the mobile apps start the same node. The CLI builds the
//! TUN itself from `[net]`; on Android the TUN is the VpnService's and comes later
//! (`Node::set_tun`), built from the node's plan (`Node::set_plan_listener`), and the socket is kept out
//! of it by `protect`.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};

use crate::config::{Config, STATE_FILE_NAME};
use crate::node::{GroupCtx, Node};
use crate::state::StateStore;
use crate::storage::{PeerStorage, PeerUpdate};
use crate::tracker_client::TrackerClient;

/// Where the TUN comes from.
pub enum Tun {
    /// Created from `[net]` (Linux, Windows, macOS): with its addresses, and, where supported,
    /// the system routes, ACL, gateway and systemd-resolved managed by the node.
    FromConfig,
    /// Handed in later with `Node::set_tun` (Android, iOS): the platform applies the plan.
    External,
}

pub struct Options {
    /// The API socket (`api.rs`): a unix socket path or `ip:port`.
    pub api_addr: String,
    pub tun: Tun,
    /// Keeps the node's socket out of the overlay (Android `VpnService.protect`).
    pub protect: Option<crate::transport::Protect>,
    /// Called with the node's plan at start and whenever it changes: a VPN service builds its
    /// interface (addresses, routes, DNS) from it.
    pub on_plan: Option<crate::node::PlanListener>,
}

/// A started node.
pub struct Running {
    pub node: Arc<Node>,
    _api: Arc<crate::api::Api>,
}

impl Running {
    /// Undoes what the node changed in the system and says goodbye to the trackers.
    pub async fn shutdown(self) {
        self.node.set_tun(None);
        self.node.shutdown().await;
    }
}

/// The TUN device with the IPv4 address from the certificate and the group's IPv6 ULA.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn build_tun(
    net: &crate::config::NetConfig,
    addr: Ipv4Addr,
    ula: std::net::Ipv6Addr,
) -> anyhow::Result<tun_rs::AsyncDevice> {
    let dev = tun_rs::DeviceBuilder::new()
        .name(&net.tun_name)
        .ipv4(addr, net.prefix, None)
        .ipv6(ula, 48u8)
        .mtu(net.mtu)
        .build_async()?;
    Ok(dev)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn build_tun(_: &crate::config::NetConfig, _: Ipv4Addr, _: std::net::Ipv6Addr) -> anyhow::Result<tun_rs::AsyncDevice> {
    bail!("on this system the TUN comes from the VPN service (Tun::External)")
}

/// Starts the node of `conf` (its one group) with data in `dir`. Returns once it runs.
pub async fn start(mut conf: Config, dir: &Path, opts: Options) -> anyhow::Result<Running> {
    let group = match conf.groups.as_slice() {
        [] => bail!("not in any group: create one (dvpn group create) or join one (dvpn group join)"),
        [g] => g.clone(),
        _ => bail!("several groups per node come later (PLAN stage 3.5): leave all but one"),
    };
    let Some(mut cert) = group.cert.clone() else { bail!("no certificate for group {}", group.name) };
    let store = Arc::new(StateStore::open(dir.join(STATE_FILE_NAME)));
    // a renewed certificate may have arrived while the config was not updated
    if let Some(c) = store.cert(&group.id, &conf.identity.id())
        && c.body.not_after > cert.body.not_after
    {
        conf.set_group_cert(&group.id, &c);
        conf.save();
        cert = c;
    }
    if conf.too_open() {
        log::warn!("{} is readable by other users, but holds secrets: chmod 600 it", conf.path().display());
    }
    if !crate::clock::trusted() {
        log::warn!("The clock is earlier than this build: certificate expiry is not checked until it is set (NTP)");
    }
    if let Err(e) = cert.verify(&group.id, crate::clock::trusted_unix()) {
        bail!("own certificate in group {}: {e}; ask an admin for a new invite", group.name);
    }
    let self_addr = cert.body.ipv4();
    let storage = Arc::new(PeerStorage::new(conf.identity.id()));
    storage.set_peer(conf.identity.id(), PeerUpdate::from_cert(&cert));

    let api_sock =
        crate::api::ApiSocket::bind(&opts.api_addr).await.with_context(|| format!("API on {}", opts.api_addr))?;

    crate::logger::attach_storage(storage.clone());
    let external = matches!(opts.tun, Tun::External);
    if conf.net.is_none() && !external {
        log::info!("Network disabled");
    }
    if conf.servers.is_empty() {
        if conf.static_peers.is_empty() {
            log::warn!("No [servers] and no [[static_peers]]: only nodes that connect to this one are reachable");
        } else {
            log::info!("No [servers]: connecting to {} static peers only", conf.static_peers.len());
        }
    }

    let transport = crate::transport::Transport::new_protected(conf.peer.bind_addr, conf.peer.port_range, opts.protect)
        .await
        .context("peer socket")?;
    if let Ok(a) = transport.local_addr() {
        log::info!("Peer | Listen address: {a}");
    }

    if let Some(net) = &conf.net
        && net.mtu < 1280
    {
        bail!("[net] mtu {} is below 1280, the minimum for IPv6", net.mtu);
    }
    let tun = match (&conf.net, external) {
        (Some(net), false) => {
            let addr = self_addr.ok_or_else(|| anyhow!("the group certificate has no IPv4 address for the TUN"))?;
            let ula = crate::ckr::ula_addr(&group.id, &conf.identity.id());
            let dev = build_tun(net, addr, ula).context("TUN")?;
            log::info!("TUN | {} {addr}/{} {ula}/48 mtu {} - started", net.tun_name, net.prefix, net.mtu);
            // public IPv6 addresses an admin gave this node (served by a gateway's NDP proxy)
            #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
            for p in &cert.body.prefixes {
                if let ipnet::IpNet::V6(n) = p
                    && n.prefix_len() == 128
                {
                    match dev.add_address_v6(n.addr(), 128u8) {
                        Ok(()) => log::info!("TUN | {} {}/128", net.tun_name, n.addr()),
                        Err(e) => log::warn!("TUN | add {}: {e}", n.addr()),
                    }
                }
            }
            Some(dev)
        }
        _ => None,
    };

    log::info!("Group {} ({}) as {}", group.name, group.id.short(), cert.body.name);
    let identity = Arc::new(conf.identity.clone());
    let links = crate::link::Links::new(
        identity.clone(),
        crate::link::Group { id: group.id, psk: group.psk, obfs: group.obfs.clone(), cert: cert.clone() },
    );
    // end-to-end sessions through relays: carried inside link sessions, no masking of their own
    let e2e = crate::link::Links::new(
        identity.clone(),
        crate::link::Group { id: group.id, psk: group.psk, obfs: crate::obfs::Profile::none(), cert: cert.clone() },
    );
    let clients = conf
        .servers
        .iter()
        .map(|s| {
            TrackerClient::new(
                s.name.clone(),
                s.addrs.clone(),
                s.key,
                identity.clone(),
                vec![cert.clone()],
                store.clone(),
            )
        })
        .collect();
    let group_id = group.id;
    let (dir1, dir2) = (dir.to_path_buf(), dir.to_path_buf());
    let upstream: crate::dns::Upstream = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    // the DNS server: on our address on a TUN of our own, inside the TUN loop on a VPN's
    let has_tun = tun.is_some() || (external && conf.net.is_some());
    let dns = (conf.dns.enable && has_tun && self_addr.is_some())
        .then(|| (conf.dns.domain.clone(), Arc::new(arc_swap::ArcSwap::from_pointee(crate::dns::Zone::new()))));
    let ctx = GroupCtx {
        id: group.id,
        secret: group.secret.clone(),
        cert: cert.clone(),
        store,
        epoch: group.epoch,
        psk: group.psk,
        identity: identity.clone(),
        on_cert: Box::new(move |c| match Config::load(&dir1) {
            Ok(mut conf) => {
                conf.set_group_cert(&group_id, c);
                conf.save();
            }
            Err(e) => log::warn!("Config | renewed certificate not saved: {e:#}"),
        }),
        statics: conf.static_peers.clone(),
        routes: conf.remote_subnets.clone(),
        exits: conf.exits.clone(),
        tun_prefix: conf.net.as_ref().map_or(24, |n| n.prefix),
        group_name: group.name.clone(),
        dns: dns.clone(),
        dns_upstream: upstream.clone(),
        resolved_tun: conf
            .net
            .as_ref()
            .filter(|_| !external && conf.dns.manage_resolved && dns.is_some())
            .map(|n| n.tun_name.clone()),
        tun_dns: external && dns.is_some(),
        config_path: conf.path().to_path_buf(),
        on_epoch: Box::new(move |epoch, psk| match Config::load(&dir2) {
            Ok(mut conf) => {
                conf.set_group_epoch(&group_id, epoch, &psk);
                conf.save();
            }
            Err(e) => log::warn!("Config | new psk epoch not saved: {e:#}"),
        }),
    };
    let node = Node::new(storage.clone(), transport, (links, e2e), clients, tun, self_addr, ctx);
    if !external {
        if conf.net.as_ref().is_some_and(|n| n.manage_routes) {
            node.manage_routes();
        }
        if let (Some((domain, zone)), Some(addr), Some(net)) = (&dns, self_addr, &conf.net) {
            tokio::spawn(crate::dns::serve(std::net::IpAddr::V4(addr), zone.clone(), domain.clone(), upstream.clone()));
            crate::dns::enable_multicast(&net.tun_name);
            if conf.dns.manage_resolved {
                let (tun, domain) = (net.tun_name.clone(), domain.clone());
                tokio::task::spawn_blocking(move || {
                    crate::dns::configure_resolved(&tun, std::net::IpAddr::V4(addr), &domain)
                });
            }
        }
        if let (Some(gw), Some(net)) = (&conf.gateway, &conf.net) {
            let ula = crate::ckr::ula_prefix(&group.id);
            let g = tokio::task::block_in_place(|| {
                crate::gateway::Gateway::start(&net.tun_name, &gw.wan, gw.ndp_proxy.clone(), ula, gw.manage_sysctl)
            });
            node.set_gateway(g);
        }
    }
    if let Some(f) = opts.on_plan {
        node.set_plan_listener(f);
    }
    node.start();
    let api = crate::api::Api::start(node.clone(), api_sock, conf.api_token_all);
    Ok(Running { node, _api: api })
}
