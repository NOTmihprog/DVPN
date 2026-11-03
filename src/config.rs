use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use ed25519_dalek::VerifyingKey;
use log::LevelFilter;
use rand::RngExt;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::crypto::{decode_b64, decode_key32, encode_b64};
use crate::group::{Cert, GroupId, GroupSecret, StaticRef, TrackerRef};
use crate::identity::Identity;
use crate::obfs::{MAX_PAD, MAX_WIRE, Profile, Template};

pub const CONFIG_FILE_NAME: &str = "config.toml";
/// Group records (`state.rs`), next to the config.
pub const STATE_FILE_NAME: &str = "state.bin";
/// Overrides `[identity] private_key`; never written to the config file.
pub const PRIVATE_KEY_ENV: &str = "DVPN_PRIVATE_KEY";

#[cfg(unix)]
pub const SOCKET_DEFAULT_DIR: &str = "/run/dvpn";
pub const SOCKET_DEFAULT_ADDR: &str = "127.0.0.1:9902";

/// Prepended to `config.toml` when it has no `[identity]` (new file, or one from v3).
const IDENTITY_SECTION: &str = r#"[identity]
# Node private key (Ed25519 seed, base64url). The public key derived from it is the node id:
# dvpn show-key. The DVPN_PRIVATE_KEY environment variable overrides it. Keep it secret.
private_key = "{private_key}"

"#;

const DEFAULT_CONFIG: &str = r#"[peer]
# local bind ip: "::" = IPv6 and IPv4 on one socket, "0.0.0.0" = IPv4 only
bind_addr = "::"

# local port or port range, example: "8647", "8647-9942"
bind_port = "8647-9942"

# Discovery servers, any number of [servers.<name>] sections; `dvpn group join` adds the
# ones from the invite. key = server Ed25519 public key, printed by `dvpn server` on start.
# [servers.example]
# addr = "203.0.113.10"
# port = 6485
# key = "..."

[net]
# tun interface name (Wintun adapter name on windows)
tun_name = "dnet"
mtu = 1350
# netmask of the group network as "255.255.255.0" or prefix length "24";
# the own address comes from the group certificate
mask = "255.255.255.0"

# Groups ([[groups]] sections) are written by `dvpn group create` (new group, this node is its
# admin) and `dvpn group join <invite>`; see `dvpn group --help`.

[app]
# Log Levels DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "INFO"
"#;

pub struct PeerConfig {
    pub bind_addr: IpAddr,
    pub port_range: (u16, u16),
}

pub struct NetConfig {
    pub tun_name: String,
    pub mtu: u16,
    /// Prefix length of the group network; the address itself comes from the certificate.
    pub prefix: u8,
    /// Install system routes for subnets behind other nodes and exits (default on).
    pub manage_routes: bool,
}

pub struct ServerConfig {
    pub name: String,
    /// As written (domain or IP), for invites.
    pub host: String,
    pub port: u16,
    /// Every address the host resolved to, IPv6 first (they are all tried at once).
    pub addrs: Vec<SocketAddr>,
    pub key: VerifyingKey,
}

impl ServerConfig {
    pub fn tracker_ref(&self) -> TrackerRef {
        TrackerRef { host: self.host.clone(), port: self.port, key: self.key.to_bytes() }
    }
}

/// A `[[groups]]` entry (PLAN §12).
#[derive(Clone, Debug)]
pub struct GroupConfig {
    pub name: String,
    pub id: GroupId,
    /// Admins only.
    pub secret: Option<GroupSecret>,
    pub epoch: u32,
    pub psk: [u8; 32],
    /// This node's membership certificate.
    pub cert: Option<Cert>,
    pub obfs: Profile,
    /// `[groups.obfs]` as written, passed on in invites.
    pub obfs_entries: Vec<(String, String)>,
}

impl GroupConfig {
    /// The own IPv4 address in the group: the first IPv4 host of the certificate.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.cert.as_ref()?.body.ipv4()
    }
}

pub struct Config {
    path: PathBuf,
    doc: DocumentMut,
    pub identity: Identity,
    pub groups: Vec<GroupConfig>,
    /// `[[static_peers]]`: nodes connected to directly, without a tracker (PLAN §10).
    pub static_peers: Vec<StaticRef>,
    /// `[ckr.remote_subnets]`: manual routes, `"<node key>" = ["192.168.50.0/24", "~10.0.0.0/8"]`.
    pub remote_subnets: Vec<crate::ckr::Route>,
    /// `[exit]`: gateways to the internet, by priority.
    pub exits: Exits,
    /// `[gateway]`: this node is a gateway to the internet for members.
    pub gateway: Option<GatewayConfig>,
    /// `[dns]`: names of members (on by default when there is a TUN).
    pub dns: DnsConfig,
    pub peer: PeerConfig,
    pub net: Option<NetConfig>,
    pub servers: Vec<ServerConfig>,
    pub log_level: LevelFilter,
    pub local_server_key: Option<[u8; 32]>,
    /// `[api] token = "all"`: on a UDP API, reading needs the token too (not only changes).
    pub api_token_all: bool,
}

/// Writes a file that holds private keys: created as 0600 on unix, and an existing file is
/// narrowed to 0600 too (§14a).
#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // mode() applies on creation, so a new file is never world-readable even briefly
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(text.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)?;
    restrict_private(path)
}

/// Windows: the file for SYSTEM, Administrators and its owner only, not inherited from its
/// folder (where `Users` may read): what 0600 is on unix (PLAN 3.14).
#[cfg(windows)]
pub fn restrict_private(path: &Path) -> std::io::Result<()> {
    // SYSTEM, Administrators, OWNER RIGHTS: by SID, the names are translated
    let ok = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-3-4:F"])
        .output()
        .is_ok_and(|o| o.status.success());
    if ok { Ok(()) } else { Err(std::io::Error::other("icacls could not restrict the file")) }
}

#[cfg(not(any(unix, windows)))]
pub fn restrict_private(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// A random host address in `net/prefix` (not the network or broadcast address).
pub fn random_host(net: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let hosts = (1u32 << (32 - prefix)) - 2;
    let n = rand::rng().random_range(1..=hosts);
    Ipv4Addr::from(u32::from(net) + n)
}

pub fn parse_mask(s: &str) -> anyhow::Result<u8> {
    if let Ok(prefix) = s.parse::<u8>() {
        if prefix <= 32 {
            return Ok(prefix);
        }
        bail!("prefix {prefix} > 32");
    }
    let m = u32::from(s.parse::<Ipv4Addr>().context("not an ipv4 mask")?);
    if m.leading_ones() + m.trailing_zeros() != 32 {
        bail!("mask {s} is not contiguous");
    }
    Ok(m.leading_ones() as u8)
}

/// "a-b" or "a" (also an integer value) as an inclusive range.
fn parse_range<T: std::str::FromStr + PartialOrd + std::fmt::Display>(s: &str) -> anyhow::Result<RangeInclusive<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let (a, b): (T, T) = (a.trim().parse()?, b.trim().parse()?);
    if a > b {
        bail!("{a} > {b}");
    }
    Ok(a..=b)
}

/// `[groups.obfs]` entries as text, in file order: integers and booleans are written as text too.
fn obfs_entries(t: &Table) -> anyhow::Result<Vec<(String, String)>> {
    t.iter()
        .map(|(k, item)| {
            let v = match item.as_value() {
                Some(toml_edit::Value::String(s)) => s.value().clone(),
                Some(toml_edit::Value::Integer(i)) => i.value().to_string(),
                Some(toml_edit::Value::Boolean(b)) => b.value().to_string(),
                _ => bail!("{k}: expected a string, integer or boolean"),
            };
            Ok((k.to_owned(), v))
        })
        .collect()
}

/// The group's obfuscation profile (PLAN §4.4) from `[groups.obfs]` entries. Unknown keys are
/// errors, so a typo cannot silently fall back to defaults.
pub fn parse_obfs(entries: &[(String, String)]) -> anyhow::Result<Profile> {
    let mut p = Profile::default();
    let (mut jmin, mut jmax) = (*p.junk_size.start(), *p.junk_size.end());
    let mut signatures: [Option<Template>; 5] = Default::default();
    for (key, text) in entries {
        let key = key.as_str();
        let pad = || -> anyhow::Result<RangeInclusive<u16>> {
            let r = parse_range::<u16>(text).with_context(|| key.to_owned())?;
            if *r.end() as usize > MAX_PAD {
                bail!("{key}: padding above {MAX_PAD}");
            }
            Ok(r)
        };
        match key {
            "jc" => p.junk_count = parse_range::<u8>(text).context("jc")?,
            "jmin" => jmin = text.trim().parse().context("jmin")?,
            "jmax" => jmax = text.trim().parse().context("jmax")?,
            "s1" => p.init_pad = pad()?,
            "s2" => p.resp_pad = pad()?,
            "s4" => p.data_pad = pad()?,
            "i1" | "i2" | "i3" | "i4" | "i5" => {
                let i = key.as_bytes()[1] - b'1';
                signatures[i as usize] = Some(text.parse().map_err(|e| anyhow!("{key}: {e}"))?);
            }
            "header_protection" => {
                if text != "true" {
                    bail!("header_protection cannot be turned off: basic masking is always on");
                }
            }
            _ => bail!("unknown key {key}"),
        }
    }
    if jmin > jmax || jmax as usize > MAX_WIRE {
        bail!("need jmin <= jmax <= {MAX_WIRE}, got {jmin}..{jmax}");
    }
    p.junk_size = jmin..=jmax;
    p.signatures = signatures.into_iter().flatten().collect();
    Ok(p)
}

/// `host:port`, `ip:port` or `[ipv6]:port`.
pub fn check_endpoint(s: &str) -> anyhow::Result<()> {
    let (host, port) = s.rsplit_once(':').ok_or_else(|| anyhow!("{s}: expected host:port"))?;
    port.parse::<u16>().map_err(|_| anyhow!("{s}: bad port"))?;
    if host.is_empty() {
        bail!("{s}: empty host");
    }
    Ok(())
}

/// `[exit]`: the gateways this node sends its internet traffic through, in priority order
/// (member names or node keys); the first one alive is used. Empty: no exit, the internet is
/// reached directly as without DVPN.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exits {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
    /// With gateways configured but none alive, keep the internet in the tunnel (dropped)
    /// instead of letting it go direct. `None` = on (the default whenever gateways are set).
    pub kill_switch: Option<bool>,
    /// DNS servers to use through the gateway while it is active (no DNS leak to the local
    /// network or the provider).
    pub dns: Vec<std::net::IpAddr>,
    /// Only these sources go through the gateway (policy routing: `ip rule from <src> lookup
    /// <table>`); the node itself and everything else reach the internet directly. Empty: the
    /// whole node goes through the gateway, unless `table` is set.
    pub v4_sources: Vec<ipnet::Ipv4Net>,
    pub v6_sources: Vec<ipnet::Ipv6Net>,
    /// The routing table for the internet routes (gateway and kill switch) instead of DVPN's
    /// own. Without `*_sources` DVPN adds no rule for it: the system's own rules (a fwmark, an
    /// interface) decide what goes there.
    pub table: Option<u32>,
}

impl Exits {
    pub fn kill_switch(&self) -> bool {
        self.kill_switch.unwrap_or(true)
    }

    /// The internet routes go to their own table, not to everyone (`*_sources` or `table`).
    pub fn split(&self) -> bool {
        self.table.is_some() || !self.v4_sources.is_empty() || !self.v6_sources.is_empty()
    }

    /// The sources routed through the gateway, both families.
    pub fn sources(&self) -> Vec<ipnet::IpNet> {
        let v4 = self.v4_sources.iter().map(|n| ipnet::IpNet::V4(n.trunc()));
        v4.chain(self.v6_sources.iter().map(|n| ipnet::IpNet::V6(n.trunc()))).collect()
    }
}

/// Tables `[exit] table` may not name: unspec, default, main, local and DVPN's own.
pub fn check_table(n: i64) -> anyhow::Result<u32> {
    let t = u32::try_from(n).map_err(|_| anyhow!("table: {n} is not a table number"))?;
    if t == 0 || (253..=255).contains(&t) || t == crate::sysroute::TABLE {
        bail!("table: {t} is reserved (0, 253-255 are the system's, {} is DVPN's)", crate::sysroute::TABLE);
    }
    Ok(t)
}

fn parse_exits(t: &dyn toml_edit::TableLike) -> anyhow::Result<Exits> {
    let list = |k: &str| -> anyhow::Result<Vec<String>> {
        let Some(item) = t.get(k) else { return Ok(Vec::new()) };
        let arr = item.as_array().ok_or_else(|| anyhow!("{k}: expected a list of names or keys"))?;
        arr.iter()
            .map(|v| v.as_str().map(|s| s.trim().to_owned()).ok_or_else(|| anyhow!("{k}: expected strings")))
            .filter(|r| r.as_ref().map_or(true, |s| !s.is_empty()))
            .collect()
    };
    for (k, _) in t.iter() {
        if !["v4", "v6", "kill_switch", "dns", "v4_sources", "v6_sources", "table"].contains(&k) {
            bail!("unknown key {k}");
        }
    }
    let kill_switch = match t.get("kill_switch") {
        Some(v) => Some(v.as_bool().ok_or_else(|| anyhow!("kill_switch: true or false"))?),
        None => None,
    };
    let dns = list("dns")?
        .iter()
        .map(|s| s.parse().map_err(|_| anyhow!("dns: {s} is not an IP address")))
        .collect::<anyhow::Result<_>>()?;
    let v4_sources = list("v4_sources")?
        .iter()
        .map(|s| {
            parse_source::<ipnet::Ipv4Net, std::net::Ipv4Addr>(s)
                .map_err(|_| anyhow!("v4_sources: {s} is not an IPv4 network"))
        })
        .collect::<anyhow::Result<_>>()?;
    let v6_sources = list("v6_sources")?
        .iter()
        .map(|s| {
            parse_source::<ipnet::Ipv6Net, std::net::Ipv6Addr>(s)
                .map_err(|_| anyhow!("v6_sources: {s} is not an IPv6 network"))
        })
        .collect::<anyhow::Result<_>>()?;
    let table = match t.get("table") {
        Some(v) => Some(check_table(v.as_integer().ok_or_else(|| anyhow!("table: expected a number"))?)?),
        None => None,
    };
    Ok(Exits { v4: list("v4")?, v6: list("v6")?, kill_switch, dns, v4_sources, v6_sources, table })
}

/// A network, or an address alone (/32, /128).
fn parse_source<N: std::str::FromStr + From<A>, A: std::str::FromStr>(s: &str) -> Result<N, ()> {
    s.parse::<N>().or_else(|_| s.parse::<A>().map(N::from)).map_err(|_| ())
}

/// `[gateway]` (PLAN §12): NAT from the tunnel to `wan`, optional NDP proxy for members'
/// public IPv6 addresses on `ndp_proxy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayConfig {
    pub wan: Vec<String>,
    pub ndp_proxy: Option<String>,
    pub manage_sysctl: bool,
}

fn parse_gateway(t: &Table) -> anyhow::Result<GatewayConfig> {
    let wan: Vec<String> = match t.get("wan") {
        Some(i) => i
            .as_array()
            .ok_or_else(|| anyhow!("wan: expected a list of interfaces"))?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| anyhow!("wan: expected strings")))
            .collect::<anyhow::Result<_>>()?,
        None => Vec::new(),
    };
    if wan.is_empty() {
        bail!("wan: give the interfaces towards the internet, e.g. wan = [\"eth0\"]");
    }
    let ndp_proxy = match t.get("ndp_proxy") {
        Some(_) => Some(get_str(t, "ndp_proxy")?.to_owned()),
        None => None,
    };
    let manage_sysctl = match t.get("manage_sysctl") {
        Some(v) => v.as_bool().ok_or_else(|| anyhow!("manage_sysctl: expected true or false"))?,
        None => true,
    };
    for (k, _) in t.iter() {
        if !["wan", "ndp_proxy", "manage_sysctl"].contains(&k) {
            bail!("unknown key {k}");
        }
    }
    Ok(GatewayConfig { wan, ndp_proxy, manage_sysctl })
}

/// `[dns]`: `enable`, `domain` (default "dvpn"), `manage_resolved` (split DNS via systemd-resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsConfig {
    pub enable: bool,
    pub domain: String,
    pub manage_resolved: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig { enable: true, domain: "dvpn".into(), manage_resolved: true }
    }
}

/// `[api]`: `token = "write"` (default: on a UDP API only changes need the token) or `"all"`.
fn parse_api(t: &Table) -> anyhow::Result<bool> {
    let mut all = false;
    for (k, v) in t.iter() {
        match k {
            "token" => {
                all = match v.as_str() {
                    Some("write") => false,
                    Some("all") => true,
                    _ => bail!("token: \"write\" or \"all\""),
                }
            }
            _ => bail!("unknown key {k}"),
        }
    }
    Ok(all)
}

fn parse_dns(t: &Table) -> anyhow::Result<DnsConfig> {
    let mut d = DnsConfig::default();
    for (k, v) in t.iter() {
        match k {
            "enable" => d.enable = v.as_bool().ok_or_else(|| anyhow!("enable: true or false"))?,
            "manage_resolved" => {
                d.manage_resolved = v.as_bool().ok_or_else(|| anyhow!("manage_resolved: true or false"))?
            }
            "domain" => {
                d.domain = v.as_str().ok_or_else(|| anyhow!("domain: a string"))?.trim_matches('.').to_lowercase();
                if d.domain.is_empty() {
                    bail!("domain is empty");
                }
            }
            _ => bail!("unknown key {k}"),
        }
    }
    Ok(d)
}

/// Writes `exits` as the `[exit]` table of `doc` (none: removes it).
fn put_exits(doc: &mut DocumentMut, exits: &Exits) {
    if exits == &Exits::default() {
        doc.remove("exit");
    } else {
        let mut t = Table::new();
        for (k, v) in [("v4", &exits.v4), ("v6", &exits.v6)] {
            if !v.is_empty() {
                let mut arr = toml_edit::Array::new();
                for e in v {
                    arr.push(e.as_str());
                }
                t[k] = value(arr);
            }
        }
        if let Some(k) = exits.kill_switch {
            t["kill_switch"] = value(k);
        }
        if !exits.dns.is_empty() {
            let mut arr = toml_edit::Array::new();
            for d in &exits.dns {
                arr.push(d.to_string());
            }
            t["dns"] = value(arr);
        }
        let sources = |v: Vec<String>| {
            let mut arr = toml_edit::Array::new();
            v.iter().for_each(|s| arr.push(s.as_str()));
            value(arr)
        };
        if !exits.v4_sources.is_empty() {
            t["v4_sources"] = sources(exits.v4_sources.iter().map(|n| n.to_string()).collect());
        }
        if !exits.v6_sources.is_empty() {
            t["v6_sources"] = sources(exits.v6_sources.iter().map(|n| n.to_string()).collect());
        }
        if let Some(n) = exits.table {
            t["table"] = value(i64::from(n));
        }
        t.decor_mut()
            .set_prefix("\n# gateways to the internet by priority (names or keys); the first alive one is used\n");
        doc["exit"] = Item::Table(t);
    }
}

/// Replaces `[exit]` in the config file at `path`, leaving the rest as it is: for a running node,
/// which keeps no `Config` (`dvpn exit` and the API's `set exit` go through here or `set_exits`).
pub fn write_exits(path: &Path, exits: &Exits) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut doc: DocumentMut = text.parse().with_context(|| format!("parse {}", path.display()))?;
    put_exits(&mut doc, exits);
    write_private(path, &doc.to_string()).with_context(|| format!("write {}", path.display()))
}

/// Reads only `[exit]` from a config file: a running node follows changes to it.
pub fn read_exits(path: &Path) -> anyhow::Result<Exits> {
    let doc: DocumentMut = std::fs::read_to_string(path)?.parse()?;
    match doc.get("exit") {
        Some(item) => parse_exits(item.as_table_like().ok_or_else(|| anyhow!("[exit] is not a table"))?),
        None => Ok(Exits::default()),
    }
}

fn parse_remote_subnets(t: &dyn toml_edit::TableLike) -> anyhow::Result<Vec<crate::ckr::Route>> {
    let mut out = Vec::new();
    for (k, v) in t.iter() {
        let node: crate::identity::NodeId = k.parse().map_err(|e| anyhow!("\"{k}\": {e} (give the full node key)"))?;
        let arr = v.as_array().ok_or_else(|| anyhow!("\"{k}\": expected a list of prefixes"))?;
        for item in arr {
            let spec = item.as_str().ok_or_else(|| anyhow!("\"{k}\": expected strings"))?;
            out.extend(crate::ckr::parse_spec(spec, node).map_err(|e| anyhow!("\"{k}\": {e}"))?);
        }
    }
    Ok(out)
}

fn parse_static_peer(t: &Table) -> anyhow::Result<StaticRef> {
    let key = get_str(t, "key")?.parse().map_err(|e| anyhow!("key: {e}"))?;
    let arr = t.get("endpoints").and_then(Item::as_array).ok_or_else(|| anyhow!("endpoints: expected a list"))?;
    let mut endpoints = Vec::new();
    for v in arr {
        let e = v.as_str().ok_or_else(|| anyhow!("endpoints: expected strings"))?;
        check_endpoint(e)?;
        endpoints.push(e.to_owned());
    }
    if endpoints.is_empty() {
        bail!("endpoints: empty");
    }
    // `group` (which group's psk) is accepted for the format of PLAN §12; with one group per
    // node it is that group
    Ok(StaticRef { key, endpoints })
}

fn parse_group(t: &Table) -> anyhow::Result<GroupConfig> {
    let name = get_str(t, "name")?.to_owned();
    let epoch = match t.get("epoch") {
        Some(i) => u32::try_from(i.as_integer().ok_or_else(|| anyhow!("epoch is not an integer"))?).context("epoch")?,
        None => 0,
    };
    let secret = match t.get("secret") {
        Some(_) => Some(GroupSecret::from_bytes(decode_key32(get_str(t, "secret")?).context("secret")?)),
        None => None,
    };
    let id: Option<GroupId> = match t.get("id") {
        Some(_) => Some(get_str(t, "id")?.parse().map_err(|e| anyhow!("id: {e}"))?),
        None => None,
    };
    let (id, psk) = match &secret {
        Some(sec) => {
            if id.is_some_and(|id| id != sec.id()) {
                bail!("id does not match the secret");
            }
            (sec.id(), sec.psk(epoch))
        }
        None => (
            id.ok_or_else(|| anyhow!("id not found"))?,
            decode_key32(get_str(t, "psk").context("members need psk (admins: secret)")?).context("psk")?,
        ),
    };
    let cert = match t.get("cert") {
        Some(_) => {
            let bytes = decode_b64(get_str(t, "cert")?).context("cert")?;
            let cert = Cert::decode(&bytes).ok_or_else(|| anyhow!("cert: not a certificate"))?;
            cert.verify(&id, None).map_err(|e| anyhow!("cert: {e}"))?;
            Some(cert)
        }
        None => None,
    };
    let obfs_entries = match t.get("obfs") {
        Some(item) => obfs_entries(item.as_table().ok_or_else(|| anyhow!("obfs is not a table"))?)?,
        None => Vec::new(),
    };
    let obfs = parse_obfs(&obfs_entries).map_err(|e| anyhow!("[groups.obfs] {e:#}"))?;
    Ok(GroupConfig { name, id, secret, epoch, psk, cert, obfs, obfs_entries })
}

pub fn parse_port_range(s: &str) -> anyhow::Result<(u16, u16)> {
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let (a, b): (u16, u16) = (a.trim().parse()?, b.trim().parse()?);
    if a > b {
        bail!("{a} > {b}");
    }
    Ok((a, b))
}

fn get_str<'a>(t: &'a Table, key: &str) -> anyhow::Result<&'a str> {
    t.get(key).ok_or_else(|| anyhow!("{key} not found"))?.as_str().ok_or_else(|| anyhow!("{key} is not a string"))
}

/// Ports are accepted both as `8647` and `"8647-9942"`.
fn get_str_or_int(t: &Table, key: &str) -> anyhow::Result<String> {
    let item = t.get(key).ok_or_else(|| anyhow!("{key} not found"))?;
    if let Some(i) = item.as_integer() {
        return Ok(i.to_string());
    }
    item.as_str().map(str::to_owned).ok_or_else(|| anyhow!("{key} is not a string or integer"))
}

fn section<'a>(doc: &'a DocumentMut, name: &str) -> Option<&'a Table> {
    doc.get(name).and_then(Item::as_table)
}

fn parse_peer(t: &Table) -> anyhow::Result<PeerConfig> {
    let bind_addr = get_str(t, "bind_addr")?.parse().context("bind_addr")?;
    let port_range = parse_port_range(&get_str_or_int(t, "bind_port")?).context("bind_port")?;
    // a v3 `peer_id` key is ignored: the node id is the [identity] public key now
    Ok(PeerConfig { bind_addr, port_range })
}

fn parse_net(t: &Table) -> anyhow::Result<NetConfig> {
    let tun_name = get_str(t, "tun_name")?.to_owned();
    let mtu = get_str_or_int(t, "mtu")?.parse().context("mtu")?;
    // a v3 / early v4 `addr` key is ignored: the address comes from the group certificate
    let prefix = parse_mask(&get_str_or_int(t, "mask")?).context("mask")?;
    let manage_routes = match t.get("manage_routes") {
        Some(v) => v.as_bool().ok_or_else(|| anyhow!("manage_routes: expected true or false"))?,
        None => true,
    };
    Ok(NetConfig { tun_name, mtu, prefix, manage_routes })
}

fn parse_server(name: &str, t: &Table) -> anyhow::Result<ServerConfig> {
    let host = get_str(t, "addr")?;
    let port: u16 = get_str_or_int(t, "port")?.parse().context("port")?;
    let mut addrs: Vec<SocketAddr> = (host.trim_start_matches('[').trim_end_matches(']'), port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}"))?
        .map(crate::transport::normalize)
        .collect();
    addrs.sort_by_key(|a| (a.is_ipv4(), *a));
    addrs.dedup();
    if addrs.is_empty() {
        bail!("{host} has no address");
    }
    let key_bytes = decode_key32(get_str(t, "key")?).context("key")?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| anyhow!("key: {e}"))?;
    Ok(ServerConfig { name: name.to_owned(), host: host.to_owned(), port, addrs, key })
}

fn parse_log_level(s: &str) -> anyhow::Result<LevelFilter> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" | "none" => LevelFilter::Info,
        "warning" | "warn" => LevelFilter::Warn,
        "error" | "critical" => LevelFilter::Error,
        "trace" => LevelFilter::Trace,
        _ => bail!("unknown log level {s}"),
    })
}

impl Config {
    /// Loads `config.toml` from `dir`, creating a default one if missing. The node key comes
    /// from `DVPN_PRIVATE_KEY` if set, else from `[identity]`, else a new one is generated and
    /// written to the file.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        Self::load_with_env_key(dir, std::env::var(PRIVATE_KEY_ENV).ok())
    }

    fn load_with_env_key(dir: &Path, env_key: Option<String>) -> anyhow::Result<Self> {
        let path = dir.join(CONFIG_FILE_NAME);
        if !path.exists() {
            write_private(&path, DEFAULT_CONFIG).with_context(|| format!("create {}", path.display()))?;
        }
        let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let mut doc: DocumentMut = text.parse().with_context(|| format!("parse {}", path.display()))?;
        let file = CONFIG_FILE_NAME;

        let file_key = match section(&doc, "identity").and_then(|t| t.get("private_key")) {
            Some(item) => {
                let s = item.as_str().ok_or_else(|| anyhow!("[identity] private_key is not a string in {file}"))?;
                Some(Identity::from_private_key_text(s).map_err(|e| anyhow!("[identity] private_key: {e} in {file}"))?)
            }
            None => None,
        };
        let env_key = env_key.filter(|s| !s.trim().is_empty());
        let identity = match (env_key, file_key) {
            (Some(s), _) => Identity::from_private_key_text(&s).map_err(|e| anyhow!("{PRIVATE_KEY_ENV}: {e}"))?,
            (None, Some(id)) => id,
            (None, None) => {
                let id = Identity::generate();
                let text = IDENTITY_SECTION.replace("{private_key}", &id.private_key_text()) + &doc.to_string();
                doc = text.parse().with_context(|| format!("parse {}", path.display()))?;
                write_private(&path, &text).with_context(|| format!("write {}", path.display()))?;
                log::info!("Generated a new node key, saved to [identity] in {file}");
                id
            }
        };

        let peer = parse_peer(section(&doc, "peer").ok_or_else(|| anyhow!("[peer] not found in {file}"))?)
            .map_err(|e| anyhow!("[peer] {e:#} in {file}"))?;

        let net = match section(&doc, "net") {
            Some(t) => Some(parse_net(t).map_err(|e| anyhow!("[net] {e:#} in {file}"))?),
            None => {
                log::info!("Section [net] not found in {file}, network disabled");
                None
            }
        };

        let mut servers = Vec::new();
        if let Some(t) = section(&doc, "servers") {
            for (name, item) in t.iter() {
                let st = item.as_table().ok_or_else(|| anyhow!("[servers.{name}] is not a table"))?;
                servers.push(parse_server(name, st).map_err(|e| anyhow!("[servers.{name}] {e:#} in {file}"))?);
            }
        }

        let log_level = match section(&doc, "app").and_then(|t| t.get("log_level")).and_then(Item::as_str) {
            Some(s) => parse_log_level(s).map_err(|e| anyhow!("[app] log_level: {e} in {file}"))?,
            None => LevelFilter::Info,
        };

        let local_server_key = match section(&doc, "local_server").and_then(|t| t.get("private_key")) {
            Some(item) => {
                let s = item.as_str().ok_or_else(|| anyhow!("[local_server] private_key is not a string"))?;
                Some(decode_key32(s).map_err(|e| anyhow!("[local_server] private_key: {e}"))?)
            }
            None => None,
        };

        let mut groups: Vec<GroupConfig> = Vec::new();
        if let Some(item) = doc.get("groups") {
            let arr =
                item.as_array_of_tables().ok_or_else(|| anyhow!("groups must be [[groups]] sections in {file}"))?;
            for (i, t) in arr.iter().enumerate() {
                let g = parse_group(t).map_err(|e| anyhow!("[[groups]] #{} {e:#} in {file}", i + 1))?;
                if groups.iter().any(|o| o.name == g.name || o.id == g.id) {
                    bail!("[[groups]] {} is listed twice in {file}", g.name);
                }
                groups.push(g);
            }
        }
        let mut static_peers = Vec::new();
        if let Some(item) = doc.get("static_peers") {
            let arr = item
                .as_array_of_tables()
                .ok_or_else(|| anyhow!("static_peers must be [[static_peers]] sections in {file}"))?;
            for (i, t) in arr.iter().enumerate() {
                static_peers
                    .push(parse_static_peer(t).map_err(|e| anyhow!("[[static_peers]] #{} {e:#} in {file}", i + 1))?);
            }
        }
        let remote_subnets = match section(&doc, "ckr").and_then(|c| c.get("remote_subnets")) {
            Some(item) => {
                let t = item.as_table_like().ok_or_else(|| anyhow!("[ckr.remote_subnets] is not a table in {file}"))?;
                parse_remote_subnets(t).map_err(|e| anyhow!("[ckr.remote_subnets] {e:#} in {file}"))?
            }
            None => Vec::new(),
        };
        let exits = match doc.get("exit") {
            Some(item) => parse_exits(item.as_table_like().ok_or_else(|| anyhow!("[exit] is not a table in {file}"))?)
                .map_err(|e| anyhow!("[exit] {e:#} in {file}"))?,
            None => Exits::default(),
        };
        let gateway = match section(&doc, "gateway") {
            Some(t) => Some(parse_gateway(t).map_err(|e| anyhow!("[gateway] {e:#} in {file}"))?),
            None => None,
        };
        let dns = match section(&doc, "dns") {
            Some(t) => parse_dns(t).map_err(|e| anyhow!("[dns] {e:#} in {file}"))?,
            None => DnsConfig::default(),
        };
        if section(&doc, "group").is_some() {
            log::warn!("[group] psk in {file} is ignored: create or join a group (dvpn group --help)");
        }
        let api_token_all = match section(&doc, "api") {
            Some(t) => parse_api(t).map_err(|e| anyhow!("[api] {e:#} in {file}"))?,
            None => false,
        };

        Ok(Config {
            path,
            doc,
            identity,
            groups,
            static_peers,
            remote_subnets,
            exits,
            gateway,
            dns,
            peer,
            net,
            servers,
            log_level,
            local_server_key,
            api_token_all,
        })
    }

    pub fn group(&self, name_or_id: &str) -> Option<&GroupConfig> {
        self.groups.iter().find(|g| g.name == name_or_id || g.id.to_string() == name_or_id)
    }

    /// Adds a `[[groups]]` entry (in memory and in the document; `save` writes it).
    pub fn add_group(&mut self, g: GroupConfig) {
        let mut t = Table::new();
        t["name"] = value(g.name.as_str());
        t["id"] = value(g.id.to_string());
        match &g.secret {
            Some(sec) => t["secret"] = value(encode_b64(sec.as_bytes())),
            None => t["psk"] = value(encode_b64(&g.psk)),
        }
        t["epoch"] = value(i64::from(g.epoch));
        if let Some(c) = &g.cert {
            t["cert"] = value(encode_b64(&c.encode()));
        }
        if !g.obfs_entries.is_empty() {
            let mut o = Table::new();
            for (k, v) in &g.obfs_entries {
                o[k.as_str()] = value(v.as_str());
            }
            t["obfs"] = Item::Table(o);
        }
        if self.doc.get("groups").is_none() {
            self.doc["groups"] = Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        if let Some(arr) = self.doc["groups"].as_array_of_tables_mut() {
            arr.push(t);
        }
        self.groups.push(g);
    }

    /// Replaces the node key (restoring a backed-up node).
    pub fn set_private_key(&mut self, identity: Identity) {
        if self.doc.get("identity").is_none() {
            self.doc["identity"] = Item::Table(Table::new());
        }
        self.doc["identity"]["private_key"] = value(identity.private_key_text());
        self.identity = identity;
    }

    /// Whether the config file can be read by others than its owner (it holds secrets).
    #[cfg(unix)]
    pub fn too_open(&self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&self.path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
    }

    #[cfg(not(unix))]
    pub fn too_open(&self) -> bool {
        false
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sets `[exit]` (an empty list removes it).
    pub fn set_exits(&mut self, exits: &Exits) {
        put_exits(&mut self.doc, exits);
        self.exits = exits.clone();
    }

    /// Replaces this node's certificate in a group (renewed by an admin).
    pub fn set_group_cert(&mut self, id: &GroupId, cert: &Cert) -> bool {
        let Some(i) = self.groups.iter().position(|g| &g.id == id) else { return false };
        self.groups[i].cert = Some(cert.clone());
        if let Some(t) = self.doc.get_mut("groups").and_then(Item::as_array_of_tables_mut).and_then(|a| a.get_mut(i)) {
            t["cert"] = value(encode_b64(&cert.encode()));
        }
        true
    }

    /// Records the psk epoch now in force (members store its psk; admins derive it).
    pub fn set_group_epoch(&mut self, id: &GroupId, epoch: u32, psk: &[u8; 32]) -> bool {
        let Some(i) = self.groups.iter().position(|g| &g.id == id) else { return false };
        let g = &mut self.groups[i];
        g.epoch = epoch;
        g.psk = *psk;
        let admin = g.secret.is_some();
        if let Some(t) = self.doc.get_mut("groups").and_then(Item::as_array_of_tables_mut).and_then(|a| a.get_mut(i)) {
            t["epoch"] = value(i64::from(epoch));
            if !admin {
                t["psk"] = value(encode_b64(psk));
            }
        }
        true
    }

    pub fn remove_group(&mut self, id: &GroupId) -> bool {
        let Some(i) = self.groups.iter().position(|g| &g.id == id) else { return false };
        self.groups.remove(i);
        if let Some(arr) = self.doc.get_mut("groups").and_then(Item::as_array_of_tables_mut) {
            arr.remove(i);
            if arr.is_empty() {
                self.doc.remove("groups");
            }
        }
        true
    }

    /// Adds `[[static_peers]]` for a node unless it is listed already; returns whether it was added.
    pub fn add_static_peer(&mut self, p: &StaticRef) -> bool {
        if p.key == self.identity.id() || self.static_peers.iter().any(|s| s.key == p.key) {
            return false;
        }
        let mut t = Table::new();
        t["key"] = value(p.key.to_string());
        let mut arr = toml_edit::Array::new();
        for e in &p.endpoints {
            arr.push(e.as_str());
        }
        t["endpoints"] = value(arr);
        if self.doc.get("static_peers").is_none() {
            self.doc["static_peers"] = Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        if let Some(a) = self.doc["static_peers"].as_array_of_tables_mut() {
            a.push(t);
        }
        self.static_peers.push(p.clone());
        true
    }

    /// Adds `[servers.<name>]` for a tracker unless one with the same key is configured.
    /// Returns whether it was added (resolving happens at the next load).
    pub fn add_server(&mut self, t: &TrackerRef) -> bool {
        let key = encode_b64(&t.key);
        let servers = self.doc.get("servers").and_then(Item::as_table);
        let exists = servers.is_some_and(|s| {
            s.iter().any(|(_, i)| i.get("key").and_then(Item::as_str).and_then(|k| decode_key32(k).ok()) == Some(t.key))
        });
        if exists {
            return false;
        }
        if self.doc.get("servers").is_none() {
            let mut s = Table::new();
            s.set_implicit(true);
            self.doc["servers"] = Item::Table(s);
        }
        let mut name = t.host.replace(['.', ':', '[', ']'], "-");
        while self.doc["servers"].get(&name).is_some() {
            name.push('_');
        }
        let mut st = Table::new();
        st["addr"] = value(t.host.as_str());
        st["port"] = value(i64::from(t.port));
        st["key"] = value(key);
        self.doc["servers"][name.as_str()] = Item::Table(st);
        true
    }

    pub fn set_local_server(&mut self, private_key: &[u8; 32], public_key: &[u8; 32]) {
        self.local_server_key = Some(*private_key);
        if self.doc.get("local_server").is_none() {
            self.doc["local_server"] = Item::Table(Table::new());
        }
        self.doc["local_server"]["private_key"] = value(encode_b64(private_key));
        self.doc["local_server"]["public_key"] = value(encode_b64(public_key));
    }

    pub fn local_server_public_key(&self) -> Option<Vec<u8>> {
        let s = section(&self.doc, "local_server")?.get("public_key")?.as_str()?;
        decode_b64(s).ok()
    }

    pub fn save(&self) {
        if let Err(e) = write_private(&self.path, &self.doc.to_string()) {
            log::warn!("Config | write file({}) error: {e}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(parse_mask("255.255.255.0").unwrap(), 24);
        assert_eq!(parse_mask("16").unwrap(), 16);
        assert!(parse_mask("255.0.255.0").is_err());
    }

    #[test]
    fn port_ranges() {
        assert_eq!(parse_port_range("8647").unwrap(), (8647, 8647));
        assert_eq!(parse_port_range("8647-9942").unwrap(), (8647, 9942));
        assert!(parse_port_range("9-1").is_err());
    }

    fn admin_group(dir: &Path) -> GroupConfig {
        let id = Config::load_with_env_key(dir, None).unwrap().identity.id();
        let secret = GroupSecret::generate();
        let cert = secret.issue(crate::group::CertBody::new(id, "a", vec!["10.10.33.5/32".parse().unwrap()]));
        GroupConfig {
            name: "home".into(),
            id: secret.id(),
            psk: secret.psk(0),
            secret: Some(secret),
            epoch: 0,
            cert: Some(cert),
            obfs: Profile::default(),
            obfs_entries: vec![("jc".into(), "1-2".into())],
        }
    }

    #[test]
    fn groups_round_trip() {
        let dir = temp_dir();
        let g = admin_group(&dir);
        let mut conf = Config::load(&dir).unwrap();
        assert!(conf.net.is_some() && conf.groups.is_empty());
        conf.add_group(g.clone());
        let member = GroupConfig {
            name: "work".into(),
            secret: None,
            id: GroupSecret::generate().id(),
            cert: None,
            ..g.clone()
        };
        conf.add_group(member.clone());
        let sp = StaticRef {
            key: Identity::generate().id(),
            endpoints: vec!["vpn.example:8647".into(), "[2001:db8::1]:8647".into()],
        };
        assert!(conf.add_static_peer(&sp));
        assert!(!conf.add_static_peer(&sp));
        let t = TrackerRef { host: "t.example".into(), port: 7000, key: [5; 32] };
        assert!(conf.add_server(&t));
        assert!(!conf.add_server(&t), "same key already configured");
        conf.save();
        let text = std::fs::read_to_string(dir.join(CONFIG_FILE_NAME)).unwrap();
        assert!(text.contains("# local bind ip"), "comments must survive save");
        assert!(text.contains("[servers.t-example]"), "{text}");

        // the server is resolved on load: drop it again before reloading (no DNS in tests)
        let mut doc: DocumentMut = text.parse().unwrap();
        doc.remove("servers");
        std::fs::write(dir.join(CONFIG_FILE_NAME), doc.to_string()).unwrap();
        let mut back = Config::load(&dir).unwrap();
        assert_eq!(back.groups.len(), 2);
        assert_eq!(back.static_peers, vec![sp]);
        let (a, m) = (&back.groups[0], &back.groups[1]);
        assert_eq!((a.id, a.psk, a.ipv4()), (g.id, g.psk, Some(Ipv4Addr::new(10, 10, 33, 5))));
        assert!(a.secret.is_some() && m.secret.is_none());
        assert_eq!((m.id, m.psk), (member.id, member.psk));
        assert_eq!(a.obfs.junk_count, 1..=2);
        assert_eq!(back.group("work").unwrap().id, member.id);
        assert_eq!(back.group(&g.id.to_string()).unwrap().name, "home");

        assert!(back.remove_group(&g.id));
        back.remove_group(&member.id);
        back.save();
        assert!(Config::load(&dir).unwrap().groups.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dvpn-test-{}", encode_b64(&crate::crypto::random_bytes::<9>())));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file_key(dir: &Path) -> Option<String> {
        let doc: DocumentMut = std::fs::read_to_string(dir.join(CONFIG_FILE_NAME)).unwrap().parse().unwrap();
        doc.get("identity")?.get("private_key")?.as_str().map(str::to_owned)
    }

    #[cfg(unix)]
    fn mode(dir: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(dir.join(CONFIG_FILE_NAME)).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn identity_generated_with_new_config() {
        let dir = temp_dir();
        let a = Config::load_with_env_key(&dir, None).unwrap();
        let text = std::fs::read_to_string(dir.join(CONFIG_FILE_NAME)).unwrap();
        assert!(text.starts_with("[identity]"), "identity goes first");
        assert_eq!(file_key(&dir).unwrap(), a.identity.private_key_text());
        #[cfg(unix)]
        assert_eq!(mode(&dir), 0o600);
        // stable across loads and saves
        a.save();
        assert_eq!(Config::load_with_env_key(&dir, None).unwrap().identity.id(), a.identity.id());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identity_added_to_config_without_one() {
        let dir = temp_dir();
        let path = dir.join(CONFIG_FILE_NAME);
        let old = DEFAULT_CONFIG.replace("{addr}", "10.10.33.7");
        std::fs::write(&path, &old).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let a = Config::load_with_env_key(&dir, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# local bind ip"), "comments must survive");
        assert!(text.contains("dvpn show-key"), "identity comment added");
        assert!(
            text.starts_with("[identity]") || text.starts_with("\n# Node private key") || text.starts_with("# Node")
        );
        assert_eq!(file_key(&dir).unwrap(), a.identity.private_key_text());
        #[cfg(unix)]
        assert_eq!(mode(&dir), 0o600, "narrowed once a key is written");
        assert_eq!(Config::load_with_env_key(&dir, None).unwrap().identity.id(), a.identity.id());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn env_key_overrides_file_and_is_not_saved() {
        let dir = temp_dir();
        let from_file = Config::load_with_env_key(&dir, None).unwrap().identity.id();
        let env = Identity::generate();
        let conf = Config::load_with_env_key(&dir, Some(env.private_key_text())).unwrap();
        assert_eq!(conf.identity.id(), env.id());
        assert_ne!(conf.identity.id(), from_file);
        conf.save();
        assert_ne!(file_key(&dir).unwrap(), env.private_key_text());
        // empty env var is ignored
        assert_eq!(Config::load_with_env_key(&dir, Some(" ".into())).unwrap().identity.id(), from_file);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn with_group(extra: &str) -> anyhow::Result<Config> {
        let dir = temp_dir();
        Config::load_with_env_key(&dir, None).unwrap();
        let path = dir.join(CONFIG_FILE_NAME);
        let secret = encode_b64(&crate::crypto::random_bytes::<32>());
        let text = std::fs::read_to_string(&path).unwrap()
            + &format!("\n[[groups]]\nname = \"g\"\nsecret = \"{secret}\"\n{extra}");
        std::fs::write(&path, text).unwrap();
        let r = Config::load_with_env_key(&dir, None);
        std::fs::remove_dir_all(dir).unwrap();
        r
    }

    #[test]
    fn group_obfs_profile() {
        assert_eq!(with_group("").unwrap().groups[0].obfs, Profile::default());
        let c = with_group(
            "[groups.obfs]\njc = \"1-2\"\njmin = 10\njmax = \"20\"\ns1 = \"5-6\"\ns2 = 7\ns4 = \"0-0\"\n\
             i2 = \"<r 3>\"\ni1 = \"<b 0xab>\"\nheader_protection = true\n",
        )
        .unwrap();
        let o = &c.groups[0].obfs;
        assert_eq!((o.junk_count.clone(), o.junk_size.clone()), (1..=2, 10..=20));
        assert_eq!((o.init_pad.clone(), o.resp_pad.clone(), o.data_pad.clone()), (5..=6, 7..=7, 0..=0));
        assert_eq!(o.signatures, vec!["<b 0xab>".parse().unwrap(), "<r 3>".parse().unwrap()], "kept in i1..i5 order");

        for (bad, why) in [
            ("jc = \"9-1\"", "9 > 1"),
            ("jmin = 300\njmax = 100", "jmin <= jmax"),
            ("jmax = 5000", "jmin <= jmax"),
            ("s1 = \"0-9999\"", "padding above"),
            ("i1 = \"<zz>\"", "unknown tag"),
            ("header_protection = false", "cannot be turned off"),
            ("h1 = \"1-5\"", "unknown key h1"),
        ] {
            let err = format!("{:#}", with_group(&format!("[groups.obfs]\n{bad}\n")).err().unwrap());
            assert!(err.contains(why) && err.contains("[groups.obfs]"), "{bad}: {err}");
        }
    }

    #[test]
    fn remote_subnets() {
        let k = Identity::generate().id();
        let c = with_group(&format!(
            "[ckr.remote_subnets]\n\"{k}\" = [\"192.168.50.0/24\", \"~10.0.0.0/8\", \"inetv6\"]\n"
        ))
        .unwrap();
        assert_eq!(c.remote_subnets.len(), 3);
        assert!(!c.remote_subnets[1].system);
        let err = format!("{:#}", with_group("[ckr.remote_subnets]\nabc = [\"10.0.0.0/8\"]\n").err().unwrap());
        assert!(err.contains("full node key"), "{err}");
        let err =
            format!("{:#}", with_group(&format!("[ckr.remote_subnets]\n\"{k}\" = [\"10.0.0.0/99\"]\n")).err().unwrap());
        assert!(err.contains("10.0.0.0/99"), "{err}");
    }

    #[test]
    fn exits() {
        let c = with_group("[exit]\nv4 = [\"vps1\", \"vps2\"]\n").unwrap();
        assert_eq!(c.exits, Exits { v4: vec!["vps1".into(), "vps2".into()], ..Default::default() });
        assert!(c.exits.kill_switch(), "on by default");
        assert!(with_group("[exit]\ndns = [\"one.one\"]\n").is_err());
        assert!(with_group("[exit]\nv5 = []\n").is_err());
        // policy routing: only some sources through the gateway, a table of the system's
        let c = with_group("[exit]\nv4 = [\"vps1\"]\nv4_sources = [\"10.10.11.0/24\", \"10.10.12.5\"]\ntable = 445\n")
            .unwrap();
        assert_eq!(c.exits.v4_sources, vec!["10.10.11.0/24".parse().unwrap(), "10.10.12.5/32".parse().unwrap()]);
        assert_eq!(c.exits.table, Some(445));
        assert!(c.exits.split());
        assert!(!with_group("[exit]\nv4 = [\"vps1\"]\n").unwrap().exits.split());
        assert!(with_group("[exit]\nv4_sources = [\"fd00::/64\"]\n").is_err(), "IPv6 in v4_sources");
        assert!(with_group("[exit]\nv6_sources = [\"10.0.0.0/8\"]\n").is_err());
        for bad in ["0", "254", "7347", "-1", "\"main\""] {
            assert!(with_group(&format!("[exit]\ntable = {bad}\n")).is_err(), "table = {bad}");
        }
        let dir = temp_dir();
        let mut c = Config::load(&dir).unwrap();
        let e = Exits {
            v4: vec!["a".into()],
            v6: vec!["b".into(), "c".into()],
            kill_switch: Some(false),
            dns: vec!["1.1.1.1".parse().unwrap()],
            v4_sources: vec!["10.10.11.0/24".parse().unwrap()],
            v6_sources: vec!["fd00::/64".parse().unwrap()],
            table: Some(445),
        };
        c.set_exits(&e);
        c.save();
        assert_eq!(read_exits(&dir.join(CONFIG_FILE_NAME)).unwrap(), e);
        c.set_exits(&Exits::default());
        c.save();
        assert_eq!(read_exits(&dir.join(CONFIG_FILE_NAME)).unwrap(), Exits::default());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn gateway() {
        let c = with_group("[gateway]\nwan = [\"eth0\"]\nndp_proxy = \"eth0\"\n").unwrap();
        assert_eq!(
            c.gateway,
            Some(GatewayConfig { wan: vec!["eth0".into()], ndp_proxy: Some("eth0".into()), manage_sysctl: true })
        );
        assert!(with_group("[gateway]\n").is_err(), "wan is required");
        assert!(with_group("[gateway]\nwan = [\"eth0\"]\nnat = true\n").is_err());
    }

    #[test]
    fn endpoints() {
        for ok in ["1.2.3.4:5", "vpn.example.com:8647", "[2001:db8::1]:8647"] {
            assert!(check_endpoint(ok).is_ok(), "{ok}");
        }
        for bad in ["1.2.3.4", "host:99999", ":80", "host:port"] {
            assert!(check_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn group_errors() {
        let err = format!("{:#}", with_group("id = \"AAAA\"").err().unwrap());
        assert!(err.contains("id"), "{err}");
        let other = GroupSecret::generate().id();
        let err = format!("{:#}", with_group(&format!("id = \"{other}\"")).err().unwrap());
        assert!(err.contains("does not match"), "{err}");
        let err = format!("{:#}", with_group("cert = \"AAAA\"").err().unwrap());
        assert!(err.contains("cert"), "{err}");
    }

    #[test]
    fn bad_identity_keys_are_errors() {
        let dir = temp_dir();
        Config::load_with_env_key(&dir, None).unwrap();
        let err = Config::load_with_env_key(&dir, Some("AAAA".into())).err().unwrap().to_string();
        assert!(err.contains(PRIVATE_KEY_ENV), "{err}");
        let path = dir.join(CONFIG_FILE_NAME);
        let text = std::fs::read_to_string(&path).unwrap();
        let key = file_key(&dir).unwrap();
        std::fs::write(&path, text.replace(&key, "broken")).unwrap();
        let err = Config::load_with_env_key(&dir, None).err().unwrap().to_string();
        assert!(err.contains("[identity] private_key"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
