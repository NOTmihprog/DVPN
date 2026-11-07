//! Operations that the CLI, the node's API and the apps share: joining a group by an invite and
//! leaving it (PLAN 7.4), and an admin's work on the group (PLAN 9.1): invites, changing and
//! revoking members, psk changes, access rules.
//!
//! The admin operations only add records to a `StateStore` and return them: the CLI saves the
//! store (a running node picks the file up), a running node applies and spreads them at once.

use std::fmt;
use std::net::Ipv4Addr;

use anyhow::bail;
use ipnet::{IpNet, Ipv4Net};

use crate::config::{Config, GroupConfig, parse_obfs};
use crate::crypto::random_bytes;
use crate::group::{CERT_TTL_SECS, Cert, CertBody, GroupId, GroupSecret, Invite, Roles, StaticRef, now_unix};
use crate::identity::NodeId;
use crate::state::{Body, Entry, StateStore};

/// What joining gave.
#[derive(Clone, Debug)]
pub struct Joined {
    /// The local name of the group (made unique if a group of that name exists).
    pub group: String,
    pub id: GroupId,
    /// This node's name and IPv4 address in the group, from the certificate.
    pub name: String,
    pub addr: Option<std::net::Ipv4Addr>,
    /// Trackers, static peers and the network mask added to the config.
    pub added: Vec<String>,
}

/// Joins the group of `invite` (its base64url text): enrolls this node's key
/// with the invite's join key, adds the group, its trackers, static peers and network mask, and
/// saves.
pub fn join(conf: &mut Config, invite: &str) -> anyhow::Result<Joined> {
    let inv = Invite::decode(invite.trim(), Some(now_unix()))?;
    if conf.groups.iter().any(|g| g.id == inv.group()) {
        bail!("already in group {}", inv.group());
    }
    if !conf.groups.is_empty() {
        bail!("this node is already in a group; several groups per node come later (PLAN stage 3.5)");
    }
    let obfs = parse_obfs(&inv.obfs).map_err(|e| anyhow::anyhow!("invite obfuscation profile: {e:#}"))?;
    let cert = inv.join.enroll(conf.identity.id());
    let body = cert.body.clone();
    let mut name = inv.name.clone();
    while conf.group(&name).is_some() {
        name.push('_');
    }
    let mut added: Vec<String> =
        inv.trackers.iter().filter(|t| conf.add_server(t)).map(|t| format!("{}:{}", t.host, t.port)).collect();
    for sp in &inv.statics {
        if conf.add_static_peer(sp) {
            added.push(format!("static {}", sp.endpoints.join(", ")));
        }
    }
    if conf.set_net_prefix(inv.net_prefix) {
        added.push(format!("network mask /{}", inv.net_prefix));
    }
    conf.add_group(GroupConfig {
        name: name.clone(),
        id: inv.group(),
        secret: None,
        epoch: inv.epoch,
        psk: inv.psk,
        cert: Some(cert),
        obfs,
        obfs_entries: inv.obfs.clone(),
    });
    conf.save();
    Ok(Joined { group: name, id: inv.group(), name: body.name.clone(), addr: body.ipv4(), added })
}

/// Leaves the group `name` (removes it, with its secret if this node administers it). Returns
/// whether the node was an admin of it.
pub fn leave(conf: &mut Config, name: &str) -> anyhow::Result<bool> {
    let Some(g) = conf.group(name) else { bail!("no group {name}") };
    let (id, admin) = (g.id, g.secret.is_some());
    conf.remove_group(&id);
    conf.save();
    Ok(admin)
}

// ---- admin operations ----

/// Why an admin operation was refused: a stable code (the API's `err`) and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpError {
    pub code: &'static str,
    pub msg: String,
}

impl OpError {
    fn new(code: &'static str, msg: impl Into<String>) -> Self {
        OpError { code, msg: msg.into() }
    }
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for OpError {}

/// Signing needs a sane clock: certificates and records carry times.
fn check_clock() -> Result<(), OpError> {
    if crate::clock::trusted() {
        Ok(())
    } else {
        Err(OpError::new("clock_untrusted", "the clock is earlier than this build: set it (NTP) before signing"))
    }
}

/// The secret of a group this node administers.
pub fn admin_secret(g: &GroupConfig) -> Result<&GroupSecret, OpError> {
    g.secret.as_ref().ok_or_else(|| OpError::new("not_admin", format!("only admins of {} can do this", g.name)))
}

/// A member among `certs`: a node key, an exact name, or a unique key prefix (names first).
pub fn find_member(certs: &[Cert], s: &str) -> Result<NodeId, OpError> {
    if let Ok(k) = s.parse() {
        return Ok(k);
    }
    let by_name: Vec<NodeId> = certs.iter().filter(|c| c.body.name == s).map(|c| c.body.node).collect();
    let hits = if by_name.is_empty() {
        certs.iter().filter(|c| c.body.node.to_string().starts_with(s)).map(|c| c.body.node).collect()
    } else {
        by_name
    };
    match hits.as_slice() {
        [k] => Ok(*k),
        [] => Err(OpError::new("member_unknown", format!("{s}: no such member key, key prefix or name"))),
        _ => Err(OpError::new("member_ambiguous", format!("{s} matches {} members, give the key", hits.len()))),
    }
}

/// The psk epoch started by `changed`, if any.
pub fn epoch_of(changed: &[Entry]) -> Option<u32> {
    changed.iter().find_map(|e| match e.body {
        Body::Epoch { epoch, .. } => Some(epoch),
        _ => None,
    })
}

/// The prefix length of the group network (`[net] mask`).
pub fn net_prefix(conf: &Config) -> u8 {
    conf.net.as_ref().map_or(24, |n| n.prefix)
}

/// A random host of `net` that is none of `taken`.
pub fn free_host(net: Ipv4Net, taken: &[Ipv4Addr]) -> Ipv4Addr {
    loop {
        let a = crate::config::random_host(net.network(), net.prefix_len());
        if !taken.contains(&a) {
            return a;
        }
    }
}

/// The certificate prefixes: the node's address first, then the subnets behind it.
pub fn host_net(addr: Ipv4Addr, routes: &[IpNet]) -> Vec<IpNet> {
    let mut v = vec![IpNet::V4(Ipv4Net::new(addr, 32).expect("/32 is valid"))];
    v.extend(routes.iter().map(IpNet::trunc));
    v
}

/// What an invite is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteRequest {
    /// The new node's name.
    pub name: String,
    /// Its address (None: a free one in the group network).
    pub addr: Option<Ipv4Addr>,
    /// How long the invite can be used.
    pub ttl_hours: u64,
    /// This node's fixed addresses (`host:port`): the new node connects to it directly.
    pub statics: Vec<String>,
    /// Subnets behind the new node.
    pub routes: Vec<IpNet>,
    pub relay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteMade {
    /// The invite string for the new node (a secret: pass it on privately).
    pub invite: String,
    pub name: String,
    pub addr: Ipv4Addr,
    /// Unix time until which it can be used.
    pub until: u64,
    /// Things that make it less useful (no trackers and no statics, ...).
    pub warnings: Vec<String>,
}

/// An invite for one new node to group `g` (needs its secret). `certs`: the members known, so
/// that a free address is picked. Adds no records: the invite carries a one-time join key.
pub fn invite(conf: &Config, g: &GroupConfig, certs: &[Cert], req: &InviteRequest) -> Result<InviteMade, OpError> {
    let secret = admin_secret(g)?;
    check_clock()?;
    if req.name.trim().is_empty() {
        return Err(OpError::new("bad_param", "name: the new node needs a name"));
    }
    let own = g.ipv4().ok_or_else(|| OpError::new("no_address", "this node has no address in the group"))?;
    let net = Ipv4Net::new(own, net_prefix(conf)).map_err(|e| OpError::new("bad_param", e.to_string()))?.trunc();
    let taken: Vec<Ipv4Addr> = certs.iter().filter_map(|c| c.body.ipv4()).chain([own]).collect();
    let addr = match req.addr {
        Some(a) if taken.contains(&a) => return Err(OpError::new("addr_taken", format!("{a} is taken by a member"))),
        Some(a) if !net.contains(&a) => {
            return Err(OpError::new("addr_invalid", format!("{a} is outside the group network {net}")));
        }
        Some(a) => a,
        None => free_host(net, &taken),
    };
    for e in &req.statics {
        crate::config::check_endpoint(e).map_err(|e| OpError::new("endpoint_invalid", format!("static {e:#}")))?;
    }
    let mut warnings = Vec::new();
    if conf.servers.is_empty() && req.statics.is_empty() {
        warnings.push("no [servers] and no statics: the new node will not find anybody".to_owned());
    }
    if !req.statics.is_empty() && conf.peer.port_range.0 != conf.peer.port_range.1 {
        warnings.push("[peer] bind_port is a range: give this node a fixed port for statics to work".to_owned());
    }
    let mut template = CertBody::new(conf.identity.id(), req.name.trim(), host_net(addr, &req.routes));
    if req.relay {
        template.roles.0 |= Roles::RELAY;
    }
    let until = now_unix() + req.ttl_hours * 3600;
    let join = secret.grant_join(template, until);
    let trackers = conf.servers.iter().map(|s| s.tracker_ref()).collect();
    let mut inv = Invite::new(&g.name, g.epoch, g.psk, g.obfs_entries.clone(), trackers, join, net_prefix(conf));
    if !req.statics.is_empty() {
        inv.statics.push(StaticRef { key: conf.identity.id(), endpoints: req.statics.clone() });
    }
    Ok(InviteMade { invite: inv.encode(), name: req.name.trim().to_owned(), addr, until, warnings })
}

/// Changes to a member's certificate (`dvpn node set`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeChange {
    pub name: Option<String>,
    pub addr: Option<Ipv4Addr>,
    pub add_routes: Vec<IpNet>,
    pub del_routes: Vec<IpNet>,
    pub relay: Option<bool>,
}

/// Issues member `node` a new certificate with `ch` applied (and a fresh validity). `certs`:
/// every member's newest certificate. Returns the certificate and its record.
pub fn change_node(
    secret: &GroupSecret,
    store: &StateStore,
    certs: &[Cert],
    node: NodeId,
    ch: &NodeChange,
) -> Result<(Cert, Entry), OpError> {
    check_clock()?;
    let base = certs.iter().filter(|c| c.body.node == node).max_by_key(|c| c.body.not_after).ok_or_else(|| {
        OpError::new(
            "member_not_seen",
            format!("{node}: not seen yet (the admin node issues its certificate when it sees it online)"),
        )
    })?;
    let mut body = base.body.clone();
    if let Some(n) = &ch.name {
        if n.trim().is_empty() {
            return Err(OpError::new("bad_param", "name: empty"));
        }
        body.name = n.trim().to_owned();
    }
    if let Some(a) = ch.addr {
        if certs.iter().filter(|c| c.body.node != node).any(|c| c.body.ipv4() == Some(a)) {
            return Err(OpError::new("addr_taken", format!("{a} is taken by another member")));
        }
        let own = body.ipv4();
        body.prefixes.retain(|p| !matches!(p, IpNet::V4(n) if Some(n.addr()) == own && n.prefix_len() == 32));
        body.prefixes.insert(0, IpNet::V4(Ipv4Net::new(a, 32).expect("/32")));
    }
    for r in &ch.del_routes {
        body.prefixes.retain(|p| p.trunc() != r.trunc());
    }
    for r in &ch.add_routes {
        let r = r.trunc();
        if !body.prefixes.contains(&r) {
            body.prefixes.push(r);
        }
    }
    match ch.relay {
        Some(true) => body.roles.0 |= Roles::RELAY,
        Some(false) => body.roles.0 &= !Roles::RELAY,
        None => {}
    }
    body.not_after = now_unix() + CERT_TTL_SECS;
    body.serial = u64::from_le_bytes(random_bytes());
    let cert = secret.issue(body);
    let entry = store.add(secret, Body::Cert(Box::new(cert.clone())), false);
    Ok((cert, entry))
}

/// Starts a new psk epoch in `lead_secs` (after `epoch`, the one in use): sealed to every member.
pub fn rotate(secret: &GroupSecret, store: &StateStore, epoch: u32, lead_secs: u64) -> Result<Vec<Entry>, OpError> {
    check_clock()?;
    Ok(store.rotate(secret, epoch, lead_secs * 1000))
}

/// Revokes `key` from the group, and with `rotate` (seconds of lead) changes the psk too, so that
/// it cannot unmask packet headers any more. `me`: this node, which cannot revoke itself.
pub fn revoke(
    secret: &GroupSecret,
    store: &StateStore,
    me: NodeId,
    key: NodeId,
    epoch: u32,
    rotate: Option<u64>,
) -> Result<Vec<Entry>, OpError> {
    check_clock()?;
    if key == me {
        return Err(OpError::new("revoke_self", "an admin cannot revoke itself; leave the group instead"));
    }
    let mut changed = vec![store.add(secret, Body::Revoke { key }, false)];
    if let Some(lead) = rotate {
        changed.extend(store.rotate(secret, epoch, lead * 1000));
    }
    Ok(changed)
}

/// Makes `text` (TOML, `doc/acl.md`) the group's access rules. Members are named by key or by
/// the name of exactly one of `certs`.
pub fn set_acl(
    secret: &GroupSecret,
    store: &StateStore,
    certs: &[Cert],
    text: &str,
) -> Result<(crate::acl::Acl, Entry), OpError> {
    check_clock()?;
    let member = |s: &str| -> Option<NodeId> {
        s.parse().ok().or_else(|| {
            let hits: Vec<NodeId> = certs.iter().filter(|c| c.body.name == s).map(|c| c.body.node).collect();
            (hits.len() == 1).then(|| hits[0])
        })
    };
    let acl = crate::acl::Acl::parse(text, &member).map_err(|e| OpError::new("acl_parse", format!("{e:#}")))?;
    let entry = store.add(secret, Body::Acl(Box::new(acl.clone())), false);
    Ok((acl, entry))
}

/// Removes the group's access rules: everybody may reach everybody.
pub fn clear_acl(secret: &GroupSecret, store: &StateStore) -> Result<Entry, OpError> {
    check_clock()?;
    Ok(store.add(secret, Body::Acl(Box::default()), true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{CertBody, GroupSecret, StaticRef};
    use crate::identity::Identity;

    fn temp_dir() -> std::path::PathBuf {
        let tag = crate::crypto::encode_b64(&crate::crypto::random_bytes::<9>());
        let dir = std::env::temp_dir().join(format!("dvpn-ops-test-{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn invite(secret: &GroupSecret, name: &str, until: u64) -> Invite {
        let template = CertBody::new(Identity::generate().id(), "phone", vec!["10.10.33.40/32".parse().unwrap()]);
        let join = secret.grant_join(template, until);
        let mut inv = Invite::new(name, 0, secret.psk(0), Vec::new(), Vec::new(), join, 24);
        inv.statics.push(StaticRef { key: Identity::generate().id(), endpoints: vec!["192.0.2.1:8647".into()] });
        inv
    }

    #[test]
    fn join_takes_the_network_mask() {
        let dir = temp_dir();
        let mut conf = Config::load(&dir).unwrap();
        assert_eq!(net_prefix(&conf), 24);
        let mut inv = invite(&GroupSecret::generate(), "home", now_unix() + 3600);
        inv.net_prefix = 16;
        let j = join(&mut conf, &inv.encode()).unwrap();
        assert!(j.added.contains(&"network mask /16".to_owned()), "{:?}", j.added);
        assert_eq!(net_prefix(&Config::load(&dir).unwrap()), 16, "saved to disk");
    }

    #[test]
    fn join_then_leave() {
        let dir = temp_dir();
        let mut conf = Config::load(&dir).unwrap();
        let secret = GroupSecret::generate();
        let inv = invite(&secret, "home", now_unix() + 3600);

        let j = join(&mut conf, &format!("  {}\n", inv.encode())).unwrap();
        assert_eq!((j.group.as_str(), j.id, j.name.as_str()), ("home", secret.id(), "phone"));
        assert_eq!(j.addr, Some("10.10.33.40".parse().unwrap()));
        assert_eq!(j.added, vec!["static 192.0.2.1:8647".to_owned()]);
        // enrolled with our own key, saved to disk
        let back = Config::load(&dir).unwrap();
        let g = back.group("home").unwrap();
        assert_eq!(g.cert.as_ref().unwrap().body.node, conf.identity.id());
        assert!(g.secret.is_none());

        let again = join(&mut conf, &inv.encode()).unwrap_err().to_string();
        assert!(again.contains("already in group"), "{again}");
        let other = join(&mut conf, &invite(&GroupSecret::generate(), "work", now_unix() + 3600).encode());
        assert!(other.unwrap_err().to_string().contains("already in a group"));

        assert!(leave(&mut conf, "nope").is_err());
        assert!(!leave(&mut conf, "home").unwrap(), "a member, not an admin");
        assert!(Config::load(&dir).unwrap().groups.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn join_refuses_bad_invites() {
        let dir = temp_dir();
        let mut conf = Config::load(&dir).unwrap();
        assert!(join(&mut conf, "not an invite").is_err());
        let expired = invite(&GroupSecret::generate(), "home", now_unix() - 1).encode();
        assert!(join(&mut conf, &expired).unwrap_err().to_string().contains("expired"));
        assert!(conf.groups.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
