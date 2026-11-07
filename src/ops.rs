//! Operations that the CLI, the node's API and the apps share: joining a group by an invite and
//! leaving it (PLAN 7.4), and an admin's work on the group (PLAN 9.1): invites, changing and
//! revoking members, psk changes, access rules.
//!
//! The admin operations only add records to a `StateStore` and return them: the CLI saves the
//! store (a running node picks the file up), a running node applies and spreads them at once.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::bail;
use ipnet::{IpNet, Ipv4Net};

use crate::config::{Config, GroupConfig, parse_obfs};
use crate::crypto::random_bytes;
use crate::group::{
    CERT_TTL_SECS, Cert, CertBody, Delegate, GroupId, GroupSecret, Invite, IssuedDelegation, Roles, StaticRef, now_unix,
};
use crate::identity::NodeId;
use crate::state::{Body, Entry, Membership, StateStore};

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
        delegate: None,
        delegations: Vec::new(),
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

/// A random host of `net` that is none of `taken` and in none of `avoid`, if there is one left.
pub fn free_host(net: Ipv4Net, taken: &[Ipv4Addr], avoid: &[IpNet]) -> Option<Ipv4Addr> {
    let free = |a: &Ipv4Addr| !taken.contains(a) && !avoid.iter().any(|n| n.contains(&IpAddr::V4(*a)));
    let tries = if net.prefix_len() < 31 { 64 } else { 0 };
    (0..tries)
        .map(|_| crate::config::random_host(net.network(), net.prefix_len()))
        .find(&free)
        .or_else(|| net.hosts().find(&free))
}

/// The certificate prefixes: the node's address first, then the subnets behind it.
pub fn host_net(addr: Ipv4Addr, routes: &[IpNet]) -> Vec<IpNet> {
    let mut v = vec![IpNet::V4(Ipv4Net::new(addr, 32).expect("/32 is valid"))];
    v.extend(routes.iter().map(IpNet::trunc));
    v
}

fn no_free_addr() -> OpError {
    OpError::new("no_free_addr", "no free address left")
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

/// Who signs an invite: an admin anywhere in the network, a delegate inside its scope.
enum Inviter<'a> {
    Admin(&'a GroupSecret),
    Delegate(&'a Delegate),
}

fn inviter<'a>(g: &'a GroupConfig, revoked: &HashSet<NodeId>) -> Result<Inviter<'a>, OpError> {
    let Some(d) = g.secret.is_none().then_some(g.delegate.as_ref()).flatten() else {
        return admin_secret(g).map(Inviter::Admin);
    };
    if revoked.contains(&d.delegation.key) {
        return Err(OpError::new("delegate_ended", "this node's right to invite was taken back"));
    }
    if now_unix() >= d.delegation.until {
        return Err(OpError::new(
            "delegate_ended",
            "this node's right to invite has expired: ask an admin for a new one",
        ));
    }
    Ok(Inviter::Delegate(d))
}

/// An invite for one new node to group `g` (needs its secret, or a delegation that allows it).
/// `certs`: the members known, so that a free address is picked. `revoked`: the group's revoked
/// keys. Adds no records: the invite carries a one-time join key.
pub fn invite(
    conf: &Config,
    g: &GroupConfig,
    certs: &[Cert],
    revoked: &HashSet<NodeId>,
    req: &InviteRequest,
) -> Result<InviteMade, OpError> {
    let inviter = inviter(g, revoked)?;
    check_clock()?;
    if req.name.trim().is_empty() {
        return Err(OpError::new("bad_param", "name: the new node needs a name"));
    }
    let own = g.ipv4().ok_or_else(|| OpError::new("no_address", "this node has no address in the group"))?;
    let net = Ipv4Net::new(own, net_prefix(conf)).map_err(|e| OpError::new("bad_param", e.to_string()))?.trunc();
    let taken: Vec<Ipv4Addr> = certs.iter().filter_map(|c| c.body.ipv4()).chain([own]).collect();
    let addr = match (req.addr, &inviter) {
        (Some(a), _) if taken.contains(&a) => {
            return Err(OpError::new("addr_taken", format!("{a} is taken by a member")));
        }
        (Some(a), Inviter::Admin(_)) if !net.contains(&a) => {
            return Err(OpError::new("addr_invalid", format!("{a} is outside the group network {net}")));
        }
        (Some(a), Inviter::Delegate(d)) if !d.delegation.covers(&IpNet::V4(Ipv4Net::from(a))) => {
            return Err(OpError::new("addr_invalid", format!("{a} is outside this node's scope")));
        }
        (Some(a), _) => a,
        (None, Inviter::Admin(_)) => {
            // the delegates' subnets are theirs to give out
            let avoid: Vec<IpNet> = g.delegations.iter().flat_map(|d| d.delegation.scope.clone()).collect();
            free_host(net, &taken, &avoid).ok_or_else(no_free_addr)?
        }
        (None, Inviter::Delegate(d)) => d
            .delegation
            .scope
            .iter()
            .filter_map(|s| match s {
                IpNet::V4(n) => free_host(*n, &taken, &[]),
                IpNet::V6(_) => None,
            })
            .next()
            .ok_or_else(no_free_addr)?,
    };
    if let Inviter::Delegate(d) = &inviter {
        if req.relay {
            return Err(OpError::new("delegate_limit", "a delegate cannot give the relay role"));
        }
        if let Some(r) = req.routes.iter().find(|r| !d.delegation.covers(&r.trunc())) {
            return Err(OpError::new("delegate_limit", format!("{r} is outside this node's scope")));
        }
    }
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
    let join = match inviter {
        Inviter::Admin(secret) => secret.grant_join(template, until),
        Inviter::Delegate(d) => d.grant_join(template, until),
    };
    let until = join.grant.until;
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

/// Why a delegate's invite certificate cannot become a regular one: the name or address is
/// another member's. A delegate does not see the members who are not online yet.
pub fn invite_conflict(cert: &Cert, certs: &[Cert], m: &Membership) -> Option<String> {
    let b = &cert.body;
    let live = |c: &&Cert| c.body.node != b.node && c.body.not_after > now_unix() && m.admits(c);
    certs.iter().filter(live).find_map(|c| {
        if c.body.name == b.name {
            Some(format!("name {} is taken", b.name))
        } else if b.ipv4().is_some() && c.body.ipv4() == b.ipv4() {
            Some(format!("address {} is taken by {}", c.body.ipv4()?, c.body.name))
        } else {
            None
        }
    })
}

/// Lets the node holding the result invite into `scope` for `days`. `g`: the group, whose
/// network holds the scope, which no other delegate may share.
pub fn add_delegate(
    conf: &Config,
    g: &GroupConfig,
    name: &str,
    scope: Vec<IpNet>,
    days: u64,
) -> Result<(Delegate, IssuedDelegation), OpError> {
    let secret = admin_secret(g)?;
    check_clock()?;
    let name = name.trim();
    if name.is_empty() {
        return Err(OpError::new("bad_param", "name: the delegate needs a name"));
    }
    if g.delegations.iter().any(|d| d.name == name) {
        return Err(OpError::new("delegate_exists", format!("delegate {name} exists: remove it first")));
    }
    if scope.is_empty() {
        return Err(OpError::new("bad_param", "scope: at least one subnet"));
    }
    let own = g.ipv4().ok_or_else(|| OpError::new("no_address", "this node has no address in the group"))?;
    let net = Ipv4Net::new(own, net_prefix(conf)).map_err(|e| OpError::new("bad_param", e.to_string()))?.trunc();
    let scope: Vec<IpNet> = scope.iter().map(IpNet::trunc).collect();
    for s in &scope {
        if !IpNet::V4(net).contains(s) {
            return Err(OpError::new("addr_invalid", format!("{s} is outside the group network {net}")));
        }
        let overlap = |o: &IpNet| o.contains(s) || s.contains(o);
        if let Some(d) = g.delegations.iter().find(|d| d.delegation.scope.iter().any(overlap)) {
            return Err(OpError::new("scope_taken", format!("{s} overlaps the scope of delegate {}", d.name)));
        }
    }
    let delegate = secret.delegate(scope, now_unix() + days * 86400);
    let issued = IssuedDelegation { name: name.to_owned(), delegation: delegate.delegation.clone() };
    Ok((delegate, issued))
}

/// Takes the right to invite back from a delegate, named or by key: invites it gave and that were
/// not used yet stop working, the members it brought in stay. Returns it and the record.
pub fn remove_delegate(
    secret: &GroupSecret,
    store: &StateStore,
    g: &GroupConfig,
    who: &str,
) -> Result<(IssuedDelegation, Entry), OpError> {
    check_clock()?;
    let d = g
        .delegations
        .iter()
        .find(|d| d.name == who || d.delegation.key.to_string() == who)
        .ok_or_else(|| OpError::new("no_delegate", format!("no delegate {who}")))?;
    Ok((d.clone(), store.add(secret, Body::Revoke { key: d.delegation.key }, false)))
}

/// Makes this node a delegate from the text an admin gave it, and saves.
pub fn accept_delegate(conf: &mut Config, text: &str) -> anyhow::Result<Delegate> {
    let Some(d) = Delegate::decode(text) else { bail!("not a valid delegation") };
    if now_unix() >= d.delegation.until {
        bail!("this delegation has expired");
    }
    if !conf.set_group_delegate(&d.delegation.group, &d) {
        bail!("this node is not in group {}", d.delegation.group);
    }
    conf.save();
    Ok(d)
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

/// Makes `rules` the ports forwarded on gateway `node` by admins. It applies them if it allows
/// that (`allow_remote`). Members are named by key from here on: a rule survives a new name.
pub fn set_forwards(
    secret: &GroupSecret,
    store: &StateStore,
    certs: &[Cert],
    node: NodeId,
    mut rules: Vec<crate::forward::Forward>,
) -> Result<Entry, OpError> {
    check_clock()?;
    crate::forward::check(&rules).map_err(|e| OpError::new("forward_invalid", e))?;
    for r in &mut rules {
        r.to = find_member(certs, &r.to)?.to_string();
    }
    let body = Body::Forward { node, rules };
    // the entry around the body: the group, id, time, signature
    if postcard::to_stdvec(&body).expect("body serializes").len() + 200 > crate::state::MAX_RECORD_LEN {
        return Err(OpError::new("forward_invalid", "too many rules for one gateway"));
    }
    Ok(store.add(secret, body, false))
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

    fn test_invite(secret: &GroupSecret, name: &str, until: u64) -> Invite {
        let template = CertBody::new(Identity::generate().id(), "phone", vec!["10.10.33.40/32".parse().unwrap()]);
        let join = secret.grant_join(template, until);
        let mut inv = Invite::new(name, 0, secret.psk(0), Vec::new(), Vec::new(), join, 24);
        inv.statics.push(StaticRef { key: Identity::generate().id(), endpoints: vec!["192.0.2.1:8647".into()] });
        inv
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    /// A config in a group 10.10.0.0/16, as its admin with `secret`, or as a member with `delegate`.
    fn group_conf(secret: &GroupSecret, admin: bool) -> (Config, GroupConfig) {
        let mut conf = Config::load(&temp_dir()).unwrap();
        conf.set_net_prefix(16);
        let cert = secret.issue(CertBody::new(conf.identity.id(), "me", vec![net("10.10.0.1/32")]));
        let g = GroupConfig {
            name: "home".into(),
            id: secret.id(),
            secret: admin.then(|| secret.clone()),
            epoch: 0,
            psk: secret.psk(0),
            cert: Some(cert),
            obfs: Default::default(),
            obfs_entries: Vec::new(),
            delegate: None,
            delegations: Vec::new(),
        };
        conf.add_group(g.clone());
        (conf, g)
    }

    fn request(addr: Option<&str>) -> InviteRequest {
        InviteRequest {
            name: "phone".into(),
            addr: addr.map(|a| a.parse().unwrap()),
            ttl_hours: 1,
            statics: Vec::new(),
            routes: Vec::new(),
            relay: false,
        }
    }

    #[test]
    fn forwards_set_by_an_admin() {
        use crate::forward::{Forward, Proto};
        let secret = GroupSecret::generate();
        let store = StateStore::memory();
        let (gw, server) = (Identity::generate().id(), Identity::generate().id());
        let certs = [secret.issue(CertBody::new(server, "server", vec![]))];
        let rule = |port, to: &str| Forward { proto: Proto::Tcp, port, to: to.into(), to_port: 80, keep_ip: false };
        let set = |rules| set_forwards(&secret, &store, &certs, gw, rules);

        set(vec![rule(8080, "server")]).unwrap();
        assert_eq!(store.forwards(&secret.id(), &gw), vec![rule(8080, &server.to_string())]);
        assert_eq!(store.forwards(&secret.id(), &server), vec![], "of that gateway only");
        assert_eq!(set(vec![rule(1, "nobody")]).unwrap_err().code, "member_unknown");
        assert_eq!(set(vec![rule(0, "server")]).unwrap_err().code, "forward_invalid");
        let many: Vec<_> = (1..40).map(|p| rule(p, "server")).collect();
        assert_eq!(set(many).unwrap_err().code, "forward_invalid");
        // the most that passes is a valid record
        let fit: Vec<_> = (1..=14).map(|p| rule(p, "server")).collect();
        set(fit).unwrap();
        set(Vec::new()).unwrap();
        assert_eq!(store.forwards(&secret.id(), &gw), vec![]);
    }

    #[test]
    fn free_host_ends() {
        let net: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let (a, b) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        assert_eq!(free_host(net, &[a], &[]), Some(b));
        assert_eq!(free_host(net, &[a, b], &[]), None, "full");
        assert_eq!(free_host(net, &[], &["10.0.0.0/30".parse().unwrap()]), None, "all avoided");
        assert_eq!(free_host("10.0.0.5/32".parse().unwrap(), &[], &[]), Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn delegate_invites_only_inside_its_scope() {
        let secret = GroupSecret::generate();
        let (admin_conf, admin) = group_conf(&secret, true);
        let (d, _) = add_delegate(&admin_conf, &admin, "carol", vec![net("10.10.40.0/24")], 30).unwrap();
        let (conf, mut g) = group_conf(&secret, false);
        let none = HashSet::new();
        assert_eq!(invite(&conf, &g, &[], &none, &request(None)).unwrap_err().code, "not_admin");
        g.delegate = Some(d.clone());

        let made = invite(&conf, &g, &[], &none, &request(None)).unwrap();
        assert!(net("10.10.40.0/24").contains(&IpAddr::V4(made.addr)), "{}", made.addr);
        let inv = Invite::decode(&made.invite, Some(now_unix())).unwrap();
        assert_eq!(inv.join.enroll(Identity::generate().id()).delegate_key(), Some(d.delegation.key));

        let code = |r: &InviteRequest, revoked: &HashSet<NodeId>| invite(&conf, &g, &[], revoked, r).unwrap_err().code;
        assert_eq!(code(&request(Some("10.10.41.5")), &none), "addr_invalid");
        assert_eq!(code(&InviteRequest { relay: true, ..request(None) }, &none), "delegate_limit");
        assert_eq!(code(&InviteRequest { routes: vec![net("0.0.0.0/0")], ..request(None) }, &none), "delegate_limit");
        assert_eq!(code(&request(None), &HashSet::from([d.delegation.key])), "delegate_ended");
    }

    #[test]
    fn admin_invites_keep_out_of_delegates_scopes() {
        let secret = GroupSecret::generate();
        let (conf, mut g) = group_conf(&secret, true);
        let (_, issued) = add_delegate(&conf, &g, "carol", vec![net("10.10.0.0/17")], 30).unwrap();
        g.delegations.push(issued);
        for _ in 0..50 {
            let made = invite(&conf, &g, &[], &HashSet::new(), &request(None)).unwrap();
            assert!(!net("10.10.0.0/17").contains(&IpAddr::V4(made.addr)), "{}", made.addr);
        }
        // but an admin can name one there
        assert!(invite(&conf, &g, &[], &HashSet::new(), &request(Some("10.10.0.9"))).is_ok());
    }

    #[test]
    fn delegates_checks() {
        let secret = GroupSecret::generate();
        let (conf, mut g) = group_conf(&secret, true);
        let add = |g: &GroupConfig, name: &str, s: &str| add_delegate(&conf, g, name, vec![net(s)], 30);
        let (_, issued) = add(&g, "carol", "10.10.40.0/24").unwrap();
        g.delegations.push(issued);
        assert_eq!(add(&g, "carol", "10.10.50.0/24").unwrap_err().code, "delegate_exists");
        assert_eq!(add(&g, "dave", "10.10.40.128/25").unwrap_err().code, "scope_taken");
        assert_eq!(add(&g, "dave", "10.10.0.0/16").unwrap_err().code, "scope_taken");
        assert_eq!(add(&g, "dave", "10.11.0.0/24").unwrap_err().code, "addr_invalid");
        assert_eq!(add(&g, " ", "10.10.50.0/24").unwrap_err().code, "bad_param");
        assert_eq!(add_delegate(&conf, &g, "dave", vec![], 30).unwrap_err().code, "bad_param");
        let (member_conf, member) = group_conf(&secret, false);
        assert_eq!(
            add_delegate(&member_conf, &member, "x", vec![net("10.10.60.0/24")], 30).unwrap_err().code,
            "not_admin"
        );

        let store = StateStore::memory();
        assert_eq!(remove_delegate(&secret, &store, &g, "nobody").unwrap_err().code, "no_delegate");
        let (d, _) = remove_delegate(&secret, &store, &g, "carol").unwrap();
        assert!(store.revoked(&g.id).contains(&d.delegation.key));
    }

    #[test]
    fn removed_delegate_keeps_its_members_not_its_invites() {
        let secret = GroupSecret::generate();
        let d = secret.delegate(vec![net("10.10.40.0/24")], now_unix() + 3600);
        let join = |a: &str| {
            d.grant_join(CertBody::new(Identity::generate().id(), "n", vec![net(a)]), now_unix() + 60)
                .enroll(Identity::generate().id())
        };
        let (member, pending) = (join("10.10.40.1/32"), join("10.10.40.2/32"));
        let store = StateStore::memory();
        let body = CertBody { group: secret.id(), ..member.body.clone() };
        store.add(&secret, Body::Cert(Box::new(secret.issue(body))), false);
        store.add(&secret, Body::Revoke { key: d.delegation.key }, false);
        let m = Membership::of(&store, &secret.id());
        assert!(m.admits(&member), "has a regular certificate, not picked up yet");
        assert!(!m.admits(&pending));
    }

    #[test]
    fn invite_conflicts() {
        let secret = GroupSecret::generate();
        let d = secret.delegate(vec![net("10.10.40.0/24")], now_unix() + 3600);
        let id = || Identity::generate().id();
        let new = d.grant_join(CertBody::new(id(), "bob", vec![net("10.10.40.1/32")]), now_unix() + 60).enroll(id());
        let cert = |name: &str, a: &str| secret.issue(CertBody::new(id(), name, vec![net(a)]));
        let m = Membership::default();
        assert_eq!(invite_conflict(&new, &[new.clone(), cert("alice", "10.10.40.2/32")], &m), None);
        assert!(invite_conflict(&new, &[cert("bob", "10.10.0.9/32")], &m).unwrap().contains("name"));
        assert!(invite_conflict(&new, &[cert("alice", "10.10.40.1/32")], &m).unwrap().contains("address"));
        // a member who is gone gives its name and address back
        let gone = cert("bob", "10.10.40.1/32");
        let m = Membership { revoked: HashSet::from([gone.body.node]), ..Default::default() };
        assert_eq!(invite_conflict(&new, &[gone], &m), None);
    }

    #[test]
    fn delegate_survives_the_config() {
        let secret = GroupSecret::generate();
        let dir = temp_dir();
        let mut conf = Config::load(&dir).unwrap();
        let inv = invite_for(&secret);
        join(&mut conf, &inv.encode()).unwrap();
        let d = secret.delegate(vec![net("10.10.33.0/24")], now_unix() + 3600);
        assert!(accept_delegate(&mut conf, "nonsense").is_err());
        let other = GroupSecret::generate().delegate(vec![net("10.10.33.0/24")], now_unix() + 3600);
        assert!(accept_delegate(&mut conf, &other.encode()).unwrap_err().to_string().contains("not in group"));
        let late = secret.delegate(vec![net("10.10.33.0/24")], now_unix() - 1);
        assert!(accept_delegate(&mut conf, &late.encode()).unwrap_err().to_string().contains("expired"));
        accept_delegate(&mut conf, &d.encode()).unwrap();

        let mut back = Config::load(&dir).unwrap();
        let g = back.group("home").unwrap();
        assert_eq!(g.delegate.as_ref().unwrap().delegation, d.delegation);

        let issued = IssuedDelegation { name: "carol".into(), delegation: d.delegation };
        let id = secret.id();
        back.set_group_delegations(&id, vec![issued.clone()]);
        back.save();
        let mut again = Config::load(&dir).unwrap();
        assert_eq!(again.group("home").unwrap().delegations, vec![issued]);
        again.set_group_delegations(&id, Vec::new());
        again.save();
        assert!(Config::load(&dir).unwrap().group("home").unwrap().delegations.is_empty());
    }

    fn invite_for(secret: &GroupSecret) -> Invite {
        test_invite(secret, "home", now_unix() + 3600)
    }

    #[test]
    fn join_takes_the_network_mask() {
        let dir = temp_dir();
        let mut conf = Config::load(&dir).unwrap();
        assert_eq!(net_prefix(&conf), 24);
        let mut inv = test_invite(&GroupSecret::generate(), "home", now_unix() + 3600);
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
        let inv = test_invite(&secret, "home", now_unix() + 3600);

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
        let other = join(&mut conf, &test_invite(&GroupSecret::generate(), "work", now_unix() + 3600).encode());
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
        let expired = test_invite(&GroupSecret::generate(), "home", now_unix() - 1).encode();
        assert!(join(&mut conf, &expired).unwrap_err().to_string().contains("expired"));
        assert!(conf.groups.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
