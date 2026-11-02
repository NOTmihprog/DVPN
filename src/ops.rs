//! Operations on a node's config that the CLI and the apps share (PLAN 7.4): joining a group by
//! an invite and leaving it.

use anyhow::bail;

use crate::config::{Config, GroupConfig, parse_obfs};
use crate::group::{GroupId, Invite, now_unix};

/// What joining gave.
#[derive(Clone, Debug)]
pub struct Joined {
    /// The local name of the group (made unique if a group of that name exists).
    pub group: String,
    pub id: GroupId,
    /// This node's name and IPv4 address in the group, from the certificate.
    pub name: String,
    pub addr: Option<std::net::Ipv4Addr>,
    /// Trackers and static peers added to the config.
    pub added: Vec<String>,
}

/// Joins the group of `invite` (its base64url text): enrolls this node's key
/// with the invite's join key, adds the group, its trackers and static peers, and saves.
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
