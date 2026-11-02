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
        let mut inv = Invite::new(name, 0, secret.psk(0), Vec::new(), Vec::new(), join);
        inv.statics.push(StaticRef { key: Identity::generate().id(), endpoints: vec!["192.0.2.1:8647".into()] });
        inv
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
