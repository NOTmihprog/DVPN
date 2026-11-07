//! Groups (PLAN §5): keys derived from the group secret, membership certificates and the
//! delegated join grants that let a new node enroll from an invite without an admin online.
//!
//! ```text
//! group_secret ─┬─ HKDF "dvpn/4 group sign"      → Ed25519 key; its public half is the group id
//!               └─ HKDF "dvpn/4 group psk" | epoch → psk of that epoch (Noise psk, header protection)
//! ```
//!
//! Admins hold the secret; members hold the psk of the current epoch and a [`Cert`]. A cert is
//! either signed by the group key directly, or delegated: the group signs a [`JoinGrant`] for a
//! one-time join key carried in an invite, and the join key signs the cert of whichever node
//! enrolls with it. Trackers and admins bind a join key to the first node seen using it.
//!
//! An admin can hand the right to invite into a part of the network to a [`Delegate`]: the group
//! signs a [`Delegation`] for a key of its own, and that key signs join grants instead of the
//! group. Such a cert stays inside the delegation's scope and has no roles; it only lasts until
//! an admin replaces it with a regular one, so a delegate signs nothing that outlives it.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey};
use hkdf::Hkdf;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::random_bytes;
use crate::identity::NodeId;

/// A group is named by its public signing key, so trackers can check certificates without
/// knowing any secret. Same encoding and validation as a node key.
pub type GroupId = NodeId;

/// Default certificate lifetime; members renew well before it ends (PLAN §5.2).
pub const CERT_TTL_SECS: u64 = 30 * 24 * 3600;
/// Default time to use an invite.
pub const JOIN_TTL_SECS: u64 = 24 * 3600;

const CERT_CTX: &[u8] = b"dvpn/4 cert\0";
const GRANT_CTX: &[u8] = b"dvpn/4 join grant\0";
const DELEGATION_CTX: &[u8] = b"dvpn/4 delegation\0";
const DELEGATE_VERSION: u8 = 1;

pub use crate::clock::now_unix;

fn hkdf32(ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm).expand_multi_info(info, &mut out).expect("32 bytes is a valid HKDF length");
    out
}

/// The admin secret of a group.
#[derive(Clone)]
pub struct GroupSecret([u8; 32]);

impl fmt::Debug for GroupSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupSecret({})", self.id())
    }
}

impl GroupSecret {
    pub fn generate() -> Self {
        GroupSecret(random_bytes())
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        GroupSecret(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&hkdf32(&self.0, &[b"dvpn/4 group sign"]))
    }

    /// Signs with the group key (state records, PLAN §8.1).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key().sign(msg)
    }

    pub fn id(&self) -> GroupId {
        self.signing_key().verifying_key().into()
    }

    /// The psk of `epoch`. Admins derive any epoch; members receive them (epoch 0 in the invite,
    /// later ones in records sealed to each member, so a revoked node cannot learn them).
    pub fn psk(&self, epoch: u32) -> [u8; 32] {
        hkdf32(&self.0, &[b"dvpn/4 group psk", &epoch.to_le_bytes()])
    }

    /// A certificate signed by the group key. `body.group` is overwritten with this group.
    pub fn issue(&self, mut body: CertBody) -> Cert {
        body.group = self.id();
        let sig = self.signing_key().sign(&body.signed_message(CERT_CTX));
        Cert { body, sig, grant: Grant::None }
    }

    /// A one-time join key for an invite. `template.node` is ignored (it becomes the join key);
    /// the enrolling node signs a cert with these fields for its own key (`Join::enroll`).
    /// Delegated certs cannot carry the admin role: admins need the secret anyway.
    pub fn grant_join(&self, mut template: CertBody, until: u64) -> Join {
        let join_key = SigningKey::from_bytes(&random_bytes());
        template.group = self.id();
        template.roles.0 &= !Roles::ADMIN;
        template.node = join_key.verifying_key().into();
        let sig = self.signing_key().sign(&grant_message(&template, until));
        Join {
            key: join_key.to_bytes(),
            grant: JoinGrant { key: template.node, until, sig },
            template,
            delegation: None,
        }
    }

    /// Lets a new key invite into `scope` until `until` (`Delegate::grant_join`).
    pub fn delegate(&self, scope: Vec<IpNet>, until: u64) -> Delegate {
        let key = SigningKey::from_bytes(&random_bytes());
        let (group, public) = (self.id(), key.verifying_key().into());
        let sig = self.signing_key().sign(&delegation_message(&group, &public, &scope, until));
        Delegate { key: key.to_bytes(), delegation: Delegation { group, key: public, scope, until, sig } }
    }
}

/// Role bits of a member (PLAN §5.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Roles(pub u8);

impl Roles {
    pub const RELAY: u8 = 1;
    pub const EXIT_V4: u8 = 2;
    pub const EXIT_V6: u8 = 4;
    pub const ADMIN: u8 = 8;

    pub fn has(self, role: u8) -> bool {
        self.0 & role == role
    }
}

/// What a certificate asserts. Serialized with postcard for signing, so field order is part
/// of the format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertBody {
    pub group: GroupId,
    pub node: NodeId,
    pub name: String,
    pub roles: Roles,
    /// Addresses and subnets the node may use and announce in the group.
    pub prefixes: Vec<IpNet>,
    /// Unix seconds.
    pub not_after: u64,
    pub serial: u64,
}

impl CertBody {
    /// A body for `node` valid for [`CERT_TTL_SECS`] from now, with a random serial; the group
    /// is filled in when it is signed.
    pub fn new(node: NodeId, name: &str, prefixes: Vec<IpNet>) -> Self {
        CertBody {
            group: node, // placeholder, replaced by issue/grant_join
            node,
            name: name.to_owned(),
            roles: Roles::default(),
            prefixes,
            not_after: now_unix() + CERT_TTL_SECS,
            serial: u64::from_le_bytes(random_bytes()),
        }
    }

    /// The node's IPv4 address in the group: the first IPv4 host prefix (/32). Wider prefixes
    /// are subnets behind the node (site-to-site).
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.prefixes.iter().find_map(|p| match p {
            IpNet::V4(n) if n.prefix_len() == 32 => Some(n.addr()),
            _ => None,
        })
    }

    /// Subnets behind the node: the prefixes other than its own host address.
    pub fn routes(&self) -> impl Iterator<Item = &IpNet> {
        let own = self.ipv4();
        self.prefixes
            .iter()
            .filter(move |p| !matches!(p, IpNet::V4(n) if Some(n.addr()) == own && n.prefix_len() == 32))
    }

    fn signed_message(&self, ctx: &[u8]) -> Vec<u8> {
        let mut m = ctx.to_vec();
        m.extend(postcard::to_stdvec(self).expect("cert body serializes"));
        m
    }
}

fn grant_message(template: &CertBody, until: u64) -> Vec<u8> {
    let mut m = template.signed_message(GRANT_CTX);
    m.extend(until.to_le_bytes());
    m
}

fn delegation_message(group: &GroupId, key: &NodeId, scope: &[IpNet], until: u64) -> Vec<u8> {
    let mut m = DELEGATION_CTX.to_vec();
    m.extend(postcard::to_stdvec(&(group, key, scope, until)).expect("delegation serializes"));
    m
}

/// The group's signature allowing `key` to sign join grants for addresses inside `scope` until
/// `until`. Revoked like a node, by `key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub group: GroupId,
    pub key: NodeId,
    pub scope: Vec<IpNet>,
    pub until: u64,
    pub sig: Signature,
}

impl Delegation {
    fn verify(&self) -> bool {
        let m = delegation_message(&self.group, &self.key, &self.scope, self.until);
        self.group.verifying_key().verify_strict(&m, &self.sig).is_ok()
    }

    /// Whether `prefix` lies inside the scope.
    pub fn covers(&self, prefix: &IpNet) -> bool {
        self.scope.iter().any(|s| s.contains(prefix))
    }
}

/// What the delegate holds: the delegation and its private key.
#[derive(Clone, Serialize, Deserialize)]
pub struct Delegate {
    pub key: [u8; 32],
    pub delegation: Delegation,
}

impl fmt::Debug for Delegate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delegate").field("delegation", &self.delegation).finish_non_exhaustive()
    }
}

impl Delegate {
    /// A one-time join key for an invite, like `GroupSecret::grant_join`, signed by this
    /// delegate. Nothing it grants outlives the delegation; roles are not its to give.
    pub fn grant_join(&self, mut template: CertBody, until: u64) -> Join {
        let d = &self.delegation;
        let until = until.min(d.until);
        let join_key = SigningKey::from_bytes(&random_bytes());
        template.group = d.group;
        template.roles = Roles::default();
        template.not_after = template.not_after.min(d.until);
        template.node = join_key.verifying_key().into();
        let sig = SigningKey::from_bytes(&self.key).sign(&grant_message(&template, until));
        let grant = JoinGrant { key: template.node, until, sig };
        Join { key: join_key.to_bytes(), grant, template, delegation: Some(Box::new(d.clone())) }
    }

    /// The text an admin passes to the delegate (a secret, like an invite).
    pub fn encode(&self) -> String {
        let mut b = vec![DELEGATE_VERSION];
        b.extend(postcard::to_stdvec(self).expect("delegate serializes"));
        crate::crypto::encode_b64(&b)
    }

    /// Reads a delegate's text: it must be signed by its group and hold the delegation's key.
    pub fn decode(s: &str) -> Option<Self> {
        let s: String = s.split_whitespace().collect();
        let b = crate::crypto::decode_b64(&s).ok()?;
        let (&version, rest) = b.split_first()?;
        let d: Delegate = postcard::from_bytes(rest).ok()?;
        let public: NodeId = SigningKey::from_bytes(&d.key).verifying_key().into();
        (version == DELEGATE_VERSION && public == d.delegation.key && d.delegation.verify()).then_some(d)
    }
}

/// A delegation as the admin who made it remembers it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedDelegation {
    pub name: String,
    pub delegation: Delegation,
}

impl IssuedDelegation {
    pub fn encode(&self) -> String {
        crate::crypto::encode_b64(&postcard::to_stdvec(self).expect("delegation serializes"))
    }

    pub fn decode(s: &str) -> Option<Self> {
        let d: Self = postcard::from_bytes(&crate::crypto::decode_b64(s).ok()?).ok()?;
        d.delegation.verify().then_some(d)
    }
}

/// The group's signature allowing `key` to sign one member certificate with the fields of the
/// template (all but `node`) until `until`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinGrant {
    pub key: NodeId,
    pub until: u64,
    pub sig: Signature,
}

/// The joining half of an invite: the private join key, the grant and the cert fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct Join {
    pub key: [u8; 32],
    pub grant: JoinGrant,
    pub template: CertBody,
    /// Present when a delegate signed the grant.
    pub delegation: Option<Box<Delegation>>,
}

impl fmt::Debug for Join {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Join").field("grant", &self.grant).field("template", &self.template).finish_non_exhaustive()
    }
}

impl Join {
    /// The certificate of `node`, signed with the join key.
    pub fn enroll(&self, node: NodeId) -> Cert {
        let body = CertBody { node, ..self.template.clone() };
        let sig = SigningKey::from_bytes(&self.key).sign(&body.signed_message(CERT_CTX));
        let grant = match &self.delegation {
            None => Grant::Join(self.grant.clone()),
            Some(d) => Grant::Delegated(self.grant.clone(), d.clone()),
        };
        Cert { body, sig, grant }
    }
}

/// Who signed a cert. The first two variants encode like the `Option<JoinGrant>` this used to
/// be, so regular and invite certificates, and the records holding them, keep their bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grant {
    /// The group key.
    None,
    /// The join key of the grant, which the group signed.
    Join(JoinGrant),
    /// The join key of the grant, which a delegate signed.
    Delegated(JoinGrant, Box<Delegation>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub body: CertBody,
    pub sig: Signature,
    pub grant: Grant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertError {
    WrongGroup,
    BadSignature,
    BadGrant,
    /// A delegated cert claiming the admin role.
    DelegatedAdmin,
    /// A delegate's cert with a role, which delegates cannot give.
    DelegateRole,
    /// A delegate's cert for prefixes outside its scope.
    OutOfScope,
    Expired,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CertError::WrongGroup => "certificate of another group",
            CertError::BadSignature => "bad certificate signature",
            CertError::BadGrant => "bad join grant",
            CertError::DelegatedAdmin => "delegated certificate with the admin role",
            CertError::DelegateRole => "delegate's certificate with a role",
            CertError::OutOfScope => "delegate's certificate outside its scope",
            CertError::Expired => "certificate expired",
        })
    }
}

impl std::error::Error for CertError {}

impl Cert {
    /// Checks the signatures and, if `now` is given, the expiry. `now` is `None` while the
    /// clock is known to be wrong (no RTC before NTP, PLAN §14a).
    pub fn verify(&self, group: &GroupId, now: Option<u64>) -> Result<(), CertError> {
        let b = &self.body;
        if &b.group != group {
            return Err(CertError::WrongGroup);
        }
        if self.grant != Grant::None && b.roles.has(Roles::ADMIN) {
            return Err(CertError::DelegatedAdmin);
        }
        let check_grant = |g: &JoinGrant, by: &NodeId| {
            let template = CertBody { node: g.key, ..b.clone() };
            by.verifying_key()
                .verify_strict(&grant_message(&template, g.until), &g.sig)
                .map_err(|_| CertError::BadGrant)
        };
        let signer = match &self.grant {
            Grant::None => *group,
            Grant::Join(g) => {
                check_grant(g, group)?;
                g.key
            }
            Grant::Delegated(g, d) => {
                if &d.group != group || !d.verify() || g.until > d.until || b.not_after > d.until {
                    return Err(CertError::BadGrant);
                }
                if b.roles != Roles::default() {
                    return Err(CertError::DelegateRole);
                }
                if !b.prefixes.iter().all(|p| d.covers(p)) {
                    return Err(CertError::OutOfScope);
                }
                check_grant(g, &d.key)?;
                g.key
            }
        };
        signer
            .verifying_key()
            .verify_strict(&b.signed_message(CERT_CTX), &self.sig)
            .map_err(|_| CertError::BadSignature)?;
        if now.is_some_and(|t| t > b.not_after) {
            return Err(CertError::Expired);
        }
        Ok(())
    }

    /// The join key a delegated cert was enrolled with.
    pub fn join_key(&self) -> Option<NodeId> {
        match &self.grant {
            Grant::None => None,
            Grant::Join(g) | Grant::Delegated(g, _) => Some(g.key),
        }
    }

    /// The key of the delegate that invited this node, while this is its invite cert.
    pub fn delegate_key(&self) -> Option<NodeId> {
        match &self.grant {
            Grant::Delegated(_, d) => Some(d.key),
            _ => None,
        }
    }

    /// Whether this is still the certificate from an invite.
    pub fn from_invite(&self) -> bool {
        self.grant != Grant::None
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("cert serializes")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }
}

/// A tracker as given in invites and config: the host as typed (domain or IP), port and key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerRef {
    pub host: String,
    pub port: u16,
    pub key: [u8; 32],
}

/// A node reachable at fixed addresses (PLAN §10), as given in invites and `[[static_peers]]`:
/// endpoints are `host:port` text (domain names are resolved when connecting).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRef {
    pub key: NodeId,
    pub endpoints: Vec<String>,
}

const INVITE_VERSION: u8 = 3;

/// Everything a node needs to join a group (PLAN §5.3), as one base64url string: the group psk
/// of the current epoch, the obfuscation profile, the network mask, trackers, and a one-time join
/// key with its grant.
#[derive(Clone, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    /// Suggested local name of the group.
    pub name: String,
    pub epoch: u32,
    pub psk: [u8; 32],
    /// `[groups.obfs]` entries as `(key, value)` text, applied as is by the joining node.
    pub obfs: Vec<(String, String)>,
    pub trackers: Vec<TrackerRef>,
    pub join: Join,
    /// Nodes to connect to directly (the inviting admin's node, if it has a fixed address): a
    /// group can work without any tracker.
    pub statics: Vec<StaticRef>,
    /// Prefix length of the group network (`[net] mask`), applied by the joining node.
    pub net_prefix: u8,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("name", &self.name)
            .field("group", &self.group())
            .field("epoch", &self.epoch)
            .field("trackers", &self.trackers)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    Encoding,
    Version(u8),
    /// The grant does not verify: corrupted, or not made by this group.
    Grant(CertError),
    Expired,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteError::Encoding => f.write_str("not an invite (bad encoding)"),
            InviteError::Version(v) => write!(f, "invite version {v} is not supported"),
            InviteError::Grant(e) => write!(f, "invalid invite: {e}"),
            InviteError::Expired => f.write_str("invite expired"),
        }
    }
}

impl std::error::Error for InviteError {}

impl Invite {
    pub fn new(
        name: &str,
        epoch: u32,
        psk: [u8; 32],
        obfs: Vec<(String, String)>,
        trackers: Vec<TrackerRef>,
        join: Join,
        net_prefix: u8,
    ) -> Self {
        Invite {
            version: INVITE_VERSION,
            name: name.to_owned(),
            epoch,
            psk,
            obfs,
            trackers,
            join,
            statics: Vec::new(),
            net_prefix,
        }
    }

    pub fn group(&self) -> GroupId {
        self.join.template.group
    }

    pub fn encode(&self) -> String {
        crate::crypto::encode_b64(&postcard::to_stdvec(self).expect("invite serializes"))
    }

    /// Decodes and checks an invite: the grant must be the group's and, if `now` is given,
    /// still usable. Whitespace anywhere is ignored (base64url has none): an invite copied from
    /// a terminal or a message comes with line breaks.
    pub fn decode(s: &str, now: Option<u64>) -> Result<Self, InviteError> {
        let s: String = s.split_whitespace().collect();
        let bytes = crate::crypto::decode_b64(&s).map_err(|_| InviteError::Encoding)?;
        let inv: Invite = postcard::from_bytes(&bytes).map_err(|_| InviteError::Encoding)?;
        if inv.version != INVITE_VERSION {
            return Err(InviteError::Version(inv.version));
        }
        if inv.net_prefix > 32 {
            return Err(InviteError::Encoding);
        }
        // the join key must be the granted one, and the grant the group's
        let probe = inv.join.enroll(inv.join.grant.key);
        probe.verify(&inv.group(), None).map_err(InviteError::Grant)?;
        if now.is_some_and(|t| t > inv.join.grant.until) {
            return Err(InviteError::Expired);
        }
        Ok(inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use proptest::prelude::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let s = GroupSecret::from_bytes([7; 32]);
        assert_eq!(s.id(), GroupSecret::from_bytes([7; 32]).id());
        assert_ne!(s.psk(0), s.psk(1));
        assert_ne!(&s.psk(0), s.id().as_bytes());
        assert_ne!(s.id(), GroupSecret::from_bytes([8; 32]).id());
    }

    #[test]
    fn direct_cert() {
        let g = GroupSecret::generate();
        let node = Identity::generate().id();
        let cert = g.issue(CertBody::new(node, "laptop", vec![net("10.10.0.5/32")]));
        assert_eq!(cert.verify(&g.id(), Some(now_unix())), Ok(()));
        assert_eq!(cert.verify(&g.id(), None), Ok(()));
        assert_eq!(Cert::decode(&cert.encode()), Some(cert.clone()));
        assert_eq!(cert.verify(&GroupSecret::generate().id(), None), Err(CertError::WrongGroup));
        assert_eq!(cert.verify(&g.id(), Some(cert.body.not_after + 1)), Err(CertError::Expired));
        assert_eq!(cert.join_key(), None);
    }

    #[test]
    fn tampered_or_forged_certs_fail() {
        let g = GroupSecret::generate();
        let node = Identity::generate().id();
        let cert = g.issue(CertBody::new(node, "a", vec![net("10.10.0.5/32")]));
        let mut c = cert.clone();
        c.body.prefixes.push(net("0.0.0.0/0"));
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
        let mut c = cert.clone();
        c.body.node = Identity::generate().id();
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
        let mut c = cert.clone();
        c.body.roles.0 |= Roles::ADMIN;
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
        // another group's signature with this group's id
        let mut c = GroupSecret::generate().issue(cert.body.clone());
        c.body.group = g.id();
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
    }

    #[test]
    fn delegated_join() {
        let g = GroupSecret::generate();
        let mut t = CertBody::new(NodeId::random(), "phone", vec![net("10.10.0.9/32")]);
        t.roles.0 = Roles::RELAY | Roles::ADMIN;
        let join = g.grant_join(t, now_unix() + JOIN_TTL_SECS);
        assert!(!join.template.roles.has(Roles::ADMIN), "admin role stripped from grants");

        let node = Identity::generate().id();
        let cert = join.enroll(node);
        assert_eq!(cert.body.node, node);
        assert_eq!(cert.body.name, "phone");
        assert!(cert.body.roles.has(Roles::RELAY));
        assert_eq!(cert.verify(&g.id(), Some(now_unix())), Ok(()));
        assert_eq!(cert.join_key(), Some(join.grant.key));
        assert_eq!(Cert::decode(&cert.encode()), Some(cert.clone()));

        // fields covered by the grant cannot be changed by the joiner, even re-signing with the join key
        let jk = SigningKey::from_bytes(&join.key);
        for f in [
            |b: &mut CertBody| b.prefixes = vec!["0.0.0.0/0".parse().unwrap()],
            |b: &mut CertBody| b.not_after += 1,
            |b: &mut CertBody| b.roles.0 |= Roles::EXIT_V4,
            |b: &mut CertBody| b.name.push('!'),
        ] {
            let mut c = cert.clone();
            f(&mut c.body);
            c.sig = jk.sign(&c.body.signed_message(CERT_CTX));
            assert_eq!(c.verify(&g.id(), None), Err(CertError::BadGrant));
        }
        // a forged grant from a non-member key
        let mut c = cert.clone();
        let fake = GroupSecret::generate().grant_join(join.template.clone(), join.grant.until);
        c.grant = Grant::Join(fake.grant.clone());
        c.sig = SigningKey::from_bytes(&fake.key).sign(&c.body.signed_message(CERT_CTX));
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadGrant));
        // a direct-looking cert signed by the join key
        let mut c = cert.clone();
        c.grant = Grant::None;
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
        // the admin bit on a delegated cert is refused before any signature check
        let mut c = cert;
        c.body.roles.0 |= Roles::ADMIN;
        assert_eq!(c.verify(&g.id(), None), Err(CertError::DelegatedAdmin));
    }

    #[test]
    fn invite_round_trip_and_checks() {
        let g = GroupSecret::generate();
        let join = g.grant_join(CertBody::new(NodeId::random(), "b", vec![net("10.10.0.7/32")]), now_unix() + 60);
        let tracker = TrackerRef { host: "tracker.example".into(), port: 6485, key: [3; 32] };
        let inv = Invite::new("home", 0, g.psk(0), vec![("jc".into(), "1-2".into())], vec![tracker.clone()], join, 16);
        let text = inv.encode();
        let back = Invite::decode(&text, Some(now_unix())).unwrap();
        assert_eq!((back.group(), back.psk, back.trackers, back.obfs.len()), (g.id(), g.psk(0), vec![tracker], 1));
        assert_eq!(back.net_prefix, 16);
        let node = Identity::generate().id();
        assert_eq!(back.join.enroll(node).verify(&g.id(), Some(now_unix())), Ok(()));

        assert_eq!(Invite::decode(&text, Some(now_unix() + 61)).err(), Some(InviteError::Expired));
        // copied from a terminal: broken into lines, indented
        let wrapped: String =
            text.as_bytes().chunks(40).map(|c| format!("  {}\r\n", std::str::from_utf8(c).unwrap())).collect();
        assert_eq!(Invite::decode(&wrapped, Some(now_unix())).unwrap().encode(), text);
        assert_eq!(Invite::decode("not an invite", None).err(), Some(InviteError::Encoding));
        // a network mask that cannot be
        let mut bad = inv.clone();
        bad.net_prefix = 33;
        assert_eq!(Invite::decode(&bad.encode(), None).err(), Some(InviteError::Encoding));
        // another join key than the granted one
        let mut bad = inv.clone();
        bad.join.key = random_bytes();
        assert!(matches!(Invite::decode(&bad.encode(), None), Err(InviteError::Grant(_))));
        // a grant claimed for another group
        let mut bad = inv;
        bad.join.template.group = GroupSecret::generate().id();
        assert!(matches!(Invite::decode(&bad.encode(), None), Err(InviteError::Grant(_))));
    }

    fn delegated(g: &GroupSecret, scope: &str, addr: &str) -> (Delegate, Cert) {
        let d = g.delegate(vec![net(scope)], now_unix() + 3600);
        let join = d.grant_join(CertBody::new(NodeId::random(), "n", vec![net(addr)]), now_unix() + 60);
        let cert = join.enroll(Identity::generate().id());
        (d, cert)
    }

    #[test]
    fn grant_keeps_the_bytes_of_an_option() {
        let g = GroupSecret::generate();
        let join = g.grant_join(CertBody::new(NodeId::random(), "n", vec![]), 60);
        let old: Option<JoinGrant> = None;
        assert_eq!(postcard::to_stdvec(&Grant::None).unwrap(), postcard::to_stdvec(&old).unwrap());
        let old = Some(join.grant.clone());
        assert_eq!(postcard::to_stdvec(&Grant::Join(join.grant)).unwrap(), postcard::to_stdvec(&old).unwrap());
    }

    #[test]
    fn delegate_invites_inside_its_scope() {
        let g = GroupSecret::generate();
        let (d, cert) = delegated(&g, "10.10.40.0/24", "10.10.40.7/32");
        assert_eq!(cert.verify(&g.id(), Some(now_unix())), Ok(()));
        assert_eq!(cert.delegate_key(), Some(d.delegation.key));
        assert!(cert.from_invite());
        assert_eq!(Cert::decode(&cert.encode()), Some(cert.clone()));
        // no longer than the delegation
        assert!(cert.body.not_after <= d.delegation.until);
        // of this group only
        assert_eq!(cert.verify(&GroupSecret::generate().id(), None), Err(CertError::WrongGroup));
        // the group did not sign this grant
        let Grant::Delegated(jg, _) = &cert.grant else { panic!() };
        let forged = Cert { grant: Grant::Join(jg.clone()), ..cert.clone() };
        assert_eq!(forged.verify(&g.id(), None), Err(CertError::BadGrant));
    }

    #[test]
    fn delegate_cannot_leave_its_limits() {
        let g = GroupSecret::generate();
        // the signatures are all right, the delegation does not allow it
        let (_, out) = delegated(&g, "10.10.40.0/24", "10.10.41.7/32");
        assert_eq!(out.verify(&g.id(), None), Err(CertError::OutOfScope));
        let (_, wide) = delegated(&g, "10.10.40.0/24", "0.0.0.0/0");
        assert_eq!(wide.verify(&g.id(), None), Err(CertError::OutOfScope));

        let d = g.delegate(vec![net("10.10.40.0/24")], now_unix() + 2 * CERT_TTL_SECS);
        let sign = |body: CertBody, until: u64| {
            let (jk, node) = (SigningKey::from_bytes(&random_bytes()), Identity::generate().id());
            let template = CertBody { node: jk.verifying_key().into(), group: g.id(), ..body };
            let sig = SigningKey::from_bytes(&d.key).sign(&grant_message(&template, until));
            let join = Join {
                key: jk.to_bytes(),
                grant: JoinGrant { key: template.node, until, sig },
                template,
                delegation: Some(Box::new(d.delegation.clone())),
            };
            join.enroll(node)
        };
        let body = || CertBody::new(NodeId::random(), "n", vec![net("10.10.40.7/32")]);
        let mut relay = body();
        relay.roles.0 = Roles::RELAY;
        assert_eq!(sign(relay, now_unix()).verify(&g.id(), None), Err(CertError::DelegateRole));
        let mut admin = body();
        admin.roles.0 = Roles::ADMIN;
        assert_eq!(sign(admin, now_unix()).verify(&g.id(), None), Err(CertError::DelegatedAdmin));
        let mut long = body();
        long.not_after = d.delegation.until + 1;
        assert_eq!(sign(long, now_unix()).verify(&g.id(), None), Err(CertError::BadGrant));
        assert_eq!(sign(body(), d.delegation.until + 1).verify(&g.id(), None), Err(CertError::BadGrant));
        // grant_join itself keeps inside: no roles, no longer than the delegation
        let mut t = body();
        t.roles.0 = Roles::RELAY;
        t.not_after = d.delegation.until + 100;
        let join = d.grant_join(t, d.delegation.until + 100);
        assert_eq!(join.enroll(Identity::generate().id()).verify(&g.id(), None), Ok(()));

        // a delegation the group did not sign
        let other = GroupSecret::generate().delegate(vec![net("10.10.40.0/24")], now_unix() + 3600);
        let mut fake = other.clone();
        fake.delegation.group = g.id();
        let cert = fake.grant_join(body(), now_unix() + 60).enroll(Identity::generate().id());
        assert_eq!(cert.verify(&g.id(), None), Err(CertError::BadGrant));
    }

    #[test]
    fn delegate_text_round_trip_and_checks() {
        let g = GroupSecret::generate();
        let d = g.delegate(vec![net("10.10.40.0/24")], now_unix() + 3600);
        let back = Delegate::decode(&format!("  {}\n", d.encode())).unwrap();
        assert_eq!((back.key, back.delegation), (d.key, d.delegation.clone()));
        assert!(Delegate::decode("not a delegate").is_none());
        // the key must be the delegated one
        let mut bad = d.clone();
        bad.key = random_bytes();
        assert!(Delegate::decode(&bad.encode()).is_none());
        // a wider scope than was signed
        let mut bad = d.clone();
        bad.delegation.scope = vec![net("0.0.0.0/0")];
        assert!(Delegate::decode(&bad.encode()).is_none());
        let issued = IssuedDelegation { name: "carol".into(), delegation: d.delegation };
        assert_eq!(IssuedDelegation::decode(&issued.encode()), Some(issued));
    }

    #[test]
    fn invite_from_a_delegate() {
        let g = GroupSecret::generate();
        let d = g.delegate(vec![net("10.10.40.0/24")], now_unix() + 3600);
        let join = d.grant_join(CertBody::new(NodeId::random(), "b", vec![net("10.10.40.7/32")]), now_unix() + 60);
        let inv = Invite::new("home", 0, g.psk(0), vec![], vec![], join, 16);
        let back = Invite::decode(&inv.encode(), Some(now_unix())).unwrap();
        assert_eq!(back.group(), g.id());
        assert_eq!(back.join.enroll(Identity::generate().id()).verify(&g.id(), Some(now_unix())), Ok(()));
    }

    proptest! {
        /// Decoding arbitrary bytes never panics, and whatever decodes does not verify.
        #[test]
        fn decode_garbage(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let g = GroupSecret::from_bytes([1; 32]);
            if let Some(c) = Cert::decode(&bytes) {
                prop_assert!(c.verify(&g.id(), None).is_err());
            }
        }
    }
}
