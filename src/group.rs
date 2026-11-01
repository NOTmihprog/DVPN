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

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

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
        Cert { body, sig, grant: None }
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
        Join { key: join_key.to_bytes(), grant: JoinGrant { key: template.node, until, sig }, template }
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
        Cert { body, sig, grant: Some(self.grant.clone()) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub body: CertBody,
    pub sig: Signature,
    /// Present for a delegated cert: `sig` is then by `grant.key`, not by the group.
    pub grant: Option<JoinGrant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertError {
    WrongGroup,
    BadSignature,
    BadGrant,
    /// A delegated cert claiming the admin role.
    DelegatedAdmin,
    Expired,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CertError::WrongGroup => "certificate of another group",
            CertError::BadSignature => "bad certificate signature",
            CertError::BadGrant => "bad join grant",
            CertError::DelegatedAdmin => "delegated certificate with the admin role",
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
        let signer = match &self.grant {
            None => *group,
            Some(g) => {
                if b.roles.has(Roles::ADMIN) {
                    return Err(CertError::DelegatedAdmin);
                }
                let template = CertBody { node: g.key, ..b.clone() };
                group
                    .verifying_key()
                    .verify_strict(&grant_message(&template, g.until), &g.sig)
                    .map_err(|_| CertError::BadGrant)?;
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
        self.grant.as_ref().map(|g| g.key)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("cert serializes")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
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
        c.grant = Some(fake.grant.clone());
        c.sig = SigningKey::from_bytes(&fake.key).sign(&c.body.signed_message(CERT_CTX));
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadGrant));
        // a direct-looking cert signed by the join key
        let mut c = cert.clone();
        c.grant = None;
        assert_eq!(c.verify(&g.id(), None), Err(CertError::BadSignature));
        // the admin bit on a delegated cert is refused before any signature check
        let mut c = cert;
        c.body.roles.0 |= Roles::ADMIN;
        assert_eq!(c.verify(&g.id(), None), Err(CertError::DelegatedAdmin));
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
