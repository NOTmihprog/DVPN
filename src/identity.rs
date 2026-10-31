//! Node identity (PLAN §3): a node is its Ed25519 public key.
//!
//! The only secret a node keeps is the 32-byte Ed25519 seed. The X25519 key used for Noise is
//! derived from it (`ed25519 → curve25519`, as in Yggdrasil and libsodium's
//! `crypto_sign_ed25519_*_to_curve25519`), so there is no second secret to store or lose.
//!
//! Text form of keys everywhere (config, CLI, API, logs): base64url without padding, 43 chars.
//! Parsing also accepts standard base64 and padding.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::{decode_b64, encode_b64, random_bytes};

pub const NODE_ID_LEN: usize = 32;
/// Length of the canonical text form (base64url, no padding).
pub const NODE_ID_TEXT_LEN: usize = 43;
/// Length of the short prefix shown in logs and tables.
pub const NODE_ID_SHORT_LEN: usize = 10;

/// Ed25519 public key of a node. Always a valid, non-weak curve point: every constructor
/// checks it, so `verifying_key()` and `x25519_public()` cannot fail.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; NODE_ID_LEN]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidNodeId(&'static str);

impl fmt::Display for InvalidNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidNodeId {}

impl NodeId {
    /// Rejects bytes that are not a curve point, and weak (small-order) keys: those would
    /// make signatures valid for almost any message and X25519 shared secrets predictable.
    pub fn from_bytes(b: &[u8; NODE_ID_LEN]) -> Result<Self, InvalidNodeId> {
        let key = VerifyingKey::from_bytes(b).map_err(|_| InvalidNodeId("not an ed25519 public key"))?;
        if key.is_weak() {
            return Err(InvalidNodeId("weak ed25519 public key"));
        }
        Ok(NodeId(*b))
    }

    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("NodeId is validated on construction")
    }

    /// The node's static X25519 public key (for Noise), birationally mapped from Ed25519.
    pub fn x25519_public(&self) -> X25519Public {
        X25519Public::from(self.verifying_key().to_montgomery().to_bytes())
    }

    /// Short prefix of the text form for logs and tables. Not unique: look the full key up
    /// by prefix where a user types it.
    pub fn short(&self) -> String {
        let mut s = self.to_string();
        s.truncate(NODE_ID_SHORT_LEN);
        s
    }
}

impl From<VerifyingKey> for NodeId {
    fn from(key: VerifyingKey) -> Self {
        NodeId(key.to_bytes())
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = InvalidNodeId;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let b: &[u8; NODE_ID_LEN] = b.try_into().map_err(|_| InvalidNodeId("key must be 32 bytes"))?;
        NodeId::from_bytes(b)
    }
}

impl FromStr for NodeId {
    type Err = InvalidNodeId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = decode_b64(s.trim()).map_err(|_| InvalidNodeId("invalid base64"))?;
        NodeId::try_from(b.as_slice())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_b64(&self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

/// Text in human-readable formats (JSON, TOML), a fixed 32-byte array in binary ones (postcard).
impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() { s.collect_str(self) } else { self.0.serialize(s) }
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            String::deserialize(d)?.parse().map_err(D::Error::custom)
        } else {
            NodeId::from_bytes(&<[u8; NODE_ID_LEN]>::deserialize(d)?).map_err(D::Error::custom)
        }
    }
}

/// A node's own keys: the Ed25519 signing key and the X25519 key derived from it.
pub struct Identity {
    signing: SigningKey,
    x25519: StaticSecret,
    id: NodeId,
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_seed(&random_bytes())
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        // X25519 clamps on use, so the unclamped SHA-512 half is the right secret here.
        let x25519 = StaticSecret::from(signing.to_scalar_bytes());
        let id = NodeId::from(signing.verifying_key());
        Identity { signing, x25519, id }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// Private key text for `config.toml` / `DVPN_PRIVATE_KEY`: the seed in base64url.
    /// Deliberately not `Display`, so it cannot end up in a log line by accident.
    pub fn private_key_text(&self) -> String {
        encode_b64(self.signing.as_bytes())
    }

    /// Parses `private_key_text()` output (standard base64 and padding accepted too).
    pub fn from_private_key_text(s: &str) -> Result<Self, InvalidNodeId> {
        let b = decode_b64(s.trim()).map_err(|_| InvalidNodeId("invalid base64"))?;
        let seed: &[u8; 32] = b.as_slice().try_into().map_err(|_| InvalidNodeId("private key must be 32 bytes"))?;
        Ok(Self::from_seed(seed))
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, <secret>)", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use proptest::prelude::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    /// RFC 8032 §7.1 test 1 seed; X25519 values computed independently with libsodium
    /// `crypto_sign_ed25519_pk_to_curve25519` / `crypto_sign_ed25519_sk_to_curve25519`.
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ED_PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const X_PUB: &str = "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e";
    const X_SEC_CLAMPED: &str = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f";

    #[test]
    fn ed25519_to_x25519_vector() {
        let id = Identity::from_seed(&hex32(SEED));
        assert_eq!(id.id().as_bytes(), &hex32(ED_PUB));
        assert_eq!(id.id().x25519_public().as_bytes(), &hex32(X_PUB));
        assert_eq!(X25519Public::from(id.x25519_secret()).as_bytes(), &hex32(X_PUB));
        let mut clamped = id.x25519_secret().to_bytes();
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert_eq!(clamped, hex32(X_SEC_CLAMPED));
    }

    #[test]
    fn x25519_dh_agrees() {
        let (a, b) = (Identity::generate(), Identity::generate());
        let ab = a.x25519_secret().diffie_hellman(&b.id().x25519_public());
        let ba = b.x25519_secret().diffie_hellman(&a.id().x25519_public());
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    #[test]
    fn text_form() {
        let id = Identity::from_seed(&hex32(SEED)).id();
        let s = id.to_string();
        assert_eq!(s, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(s.len(), NODE_ID_TEXT_LEN);
        assert_eq!(id.short(), "11qYAYKxCr");
        // standard alphabet and padding are accepted too
        assert_eq!("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".parse::<NodeId>().unwrap(), id);
        assert_eq!(format!(" {s}\n").parse::<NodeId>().unwrap(), id);
    }

    #[test]
    fn rejects_bad_keys() {
        assert!("".parse::<NodeId>().is_err());
        assert!("not base64!".parse::<NodeId>().is_err());
        // 31 bytes
        assert!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse::<NodeId>().is_err());
        // identity point (small order): weak
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert_eq!(NodeId::from_bytes(&ident), Err(InvalidNodeId("weak ed25519 public key")));
        // y = 2 is not on the curve
        let mut off = [0u8; 32];
        off[0] = 2;
        assert_eq!(NodeId::from_bytes(&off), Err(InvalidNodeId("not an ed25519 public key")));
    }

    #[test]
    fn private_key_text_round_trip() {
        let a = Identity::generate();
        let text = a.private_key_text();
        assert_eq!(text.len(), 43);
        let b = Identity::from_private_key_text(&text).unwrap();
        assert_eq!(a.id(), b.id());
        assert!(Identity::from_private_key_text("AAAA").is_err());
        assert!(!format!("{a:?}").contains(&text));
    }

    #[test]
    fn signatures_verify_with_node_id() {
        let a = Identity::generate();
        let sig = a.sign(b"announce");
        assert!(a.id().verifying_key().verify(b"announce", &sig).is_ok());
        assert!(a.id().verifying_key().verify(b"announcf", &sig).is_err());
    }

    #[test]
    fn serde_json_and_postcard() {
        let id = Identity::generate().id();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), id);
        let bin = postcard::to_stdvec(&id).unwrap();
        assert_eq!(bin.len(), 32); // fixed array, no length prefix
        assert_eq!(postcard::from_bytes::<NodeId>(&bin).unwrap(), id);
        assert!(serde_json::from_str::<NodeId>("\"AAAA\"").is_err());
        let mut weak = [0u8; 32];
        weak[0] = 1;
        assert!(postcard::from_bytes::<NodeId>(&weak).is_err());
    }

    proptest! {
        #[test]
        fn text_round_trip(seed in any::<[u8; 32]>()) {
            let id = Identity::from_seed(&seed).id();
            let s = id.to_string();
            prop_assert_eq!(s.len(), NODE_ID_TEXT_LEN);
            prop_assert_eq!(s.parse::<NodeId>().unwrap(), id);
        }

        #[test]
        fn parse_never_panics(s in "\\PC{0,64}") {
            let _ = s.parse::<NodeId>();
        }
    }
}
