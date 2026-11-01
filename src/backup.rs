//! Password-protected backup of a group's admin material (PLAN §14a): without the group secret
//! nobody can invite, renew certificates, revoke or change the psk, so losing the only admin
//! node would freeze the group. The file is text (base64url), so it can be printed or pasted.
//!
//! ```text
//! "dvpn-backup:" base64url( [version 1][m_kib u32][t u32][p u32][salt 16][nonce 24][ciphertext] )
//! ```
//! Key: Argon2id(password, salt) with the stored parameters; cipher: XChaCha20-Poly1305 with the
//! header as associated data, so the parameters cannot be swapped.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::crypto::{decode_b64, encode_b64, random_bytes};
use crate::group::{Cert, StaticRef, TrackerRef};

const PREFIX: &str = "dvpn-backup:";
const VERSION: u8 = 1;
const HEADER: usize = 1 + 4 + 4 + 4 + 16 + 24;

/// Argon2id cost: 64 MiB, 3 passes (the OWASP baseline is 19 MiB / 2 passes).
pub const DEFAULT_COST: (u32, u32, u32) = (64 * 1024, 3, 1);

/// What a new admin node needs to take over a group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    pub group_name: String,
    pub secret: [u8; 32],
    pub epoch: u32,
    pub obfs: Vec<(String, String)>,
    pub trackers: Vec<TrackerRef>,
    pub statics: Vec<StaticRef>,
    /// The admin node's certificate: name and address for the restored node.
    pub cert: Option<Cert>,
    /// The admin node's private key, to restore the same node (`restore --with-key`).
    pub node_key: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackupError {
    Format,
    Version(u8),
    /// Wrong password, or the file was changed.
    Decrypt,
    Params,
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::Format => f.write_str("not a dvpn backup"),
            BackupError::Version(v) => write!(f, "backup version {v} is not supported"),
            BackupError::Decrypt => f.write_str("wrong password, or the backup is damaged"),
            BackupError::Params => f.write_str("bad key derivation parameters"),
        }
    }
}

impl std::error::Error for BackupError {}

fn derive(password: &[u8], salt: &[u8], (m, t, p): (u32, u32, u32)) -> Result<[u8; 32], BackupError> {
    // refuse absurd costs from a crafted file (memory is in KiB: at most 4 GiB)
    if m > 4 * 1024 * 1024 || t > 64 || p > 64 {
        return Err(BackupError::Params);
    }
    let params = Params::new(m, t, p, Some(32)).map_err(|_| BackupError::Params)?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| BackupError::Params)?;
    Ok(key)
}

impl Backup {
    pub fn seal(&self, password: &str, cost: (u32, u32, u32)) -> String {
        let salt: [u8; 16] = random_bytes();
        let nonce: [u8; 24] = random_bytes();
        let mut out = Vec::with_capacity(HEADER + 256);
        out.push(VERSION);
        for v in [cost.0, cost.1, cost.2] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        let key = derive(password.as_bytes(), &salt, cost).expect("own parameters are valid");
        let plain = postcard::to_stdvec(self).expect("backup serializes");
        let ct = XChaCha20Poly1305::new(&key.into())
            .encrypt(&XNonce::from(nonce), Payload { msg: &plain, aad: &out })
            .expect("encrypt");
        out.extend_from_slice(&ct);
        format!("{PREFIX}{}", encode_b64(&out))
    }

    pub fn open(text: &str, password: &str) -> Result<Self, BackupError> {
        let b = text.trim().strip_prefix(PREFIX).ok_or(BackupError::Format)?;
        let b = decode_b64(b).map_err(|_| BackupError::Format)?;
        if b.len() < HEADER + 16 {
            return Err(BackupError::Format);
        }
        if b[0] != VERSION {
            return Err(BackupError::Version(b[0]));
        }
        let u = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let cost = (u(1), u(5), u(9));
        let (salt, nonce) = (&b[13..29], &b[29..53]);
        let key = derive(password.as_bytes(), salt, cost)?;
        let plain = XChaCha20Poly1305::new(&key.into())
            .decrypt(
                &XNonce::try_from(nonce).map_err(|_| BackupError::Format)?,
                Payload { msg: &b[HEADER..], aad: &b[..HEADER] },
            )
            .map_err(|_| BackupError::Decrypt)?;
        postcard::from_bytes(&plain).map_err(|_| BackupError::Format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters: the tests check the format, not the cost.
    const CHEAP: (u32, u32, u32) = (64, 1, 1);

    fn sample() -> Backup {
        Backup {
            group_name: "home".into(),
            secret: [7; 32],
            epoch: 3,
            obfs: vec![("jc".into(), "1-2".into())],
            trackers: vec![TrackerRef { host: "t.example".into(), port: 6485, key: [1; 32] }],
            statics: vec![],
            cert: None,
            node_key: Some("k".into()),
        }
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let b = sample();
        let text = b.seal("correct horse", CHEAP);
        assert!(text.starts_with(PREFIX));
        assert_eq!(Backup::open(&text, "correct horse"), Ok(b));
        assert_eq!(Backup::open(&text, "wrong"), Err(BackupError::Decrypt));
        assert_eq!(Backup::open("hello", "x"), Err(BackupError::Format));
    }

    #[test]
    fn header_is_authenticated() {
        let text = sample().seal("pw", CHEAP);
        let mut raw = decode_b64(text.strip_prefix(PREFIX).unwrap()).unwrap();
        raw[1] ^= 1; // m: 64 -> 65 KiB gives another key, and the header is the AAD anyway
        let tampered = format!("{PREFIX}{}", encode_b64(&raw));
        assert_eq!(Backup::open(&tampered, "pw"), Err(BackupError::Decrypt));
        let mut raw = decode_b64(text.strip_prefix(PREFIX).unwrap()).unwrap();
        raw[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        let huge = format!("{PREFIX}{}", encode_b64(&raw));
        assert_eq!(Backup::open(&huge, "pw"), Err(BackupError::Params), "no 4 TiB allocation from a crafted file");
    }
}
