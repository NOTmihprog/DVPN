use std::fmt;
use std::str::FromStr;

use rand::RngExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PEER_ID_LEN: usize = 32;

const SYMBOLS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// 32 ASCII alphanumeric characters. Knowing a peer id is what lets a node claim it on the
/// tracker, so ids are meant to be shared only inside the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl PeerId {
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut id = [0u8; PEER_ID_LEN];
        for b in id.iter_mut() {
            *b = SYMBOLS[rng.random_range(0..SYMBOLS.len())];
        }
        PeerId(id)
    }

    pub fn as_str(&self) -> &str {
        // Only ever constructed from ASCII alphanumerics.
        std::str::from_utf8(&self.0).unwrap()
    }

    pub fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.0
    }

    /// Whether `s` looks like a peer id; used by the logger to find ids inside messages.
    pub fn is_valid(s: &[u8]) -> bool {
        s.len() == PEER_ID_LEN && s.iter().all(u8::is_ascii_alphanumeric)
    }
}

#[derive(Debug)]
pub struct InvalidPeerId(String);

impl fmt::Display for InvalidPeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for InvalidPeerId {}

impl FromStr for PeerId {
    type Err = InvalidPeerId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PEER_ID_LEN {
            return Err(InvalidPeerId(format!("len {} != {PEER_ID_LEN}", s.len())));
        }
        if let Some(c) = s.chars().find(|c| !c.is_ascii_alphanumeric()) {
            return Err(InvalidPeerId(format!("symbol '{c}' not allowed")));
        }
        let mut id = [0u8; PEER_ID_LEN];
        id.copy_from_slice(s.as_bytes());
        Ok(PeerId(id))
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = InvalidPeerId;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b).map_err(|_| InvalidPeerId("not utf-8".into()))?.parse()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_valid() {
        let id = PeerId::generate();
        assert_eq!(id.as_str().parse::<PeerId>().unwrap(), id);
    }

    #[test]
    fn rejects_bad_ids() {
        assert!("short".parse::<PeerId>().is_err());
        assert!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-".parse::<PeerId>().is_err());
    }
}
