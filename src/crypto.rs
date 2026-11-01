use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

/// Accepts url-safe and standard base64, with or without padding.
pub fn decode_b64(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let padded = format!("{s}{}", "=".repeat((4 - s.len() % 4) % 4));
    URL_SAFE.decode(&padded).or_else(|_| STANDARD.decode(&padded)).context("invalid base64")
}

pub fn decode_key32(s: &str) -> anyhow::Result<[u8; 32]> {
    let b = decode_b64(s)?;
    match <[u8; 32]>::try_from(b.as_slice()) {
        Ok(k) => Ok(k),
        Err(_) => bail!("key must be 32 bytes, got {}", b.len()),
    }
}

/// Canonical text form of keys and blobs everywhere (PLAN §3): base64url without padding.
pub fn encode_b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_variants() {
        let k = random_bytes::<32>();
        let text = encode_b64(&k);
        assert_eq!(text.len(), 43, "base64url without padding");
        assert!(!text.contains(['=', '+', '/']));
        assert_eq!(decode_key32(&text).unwrap(), k);
        // older forms keep parsing: padded url-safe (v3 configs) and standard
        assert_eq!(decode_key32(&URL_SAFE.encode(k)).unwrap(), k);
        assert_eq!(decode_key32(&STANDARD.encode(k)).unwrap(), k);
    }
}
