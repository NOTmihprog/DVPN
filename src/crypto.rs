use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::proto::{ANNOUNCE_SIG_CTX, HELLO, HELLO_ACK, HELLO_ACK_LEN, HELLO_LEN, HELLO_SIG_CTX, KEYS_CTX, TRACKER};
use crate::replay::ReplayWindow;

const TAG_LEN: usize = 16;
/// `[TRACKER][counter 8]`
const TRACKER_HDR: usize = 1 + 8;

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

/// An established tracker session. Each direction has its own key, so plain counters are safe nonces.
pub struct TrackerSession {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_counter: u64,
    replay: ReplayWindow,
    /// What a node signs to prove it owns the key it announces in this session (§11).
    announce_msg: Vec<u8>,
}

fn counter_nonce(n: u64) -> Nonce {
    let mut nonce = Nonce::default();
    nonce[..8].copy_from_slice(&n.to_le_bytes());
    nonce
}

impl TrackerSession {
    fn derive(
        shared: &[u8; 32],
        nonce: &[u8; 16],
        client_pub: &[u8; 32],
        server_pub: &[u8; 32],
        is_client: bool,
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(nonce), shared);
        let mut okm = [0u8; 64];
        let info = [KEYS_CTX, client_pub, server_pub].concat();
        hk.expand(&info, &mut okm).expect("64 bytes is a valid HKDF length");
        let c2s = ChaCha20Poly1305::new_from_slice(&okm[..32]).unwrap();
        let s2c = ChaCha20Poly1305::new_from_slice(&okm[32..]).unwrap();
        let (tx, rx) = if is_client { (c2s, s2c) } else { (s2c, c2s) };
        let announce_msg = [ANNOUNCE_SIG_CTX, client_pub, nonce, server_pub].concat();
        TrackerSession { tx, rx, tx_counter: 0, replay: ReplayWindow::default(), announce_msg }
    }

    /// The handshake transcript `ctx|client_eph|nonce|server_eph`, unique to this session, so an
    /// `Announce` signature cannot be replayed in another session.
    pub fn announce_msg(&self) -> &[u8] {
        &self.announce_msg
    }

    pub fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        self.tx_counter += 1;
        let mut out = Vec::with_capacity(TRACKER_HDR + msg.len() + TAG_LEN);
        out.push(TRACKER);
        out.extend_from_slice(&self.tx_counter.to_le_bytes());
        out.extend_from_slice(msg);
        let tag = self
            .tx
            .encrypt_inout_detached(
                &counter_nonce(self.tx_counter),
                &[TRACKER],
                InOutBuf::from(&mut out[TRACKER_HDR..]),
            )
            .expect("plaintext within AEAD limits");
        out.extend_from_slice(&tag);
        out
    }

    pub fn open(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < TRACKER_HDR + TAG_LEN || packet[0] != TRACKER {
            return None;
        }
        let n = u64::from_le_bytes(packet[1..TRACKER_HDR].try_into().unwrap());
        if !self.replay.check(n) {
            return None;
        }
        let end = packet.len() - TAG_LEN;
        let mut plain = packet[TRACKER_HDR..end].to_vec();
        let tag = Tag::try_from(&packet[end..]).ok()?;
        self.rx.decrypt_inout_detached(&counter_nonce(n), &[TRACKER], InOutBuf::from(&mut plain[..]), &tag).ok()?;
        self.replay.accept(n);
        Some(plain)
    }
}

fn hello_sig_msg(client_pub: &[u8; 32], nonce: &[u8; 16], server_pub: &[u8; 32]) -> Vec<u8> {
    [HELLO_SIG_CTX, client_pub, nonce, server_pub].concat()
}

/// Client side of the tracker handshake, kept until the matching HELLO_ACK arrives.
pub struct ClientHandshake {
    secret: StaticSecret,
    public: [u8; 32],
    nonce: [u8; 16],
}

impl ClientHandshake {
    // Not `Default`: every call draws fresh random keys, which `Default` would hide.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let secret = StaticSecret::from(random_bytes::<32>());
        let public = PublicKey::from(&secret).to_bytes();
        ClientHandshake { secret, public, nonce: random_bytes() }
    }

    pub fn hello(&self) -> Vec<u8> {
        let mut p = vec![0u8; HELLO_LEN];
        p[0] = HELLO;
        p[1..33].copy_from_slice(&self.public);
        p[33..49].copy_from_slice(&self.nonce);
        p
    }

    pub fn finish(&self, ack: &[u8], server_key: &VerifyingKey) -> Option<TrackerSession> {
        if ack.len() != HELLO_ACK_LEN || ack[0] != HELLO_ACK {
            return None;
        }
        let server_pub: [u8; 32] = ack[1..33].try_into().unwrap();
        let sig = Signature::from_bytes(ack[33..97].try_into().unwrap());
        server_key.verify(&hello_sig_msg(&self.public, &self.nonce, &server_pub), &sig).ok()?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(server_pub));
        if !shared.was_contributory() {
            return None;
        }
        Some(TrackerSession::derive(shared.as_bytes(), &self.nonce, &self.public, &server_pub, true))
    }
}

/// Server side: answers a HELLO, returning the HELLO_ACK and the new session.
pub fn server_accept(hello: &[u8], identity: &SigningKey) -> Option<(Vec<u8>, TrackerSession)> {
    if hello.len() < HELLO_LEN || hello[0] != HELLO {
        return None;
    }
    let client_pub: [u8; 32] = hello[1..33].try_into().unwrap();
    let nonce: [u8; 16] = hello[33..49].try_into().unwrap();
    let secret = StaticSecret::from(random_bytes::<32>());
    let server_pub = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(client_pub));
    if !shared.was_contributory() {
        return None;
    }
    let sig = identity.sign(&hello_sig_msg(&client_pub, &nonce, &server_pub));
    let mut ack = Vec::with_capacity(HELLO_ACK_LEN);
    ack.push(HELLO_ACK);
    ack.extend_from_slice(&server_pub);
    ack.extend_from_slice(&sig.to_bytes());
    Some((ack, TrackerSession::derive(shared.as_bytes(), &nonce, &client_pub, &server_pub, false)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_handshake_and_messages() {
        let identity = SigningKey::from_bytes(&random_bytes());
        let hs = ClientHandshake::new();
        let (ack, mut server) = server_accept(&hs.hello(), &identity).unwrap();
        let mut client = hs.finish(&ack, &identity.verifying_key()).unwrap();

        let p = client.seal(b"hello");
        assert_eq!(server.open(&p).unwrap(), b"hello");
        assert!(server.open(&p).is_none(), "replay must be rejected");
        let p = server.seal(b"world");
        assert_eq!(client.open(&p).unwrap(), b"world");
    }

    #[test]
    fn handshake_rejects_wrong_server_key() {
        let identity = SigningKey::from_bytes(&random_bytes());
        let other = SigningKey::from_bytes(&random_bytes());
        let hs = ClientHandshake::new();
        let (ack, _) = server_accept(&hs.hello(), &identity).unwrap();
        assert!(hs.finish(&ack, &other.verifying_key()).is_none());
    }

    #[test]
    fn short_hello_rejected() {
        let identity = SigningKey::from_bytes(&random_bytes());
        let hello = ClientHandshake::new().hello();
        assert!(server_accept(&hello[..49], &identity).is_none());
    }

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
