//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake (PLAN §4.1), the WireGuard scheme.
//!
//! ```text
//! <- s
//! ...
//! -> e, es, s, ss          message 1: e(32) | enc(s)(32+16) | enc(payload)(n+16)
//! <- e, ee, se, psk        message 2: e(32) | enc(payload)(n+16)
//! ```
//! The responder's static key is known in advance (K); the initiator sends its own encrypted (I).
//! The group psk is mixed in only at the end of message 2 (psk2), so the responder can read the
//! message 1 payload (group id, timestamp) first and pick the psk from it.
//!
//! Ephemeral keys come from the caller: the obfuscation layer needs ones whose public key has an
//! Elligator2 representative, and it may use a "dirty" public key (with a small-order component),
//! so the public part is passed separately instead of being recomputed here.
//!
//! Wire framing (indices, counters, masking) lives elsewhere; this module only turns keys and
//! payloads into handshake messages and transport keys. Cross-checked against `snow` in tests.

use blake2::Blake2s256;
use blake2::digest::Digest;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hmac::{Mac, SimpleHmac};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// Mixed into the handshake hash, so a v4 handshake cannot be confused with anything else.
pub const PROLOGUE: &[u8] = b"dvpn/4";

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Message 1 without payload: e + encrypted s + payload tag.
pub const INIT_OVERHEAD: usize = KEY_LEN + KEY_LEN + TAG_LEN + TAG_LEN;
/// Message 2 without payload: e + payload tag.
pub const RESP_OVERHEAD: usize = KEY_LEN + TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Too short, a low-order key, or an AEAD tag mismatch (wrong keys, psk or tampering).
    Invalid,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid handshake message")
    }
}

impl std::error::Error for Error {}

/// An ephemeral key pair supplied by the caller (see the module docs).
#[derive(Clone)]
pub struct Ephemeral {
    pub secret: StaticSecret,
    pub public: [u8; KEY_LEN],
}

impl Ephemeral {
    /// A plain random ephemeral (no Elligator2 constraint).
    pub fn random() -> Self {
        let secret = StaticSecret::from(crate::crypto::random_bytes::<32>());
        let public = PublicKey::from(&secret).to_bytes();
        Ephemeral { secret, public }
    }
}

type HmacBlake2s = SimpleHmac<Blake2s256>;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacBlake2s as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Noise HKDF with BLAKE2s: up to three 32-byte outputs.
fn hkdf<const N: usize>(ck: &[u8; 32], ikm: &[u8]) -> [[u8; 32]; N] {
    let prk = hmac(ck, &[ikm]);
    let mut out = [[0u8; 32]; N];
    let mut prev = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let prev_part: &[u8] = if i == 0 { &[] } else { &prev };
        *o = hmac(&prk, &[prev_part, &[i as u8 + 1]]);
        prev = *o;
    }
    out
}

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(b)
}

fn dh(secret: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32], Error> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    // A low-order peer key would make the shared secret predictable.
    if shared.was_contributory() { Ok(shared.to_bytes()) } else { Err(Error::Invalid) }
}

/// Noise SymmetricState (with the CipherState folded in).
#[derive(Clone)]
struct Symmetric {
    ck: [u8; 32],
    h: [u8; 32],
    k: Option<[u8; 32]>,
    n: u64,
}

impl Symmetric {
    fn new() -> Self {
        // the protocol name is longer than HASHLEN, so h = HASH(name)
        let h = hash(&[PROTOCOL_NAME]);
        let mut s = Symmetric { ck: h, h, k: None, n: 0 };
        s.mix_hash(PROLOGUE);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let [ck, k] = hkdf::<2>(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let [ck, th, k] = hkdf::<3>(&self.ck, ikm);
        self.ck = ck;
        self.mix_hash(&th);
        self.k = Some(k);
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plain: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        match self.k {
            Some(k) => {
                let c = ChaCha20Poly1305::new(&k.into())
                    .encrypt(&nonce(self.n), Payload { msg: plain, aad: &self.h })
                    .expect("plaintext within AEAD limits");
                self.n += 1;
                out.extend_from_slice(&c);
            }
            None => out.extend_from_slice(plain),
        }
        let h = hash(&[&self.h, &out[start..]]);
        self.h = h;
    }

    fn decrypt_and_hash(&mut self, c: &[u8]) -> Result<Vec<u8>, Error> {
        let plain = match self.k {
            Some(k) => {
                let p = ChaCha20Poly1305::new(&k.into())
                    .decrypt(&nonce(self.n), Payload { msg: c, aad: &self.h })
                    .map_err(|_| Error::Invalid)?;
                self.n += 1;
                p
            }
            None => c.to_vec(),
        };
        self.mix_hash(c);
        Ok(plain)
    }

    /// Split into (initiator -> responder, responder -> initiator) keys.
    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let [a, b] = hkdf::<2>(&self.ck, &[]);
        (a, b)
    }
}

/// Transport keys after a handshake. Stateless: the caller supplies the counter (sent in clear
/// next to the ciphertext, as UDP reorders packets) and keeps its own replay window.
pub struct Transport {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    /// Final handshake hash; identifies the session (channel binding), e.g. for logs or tests.
    pub handshake_hash: [u8; 32],
}

impl Transport {
    fn new(send: [u8; 32], recv: [u8; 32], handshake_hash: [u8; 32]) -> Self {
        Transport {
            send: ChaCha20Poly1305::new(&send.into()),
            recv: ChaCha20Poly1305::new(&recv.into()),
            handshake_hash,
        }
    }

    /// Encrypts `buf` in place; returns the tag to append.
    pub fn seal(&self, counter: u64, aad: &[u8], buf: &mut [u8]) -> Tag {
        self.send.encrypt_inout_detached(&nonce(counter), aad, buf.into()).expect("plaintext within AEAD limits")
    }

    /// Decrypts `buf` in place. Check the replay window before, and accept the counter into it
    /// only after this returns true.
    pub fn open(&self, counter: u64, aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        self.recv.decrypt_inout_detached(&nonce(counter), aad, buf.into(), &Tag::from(*tag)).is_ok()
    }
}

/// Initiator after sending message 1, waiting for message 2.
pub struct Initiator {
    sym: Symmetric,
    e: StaticSecret,
    s: StaticSecret,
    psk: [u8; 32],
}

impl Initiator {
    /// Writes message 1 to the end of `out`.
    pub fn start(
        local: &StaticSecret,
        remote_static: &[u8; 32],
        psk: &[u8; 32],
        e: Ephemeral,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Self, Error> {
        let mut sym = Symmetric::new();
        sym.mix_hash(remote_static); // pre-message <- s
        // e (psk handshakes also MixKey the ephemeral)
        out.extend_from_slice(&e.public);
        sym.mix_hash(&e.public);
        sym.mix_key(&e.public);
        // es
        sym.mix_key(&dh(&e.secret, remote_static)?);
        // s
        sym.encrypt_and_hash(PublicKey::from(local).as_bytes(), out);
        // ss
        sym.mix_key(&dh(local, remote_static)?);
        sym.encrypt_and_hash(payload, out);
        Ok(Initiator { sym, e: e.secret, s: local.clone(), psk: *psk })
    }

    /// Reads message 2; returns the transport keys and the responder's payload.
    pub fn finish(mut self, msg: &[u8]) -> Result<(Transport, Vec<u8>), Error> {
        if msg.len() < RESP_OVERHEAD {
            return Err(Error::Invalid);
        }
        let re: [u8; 32] = msg[..KEY_LEN].try_into().unwrap();
        self.sym.mix_hash(&re);
        self.sym.mix_key(&re);
        self.sym.mix_key(&dh(&self.e, &re)?); // ee
        self.sym.mix_key(&dh(&self.s, &re)?); // se
        self.sym.mix_key_and_hash(&self.psk);
        let payload = self.sym.decrypt_and_hash(&msg[KEY_LEN..])?;
        let (i2r, r2i) = self.sym.split();
        Ok((Transport::new(i2r, r2i, self.sym.h), payload))
    }
}

/// Responder after reading message 1: knows who is calling and their payload, not yet the psk.
pub struct Responder {
    sym: Symmetric,
    re: [u8; 32],
    rs: [u8; 32],
}

impl Responder {
    /// Reads message 1; returns the state, the initiator's static key and its payload.
    pub fn read(local: &StaticSecret, msg: &[u8]) -> Result<(Self, [u8; 32], Vec<u8>), Error> {
        if msg.len() < INIT_OVERHEAD {
            return Err(Error::Invalid);
        }
        let mut sym = Symmetric::new();
        sym.mix_hash(PublicKey::from(local).as_bytes());
        let re: [u8; 32] = msg[..KEY_LEN].try_into().unwrap();
        sym.mix_hash(&re);
        sym.mix_key(&re);
        sym.mix_key(&dh(local, &re)?); // es
        let rs: [u8; 32] =
            sym.decrypt_and_hash(&msg[KEY_LEN..KEY_LEN + KEY_LEN + TAG_LEN])?.try_into().map_err(|_| Error::Invalid)?;
        sym.mix_key(&dh(local, &rs)?); // ss
        let payload = sym.decrypt_and_hash(&msg[KEY_LEN + KEY_LEN + TAG_LEN..])?;
        Ok((Responder { sym, re, rs }, rs, payload))
    }

    /// Writes message 2 to the end of `out`; returns the transport keys.
    pub fn reply(
        mut self,
        psk: &[u8; 32],
        e: Ephemeral,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Transport, Error> {
        out.extend_from_slice(&e.public);
        self.sym.mix_hash(&e.public);
        self.sym.mix_key(&e.public);
        self.sym.mix_key(&dh(&e.secret, &self.re)?); // ee
        self.sym.mix_key(&dh(&e.secret, &self.rs)?); // se
        self.sym.mix_key_and_hash(psk);
        self.sym.encrypt_and_hash(payload, out);
        let (i2r, r2i) = self.sym.split();
        Ok(Transport::new(r2i, i2r, self.sym.h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;
    use proptest::prelude::*;

    const NOISE: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

    struct Keys {
        i: StaticSecret,
        r: StaticSecret,
        r_pub: [u8; 32],
        psk: [u8; 32],
    }

    fn keys() -> Keys {
        let (i, r) = (StaticSecret::from(random_bytes::<32>()), StaticSecret::from(random_bytes::<32>()));
        let r_pub = PublicKey::from(&r).to_bytes();
        Keys { i, r, r_pub, psk: random_bytes() }
    }

    fn roundtrip(t_a: &Transport, t_b: &Transport, msg: &[u8]) -> bool {
        let mut buf = msg.to_vec();
        let tag = t_a.seal(7, b"aad", &mut buf);
        t_b.open(7, b"aad", &mut buf, &tag.into()) && buf == msg
    }

    #[test]
    fn handshake_and_transport() {
        let k = keys();
        let mut m1 = Vec::new();
        let ini = Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"hello", &mut m1).unwrap();
        assert_eq!(m1.len(), INIT_OVERHEAD + 5);
        let (resp, rs, p1) = Responder::read(&k.r, &m1).unwrap();
        assert_eq!(rs, PublicKey::from(&k.i).to_bytes());
        assert_eq!(p1, b"hello");
        let mut m2 = Vec::new();
        let tr = resp.reply(&k.psk, Ephemeral::random(), b"welcome", &mut m2).unwrap();
        assert_eq!(m2.len(), RESP_OVERHEAD + 7);
        let (ti, p2) = ini.finish(&m2).unwrap();
        assert_eq!(p2, b"welcome");
        assert_eq!(ti.handshake_hash, tr.handshake_hash);
        assert!(roundtrip(&ti, &tr, b"ping"));
        assert!(roundtrip(&tr, &ti, b"pong"));
        // directions use different keys
        let mut buf = b"x".to_vec();
        let tag = ti.seal(1, b"", &mut buf);
        assert!(!ti.open(1, b"", &mut buf, &tag.into()));
    }

    #[test]
    fn wrong_psk_fails_at_message_2() {
        let k = keys();
        let mut m1 = Vec::new();
        let ini = Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"", &mut m1).unwrap();
        let (resp, _, _) = Responder::read(&k.r, &m1).unwrap();
        let mut m2 = Vec::new();
        resp.reply(&random_bytes(), Ephemeral::random(), b"", &mut m2).unwrap();
        assert_eq!(ini.finish(&m2).err(), Some(Error::Invalid));
    }

    #[test]
    fn wrong_responder_key_fails_at_message_1() {
        let k = keys();
        let mut m1 = Vec::new();
        Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"", &mut m1).unwrap();
        let other = StaticSecret::from(random_bytes::<32>());
        assert_eq!(Responder::read(&other, &m1).err(), Some(Error::Invalid));
    }

    #[test]
    fn tampering_and_short_messages_rejected() {
        let k = keys();
        let mut m1 = Vec::new();
        Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"payload", &mut m1).unwrap();
        for i in 0..m1.len() {
            let mut bad = m1.clone();
            bad[i] ^= 0x80;
            assert!(Responder::read(&k.r, &bad).is_err(), "flip at byte {i} accepted");
        }
        assert!(Responder::read(&k.r, &m1[..INIT_OVERHEAD - 1]).is_err());
        assert!(Responder::read(&k.r, &[]).is_err());
    }

    #[test]
    fn low_order_ephemeral_rejected() {
        let k = keys();
        let mut m1 = Vec::new();
        Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"", &mut m1).unwrap();
        m1[..32].copy_from_slice(&[0u8; 32]); // the identity point
        assert_eq!(Responder::read(&k.r, &m1).err(), Some(Error::Invalid));
    }

    fn snow_builder<'a>(local: &'a [u8; 32], psk: &'a [u8; 32]) -> snow::Builder<'a> {
        let params: snow::params::NoiseParams = NOISE.parse().unwrap();
        snow::Builder::new(params).prologue(PROLOGUE).unwrap().local_private_key(local).unwrap().psk(2, psk).unwrap()
    }

    fn snow_transport_check(ours: &Transport, theirs: &mut snow::StatelessTransportState) {
        // ours -> snow
        let mut buf = b"from dvpn".to_vec();
        let tag = ours.seal(3, &[], &mut buf);
        buf.extend_from_slice(&tag);
        let mut out = [0u8; 64];
        let n = theirs.read_message(3, &buf, &mut out).unwrap();
        assert_eq!(&out[..n], b"from dvpn");
        // snow -> ours
        let mut c = [0u8; 64];
        let n = theirs.write_message(9, b"from snow", &mut c).unwrap();
        let (body, tag) = c[..n].split_at_mut(n - TAG_LEN);
        assert!(ours.open(9, &[], body, &tag.try_into().unwrap()));
        assert_eq!(body, b"from snow");
    }

    #[test]
    fn interop_ours_initiator_snow_responder() {
        let k = keys();
        let r_bytes = k.r.to_bytes();
        let mut snow_r = snow_builder(&r_bytes, &k.psk).build_responder().unwrap();
        let mut m1 = Vec::new();
        let ini = Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), b"init payload", &mut m1).unwrap();
        let mut buf = [0u8; 256];
        let n = snow_r.read_message(&m1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"init payload");
        assert_eq!(snow_r.get_remote_static().unwrap(), PublicKey::from(&k.i).as_bytes());
        let mut m2 = [0u8; 256];
        let n = snow_r.write_message(b"resp payload", &mut m2).unwrap();
        let (ti, p2) = ini.finish(&m2[..n]).unwrap();
        assert_eq!(p2, b"resp payload");
        assert_eq!(&ti.handshake_hash[..], snow_r.get_handshake_hash());
        let mut ts = snow_r.into_stateless_transport_mode().unwrap();
        snow_transport_check(&ti, &mut ts);
    }

    #[test]
    fn interop_snow_initiator_ours_responder() {
        let k = keys();
        let i_bytes = k.i.to_bytes();
        let mut snow_i = snow_builder(&i_bytes, &k.psk).remote_public_key(&k.r_pub).unwrap().build_initiator().unwrap();
        let mut m1 = [0u8; 256];
        let n = snow_i.write_message(b"init payload", &mut m1).unwrap();
        let (resp, rs, p1) = Responder::read(&k.r, &m1[..n]).unwrap();
        assert_eq!(rs, PublicKey::from(&k.i).to_bytes());
        assert_eq!(p1, b"init payload");
        let mut m2 = Vec::new();
        let tr = resp.reply(&k.psk, Ephemeral::random(), b"resp payload", &mut m2).unwrap();
        let mut buf = [0u8; 256];
        let n = snow_i.read_message(&m2, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"resp payload");
        assert_eq!(&tr.handshake_hash[..], snow_i.get_handshake_hash());
        let mut ts = snow_i.into_stateless_transport_mode().unwrap();
        snow_transport_check(&tr, &mut ts);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn responder_read_never_panics(msg in proptest::collection::vec(any::<u8>(), 0..200)) {
            let r = StaticSecret::from([7u8; 32]);
            let _ = Responder::read(&r, &msg);
        }

        #[test]
        fn payloads_round_trip(p1 in proptest::collection::vec(any::<u8>(), 0..300),
                               p2 in proptest::collection::vec(any::<u8>(), 0..300)) {
            let k = keys();
            let mut m1 = Vec::new();
            let ini = Initiator::start(&k.i, &k.r_pub, &k.psk, Ephemeral::random(), &p1, &mut m1).unwrap();
            let (resp, _, got1) = Responder::read(&k.r, &m1).unwrap();
            prop_assert_eq!(&got1, &p1);
            let mut m2 = Vec::new();
            resp.reply(&k.psk, Ephemeral::random(), &p2, &mut m2).unwrap();
            let (_, got2) = ini.finish(&m2).unwrap();
            prop_assert_eq!(&got2, &p2);
        }
    }
}
