//! Sessions with trackers (PLAN §11.1), on the wire exactly like sessions between nodes: Noise
//! IKpsk2 with Elligator2 ephemerals, masked headers, random padding and junk before handshakes.
//! A tracker on the node's one socket must not stand out: a fixed-format handshake would point
//! DPI at the tracker and at everybody who talks to it.
//!
//! The header protection key and the Noise psk are derived from the tracker's public key, which
//! clients know from the config or invite (the tracker serves many groups, so no group key fits).
//! The client's static key is its node key, so the handshake itself proves who announces.
//!
//! Against active probing the tracker answers an HS_INIT only if it carries a TAI64N timestamp
//! within `MAX_SKEW` of its clock and newer than the last one from that client key: garbage and
//! replayed handshakes get no answer, like a closed UDP port. The answer is never larger than the
//! request (no amplification).

use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::elligator;
use crate::identity::{Identity, NodeId};
use crate::link::{Session, with_decoded_ephemeral};
use crate::noise::{self, Initiator, PROTOCOL_VERSION, Responder, Tai64n};
use crate::obfs::{MAX_PAD, Obfs, Profile};
use crate::proto::{HS_INIT, HS_INIT_HDR, HS_RESP, HS_RESP_HDR};

/// Handshakes whose timestamp is further from the tracker's clock are not answered.
pub const MAX_SKEW: Duration = Duration::from_secs(10 * 60);
/// `[version][tai64n 12][node key 32]`
const PAYLOAD_LEN: usize = 1 + 12 + 32;

fn derive(key: &NodeId, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, key.as_bytes()).expand(info, &mut out).expect("32 bytes");
    out
}

/// What both ends derive from the tracker key.
pub struct TrackerKeys {
    pub server: NodeId,
    pub obfs: Arc<Obfs>,
    psk: [u8; 32],
}

impl TrackerKeys {
    pub fn new(server: NodeId) -> Self {
        let obfs = Arc::new(Obfs::new(&derive(&server, b"dvpn/4 tracker obfs"), Profile::default()));
        TrackerKeys { server, obfs, psk: derive(&server, b"dvpn/4 tracker psk") }
    }

    /// Pads (at most up to `max_wire` bytes in total) and masks a handshake packet.
    fn finish(&self, ty: u8, mut out: Vec<u8>, max_wire: usize) -> Vec<u8> {
        let len = out.len();
        let pad = self.obfs.pad_len(ty, len, max_wire.saturating_sub(len).min(MAX_PAD));
        out[1..3].copy_from_slice(&pad.to_le_bytes());
        out.resize(len + pad as usize, 0);
        let n = self.obfs.finish(&mut out, len, pad);
        out.truncate(n);
        out
    }
}

/// A client handshake waiting for the answer.
#[derive(Clone)]
pub struct ClientHello {
    pub idx: u32,
    initiator: Initiator,
}

/// The packets that open a session with the tracker (junk, then HS_INIT), and the state to
/// finish it with.
pub fn client_hello(keys: &TrackerKeys, me: &Identity, idx: u32) -> Option<(Vec<Vec<u8>>, ClientHello)> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(PROTOCOL_VERSION);
    payload.extend_from_slice(&Tai64n::now().0);
    payload.extend_from_slice(me.id().as_bytes());
    let mut out = vec![HS_INIT, 0, 0];
    out.extend_from_slice(&idx.to_le_bytes());
    let (e, repr) = elligator::ephemeral();
    let remote = keys.server.x25519_public().to_bytes();
    let initiator = Initiator::start(me.x25519_secret(), &remote, &keys.psk, e, &payload, &mut out).ok()?;
    out[HS_INIT_HDR..HS_INIT_HDR + 32].copy_from_slice(&repr);
    let mut packets = keys.obfs.prelude();
    packets.push(keys.finish(HS_INIT, out, usize::MAX));
    Some((packets, ClientHello { idx, initiator }))
}

/// Finishes the client side from an unmasked HS_RESP addressed to `hello.idx`.
pub fn client_finish(keys: &TrackerKeys, hello: &ClientHello, packet: &[u8]) -> Option<Session> {
    if packet.first() != Some(&HS_RESP) {
        return None;
    }
    let sender_idx = u32::from_le_bytes(packet.get(3..7)?.try_into().unwrap());
    let (transport, _) = hello.initiator.clone().finish(&with_decoded_ephemeral(&packet[HS_RESP_HDR..])?).ok()?;
    Some(Session::new(keys.server, hello.idx, sender_idx, transport, keys.obfs.clone(), true))
}

/// The receiver index of an unmasked HS_RESP.
pub fn resp_receiver_idx(packet: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(packet.get(7..HS_RESP_HDR)?.try_into().unwrap()))
}

/// A verified client handshake, before the tracker decides to answer it.
pub struct Accepted {
    pub node: NodeId,
    pub timestamp: Tai64n,
    responder: Responder,
    sender_idx: u32,
}

/// Reads an unmasked HS_INIT: the client's key (as claimed in the payload and proven by the
/// handshake) and its timestamp. The caller checks freshness, then calls `reply`.
pub fn server_read(server: &Identity, packet: &[u8]) -> Option<Accepted> {
    let sender_idx = u32::from_le_bytes(packet.get(3..HS_INIT_HDR)?.try_into().unwrap());
    let (responder, rs, payload) =
        Responder::read(server.x25519_secret(), &with_decoded_ephemeral(&packet[HS_INIT_HDR..])?).ok()?;
    if payload.len() < PAYLOAD_LEN || payload[0] != PROTOCOL_VERSION {
        return None;
    }
    let node = NodeId::try_from(&payload[13..45]).ok()?;
    if node.x25519_public().to_bytes() != rs {
        return None;
    }
    let timestamp = Tai64n(payload[1..13].try_into().unwrap());
    Some(Accepted { node, timestamp, responder, sender_idx })
}

/// Whether a handshake timestamp is within `MAX_SKEW` of now. A tracker whose own clock is
/// certainly wrong cannot judge, and accepts it (replays are still caught per client key).
pub fn fresh(t: Tai64n) -> bool {
    if !crate::clock::trusted() {
        return true;
    }
    let now = Tai64n::now();
    let secs = |t: &Tai64n| u64::from_be_bytes(t.0[..8].try_into().unwrap());
    secs(&now).abs_diff(secs(&t)) <= MAX_SKEW.as_secs()
}

impl Accepted {
    /// The session and the HS_RESP to send, never longer than the request (`request_len`).
    pub fn reply(self, keys: &TrackerKeys, local_idx: u32, request_len: usize) -> Option<(Session, Vec<u8>)> {
        let mut out = vec![HS_RESP, 0, 0];
        out.extend_from_slice(&local_idx.to_le_bytes());
        out.extend_from_slice(&self.sender_idx.to_le_bytes());
        let (e, repr) = elligator::ephemeral();
        let transport = self.responder.reply(&keys.psk, e, &[], &mut out).ok()?;
        out[HS_RESP_HDR..HS_RESP_HDR + 32].copy_from_slice(&repr);
        debug_assert!(out.len() <= request_len);
        let session = Session::new(self.node, local_idx, self.sender_idx, transport, keys.obfs.clone(), false);
        Some((session, keys.finish(HS_RESP, out, request_len)))
    }
}

/// Sizes of the logical handshake packets: the answer is always smaller than the request.
pub const INIT_LEN: usize = HS_INIT_HDR + noise::INIT_OVERHEAD + PAYLOAD_LEN;
pub const RESP_LEN: usize = HS_RESP_HDR + noise::RESP_OVERHEAD;
const _: () = assert!(RESP_LEN < INIT_LEN);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DATA_HDR, KIND_CONTROL};

    fn setup() -> (Identity, TrackerKeys, Identity) {
        let server = Identity::generate();
        let keys = TrackerKeys::new(server.id());
        (server, keys, Identity::generate())
    }

    fn unmask(keys: &TrackerKeys, p: &[u8]) -> Option<Vec<u8>> {
        let mut p = p.to_vec();
        let n = keys.obfs.open(&mut p)?;
        p.truncate(n);
        Some(p)
    }

    #[test]
    fn handshake_and_data() {
        let (server, keys, client) = setup();
        let (packets, hello) = client_hello(&keys, &client, 7).unwrap();
        let init = packets.last().unwrap();
        for junk in &packets[..packets.len() - 1] {
            assert!(unmask(&keys, junk).is_none_or(|p| server_read(&server, &p).is_none()));
        }
        let acc = server_read(&server, &unmask(&keys, init).unwrap()).unwrap();
        assert_eq!(acc.node, client.id());
        assert!(fresh(acc.timestamp));
        let (srv, resp) = acc.reply(&keys, 9, init.len()).unwrap();
        assert!(resp.len() <= init.len(), "no amplification");
        let resp = unmask(&keys, &resp).unwrap();
        assert_eq!(resp_receiver_idx(&resp), Some(7));
        let cli = client_finish(&keys, &hello, &resp).unwrap();

        let mut buf = vec![0u8; 256];
        buf[DATA_HDR] = KIND_CONTROL;
        buf[DATA_HDR + 1..DATA_HDR + 6].copy_from_slice(b"hello");
        let n = cli.seal(&mut buf, 6).unwrap();
        let mut p = unmask(&keys, &buf[..n]).unwrap();
        let r = srv.open(&mut p).unwrap();
        assert_eq!(&p[r][1..], b"hello");
    }

    #[test]
    fn wrong_tracker_key_no_session() {
        let (_, keys, client) = setup();
        let other = Identity::generate();
        let (packets, _) = client_hello(&keys, &client, 1).unwrap();
        // another tracker cannot even unmask it, and with the right mask its key does not fit
        let p = packets.last().unwrap();
        let other_keys = TrackerKeys::new(other.id());
        assert!(unmask(&other_keys, p).is_none_or(|u| server_read(&other, &u).is_none()));
        assert!(server_read(&other, &unmask(&keys, p).unwrap()).is_none());
    }

    #[test]
    fn stale_timestamps_are_not_fresh() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(fresh(Tai64n::from_unix(now - 60, 0)));
        assert!(!fresh(Tai64n::from_unix(now - MAX_SKEW.as_secs() - 5, 0)));
        assert!(!fresh(Tai64n::from_unix(now + MAX_SKEW.as_secs() + 5, 0)));
    }

    #[test]
    fn resp_never_larger_than_init() {
        let (server, keys, client) = setup();
        for _ in 0..50 {
            let (packets, _) = client_hello(&keys, &client, 1).unwrap();
            let init = packets.last().unwrap();
            let acc = server_read(&server, &unmask(&keys, init).unwrap()).unwrap();
            let (_, resp) = acc.reply(&keys, 2, init.len()).unwrap();
            assert!(resp.len() <= init.len());
        }
    }
}
