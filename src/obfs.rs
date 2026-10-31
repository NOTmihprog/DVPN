//! Obfuscation layer (PLAN §4.4): no fixed byte, field or size on the wire for peer packets.
//!
//! Every logical packet starts `[type][pad_len u16 LE][rest of header]...`; on the wire:
//! - `pad_len` random bytes are appended (sizes vary, capped so datagrams don't fragment);
//! - the header (type, pad_len, indices, counter: at most 15 bytes) is XORed with a ChaCha20
//!   keystream keyed by the group's header-protection key, with the nonce taken from wire bytes
//!   16..32, which are always random (an Elligator2 representative in handshakes, AEAD output in
//!   DATA), as QUIC does. Without the group key even the packet type is unreadable.
//!
//! Tampering is caught downstream: a changed header or length makes the Noise/AEAD check fail.
//!
//! Tracker traffic is not masked yet (stage 3.9); the node tells it apart by source address.

use std::ops::{Range, RangeInclusive};

use blake2::{Blake2s256, Digest};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::RngExt;

use crate::proto::{DATA, DATA_HDR, HS_INIT, HS_INIT_HDR, HS_RESP, HS_RESP_HDR};

/// Where the header-protection nonce is sampled from; never overlaps a header.
const SAMPLE: Range<usize> = 16..32;
/// Smallest valid wire packet: the sample must be present. (A DATA packet with an empty body is
/// exactly this long: 15 header + 1 kind + 16 tag.)
pub const MIN_WIRE: usize = SAMPLE.end;
/// Padding never makes a datagram longer than this: 1500 MTU - 40 IPv6 - 8 UDP.
pub const MAX_WIRE: usize = 1452;
/// Upper bound of any padding range; buffers reserve this much after a packet.
pub const MAX_PAD: usize = 512;

/// Header length of each logical packet type, `None` for anything else.
pub fn header_len(ty: u8) -> Option<usize> {
    match ty {
        HS_INIT => Some(HS_INIT_HDR),
        HS_RESP => Some(HS_RESP_HDR),
        DATA => Some(DATA_HDR),
        _ => None,
    }
}

/// Padding ranges per packet type (AmneziaWG's s1/s2 and content padding). Shared by the whole
/// group so all members look alike; configurable in stage 2.6.
#[derive(Clone, Debug)]
pub struct Profile {
    pub init_pad: RangeInclusive<u16>,
    pub resp_pad: RangeInclusive<u16>,
    pub data_pad: RangeInclusive<u16>,
}

impl Default for Profile {
    /// Moderate: handshakes vary by up to 96 bytes, data by up to 48.
    fn default() -> Self {
        Profile { init_pad: 0..=96, resp_pad: 0..=96, data_pad: 0..=48 }
    }
}

pub struct Obfs {
    hp_key: [u8; 32],
    profile: Profile,
}

impl Obfs {
    pub fn new(psk: &[u8; 32], profile: Profile) -> Self {
        let hp_key = Blake2s256::new().chain_update(b"dvpn/4 header protection").chain_update(psk).finalize().into();
        Obfs { hp_key, profile }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 16] {
        let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
        let nonce: [u8; 12] = sample[4..16].try_into().unwrap();
        let mut c = ChaCha20::new(&self.hp_key.into(), &nonce.into());
        c.seek(u64::from(counter) * 64);
        let mut m = [0u8; 16];
        c.apply_keystream(&mut m);
        m
    }

    /// How much padding to add to a packet of type `ty` that is `len` bytes long, with `room`
    /// bytes of buffer free after it.
    pub fn pad_len(&self, ty: u8, len: usize, room: usize) -> u16 {
        let range = match ty {
            HS_INIT => &self.profile.init_pad,
            HS_RESP => &self.profile.resp_pad,
            _ => &self.profile.data_pad,
        };
        let want = rand::rng().random_range(range.clone()) as usize;
        want.min(room).min(MAX_WIRE.saturating_sub(len)) as u16
    }

    /// Turns the logical packet `buf[..len]` (with `pad` already written into its header) into a
    /// wire packet: appends `pad` random bytes and masks the header. Returns the wire length.
    pub fn finish(&self, buf: &mut [u8], len: usize, pad: u16) -> usize {
        let wire = len + pad as usize;
        debug_assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), pad);
        debug_assert!(wire >= MIN_WIRE, "packet too short to sample");
        rand::fill(&mut buf[len..wire]);
        let hdr = header_len(buf[0]).expect("known packet type");
        let m = self.mask(&buf[SAMPLE]);
        buf[..hdr].iter_mut().zip(m).for_each(|(b, k)| *b ^= k);
        wire
    }

    /// Unmasks a wire packet in place; returns its logical length (padding excluded), or `None`
    /// if it cannot be one of ours.
    pub fn open(&self, wire: &mut [u8]) -> Option<usize> {
        if wire.len() < MIN_WIRE {
            return None;
        }
        let m = self.mask(&wire[SAMPLE]);
        let hdr = header_len(wire[0] ^ m[0])?;
        wire[..hdr].iter_mut().zip(m).for_each(|(b, k)| *b ^= k);
        let pad = u16::from_le_bytes([wire[1], wire[2]]) as usize;
        let len = wire.len().checked_sub(pad)?;
        // every real packet is at least MIN_WIRE long before padding
        (len >= MIN_WIRE).then_some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    /// A logical packet of type `ty` with `body` random bytes after the header, padded and
    /// masked; returns (logical, wire).
    fn make(o: &Obfs, ty: u8, body: usize) -> (Vec<u8>, Vec<u8>) {
        let hdr = header_len(ty).unwrap();
        let mut buf = vec![0u8; hdr + body + MAX_PAD];
        buf[0] = ty;
        rand::fill(&mut buf[3..hdr + body]);
        let len = hdr + body;
        let pad = o.pad_len(ty, len, MAX_PAD);
        buf[1..3].copy_from_slice(&pad.to_le_bytes());
        let logical = buf[..len].to_vec();
        let n = o.finish(&mut buf, len, pad);
        buf.truncate(n);
        (logical, buf)
    }

    #[test]
    fn round_trip_every_type() {
        let o = Obfs::new(&random_bytes(), Profile::default());
        for ty in [HS_INIT, HS_RESP, DATA] {
            for body in [32, 100, 1400] {
                let (logical, mut wire) = make(&o, ty, body);
                let len = o.open(&mut wire).unwrap();
                assert_eq!(&wire[..len], &logical[..], "type {ty:#x} body {body}");
            }
        }
    }

    #[test]
    fn other_group_cannot_read_the_header() {
        let (a, b) = (Obfs::new(&[1; 32], Profile::default()), Obfs::new(&[2; 32], Profile::default()));
        let mut rejected = 0;
        for _ in 0..200 {
            let (logical, mut wire) = make(&a, DATA, 64);
            match b.open(&mut wire) {
                None => rejected += 1,
                Some(len) => assert_ne!(&wire[..len], &logical[..]),
            }
        }
        assert!(rejected > 180, "a foreign key decodes a valid type only by chance ({rejected}/200 rejected)");
    }

    #[test]
    fn short_and_garbage_packets() {
        let o = Obfs::new(&random_bytes(), Profile::default());
        assert!(o.open(&mut [0u8; MIN_WIRE - 1]).is_none());
        for _ in 0..1000 {
            let mut junk: Vec<u8> = (0..rand::random_range(0..200usize)).map(|_| rand::random()).collect();
            if let Some(len) = o.open(&mut junk) {
                assert!(len >= MIN_WIRE && len <= junk.len());
            }
        }
    }

    #[test]
    fn padding_respects_room_and_mtu() {
        let o = Obfs::new(&random_bytes(), Profile { init_pad: 400..=400, resp_pad: 0..=0, data_pad: 300..=300 });
        assert_eq!(o.pad_len(HS_INIT, 100, 1000), 400);
        assert_eq!(o.pad_len(HS_INIT, 100, 10), 10, "limited by buffer room");
        assert_eq!(o.pad_len(DATA, MAX_WIRE - 5, 1000), 5, "limited by MTU");
        assert_eq!(o.pad_len(DATA, MAX_WIRE + 100, 1000), 0, "already larger: no padding");
        assert_eq!(o.pad_len(HS_RESP, 100, 1000), 0);
    }

    /// Stage 2 acceptance: no constant bytes in the header area, and no fixed size.
    #[test]
    fn wire_header_entropy_and_size_spread() {
        let o = Obfs::new(&random_bytes(), Profile::default());
        const N: usize = 4096;
        let mut counts = vec![[0u32; 256]; 16];
        let mut sizes = std::collections::HashSet::new();
        for i in 0..N {
            // same type and same logical size every time, as keepalives would be
            let ty = [DATA, HS_INIT, HS_RESP][i % 3];
            let (_, wire) = make(&o, ty, 80);
            for (pos, c) in counts.iter_mut().enumerate() {
                c[wire[pos] as usize] += 1;
            }
            sizes.insert((ty, wire.len()));
        }
        // chi-square over 256 bins (255 dof): mean 255, sd ~22.6; > 400 would be a clear bias
        for (pos, c) in counts.iter().enumerate() {
            let e = N as f64 / 256.0;
            let chi2: f64 = c.iter().map(|&o| (o as f64 - e).powi(2) / e).sum();
            assert!(chi2 < 400.0, "byte {pos} is biased (chi2 {chi2:.0})");
        }
        assert!(sizes.len() > 3 * 40, "only {} distinct (type, size) pairs", sizes.len());
    }
}
