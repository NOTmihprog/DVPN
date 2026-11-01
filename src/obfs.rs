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
use chacha20::cipher::{KeyIvInit, StreamCipher};
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

/// One piece of a signature packet template (AmneziaWG `i1..i5` syntax).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Piece {
    /// `<b 0x0102..>` fixed bytes
    Bytes(Vec<u8>),
    /// `<r N>` random bytes
    Random(usize),
    /// `<rc N>` random ASCII letters
    Letters(usize),
    /// `<rd N>` random ASCII digits
    Digits(usize),
    /// `<t>` unix time, u32 big-endian
    Time,
}

/// A signature packet sent before handshakes, built from a template like
/// `<b 0x16030301> <r 8> <t>`, so the start of a flow can resemble some harmless protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template(Vec<Piece>);

impl std::str::FromStr for Template {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut pieces = Vec::new();
        let mut rest = s.trim();
        while !rest.is_empty() {
            let inner = rest
                .strip_prefix('<')
                .and_then(|r| r.split_once('>'))
                .ok_or_else(|| format!("expected <tag> at {rest:?}"))?;
            let (tag, after) = inner;
            rest = after.trim_start();
            let mut words = tag.split_whitespace();
            let name = words.next().unwrap_or_default();
            let arg = words.next();
            if words.next().is_some() {
                return Err(format!("too many arguments in <{tag}>"));
            }
            let count = || -> Result<usize, String> {
                let n: usize = arg
                    .ok_or(format!("<{name}> needs a length"))?
                    .parse()
                    .map_err(|_| format!("bad length in <{tag}>"))?;
                if n == 0 || n > MAX_WIRE { Err(format!("length out of range in <{tag}>")) } else { Ok(n) }
            };
            pieces.push(match name {
                "b" => {
                    let hex =
                        arg.and_then(|a| a.strip_prefix("0x")).ok_or(format!("<b> needs 0x-prefixed hex: <{tag}>"))?;
                    // checked before slicing: a multi-byte character would split mid-char
                    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(format!("bad hex in <{tag}>"));
                    }
                    if hex.is_empty() || hex.len() % 2 != 0 {
                        return Err(format!("odd or empty hex in <{tag}>"));
                    }
                    let bytes = (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                        .collect::<Result<Vec<u8>, _>>()
                        .map_err(|_| format!("bad hex in <{tag}>"))?;
                    Piece::Bytes(bytes)
                }
                "r" => Piece::Random(count()?),
                "rc" => Piece::Letters(count()?),
                "rd" => Piece::Digits(count()?),
                "t" if arg.is_none() => Piece::Time,
                _ => return Err(format!("unknown tag <{tag}>")),
            });
        }
        let t = Template(pieces);
        match t.len() {
            0 => Err("empty template".into()),
            n if n > MAX_WIRE => Err(format!("template makes {n}-byte packets, more than {MAX_WIRE}")),
            _ => Ok(t),
        }
    }
}

impl Template {
    fn len(&self) -> usize {
        self.0
            .iter()
            .map(|p| match p {
                Piece::Bytes(b) => b.len(),
                Piece::Random(n) | Piece::Letters(n) | Piece::Digits(n) => *n,
                Piece::Time => 4,
            })
            .sum()
    }

    pub fn generate(&self) -> Vec<u8> {
        const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = rand::rng();
        let mut out = Vec::with_capacity(self.len());
        for p in &self.0 {
            match p {
                Piece::Bytes(b) => out.extend_from_slice(b),
                Piece::Random(n) => out.extend((0..*n).map(|_| rng.random::<u8>())),
                Piece::Letters(n) => out.extend((0..*n).map(|_| LETTERS[rng.random_range(0..LETTERS.len())])),
                Piece::Digits(n) => out.extend((0..*n).map(|_| b'0' + rng.random_range(0..10u8))),
                Piece::Time => {
                    let t = crate::clock::now();
                    out.extend_from_slice(&(t.as_secs() as u32).to_be_bytes());
                }
            }
        }
        out
    }
}

/// The group's obfuscation profile (`[group.obfs]`), the same for all members so they look
/// alike. Names follow AmneziaWG; its `h1..h4` (message type ranges) are not needed because the
/// type is masked entirely, and `content_padding` is what `s4` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `jc`: junk packets sent before each handshake initiation.
    pub junk_count: RangeInclusive<u8>,
    /// `jmin`..`jmax`: their sizes.
    pub junk_size: RangeInclusive<u16>,
    /// `i1`..`i5`: signature packets sent before the junk, in order.
    pub signatures: Vec<Template>,
    /// `s1`: padding of handshake initiations.
    pub init_pad: RangeInclusive<u16>,
    /// `s2`: padding of handshake responses.
    pub resp_pad: RangeInclusive<u16>,
    /// `s4`: padding of data packets.
    pub data_pad: RangeInclusive<u16>,
}

impl Profile {
    /// No junk and no padding: for end-to-end sessions inside `FORWARD`, whose packets are
    /// padded and masked by the link session that carries them anyway.
    pub fn none() -> Self {
        Profile {
            junk_count: 0..=0,
            junk_size: 40..=40,
            signatures: Vec::new(),
            init_pad: 0..=0,
            resp_pad: 0..=0,
            data_pad: 0..=0,
        }
    }
}

impl Default for Profile {
    /// Moderate: 4-8 junk packets of 40-200 bytes, handshakes vary by up to 96 bytes, data by 48.
    fn default() -> Self {
        Profile {
            junk_count: 4..=8,
            junk_size: 40..=200,
            signatures: Vec::new(),
            init_pad: 0..=96,
            resp_pad: 0..=96,
            data_pad: 0..=48,
        }
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
        // Nonce only, block counter 0: a counter taken from the packet could be 0xffffffff, where
        // the keystream ends and the cipher panics - a one-packet remote crash (found by fuzzing).
        let nonce: [u8; 12] = sample[..12].try_into().unwrap();
        let mut c = ChaCha20::new(&self.hp_key.into(), &nonce.into());
        let mut m = [0u8; 16];
        c.apply_keystream(&mut m);
        m
    }

    /// Packets to send right before a handshake initiation: the signature packets, then junk.
    /// They are not ours to the receiver (no valid header/MAC) and get dropped there.
    pub fn prelude(&self) -> Vec<Vec<u8>> {
        let mut rng = rand::rng();
        let mut out: Vec<Vec<u8>> = self.profile.signatures.iter().map(Template::generate).collect();
        for _ in 0..rng.random_range(self.profile.junk_count.clone()) {
            let n = rng.random_range(self.profile.junk_size.clone()) as usize;
            out.push((0..n).map(|_| rng.random::<u8>()).collect());
        }
        out
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
        // regression (fuzzing): an all-0xff sample once overflowed the ChaCha20 block counter
        let _ = o.open(&mut [0xffu8; 64]);
        for _ in 0..1000 {
            let mut junk: Vec<u8> = (0..rand::random_range(0..200usize)).map(|_| rand::random()).collect();
            if let Some(len) = o.open(&mut junk) {
                assert!(len >= MIN_WIRE && len <= junk.len());
            }
        }
    }

    #[test]
    fn templates() {
        let t: Template = "<b 0x16030301> <r 8> <rc 5><rd 3> <t>".parse().unwrap();
        let p = t.generate();
        assert_eq!(p.len(), 4 + 8 + 5 + 3 + 4);
        assert_eq!(&p[..4], &[0x16, 0x03, 0x03, 0x01]);
        assert!(p[12..17].iter().all(u8::is_ascii_alphabetic));
        assert!(p[17..20].iter().all(u8::is_ascii_digit));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
        let t_val = u32::from_be_bytes(p[20..24].try_into().unwrap());
        assert!(now.abs_diff(t_val) <= 2);
        assert_ne!(t.generate()[4..12], p[4..12], "random part differs between packets");
        for bad in [
            "<b 0x\u{570b}>",
            "<b 0x8\u{570b}4>",
            "",
            "<b 0x>",
            "<b 0x123>",
            "<b 1234>",
            "<b 0xzz>",
            "<r>",
            "<r 0>",
            "<r x>",
            "<q 3>",
            "<t 4>",
            "b 0x00",
            "<r 99999>",
            "<r 1 2>",
        ] {
            assert!(bad.parse::<Template>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn prelude_counts_and_sizes() {
        let profile = Profile {
            junk_count: 2..=3,
            junk_size: 10..=20,
            signatures: vec!["<b 0xaabb>".parse().unwrap(), "<r 4>".parse().unwrap()],
            ..Profile::default()
        };
        let o = Obfs::new(&random_bytes(), profile);
        for _ in 0..50 {
            let p = o.prelude();
            assert!((4..=5).contains(&p.len()));
            assert_eq!(p[0], [0xaa, 0xbb]);
            assert_eq!(p[1].len(), 4);
            assert!(p[2..].iter().all(|j| (10..=20).contains(&j.len())));
        }
        let none = Obfs::new(&random_bytes(), Profile { junk_count: 0..=0, ..Profile::default() });
        assert!(none.prelude().is_empty());
    }

    #[test]
    fn padding_respects_room_and_mtu() {
        let o = Obfs::new(
            &random_bytes(),
            Profile { init_pad: 400..=400, resp_pad: 0..=0, data_pad: 300..=300, ..Profile::default() },
        );
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
