//! Minimal IPv4 / IPv6 header parsing for the TUN path.
//!
//! Only what routing needs: version, source, destination, TTL / Hop Limit. Headers that
//! claim more bytes than the buffer holds are rejected, so the fields read are always in bounds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPV4_MIN_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 TTL or IPv6 Hop Limit.
    pub ttl: u8,
    /// Length of the IP packet as declared by its header (≤ buffer length).
    pub len: usize,
}

/// IP version from the first nibble, if the buffer is not empty.
pub fn version(p: &[u8]) -> Option<u8> {
    p.first().map(|b| b >> 4)
}

pub fn parse(p: &[u8]) -> Option<IpInfo> {
    match version(p)? {
        4 => parse_v4(p),
        6 => parse_v6(p),
        _ => None,
    }
}

fn parse_v4(p: &[u8]) -> Option<IpInfo> {
    if p.len() < IPV4_MIN_HEADER {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if ihl < IPV4_MIN_HEADER || ihl > p.len() || total < ihl || total > p.len() {
        return None;
    }
    let addr = |i: usize| Ipv4Addr::new(p[i], p[i + 1], p[i + 2], p[i + 3]);
    Some(IpInfo { src: addr(12).into(), dst: addr(16).into(), ttl: p[8], len: total })
}

fn parse_v6(p: &[u8]) -> Option<IpInfo> {
    if p.len() < IPV6_HEADER {
        return None;
    }
    let total = IPV6_HEADER + usize::from(u16::from_be_bytes([p[4], p[5]]));
    // Payload length 0 means a jumbogram (hop-by-hop option); never valid on a TUN with our MTU.
    if (total == IPV6_HEADER && p.len() > IPV6_HEADER) || total > p.len() {
        return None;
    }
    let addr = |i: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&p[i..i + 16]).unwrap());
    Some(IpInfo { src: addr(8).into(), dst: addr(24).into(), ttl: p[7], len: total })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn v4(src: [u8; 4], dst: [u8; 4], ttl: u8, payload: usize) -> Vec<u8> {
        let total = IPV4_MIN_HEADER + payload;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = ttl;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    pub fn v6(src: Ipv6Addr, dst: Ipv6Addr, hop: u8, payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; IPV6_HEADER + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        p[6] = 17;
        p[7] = hop;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn parses_v4() {
        let p = v4([10, 0, 0, 1], [10, 0, 0, 2], 64, 8);
        let i = parse(&p).unwrap();
        assert_eq!(i.src, IpAddr::from([10, 0, 0, 1]));
        assert_eq!(i.dst, IpAddr::from([10, 0, 0, 2]));
        assert_eq!((i.ttl, i.len), (64, 28));
    }

    #[test]
    fn v4_with_options_and_trailing_bytes() {
        let mut p = v4([1, 1, 1, 1], [2, 2, 2, 2], 1, 8);
        p[0] = 0x46; // ihl = 24 bytes
        let mut padded = p.clone();
        padded.extend_from_slice(&[0; 4]); // e.g. ethernet padding after the IP packet
        assert_eq!(parse(&p).unwrap().len, 28);
        assert_eq!(parse(&padded).unwrap().len, 28);
    }

    #[test]
    fn rejects_bad_v4() {
        let good = v4([1, 1, 1, 1], [2, 2, 2, 2], 64, 0);
        assert!(parse(&good[..19]).is_none(), "short");
        let mut p = good.clone();
        p[0] = 0x44; // ihl < 5
        assert!(parse(&p).is_none());
        let mut p = good.clone();
        p[0] = 0x4f; // ihl 60 > buffer
        assert!(parse(&p).is_none());
        let mut p = good.clone();
        p[2..4].copy_from_slice(&100u16.to_be_bytes()); // total > buffer
        assert!(parse(&p).is_none());
        let mut p = good;
        p[2..4].copy_from_slice(&10u16.to_be_bytes()); // total < header
        assert!(parse(&p).is_none());
    }

    #[test]
    fn parses_v6() {
        let (a, b) = ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap());
        let p = v6(a, b, 3, 12);
        let i = parse(&p).unwrap();
        assert_eq!((i.src, i.dst), (IpAddr::V6(a), IpAddr::V6(b)));
        assert_eq!((i.ttl, i.len), (3, 52));
    }

    #[test]
    fn rejects_bad_v6() {
        let (a, b) = ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap());
        let good = v6(a, b, 64, 8);
        assert!(parse(&good[..39]).is_none(), "short");
        let mut p = good.clone();
        p[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse(&p).is_none(), "payload length past buffer");
        let mut p = good;
        p[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(parse(&p).is_none(), "jumbogram");
        assert!(parse(&v6(a, b, 64, 0)).is_some(), "empty payload, exact length");
    }

    #[test]
    fn rejects_other_versions() {
        assert!(parse(&[]).is_none());
        let mut p = v4([1, 1, 1, 1], [2, 2, 2, 2], 64, 0);
        p[0] = 0x55;
        assert!(parse(&p).is_none());
    }
}
