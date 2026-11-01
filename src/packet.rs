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

/// Lowers the TTL / Hop Limit by `n` (relays passed, PLAN §6.4); the IPv4 header checksum is
/// updated incrementally (RFC 1624). `false` if the packet would expire (TTL ≤ n) or is not IP.
pub fn decrement_ttl(p: &mut [u8], n: u8) -> bool {
    if n == 0 {
        return true;
    }
    match version(p) {
        Some(4) if p.len() >= IPV4_MIN_HEADER && p[8] > n => {
            let old = u16::from_be_bytes([p[8], p[9]]);
            p[8] -= n;
            let new = u16::from_be_bytes([p[8], p[9]]);
            // HC' = ~(~HC + ~m + m')
            let hc = u16::from_be_bytes([p[10], p[11]]);
            let mut sum = u32::from(!hc) + u32::from(!old) + u32::from(new);
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            true
        }
        Some(6) if p.len() >= IPV6_HEADER && p[7] > n => {
            p[7] -= n;
            true
        }
        _ => false,
    }
}

/// What an ICMP error quotes of the offending packet: its IP header and the first 8 bytes of
/// the payload (enough for traceroute to match its probes).
pub fn quote(p: &[u8]) -> Vec<u8> {
    let hdr = match version(p) {
        Some(4) if !p.is_empty() => usize::from(p[0] & 0x0f) * 4,
        _ => IPV6_HEADER,
    };
    p[..p.len().min(hdr + 8)].to_vec()
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [b] = chunks.remainder() {
            sum += u32::from(*b) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP Time Exceeded (IPv4 type 11 / ICMPv6 type 3) from `from` to the source of the quoted
/// packet, as a relay on the path would send it, for traceroute through the mesh. `None` if
/// `from` is not of the quoted packet's family.
pub fn icmp_time_exceeded(from: IpAddr, quoted: &[u8]) -> Option<Vec<u8>> {
    let orig = parse_quoted(quoted)?;
    match (from, orig) {
        (IpAddr::V4(f), IpAddr::V4(to)) => {
            let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quoted);
            let c = checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let total = IPV4_MIN_HEADER + icmp.len();
            let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p.extend_from_slice(&f.octets());
            p.extend_from_slice(&to.octets());
            let c = checksum(&[&p]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            p.extend_from_slice(&icmp);
            Some(p)
        }
        (IpAddr::V6(f), IpAddr::V6(to)) => {
            let mut icmp = vec![3, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quoted);
            let len = (icmp.len() as u32).to_be_bytes();
            let c = checksum(&[&f.octets(), &to.octets(), &len, &[0, 0, 0, 58], &icmp]);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            p.extend_from_slice(&[58, 64]);
            p.extend_from_slice(&f.octets());
            p.extend_from_slice(&to.octets());
            p.extend_from_slice(&icmp);
            Some(p)
        }
        _ => None,
    }
}

/// Source address of a quoted (truncated) packet.
fn parse_quoted(q: &[u8]) -> Option<IpAddr> {
    match version(q)? {
        4 if q.len() >= IPV4_MIN_HEADER => Some(IpAddr::V4(Ipv4Addr::new(q[12], q[13], q[14], q[15]))),
        6 if q.len() >= IPV6_HEADER => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&q[8..24]).unwrap()))),
        _ => None,
    }
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

    proptest::proptest! {
        #[test]
        fn roundtrip_v4(src: [u8; 4], dst: [u8; 4], ttl: u8, payload in 0usize..1500, extra in 0usize..16) {
            let mut p = v4(src, dst, ttl, payload);
            p.resize(p.len() + extra, 0);
            let i = parse(&p).unwrap();
            proptest::prop_assert_eq!(i, IpInfo { src: src.into(), dst: dst.into(), ttl, len: 20 + payload });
        }

        #[test]
        fn roundtrip_v6(src: [u8; 16], dst: [u8; 16], hop: u8, payload in 1usize..1500, extra in 0usize..16) {
            let (s6, d6) = (Ipv6Addr::from(src), Ipv6Addr::from(dst));
            let mut p = v6(s6, d6, hop, payload);
            p.resize(p.len() + extra, 0);
            let i = parse(&p).unwrap();
            proptest::prop_assert_eq!(i, IpInfo { src: s6.into(), dst: d6.into(), ttl: hop, len: 40 + payload });
        }

        #[test]
        fn never_reads_past_buffer(data: Vec<u8>) {
            if let Some(i) = parse(&data) {
                proptest::prop_assert!(i.len <= data.len());
            }
        }
    }

    #[test]
    fn rejects_other_versions() {
        assert!(parse(&[]).is_none());
        let mut p = v4([1, 1, 1, 1], [2, 2, 2, 2], 64, 0);
        p[0] = 0x55;
        assert!(parse(&p).is_none());
    }

    #[test]
    fn ttl_decrement_keeps_checksum_valid() {
        let mut p = v4([10, 0, 0, 1], [10, 0, 0, 2], 5, 8);
        let c = super::checksum(&[&p[..20]]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        assert!(decrement_ttl(&mut p, 2));
        assert_eq!(p[8], 3);
        assert_eq!(super::checksum(&[&p[..20]]), 0, "header checksum still valid");
        assert!(!decrement_ttl(&mut p, 3), "would expire");
        let mut q = v6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 4, 8);
        assert!(decrement_ttl(&mut q, 1));
        assert_eq!(q[7], 3);
    }

    #[test]
    fn time_exceeded_packets() {
        let mut p = v4([10, 0, 0, 1], [10, 0, 0, 3], 1, 40);
        let c = super::checksum(&[&p[..20]]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let q = quote(&p);
        assert_eq!(q.len(), 28);
        let te = icmp_time_exceeded("10.0.0.2".parse().unwrap(), &q).unwrap();
        let info = parse(&te).unwrap();
        assert_eq!((info.src, info.dst), ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap()));
        assert_eq!(super::checksum(&[&te[..20]]), 0);
        assert_eq!(super::checksum(&[&te[20..]]), 0, "icmp checksum");
        assert_eq!((te[20], te[9]), (11, 1));

        let (s6, d6, r6): (Ipv6Addr, Ipv6Addr, Ipv6Addr) =
            ("fd00::1".parse().unwrap(), "fd00::3".parse().unwrap(), "fd00::2".parse().unwrap());
        let p6 = v6(s6, d6, 1, 40);
        let te6 = icmp_time_exceeded(IpAddr::V6(r6), &quote(&p6)).unwrap();
        let info = parse(&te6).unwrap();
        assert_eq!((info.src, info.dst), (IpAddr::V6(r6), IpAddr::V6(s6)));
        let icmp = &te6[40..];
        let len = (icmp.len() as u32).to_be_bytes();
        assert_eq!(super::checksum(&[&r6.octets(), &s6.octets(), &len, &[0, 0, 0, 58], icmp]), 0);
        assert!(icmp_time_exceeded("10.0.0.2".parse().unwrap(), &quote(&p6)).is_none(), "family mismatch");
    }
}
