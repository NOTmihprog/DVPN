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
        let (pairs, rest) = part.as_chunks::<2>();
        for c in pairs {
            sum += u32::from(u16::from_be_bytes(*c));
        }
        if let [b] = rest {
            sum += u32::from(*b) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The ICMP errors DVPN generates on behalf of the path (PLAN §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpError {
    /// A relay: the hop limit ran out (traceroute).
    TimeExceeded,
    /// No way to the destination node (from a relay, or nothing to try at the source).
    HostUnreachable,
    /// The kill switch: the internet is blocked while no gateway is alive.
    Prohibited,
    /// Does not fit the path: IPv4 "fragmentation needed" (DF set) / ICMPv6 "packet too big".
    TooBig(u16),
}

impl IcmpError {
    /// (type, code, the 32 bits after the checksum) for IPv4 and IPv6.
    fn codes(self, v6: bool) -> (u8, u8, u32) {
        match (self, v6) {
            (IcmpError::TimeExceeded, false) => (11, 0, 0),
            (IcmpError::TimeExceeded, true) => (3, 0, 0),
            (IcmpError::HostUnreachable, false) => (3, 1, 0),
            (IcmpError::HostUnreachable, true) => (1, 3, 0),
            (IcmpError::Prohibited, false) => (3, 13, 0),
            (IcmpError::Prohibited, true) => (1, 1, 0),
            (IcmpError::TooBig(mtu), false) => (3, 4, u32::from(mtu)),
            (IcmpError::TooBig(mtu), true) => (2, 0, u32::from(mtu)),
        }
    }
}

/// An ICMP error from `from` to the source of the quoted packet, as a router on the path would
/// send it. `None` if `from` is not of the quoted packet's family.
pub fn icmp_error(kind: IcmpError, from: IpAddr, quoted: &[u8]) -> Option<Vec<u8>> {
    let orig = parse_quoted(quoted)?;
    let (ty, code, rest) = kind.codes(orig.is_ipv6());
    let mut icmp = vec![ty, code, 0, 0];
    icmp.extend_from_slice(&rest.to_be_bytes());
    icmp.extend_from_slice(quoted);
    match (from, orig) {
        (IpAddr::V4(f), IpAddr::V4(to)) => {
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

/// ICMP Time Exceeded (IPv4 type 11 / ICMPv6 type 3), for traceroute through the mesh.
pub fn icmp_time_exceeded(from: IpAddr, quoted: &[u8]) -> Option<Vec<u8>> {
    icmp_error(IcmpError::TimeExceeded, from, quoted)
}

/// Whether an IPv4 packet has "don't fragment" set (IPv6 packets are never fragmented on the way).
pub fn dont_fragment(p: &[u8]) -> bool {
    match version(p) {
        Some(4) => p.get(6).is_some_and(|b| b & 0x40 != 0),
        _ => true,
    }
}

/// UDP payload of an IPv4/IPv6 packet: (source port, destination port, payload). IPv6 extension
/// headers are not followed.
pub fn udp(p: &[u8]) -> Option<(u16, u16, &[u8])> {
    let off = match version(p)? {
        4 if p.len() >= IPV4_MIN_HEADER && p[9] == 17 => usize::from(p[0] & 0x0f) * 4,
        6 if p.len() >= IPV6_HEADER && p[6] == 17 => IPV6_HEADER,
        _ => return None,
    };
    let h = p.get(off..off + 8)?;
    let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
    let data = p.get(off + 8..off + len.max(8))?;
    Some((u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[2], h[3]]), data))
}

/// A UDP packet (IPv4 or IPv6, by the addresses) with valid checksums.
pub fn udp_packet(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8], ttl: u8) -> Option<Vec<u8>> {
    let ulen = 8 + payload.len();
    let mut udp = Vec::with_capacity(ulen);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(ulen as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let c = checksum(&[&s.octets(), &d.octets(), &[0, 17], &(ulen as u16).to_be_bytes(), &udp]);
            udp[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
            let total = IPV4_MIN_HEADER + ulen;
            let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, ttl, 17, 0, 0];
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let c = checksum(&[&p]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            p.extend_from_slice(&udp);
            Some(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let c = checksum(&[&s.octets(), &d.octets(), &(ulen as u32).to_be_bytes(), &[0, 0, 0, 17], &udp]);
            udp[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&(ulen as u16).to_be_bytes());
            p.extend_from_slice(&[17, ttl]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&udp);
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

    #[test]
    fn icmp_errors() {
        let p = v4([10, 0, 0, 1], [10, 0, 0, 3], 64, 1400);
        let from: IpAddr = "10.0.0.3".parse().unwrap();
        let tb = icmp_error(IcmpError::TooBig(1368), from, &quote(&p)).unwrap();
        assert_eq!((tb[20], tb[21]), (3, 4));
        assert_eq!(u16::from_be_bytes([tb[26], tb[27]]), 1368, "next-hop MTU");
        assert_eq!(super::checksum(&[&tb[20..]]), 0);
        let un = icmp_error(IcmpError::HostUnreachable, from, &quote(&p)).unwrap();
        assert_eq!((un[20], un[21]), (3, 1));
        let p6 = v6("fd00::1".parse().unwrap(), "fd00::3".parse().unwrap(), 64, 1400);
        let tb6 = icmp_error(IcmpError::TooBig(1368), "fd00::3".parse().unwrap(), &quote(&p6)).unwrap();
        assert_eq!((tb6[40], tb6[41]), (2, 0));
        assert_eq!(u32::from_be_bytes(tb6[44..48].try_into().unwrap()), 1368);
        let pr6 = icmp_error(IcmpError::Prohibited, "fd00::3".parse().unwrap(), &quote(&p6)).unwrap();
        assert_eq!((pr6[40], pr6[41]), (1, 1));
        let mut df = v4([10, 0, 0, 1], [10, 0, 0, 3], 64, 8);
        assert!(!dont_fragment(&df));
        df[6] |= 0x40;
        assert!(dont_fragment(&df));
    }
}
