//! Names of members (PLAN §14a, MagicDNS): the node answers DNS on its own overlay address for
//! `<member>.<domain>` and `<member>.<group>.<domain>` (A: its IPv4, AAAA: its group ULA and
//! public IPv6), from the members' certificates. Only that zone: with systemd-resolved the node
//! makes it a split-DNS domain of the TUN link (`~dvpn`), so other names never come here and
//! nothing has to be forwarded. Names are matched case-insensitively; other questions under the
//! domain get NXDOMAIN, questions outside it REFUSED.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TTL: u32 = 30;

/// name (lowercase, fully qualified without the trailing dot) -> addresses
pub type Zone = HashMap<String, Vec<IpAddr>>;

/// A DNS label from a member name: lowercase, letters, digits and '-' only.
pub fn label(name: &str) -> String {
    let l: String =
        name.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect();
    l.trim_matches('-').to_owned()
}

/// Reads the question name; returns (name, type, end of the question).
fn question(q: &[u8]) -> Option<(String, u16, usize)> {
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *q.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len > 63 {
            return None; // no compression in questions
        }
        labels.push(std::str::from_utf8(q.get(i + 1..i + 1 + len)?).ok()?.to_lowercase());
        i += 1 + len;
    }
    let ty = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((labels.join("."), ty, i + 4))
}

/// The answer to a query, `None` for what is not a query worth answering.
pub fn answer(query: &[u8], zone: &Zone, domain: &str) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, ty, end) = question(query)?;
    let in_zone = name == domain || name.ends_with(&format!(".{domain}"));
    let mut out = Vec::with_capacity(end + 64);
    out.extend_from_slice(&query[..2]); // id
    let rd = query[2] & 0x01;
    out.push(0x84 | rd); // response, authoritative
    let addrs = zone.get(&name);
    let rcode = if !in_zone {
        5 // refused
    } else if addrs.is_none() {
        3 // nxdomain
    } else {
        0
    };
    out.push(rcode);
    let records: Vec<&IpAddr> = addrs
        .into_iter()
        .flatten()
        .filter(|a| matches!((ty, a), (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))))
        .collect();
    out.extend_from_slice(&1u16.to_be_bytes()); // questions
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // authority, additional
    out.extend_from_slice(&query[12..end]);
    for a in records {
        out.extend_from_slice(&[0xc0, 12]); // the question's name
        let (t, data) = match a {
            IpAddr::V4(v) => (TYPE_A, v.octets().to_vec()),
            IpAddr::V6(v) => (TYPE_AAAA, v.octets().to_vec()),
        };
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    Some(out)
}

/// Serves `zone` on `addr:53` until the process ends.
pub async fn serve(addr: IpAddr, zone: Arc<ArcSwap<Zone>>, domain: String) {
    let sock = match UdpSocket::bind(SocketAddr::new(addr, 53)).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("DNS | cannot listen on {addr}:53: {e}");
            return;
        }
    };
    log::info!("DNS | names of members under .{domain} on {addr}:53");
    let mut buf = [0u8; 512];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        if let Some(reply) = answer(&buf[..n], &zone.load(), &domain) {
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

/// Points systemd-resolved at us for the domain on the TUN link (split DNS); `false` if
/// resolvectl is not there or failed.
pub fn configure_resolved(tun: &str, addr: IpAddr, domain: &str) -> bool {
    let ok =
        |args: &[&str]| std::process::Command::new("resolvectl").args(args).output().is_ok_and(|o| o.status.success());
    let done = ok(&["dns", tun, &addr.to_string()]) && ok(&["domain", tun, &format!("~{domain}")]);
    if done {
        log::info!("DNS | systemd-resolved sends *.{domain} to {addr}");
    } else {
        log::info!("DNS | systemd-resolved not configured: point *.{domain} at {addr} by hand if needed");
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, ty: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&ty.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    fn zone() -> Zone {
        HashMap::from([("phone.dvpn".to_owned(), vec!["10.10.33.40".parse().unwrap(), "fd00::40".parse().unwrap()])])
    }

    #[test]
    fn answers() {
        let z = zone();
        let r = answer(&query("Phone.DVPN", TYPE_A), &z, "dvpn").unwrap();
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(r[3] & 0x0f, 0, "noerror");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one A record");
        assert_eq!(&r[r.len() - 4..], &[10, 10, 33, 40]);
        let r = answer(&query("phone.dvpn", TYPE_AAAA), &z, "dvpn").unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        let r = answer(&query("nobody.dvpn", TYPE_A), &z, "dvpn").unwrap();
        assert_eq!(r[3] & 0x0f, 3, "nxdomain");
        let r = answer(&query("example.com", TYPE_A), &z, "dvpn").unwrap();
        assert_eq!(r[3] & 0x0f, 5, "refused");
        let r = answer(&query("phone.dvpn", 16), &z, "dvpn").unwrap();
        assert_eq!((r[3] & 0x0f, u16::from_be_bytes([r[6], r[7]])), (0, 0), "TXT: name exists, no data");
        assert!(answer(&[0; 5], &z, "dvpn").is_none());
        assert!(answer(&r, &z, "dvpn").is_none(), "a response is not answered");
    }

    #[test]
    fn labels() {
        assert_eq!(label("PC rinacs228 (Windows)"), "pc-rinacs228--windows");
        assert_eq!(label("msk-mihprog-firstvds"), "msk-mihprog-firstvds");
    }
}
