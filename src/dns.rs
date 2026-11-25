//! Names of members (PLAN §14a, MagicDNS): the node answers DNS on its own overlay address for
//! `<member>.<domain>` and `<member>.<group>.<domain>` (A: its IPv4, AAAA: its group ULA and
//! public IPv6), from the members' certificates. Only that zone: with systemd-resolved the node
//! makes it a split-DNS domain of the TUN link (`~dvpn`), so other names never come here and
//! nothing has to be forwarded. Names are matched case-insensitively; other questions under the
//! domain get NXDOMAIN, questions outside it REFUSED.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, SemaphorePermit};

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
    let end = i + 4; // the class must be there too: the answer copies the question
    (end <= q.len()).then(|| (labels.join("."), ty, end))
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

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_V6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// Sets the multicast flag on the TUN (off by default for TUN devices): without it the system
/// sends no mDNS queries there.
pub fn enable_multicast(tun: &str) {
    if cfg!(target_os = "linux") {
        let _ = std::process::Command::new("ip").args(["link", "set", "dev", tun, "multicast", "on"]).output();
    }
}

/// The mDNS answer to a query for `<member>.local` (A / AAAA / ANY), looked up as
/// `<member>.<domain>` in the zone: the response message and the addresses it is about (the
/// first is the packet's source). `None` for anything we do not know (mDNS sends no negatives).
pub fn mdns_answer(query: &[u8], zone: &Zone, domain: &str) -> Option<(Vec<u8>, Vec<IpAddr>)> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([query[4], query[5]]);
    let mut i = 12;
    let mut answers: Vec<(String, IpAddr)> = Vec::new();
    for _ in 0..qd.min(16) {
        let mut labels = Vec::new();
        loop {
            let len = *query.get(i)? as usize;
            if len == 0 {
                i += 1;
                break;
            }
            if len > 63 {
                return None;
            }
            labels.push(std::str::from_utf8(query.get(i + 1..i + 1 + len)?).ok()?.to_lowercase());
            i += 1 + len;
        }
        let ty = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
        i += 4;
        let [host, local] = labels.as_slice() else { continue };
        if local != "local" {
            continue;
        }
        for a in zone.get(&format!("{host}.{domain}")).into_iter().flatten() {
            let fits = matches!((ty, a), (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_)) | (255, _));
            if fits {
                answers.push((format!("{host}.local"), *a));
            }
        }
    }
    if answers.is_empty() {
        return None;
    }
    let mut out = vec![0, 0, 0x84, 0, 0, 0];
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    for (name, a) in &answers {
        for l in name.split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        let (t, data) = match a {
            IpAddr::V4(v) => (TYPE_A, v.octets().to_vec()),
            IpAddr::V6(v) => (TYPE_AAAA, v.octets().to_vec()),
        };
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&0x8001u16.to_be_bytes()); // IN, cache flush: we own the name
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    Some((out, answers.into_iter().map(|(_, a)| a).collect()))
}

/// Serves `zone` on `addr:53` until the process ends.
/// DNS servers to forward other names to (`[exit] dns`, while a gateway is active).
pub type Upstream = Arc<ArcSwap<Vec<IpAddr>>>;

/// Whether a query asks for a name in our zone.
pub fn in_zone(query: &[u8], domain: &str) -> bool {
    question(query).is_some_and(|(name, _, _)| name == domain || name.ends_with(&format!(".{domain}")))
}

/// Queries being forwarded at once: by the process, and for one client.
const MAX_FORWARDS: usize = 256;
const MAX_CLIENT_FORWARDS: usize = 128;
static FORWARDS: Semaphore = Semaphore::const_new(MAX_FORWARDS);
/// How long one server may take to answer.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether `r` answers `query`: its id, a response, and the same question (`end`: where that ends).
fn answers_query(r: &[u8], query: &[u8], end: usize) -> bool {
    r.len() >= end
        && r[..2] == query[..2]
        && r[2] & 0x80 != 0
        && r[4..6] == query[4..6]
        && r[12..end].eq_ignore_ascii_case(&query[12..end])
}

/// Asks one server. The socket is connected: only its answers come in, and others than to this
/// query are passed over.
async fn ask(
    query: &[u8],
    end: usize,
    server: IpAddr,
    protect: Option<&crate::transport::Protect>,
) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let up = UdpSocket::bind(bind).await?;
    crate::transport::protect_socket(&up, protect)?;
    up.connect(SocketAddr::new(server, 53)).await?;
    up.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = up.recv(&mut buf).await?;
        if answers_query(&buf[..n], query, end) {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

/// A place among the queries being forwarded, if there is one left: taken before a task is made
/// for the query.
pub fn forward_permit() -> Option<SemaphorePermit<'static>> {
    FORWARDS.try_acquire().ok()
}

/// Asks the upstream servers in turn for `query`; the first answer. `protect` keeps the socket out of the VPN (the system's own DNS servers
/// on Android).
pub async fn forward_once(
    _permit: SemaphorePermit<'static>,
    query: &[u8],
    upstream: &[IpAddr],
    protect: Option<&crate::transport::Protect>,
) -> Option<Vec<u8>> {
    let (_, _, end) = question(query)?;
    for server in upstream {
        if let Ok(Ok(r)) = tokio::time::timeout(FORWARD_TIMEOUT, ask(query, end, *server, protect)).await {
            return Some(r);
        }
    }
    None
}

/// Serves `zone` on `addr:53` until the process ends; other names go to `upstream` if set.
pub async fn serve(addr: IpAddr, zone: Arc<ArcSwap<Zone>>, domain: String, upstream: Upstream) {
    let sock = match UdpSocket::bind(SocketAddr::new(addr, 53)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::warn!("DNS | cannot listen on {addr}:53: {e}");
            return;
        }
    };
    log::info!("DNS | names of members under .{domain} on {addr}:53");
    let clients: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>> = Default::default();
    let mut buf = [0u8; 512];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            // errors come back at once: no spinning on them (see `Api::recv_loop`)
            tokio::task::yield_now().await;
            continue;
        };
        let up = upstream.load();
        if !up.is_empty() && n >= 12 && !in_zone(&buf[..n], &domain) {
            // before the task: a flood must not pile them up either
            let Some(permit) = forward_permit() else { continue };
            {
                let mut c = clients.lock();
                let n = c.entry(from.ip()).or_insert(0);
                if *n >= MAX_CLIENT_FORWARDS {
                    continue;
                }
                *n += 1;
            }
            let (query, up, sock, clients) = (buf[..n].to_vec(), up.to_vec(), sock.clone(), clients.clone());
            tokio::spawn(async move {
                if let Some(r) = forward_once(permit, &query, &up, None).await {
                    let _ = sock.send_to(&r, from).await;
                }
                let mut c = clients.lock();
                if let Some(n) = c.get_mut(&from.ip()) {
                    *n -= 1;
                    if *n == 0 {
                        c.remove(&from.ip());
                    }
                }
            });
            continue;
        }
        if let Some(reply) = answer(&buf[..n], &zone.load(), &domain) {
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

/// Windows: the Name Resolution Policy Table (NRPT) sends `.<domain>`, and with a gateway in
/// use every name (`.`), to the node's DNS server. The rules carry the comment `dvpn` /
/// `dvpn-all`; they outlive the process, so they are removed on exit and on the next start.
#[cfg(windows)]
mod nrpt {
    use std::net::IpAddr;
    use std::sync::Mutex;

    /// Our DNS server, for the rule for all names.
    static SERVER: Mutex<Option<IpAddr>> = Mutex::new(None);

    fn ps(script: &str) -> bool {
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .is_ok_and(|o| o.status.success() && o.stderr.is_empty())
    }

    fn remove(comment: &str) -> String {
        format!(
            "Get-DnsClientNrptRule | Where-Object Comment -eq '{comment}' | \
             ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}"
        )
    }

    fn add(namespace: &str, server: IpAddr, comment: &str) -> String {
        format!(
            "Add-DnsClientNrptRule -Namespace '{namespace}' -NameServers '{server}' -Comment '{comment}' | Out-Null"
        )
    }

    pub fn configure(server: IpAddr, domain: &str) -> bool {
        *SERVER.lock().unwrap_or_else(|e| e.into_inner()) = Some(server);
        let script = format!(
            "{}; {}; {}; Clear-DnsClientCache",
            remove("dvpn"),
            remove("dvpn-all"),
            add(&format!(".{domain}"), server, "dvpn")
        );
        ps(&script)
    }

    pub fn route_all(all: bool) -> bool {
        let Some(server) = *SERVER.lock().unwrap_or_else(|e| e.into_inner()) else { return false };
        let script = if all {
            format!("{}; {}; Clear-DnsClientCache", remove("dvpn-all"), add(".", server, "dvpn-all"))
        } else {
            format!("{}; Clear-DnsClientCache", remove("dvpn-all"))
        };
        ps(&script)
    }

    pub fn clear() {
        ps(&format!("{}; {}; Clear-DnsClientCache", remove("dvpn"), remove("dvpn-all")));
    }
}

/// Windows: removes our NRPT rules (on exit).
#[cfg(windows)]
pub fn resolved_clear() {
    nrpt::clear();
}

/// All names to us (and so through the gateway) or only our domain, in systemd-resolved.
#[cfg(windows)]
pub fn resolved_route_all(_tun: &str, domain: &str, all: bool) {
    if nrpt::route_all(all) {
        log::info!(
            "DNS | Windows NRPT: {}",
            if all { "all names through the tunnel".to_owned() } else { format!("only *.{domain}") }
        );
    }
}

/// All names to us (and so through the gateway) or only our domain, in systemd-resolved.
#[cfg(not(windows))]
pub fn resolved_route_all(tun: &str, domain: &str, all: bool) {
    let run =
        |args: &[&str]| std::process::Command::new("resolvectl").args(args).output().is_ok_and(|o| o.status.success());
    let d = format!("~{domain}");
    let ok = if all { run(&["domain", tun, &d, "~."]) } else { run(&["domain", tun, &d]) };
    let _ = run(&["default-route", tun, if all { "yes" } else { "no" }]);
    if ok {
        log::info!("DNS | systemd-resolved: {} through the tunnel", if all { "all names" } else { "only *.dvpn" });
    }
}

/// Windows: an NRPT rule sends `*.<domain>` to us (split DNS).
#[cfg(windows)]
pub fn configure_resolved(_tun: &str, addr: IpAddr, domain: &str) -> bool {
    let done = nrpt::configure(addr, domain);
    if done {
        log::info!("DNS | Windows NRPT sends *.{domain} to {addr}");
    } else {
        log::info!("DNS | NRPT not configured: point *.{domain} at {addr} by hand if needed");
    }
    done
}

/// Points systemd-resolved at us for the domain on the TUN link (split DNS) and lets it ask
/// mDNS there (`<member>.local`); `false` if resolvectl is not there or failed.
#[cfg(not(windows))]
pub fn configure_resolved(tun: &str, addr: IpAddr, domain: &str) -> bool {
    let ok =
        |args: &[&str]| std::process::Command::new("resolvectl").args(args).output().is_ok_and(|o| o.status.success());
    let done = ok(&["dns", tun, &addr.to_string()]) && ok(&["domain", tun, &format!("~{domain}")]);
    let _ = ok(&["mdns", tun, "resolve"]);
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
    fn question_without_a_class_is_no_query() {
        // header, root name, type, and the class cut short
        let mut q = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let zone = Zone::new();
        assert!(answer(&q, &zone, "dvpn").is_none());
        assert!(!in_zone(&q, ""));
        q.push(0);
        assert!(answer(&q, &zone, "dvpn").is_none());
        q.push(1);
        assert!(answer(&q, &zone, "dvpn").is_some(), "a whole question is answered");
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
    fn mdns() {
        let z = zone();
        let mut q = query("phone.local", TYPE_A);
        q[..2].copy_from_slice(&[0, 0]);
        let (r, addrs) = mdns_answer(&q, &z, "dvpn").unwrap();
        assert_eq!(addrs, vec!["10.10.33.40".parse::<IpAddr>().unwrap()]);
        assert_eq!((r[2], u16::from_be_bytes([r[6], r[7]])), (0x84, 1));
        assert_eq!(&r[r.len() - 4..], &[10, 10, 33, 40]);
        assert!(mdns_answer(&query("nobody.local", TYPE_A), &z, "dvpn").is_none(), "no negative answers");
        assert!(mdns_answer(&query("phone.dvpn", TYPE_A), &z, "dvpn").is_none(), "only .local");
        let (r, _) = mdns_answer(&query("phone.local", 255), &z, "dvpn").unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 2, "ANY: A and AAAA");
    }

    #[test]
    fn labels() {
        assert_eq!(label("PC rinacs228 (Windows)"), "pc-rinacs228--windows");
        assert_eq!(label("msk-mihprog-firstvds"), "msk-mihprog-firstvds");
    }

    #[cfg(target_os = "linux")]
    mod upstream {
        use super::*;

        /// What reaches the node before the real answer.
        #[derive(Clone, Copy, Debug)]
        enum Forgery {
            None,
            OtherSender,
            OtherQuestion,
            OtherId,
        }

        fn reply(q: &[u8], last: u8) -> Vec<u8> {
            let name = question(q).unwrap().0;
            let zone = HashMap::from([(name.clone(), vec![IpAddr::from([192, 0, 2, last])])]);
            answer(q, &zone, &name).unwrap()
        }

        /// A DNS server on 127.0.0.2:53 that answers 192.0.2.1 after the forgery (192.0.2.66).
        async fn serve_forged(f: Forgery) -> tokio::task::JoinHandle<()> {
            let sock = UdpSocket::bind("127.0.0.2:53").await.unwrap();
            let other = UdpSocket::bind("127.0.0.3:53").await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                match f {
                    Forgery::None => {}
                    Forgery::OtherSender => drop(other.send_to(&reply(q, 66), from).await),
                    Forgery::OtherQuestion => {
                        let mut other_q = query("evil.example", TYPE_A);
                        other_q[..2].copy_from_slice(&q[..2]);
                        drop(sock.send_to(&reply(&other_q, 66), from).await)
                    }
                    Forgery::OtherId => {
                        let mut r = reply(q, 66);
                        r[0] ^= 0xff;
                        drop(sock.send_to(&r, from).await)
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = sock.send_to(&reply(q, 1), from).await;
            })
        }

        const FORGERIES: [Forgery; 4] = [Forgery::None, Forgery::OtherSender, Forgery::OtherQuestion, Forgery::OtherId];

        fn check(bad: &mut Vec<String>, f: Forgery, got: Option<Vec<u8>>) {
            let q = query("example.com", TYPE_A);
            if got.as_deref() != Some(&reply(&q, 1)) {
                let ip = got.map(|r| r[r.len() - 4..].to_vec());
                bad.push(format!("{f:?}: got {ip:?}"));
            }
        }

        #[tokio::test]
        async fn forward_once_takes_only_the_servers_answer() {
            let name = "dns::tests::upstream::forward_once_takes_only_the_servers_answer";
            if !crate::testutil::in_netns(name, None) {
                return;
            }
            let mut bad = Vec::new();
            for f in FORGERIES {
                let server = serve_forged(f).await;
                let up = ["127.0.0.2".parse().unwrap()];
                let got = forward_once(forward_permit().unwrap(), &query("example.com", TYPE_A), &up, None).await;
                server.await.unwrap();
                check(&mut bad, f, got);
            }
            assert!(bad.is_empty(), "{bad:#?}");
        }

        fn start() -> tokio::task::JoinHandle<()> {
            let up = Arc::new(ArcSwap::from_pointee(vec!["127.0.0.2".parse().unwrap()]));
            let zone = Arc::new(ArcSwap::from_pointee(zone()));
            tokio::spawn(serve("127.0.0.1".parse().unwrap(), zone, "dvpn".into(), up))
        }

        #[tokio::test]
        async fn serve_takes_only_the_servers_answer() {
            if !crate::testutil::in_netns("dns::tests::upstream::serve_takes_only_the_servers_answer", None) {
                return;
            }
            start();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut bad = Vec::new();
            for f in FORGERIES {
                let server = serve_forged(f).await;
                let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                c.send_to(&query("example.com", TYPE_A), "127.0.0.1:53").await.unwrap();
                let mut buf = vec![0u8; 512];
                let n = tokio::time::timeout(Duration::from_secs(3), c.recv(&mut buf)).await;
                server.await.unwrap();
                check(&mut bad, f, n.ok().map(|n| buf[..n.unwrap()].to_vec()));
            }
            assert!(bad.is_empty(), "{bad:#?}");
        }

        /// A task is only made for a query that has its place: many sources at once do not get
        /// more tasks than there are places left.
        #[tokio::test]
        async fn no_tasks_beyond_the_limit() {
            if !crate::testutil::in_netns("dns::tests::upstream::no_tasks_beyond_the_limit", None) {
                return;
            }
            let _silent = UdpSocket::bind("127.0.0.2:53").await.unwrap();
            start();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _others = FORWARDS.try_acquire_many(MAX_FORWARDS as u32 - 2).unwrap();
            let alive = || tokio::runtime::Handle::current().metrics().num_alive_tasks();
            let before = alive();
            // more than the runtime runs between two looks at `alive` (61), fewer than one read of the socket
            for i in 0..120 {
                let c = std::net::UdpSocket::bind((format!("127.0.1.{}", i + 1), 0)).unwrap();
                c.send_to(&query("example.com", TYPE_A), "127.0.0.1:53").unwrap();
            }
            let mut most = 0;
            for _ in 0..500 {
                tokio::task::yield_now().await;
                most = most.max(alive() - before);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(alive() - before, 2, "the places left are used");
            assert_eq!(most, 2, "tasks for 2 places");
        }

        /// Clients asking faster than a (silent) server answers do not use up the node's sockets,
        /// and names of members are still answered.
        #[tokio::test]
        async fn forwarded_queries_are_limited() {
            if !crate::testutil::in_netns("dns::tests::upstream::forwarded_queries_are_limited", None) {
                return;
            }
            let _silent = UdpSocket::bind("127.0.0.2:53").await.unwrap();
            start();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let fds = || std::fs::read_dir("/proc/self/fd").unwrap().count();
            let before = fds();
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for i in 0..800 {
                c.send_to(&query(&format!("n{i}.example.com"), TYPE_A), "127.0.0.1:53").await.unwrap();
                if i % 20 == 0 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let used = fds() - before;
            c.send_to(&query("phone.dvpn", TYPE_A), "127.0.0.1:53").await.unwrap();
            let mut buf = [0u8; 512];
            let own = tokio::time::timeout(Duration::from_secs(1), c.recv(&mut buf)).await;
            assert!(own.is_ok(), "no answer for a member's name");
            assert!(used <= 300, "{used} sockets for 800 queries");
        }
    }
}
