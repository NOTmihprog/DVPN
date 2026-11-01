//! The node's single UDP socket (PLAN §9.1), shared by tracker and peer traffic: hole punching
//! only works if peers talk to each other from the port the tracker saw. Bound to `[::]` it is
//! dual-stack (`IPV6_V6ONLY` off): IPv4 peers show up as `::ffff:a.b.c.d`, which is turned back
//! into plain IPv4 here, so the rest of the code sees one address per peer. Bound to an IPv4
//! address it is IPv4-only, to a specific IPv6 address IPv6-only. It can be rebound to a new
//! random port from the configured range when every tracker becomes unreachable.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rand::RngExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// `::ffff:a.b.c.d` -> `a.b.c.d`, so a peer has one address whatever socket saw it.
pub fn normalize(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        _ => a,
    }
}

/// Which address families a socket can send to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Families {
    pub v4: bool,
    pub v6: bool,
}

impl Families {
    pub fn reaches(&self, a: &SocketAddr) -> bool {
        if a.is_ipv4() { self.v4 } else { self.v6 }
    }
}

/// Binds a UDP socket: `::` gives a dual-stack socket. Returns it with its families.
pub fn bind_udp(addr: IpAddr, port: u16) -> io::Result<(UdpSocket, Families)> {
    let sa = SocketAddr::new(addr, port);
    let sock = Socket::new(Domain::for_address(sa), Type::DGRAM, Some(Protocol::UDP))?;
    let families = match addr {
        IpAddr::V4(_) => Families { v4: true, v6: false },
        IpAddr::V6(ip) => {
            let dual = ip.is_unspecified();
            sock.set_only_v6(!dual)?;
            Families { v4: dual, v6: true }
        }
    };
    sock.set_nonblocking(true)?;
    // our own packets bypass the overlay routes (sysroute.rs); needs CAP_NET_ADMIN
    #[cfg(target_os = "linux")]
    if let Err(e) = sock.set_mark(crate::sysroute::FWMARK) {
        log::debug!("Transport | no fwmark on the socket: {e}");
    }
    sock.bind(&sa.into())?;
    Ok((UdpSocket::from_std(sock.into())?, families))
}

/// The destination as the socket needs it: IPv4 addresses are mapped into IPv6 on a dual-stack
/// socket. `None` if the socket cannot reach it.
pub fn wire_addr(families: Families, a: SocketAddr) -> Option<SocketAddr> {
    let a = normalize(a);
    match a {
        SocketAddr::V4(v4) if families.v6 && families.v4 => {
            Some(SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()))
        }
        _ if families.reaches(&a) => Some(a),
        _ => None,
    }
}

pub struct Transport {
    sock: ArcSwap<UdpSocket>,
    families: Families,
    rebound: Notify,
    bind_addr: IpAddr,
    port_range: (u16, u16),
}

fn random_port(range: (u16, u16)) -> u16 {
    rand::rng().random_range(range.0..=range.1)
}

impl Transport {
    /// Binds a random port of `port_range`. If a dual-stack socket is asked for but the system
    /// has no IPv6, falls back to IPv4 only.
    pub async fn new(bind_addr: IpAddr, port_range: (u16, u16)) -> io::Result<Arc<Self>> {
        let mut bind_addr = bind_addr;
        let mut last_err = None;
        for attempt in 0..16 {
            match bind_udp(bind_addr, random_port(port_range)) {
                Ok((sock, families)) => {
                    return Ok(Arc::new(Transport {
                        sock: ArcSwap::from_pointee(sock),
                        families,
                        rebound: Notify::new(),
                        bind_addr,
                        port_range,
                    }));
                }
                Err(e) if attempt == 0 && bind_addr == IpAddr::V6(Ipv6Addr::UNSPECIFIED) => {
                    log::warn!("Transport | no dual-stack socket ({e}), using IPv4 only");
                    bind_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    }

    pub fn families(&self) -> Families {
        self.families
    }

    pub fn can_change_port(&self) -> bool {
        self.port_range.0 != self.port_range.1
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.load().local_addr()
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) {
        let Some(to) = wire_addr(self.families, addr) else {
            log::trace!("Transport | {addr} not reachable from this socket");
            return;
        };
        let sock = self.sock.load_full();
        if let Err(e) = sock.send_to(buf, to).await {
            log::debug!("Transport | send to {addr} error: {e}");
        }
    }

    /// Receives from whichever socket is current, switching over when it gets rebound.
    pub async fn recv_from(&self, buf: &mut [u8]) -> (usize, SocketAddr) {
        loop {
            let sock = self.sock.load_full();
            tokio::select! {
                r = sock.recv_from(buf) => match r {
                    Ok((n, from)) => return (n, normalize(from)),
                    Err(e) => {
                        // e.g. ICMP port unreachable surfaced as ECONNREFUSED / WSAECONNRESET
                        log::debug!("Transport | recv error: {e}");
                    }
                },
                _ = self.rebound.notified() => {}
            }
        }
    }

    pub async fn change_port(&self) {
        loop {
            let port = random_port(self.port_range);
            match bind_udp(self.bind_addr, port) {
                Ok((sock, _)) => {
                    self.sock.store(Arc::new(sock));
                    self.rebound.notify_waiters();
                    log::warn!("Transport | Port changed, new port {port}");
                    return;
                }
                Err(e) => {
                    log::warn!("Transport | Change port to {port} error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Addresses of this host's interfaces worth telling peers about (PLAN §9.1): not loopback,
/// not link-local IPv6 (needs a scope), not the overlay interface `tun_name`.
pub fn local_candidates(port: u16, families: Families, tun_name: Option<&str>) -> Vec<SocketAddr> {
    let Ok(ifs) = if_addrs::get_if_addrs() else { return Vec::new() };
    let mut out: Vec<SocketAddr> = ifs
        .into_iter()
        .filter(|i| !i.is_loopback() && Some(i.name.as_str()) != tun_name)
        .map(|i| SocketAddr::new(i.ip(), port))
        .filter(|a| match a.ip() {
            IpAddr::V4(ip) => !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        })
        .filter(|a| families.reaches(a))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_normalized() {
        let mapped: SocketAddr = "[::ffff:203.0.113.5]:7000".parse().unwrap();
        assert_eq!(normalize(mapped), "203.0.113.5:7000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::5]:7000".parse().unwrap();
        assert_eq!(normalize(v6), v6);
    }

    #[test]
    fn wire_addresses() {
        let dual = Families { v4: true, v6: true };
        let v4only = Families { v4: true, v6: false };
        let v6only = Families { v4: false, v6: true };
        let a4: SocketAddr = "203.0.113.5:7000".parse().unwrap();
        let a6: SocketAddr = "[2001:db8::5]:7000".parse().unwrap();
        assert_eq!(wire_addr(dual, a4), Some("[::ffff:203.0.113.5]:7000".parse().unwrap()));
        assert_eq!(wire_addr(dual, a6), Some(a6));
        assert_eq!(wire_addr(v4only, a4), Some(a4));
        assert_eq!(wire_addr(v4only, a6), None);
        assert_eq!(wire_addr(v6only, a4), None);
    }

    #[tokio::test]
    async fn dual_stack_socket_talks_both_families() {
        let Ok((server, fam)) = bind_udp("::".parse().unwrap(), 0) else { return }; // no IPv6 here
        assert_eq!(fam, Families { v4: true, v6: true });
        let port = server.local_addr().unwrap().port();
        let (c4, _) = bind_udp("127.0.0.1".parse().unwrap(), 0).unwrap();
        c4.send_to(b"four", ("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"four");
        let from = normalize(from);
        assert!(from.is_ipv4(), "{from}");
        server.send_to(b"back", wire_addr(fam, from).unwrap()).await.unwrap();
        let (n, _) = c4.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"back");
        if let Ok((c6, _)) = bind_udp("::1".parse().unwrap(), 0) {
            c6.send_to(b"six", ("::1", port)).await.unwrap();
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!((&buf[..n], from.is_ipv6()), (&b"six"[..], true));
        }
    }
}
