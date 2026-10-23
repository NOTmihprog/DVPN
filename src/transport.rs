use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// The single UDP socket shared by tracker traffic and peer traffic: hole punching only works
/// if peers talk to each other from the same port the tracker saw. It can be rebound to a new
/// random port from the configured range when every tracker becomes unreachable.
pub struct Transport {
    sock: ArcSwap<UdpSocket>,
    rebound: Notify,
    bind_addr: Ipv4Addr,
    port_range: (u16, u16),
}

fn random_port(range: (u16, u16)) -> u16 {
    rand::rng().random_range(range.0..=range.1)
}

async fn bind(addr: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddrV4::new(addr, port)).await
}

impl Transport {
    pub async fn new(bind_addr: Ipv4Addr, port_range: (u16, u16)) -> io::Result<Arc<Self>> {
        let mut last_err = None;
        for _ in 0..16 {
            match bind(bind_addr, random_port(port_range)).await {
                Ok(sock) => {
                    return Ok(Arc::new(Transport {
                        sock: ArcSwap::from_pointee(sock),
                        rebound: Notify::new(),
                        bind_addr,
                        port_range,
                    }));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    }

    pub fn can_change_port(&self) -> bool {
        self.port_range.0 != self.port_range.1
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.load().local_addr()
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) {
        let sock = self.sock.load_full();
        if let Err(e) = sock.send_to(buf, addr).await {
            log::debug!("Transport | send to {addr} error: {e}");
        }
    }

    /// Receives from whichever socket is current, switching over when it gets rebound.
    pub async fn recv_from(&self, buf: &mut [u8]) -> (usize, SocketAddr) {
        loop {
            let sock = self.sock.load_full();
            tokio::select! {
                r = sock.recv_from(buf) => match r {
                    Ok(r) => return r,
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
            match bind(self.bind_addr, port).await {
                Ok(sock) => {
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
