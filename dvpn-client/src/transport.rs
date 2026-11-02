//! The datagram socket to the node: UDP, or a unix socket with an address of our own.

use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::UdpSocket;
#[cfg(unix)]
use tokio::net::UnixDatagram;

use crate::ApiAddr;

pub enum Socket {
    Udp(UdpSocket),
    #[cfg(unix)]
    Unix {
        sock: UnixDatagram,
        node: std::path::PathBuf,
        me: std::path::PathBuf,
    },
}

impl Socket {
    pub async fn open(addr: &ApiAddr) -> std::io::Result<Socket> {
        match addr {
            ApiAddr::Udp(a) => {
                let local: std::net::SocketAddr =
                    if a.is_ipv4() { "127.0.0.1:0".parse().unwrap() } else { "[::1]:0".parse().unwrap() };
                let s = UdpSocket::bind(local).await?;
                s.connect(a).await?;
                Ok(Socket::Udp(s))
            }
            #[cfg(unix)]
            ApiAddr::Unix(node) => {
                // a datagram client needs an address of its own for the answers
                static N: AtomicU32 = AtomicU32::new(0);
                let dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, Into::into);
                let me =
                    dir.join(format!("dvpn-client-{}-{}.sock", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
                let _ = std::fs::remove_file(&me);
                let sock = UnixDatagram::bind(&me)?;
                Ok(Socket::Unix { sock, node: node.clone(), me })
            }
            #[cfg(not(unix))]
            ApiAddr::Unix(p) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{}: unix sockets are not supported here", p.display()),
            )),
        }
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Socket::Udp(s) => s.send(data).await.map(|_| ()),
            #[cfg(unix)]
            Socket::Unix { sock, node, .. } => sock.send_to(data, node).await.map(|_| ()),
        }
    }

    /// Without waiting (for `Drop`): whether it went out does not matter.
    pub fn try_send(&self, data: &[u8]) {
        let _ = match self {
            Socket::Udp(s) => s.try_send(data),
            #[cfg(unix)]
            Socket::Unix { sock, node, .. } => sock.try_send_to(data, node),
        };
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Socket::Udp(s) => s.recv(buf).await,
            #[cfg(unix)]
            Socket::Unix { sock, .. } => sock.recv(buf).await,
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Socket::Unix { me, .. } = self {
            let _ = std::fs::remove_file(me);
        }
    }
}
