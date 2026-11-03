//! The datagram socket to the node: UDP, or a unix socket with an address of our own.
//!
//! On Linux that address is first an abstract one (no file): a node run by systemd with
//! `PrivateTmp` / `ProtectHome` does not see `/tmp` or `/run/user`, where a file would be, and
//! could not answer. The socket is connected to the node's, so only the node can send to it.
//! A node older than 4.2.1 does not answer an abstract address: then a file, as before.

#[cfg(unix)]
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
        /// The file to remove when done (none for an abstract address).
        me: Option<std::path::PathBuf>,
    },
}

impl Socket {
    /// `abstract_addr`: a unix socket's own address in the abstract namespace (Linux only;
    /// elsewhere a file anyway).
    pub async fn open(addr: &ApiAddr, abstract_addr: bool) -> std::io::Result<Socket> {
        // only unix sockets on Linux have abstract addresses
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = abstract_addr;
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
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if abstract_addr {
                    #[cfg(target_os = "android")]
                    use std::os::android::net::SocketAddrExt;
                    #[cfg(target_os = "linux")]
                    use std::os::linux::net::SocketAddrExt;
                    let name = format!("dvpn-client-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed));
                    let me = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
                    let s = std::os::unix::net::UnixDatagram::bind_addr(&me)?;
                    // connected: datagrams from anybody but the node are refused by the kernel
                    s.connect(node)?;
                    s.set_nonblocking(true)?;
                    return Ok(Socket::Unix { sock: UnixDatagram::from_std(s)?, node: node.clone(), me: None });
                }
                let dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, Into::into);
                let me =
                    dir.join(format!("dvpn-client-{}-{}.sock", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
                let _ = std::fs::remove_file(&me);
                let sock = UnixDatagram::bind(&me)?;
                Ok(Socket::Unix { sock, node: node.clone(), me: Some(me) })
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
        if let Socket::Unix { me: Some(me), .. } = self {
            let _ = std::fs::remove_file(me);
        }
    }
}
