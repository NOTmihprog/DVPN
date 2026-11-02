use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// The node's API address when it has no TUN or no `/run/dvpn` (and on Windows).
pub const DEFAULT_UDP: &str = "127.0.0.1:9902";
/// Where a node with a TUN puts its unix socket: `<dir>/<tun_name>.sock`.
pub const SOCKET_DIR: &str = "/run/dvpn";
/// The node's default TUN name (`[net] tun_name`).
pub const DEFAULT_TUN: &str = "dnet";
/// Environment variable with the API address, checked first by [`ApiAddr::detect`].
pub const ENV: &str = "DVPN_API";

/// Where a node's API listens.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ApiAddr {
    Udp(SocketAddr),
    /// A unix datagram socket (not on Windows).
    Unix(PathBuf),
}

impl ApiAddr {
    /// The address the `dvpn` CLI would use: `DVPN_API`, else the unix socket of TUN `tun`
    /// (`dnet` by default) if it exists, else UDP `127.0.0.1:9902`.
    pub fn detect(tun: Option<&str>) -> ApiAddr {
        if let Some(a) = std::env::var(ENV).ok().and_then(|s| s.parse().ok()) {
            return a;
        }
        if cfg!(unix) {
            let p = PathBuf::from(SOCKET_DIR).join(format!("{}.sock", tun.unwrap_or(DEFAULT_TUN)));
            if p.exists() {
                return ApiAddr::Unix(p);
            }
        }
        ApiAddr::Udp(DEFAULT_UDP.parse().expect("valid address"))
    }
}

/// `ip:port` is UDP, anything else a unix socket path (as for `dvpn -a`).
impl FromStr for ApiAddr {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.parse::<SocketAddr>() {
            Ok(a) => ApiAddr::Udp(a),
            Err(_) => ApiAddr::Unix(PathBuf::from(s)),
        })
    }
}

impl fmt::Display for ApiAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiAddr::Udp(a) => write!(f, "{a}"),
            ApiAddr::Unix(p) => write!(f, "{}", p.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!("127.0.0.1:9000".parse::<ApiAddr>().unwrap(), ApiAddr::Udp("127.0.0.1:9000".parse().unwrap()));
        assert_eq!("[::1]:9000".parse::<ApiAddr>().unwrap(), ApiAddr::Udp("[::1]:9000".parse().unwrap()));
        assert_eq!("/run/dvpn/x.sock".parse::<ApiAddr>().unwrap(), ApiAddr::Unix("/run/dvpn/x.sock".into()));
        assert_eq!("/run/dvpn/x.sock".parse::<ApiAddr>().unwrap().to_string(), "/run/dvpn/x.sock");
    }
}
