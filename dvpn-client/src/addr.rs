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
/// Environment variable with the token of a UDP API, checked before the node's token file.
pub const TOKEN_ENV: &str = "DVPN_API_TOKEN";

/// Where a node's API listens.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ApiAddr {
    Udp(SocketAddr),
    /// A unix datagram socket (not on Windows).
    Unix(PathBuf),
}

impl ApiAddr {
    /// The address the `dvpn` CLI would use: `DVPN_API`, else the unix socket of TUN `tun`
    /// (`dnet` by default) in `/run/dvpn` (a node of root or a service) or in
    /// `$XDG_RUNTIME_DIR/dvpn` (the user's own node), if there is one, else UDP `127.0.0.1:9902`.
    pub fn detect(tun: Option<&str>) -> ApiAddr {
        if let Some(a) = std::env::var(ENV).ok().and_then(|s| s.parse().ok()) {
            return a;
        }
        if cfg!(unix) {
            let mut dirs = vec![PathBuf::from(SOCKET_DIR)];
            dirs.extend(std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("dvpn")));
            for dir in dirs {
                let p = dir.join(format!("{}.sock", tun.unwrap_or(DEFAULT_TUN)));
                if p.exists() {
                    return ApiAddr::Unix(p);
                }
            }
        }
        ApiAddr::Udp(DEFAULT_UDP.parse().expect("valid address"))
    }

    /// The token of a UDP API (changes need it, `doc/api.md`): `DVPN_API_TOKEN`, else the file the
    /// node wrote for its port, if this user may read it. None for a unix socket (its file's
    /// permissions decide).
    pub fn find_token(&self) -> Option<String> {
        let ApiAddr::Udp(a) = self else { return None };
        if let Ok(t) = std::env::var(TOKEN_ENV) {
            return Some(t.trim().to_owned());
        }
        token_dirs().into_iter().find_map(|d| {
            let t = std::fs::read_to_string(d.join(format!("api-{}.token", a.port()))).ok()?;
            Some(t.trim().to_owned()).filter(|t| !t.is_empty())
        })
    }
}

/// Where a node writes the token of its UDP API (the same list as the node's).
fn token_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(unix) {
        v.push(PathBuf::from(SOCKET_DIR));
        v.extend(std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("dvpn")));
    } else {
        for var in ["ProgramData", "LOCALAPPDATA"] {
            v.extend(std::env::var_os(var).map(|d| PathBuf::from(d).join("dvpn")));
        }
    }
    v
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
