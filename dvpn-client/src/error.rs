use std::fmt;

/// What went wrong with a request.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The node did not answer in time (not running, or the address is wrong).
    Timeout,
    /// The client is gone (its receive task stopped).
    Closed,
    /// The node does not serve this API version (`min..=max` it does).
    VersionUnsupported {
        min: u64,
        max: u64,
        msg: String,
    },
    /// The node refused the request: `err` and `msg` of its answer.
    Api {
        code: ErrorCode,
        msg: String,
    },
    /// An answer of the wrong shape.
    Protocol(String),
}

impl Error {
    /// The node's error code, if the node refused the request.
    pub fn code(&self) -> Option<&ErrorCode> {
        match self {
            Error::Api { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Timeout => write!(f, "no answer from the node's API: is the node running?"),
            Error::Closed => write!(f, "the API client is closed"),
            Error::VersionUnsupported { msg, .. } => write!(f, "{msg}"),
            Error::Api { code, msg } => write!(f, "{msg} ({code})"),
            Error::Protocol(m) => write!(f, "unexpected answer from the node: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

macro_rules! codes {
    ($($variant:ident = $text:literal,)*) => {
        /// The node's error codes (`err`, `doc/api.md`). Codes this version does not know come
        /// as `Other`.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum ErrorCode {
            $($variant,)*
            Other(String),
        }

        impl ErrorCode {
            pub fn as_str(&self) -> &str {
                match self {
                    $(ErrorCode::$variant => $text,)*
                    ErrorCode::Other(s) => s,
                }
            }
        }

        impl From<&str> for ErrorCode {
            fn from(s: &str) -> Self {
                match s {
                    $($text => ErrorCode::$variant,)*
                    other => ErrorCode::Other(other.to_owned()),
                }
            }
        }
    };
}

codes! {
    VersionUnsupported = "version_unsupported",
    UnknownType = "unknown_type",
    UnknownRequest = "unknown_request",
    BadParam = "bad_param",
    KeyValidate = "key_validate_error",
    KeyAmbiguous = "key_ambiguous",
    ServerNotFound = "server_not_found",
    NameNotStr = "name_not_str",
    AddrValidate = "addr_validate_error",
    EndpointValidate = "endpoint_validate_error",
    SubArgsNotDict = "sub_args_not_dict",
    ForceNotBool = "force_not_bool",
    PeerNotExist = "peer_not_exist",
    DeleteSelf = "error_delete_self_peer",
    NotInt = "not_int",
    OutOfRange = "out_of_range",
    RouteExist = "route_exist",
    RouteNotExist = "route_not_exist",
    NotPermission = "not_permission",
    GatewayUnknown = "gateway_unknown",
    GatewaySelf = "gateway_self",
    DnsInvalid = "dns_invalid",
    SourcesInvalid = "sources_invalid",
    TableInvalid = "table_invalid",
    ConfigWrite = "config_write",
    ConfigRead = "config_read",
    NotAdmin = "not_admin",
    ClockUntrusted = "clock_untrusted",
    MemberUnknown = "member_unknown",
    MemberAmbiguous = "member_ambiguous",
    MemberNotSeen = "member_not_seen",
    AddrTaken = "addr_taken",
    AddrInvalid = "addr_invalid",
    EndpointInvalid = "endpoint_invalid",
    RouteInvalid = "route_invalid",
    NoAddress = "no_address",
    RevokeSelf = "revoke_self",
    AclParse = "acl_parse",
    NotPermitted = "not_permitted",
    TooLarge = "too_large",
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for s in ["key_validate_error", "gateway_self", "route_exist", "config_write"] {
            let c = ErrorCode::from(s);
            assert!(!matches!(c, ErrorCode::Other(_)), "{s}");
            assert_eq!(c.as_str(), s);
        }
        assert_eq!(ErrorCode::from("brand_new"), ErrorCode::Other("brand_new".into()));
        assert_eq!(ErrorCode::from("brand_new").to_string(), "brand_new");
        let e = Error::Api { code: ErrorCode::KeyValidate, msg: "bob: no such node key or name".into() };
        assert_eq!(e.to_string(), "bob: no such node key or name (key_validate_error)");
        assert_eq!(e.code(), Some(&ErrorCode::KeyValidate));
    }
}
