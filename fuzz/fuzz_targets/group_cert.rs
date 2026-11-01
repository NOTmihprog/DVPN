#![no_main]
//! Membership certificates and invites from untrusted input (handshake payloads, the tracker,
//! pasted invites): decoding never panics, and nothing the fuzzer builds verifies for a group
//! whose key it does not have.

use std::sync::OnceLock;

use dvpn::group::{Cert, GroupId, GroupSecret, Invite};
use libfuzzer_sys::fuzz_target;

fn group() -> &'static GroupId {
    static G: OnceLock<GroupId> = OnceLock::new();
    G.get_or_init(|| GroupSecret::from_bytes([3; 32]).id())
}

fuzz_target!(|data: &[u8]| {
    if let Some(cert) = Cert::decode(data) {
        assert!(cert.verify(group(), None).is_err(), "fuzzer forged a certificate");
        assert_eq!(Cert::decode(&cert.encode()), Some(cert));
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(inv) = Invite::decode(text, None)
    {
        assert_ne!(&inv.group(), group(), "fuzzer forged an invite");
    }
});
