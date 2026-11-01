#![no_main]
//! Everything a peer datagram goes through on receive: unmasking (obfs), then HS_INIT / HS_RESP /
//! DATA handling. Arbitrary bytes from the network must never panic; with fixed keys, anything
//! accepted would be a forgery, so nothing may be accepted either.

use std::sync::{Arc, OnceLock};

use dvpn::group::{CertBody, GroupSecret};
use dvpn::identity::Identity;
use dvpn::link::{Group, Links};
use libfuzzer_sys::fuzz_target;

/// Built once: nothing is ever accepted, so no state carries over between inputs.
fn links() -> &'static Links {
    static L: OnceLock<Links> = OnceLock::new();
    L.get_or_init(|| {
        let me = Arc::new(Identity::from_seed(&[1; 32]));
        let secret = GroupSecret::from_bytes([3; 32]);
        let cert = secret.issue(CertBody::new(me.id(), "fuzz", vec![]));
        let group = Group { id: secret.id(), psk: secret.psk(0), obfs: Default::default(), cert };
        Links::new(me, group)
    })
}

fuzz_target!(|data: &[u8]| {
    let mut packet = data.to_vec();
    assert!(links().receive(&mut packet).is_none(), "fuzzer forged a packet");
});
