#![no_main]
//! Everything a peer datagram goes through on receive: unmasking (obfs), then HS_INIT / HS_RESP /
//! DATA handling. Arbitrary bytes from the network must never panic; with fixed keys, anything
//! accepted would be a forgery, so nothing may be accepted either.

use std::sync::{Arc, OnceLock};

use dvpn::identity::{Identity, NodeId};
use dvpn::link::{Group, Links};
use libfuzzer_sys::fuzz_target;

/// Built once: nothing is ever accepted, so no state carries over between inputs.
fn links() -> &'static (Links, NodeId) {
    static L: OnceLock<(Links, NodeId)> = OnceLock::new();
    L.get_or_init(|| {
        let me = Arc::new(Identity::from_seed(&[1; 32]));
        (Links::new(me, Group::from_psk([3; 32])), Identity::from_seed(&[2; 32]).id())
    })
}

fuzz_target!(|data: &[u8]| {
    let (links, peer) = links();
    let mut packet = data.to_vec();
    assert!(links.receive(&mut packet, || vec![*peer]).is_none(), "fuzzer forged a packet");
});
