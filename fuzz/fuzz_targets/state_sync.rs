#![no_main]
//! Group records from neighbours and trackers: sync messages and records never panic, and
//! nothing the fuzzer builds is accepted into a group whose key it does not have.

use dvpn::group::GroupSecret;
use dvpn::state::{StateStore, SyncMsg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let group = GroupSecret::from_bytes([3; 32]).id();
    let store = StateStore::memory();
    if let Some(msg) = SyncMsg::decode(data) {
        let (_, changed) = msg.handle(&store, |g| *g == group);
        assert!(changed.is_empty(), "fuzzer forged a record");
    }
});
