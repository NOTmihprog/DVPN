#![no_main]
//! Tracker message decoding (plaintext after the session layer): never panics, and every
//! message it accepts survives an encode/decode round trip.

use dvpn::proto::TrackerMsg;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(msg) = TrackerMsg::decode(data) {
        let again = TrackerMsg::decode(&msg.encode()).expect("re-encoded message must decode");
        assert_eq!(format!("{msg:?}"), format!("{again:?}"));
    }
});
