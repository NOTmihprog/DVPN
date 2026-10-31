#![no_main]
//! Signature packet templates from `[group.obfs] i1..i5` (config input): parsing never panics,
//! and an accepted template only ever produces packets that fit a datagram.

use dvpn::obfs::{MAX_WIRE, Template};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(t) = s.parse::<Template>() {
        let p = t.generate();
        assert!(!p.is_empty() && p.len() <= MAX_WIRE);
    }
});
