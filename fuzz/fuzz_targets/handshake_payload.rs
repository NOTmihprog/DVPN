#![no_main]
//! Handshake payload decoding (version, flags, TAI64N, group id, certificate): never panics, and
//! every accepted payload survives an encode/decode round trip.

use dvpn::noise::HandshakePayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = HandshakePayload::decode(data) {
        let encoded = p.encode();
        assert!(data.starts_with(&encoded), "encoding differs from the accepted prefix");
        assert_eq!(HandshakePayload::decode(&encoded), Ok(p));
    }
});
