#![no_main]
//! IP header parsing on the TUN path: never panics, and whatever it accepts lies within the buffer.

use dvpn::packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(info) = packet::parse(data) {
        assert!(info.len <= data.len());
        assert_eq!(info.src.is_ipv4(), info.dst.is_ipv4());
        assert_eq!(Some(if info.src.is_ipv4() { 4 } else { 6 }), packet::version(data));
    }
});
