#![no_main]
//! DNS and mDNS queries come from any member, or from a local process: arbitrary bytes never
//! panic (with `panic = "abort"` that would be the whole node), with names in the zone or not.

use std::sync::OnceLock;

use dvpn::dns::{Zone, answer, in_zone, mdns_answer};
use libfuzzer_sys::fuzz_target;

fn zone() -> &'static Zone {
    static Z: OnceLock<Zone> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = Zone::new();
        z.insert("a.dvpn".into(), vec!["10.10.33.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        z.insert("dvpn".into(), vec!["10.10.33.2".parse().unwrap()]);
        z
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = answer(data, zone(), "dvpn");
    let _ = mdns_answer(data, zone(), "dvpn");
    let _ = in_zone(data, "dvpn");
});
