#![no_main]
//! Everything a tracker does with a datagram: unmasking, handshakes, session packets. Arbitrary
//! bytes never panic and never get an answer (an answer would let a prober find trackers).

use std::sync::{Mutex, OnceLock};

use dvpn::identity::Identity;
use dvpn::tracker_server::Server;
use libfuzzer_sys::fuzz_target;

fn server() -> &'static Mutex<Server> {
    static S: OnceLock<Mutex<Server>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Server::new(Identity::from_seed(&[5; 32]))))
}

fuzz_target!(|data: &[u8]| {
    let out = server().lock().unwrap().handle(data, "198.51.100.1:4000".parse().unwrap());
    assert!(out.is_empty(), "the tracker answered a forged datagram");
});
