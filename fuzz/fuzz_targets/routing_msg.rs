#![no_main]
//! Mesh routing messages from neighbours: never panic, and no LSA the fuzzer builds gets into
//! the database (LSAs are signed by their origin's key) unless it carries a valid signature.

use std::collections::HashSet;

use dvpn::identity::Identity;
use dvpn::router::{Lsdb, RouteTable, RoutingMsg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(msg) = RoutingMsg::decode(data) else { return };
    let group = Identity::from_seed(&[9; 32]).id();
    let mut db = Lsdb::new(group);
    if let RoutingMsg::Lsas(lsas) = msg {
        for l in lsas {
            let ok = l.open().is_some();
            assert!(!db.insert(l, &HashSet::new()) || ok, "unsigned LSA accepted");
        }
    }
    let me = Identity::from_seed(&[1; 32]).id();
    let _ = RouteTable::compute(me, &db, &|_| true, &RouteTable::default());
});
