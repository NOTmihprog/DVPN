#![no_main]
//! CKR entry syntax from the config (`[ckr.remote_subnets]`, `--route`): any text either parses
//! or is an error, never a panic; what parses is a valid, truncated prefix, and the table built
//! from it answers lookups inside it.

use std::sync::OnceLock;

use dvpn::ckr::{CkrTable, Target, parse_spec};
use dvpn::identity::{Identity, NodeId};
use libfuzzer_sys::fuzz_target;

fn node() -> NodeId {
    static N: OnceLock<NodeId> = OnceLock::new();
    *N.get_or_init(|| Identity::from_seed(&[1; 32]).id())
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(routes) = parse_spec(text, node()) else { return };
    let table = CkrTable::new(routes.clone());
    for r in &routes {
        assert_eq!(r.net, r.net.trunc());
        let hit = table.target(r.net.network());
        assert!(hit.is_some(), "{text}: no entry for {}", r.net);
        if let Some(Target::Node(n)) = hit {
            assert_eq!(n, node());
        }
    }
});
