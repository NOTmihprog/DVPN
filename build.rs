//! Records the build time: a wall clock earlier than that is certainly wrong (a router without
//! RTC before NTP), see `src/clock.rs`. `SOURCE_DATE_EPOCH` is honoured for reproducible builds.
fn main() {
    let t = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    });
    println!("cargo:rustc-env=DVPN_BUILD_UNIX={t}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
