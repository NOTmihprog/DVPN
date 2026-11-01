//! Wall clock (PLAN §14a «часы без RTC»). Certificate expiry, record timestamps and handshake
//! timestamps depend on it, but a router without RTC shows 1970 until NTP sets it. A clock
//! earlier than the build time is certainly wrong; until it is right the node does not judge
//! expiry or "records from the future", and does not sign records (an admin with a wrong clock
//! would lose every last-writer-wins race or win them all). Once NTP sets the clock everything
//! goes on by itself: trackers answer again (handshake timestamps are fresh), records sync.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

/// Unix seconds when this binary was built.
pub fn build_time() -> u64 {
    static T: OnceLock<u64> = OnceLock::new();
    *T.get_or_init(|| env!("DVPN_BUILD_UNIX").parse().unwrap_or(0))
}

/// For tests only: a file holding a clock offset in seconds (e.g. -1700000000 for "1970"),
/// read at most once a second. Without the variable the system clock is used as is.
pub const TEST_SKEW_ENV: &str = "DVPN_TEST_CLOCK_SKEW_FILE";

fn test_skew() -> i64 {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    static CACHE: Mutex<Option<(Instant, i64)>> = Mutex::new(None);
    let Some(path) = PATH.get_or_init(|| std::env::var_os(TEST_SKEW_ENV).map(PathBuf::from)) else { return 0 };
    let mut c = CACHE.lock();
    if let Some((at, v)) = *c
        && at.elapsed() < Duration::from_secs(1)
    {
        return v;
    }
    let v = std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    *c = Some((Instant::now(), v));
    v
}

/// Time since the unix epoch by the wall clock.
pub fn now() -> Duration {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    match test_skew() {
        0 => d,
        s if s > 0 => d + Duration::from_secs(s as u64),
        s => d.saturating_sub(Duration::from_secs(s.unsigned_abs())),
    }
}

pub fn now_unix() -> u64 {
    now().as_secs()
}

pub fn now_ms() -> u64 {
    now().as_millis() as u64
}

/// Whether the clock can be right (not earlier than the build).
pub fn trusted() -> bool {
    now_unix() >= build_time()
}

/// The time to check expiry against, `None` while the clock is certainly wrong.
pub fn trusted_unix() -> Option<u64> {
    let n = now_unix();
    (n >= build_time()).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_time_is_sane() {
        let b = build_time();
        assert!(b > 1_700_000_000, "build time {b}");
        assert!(b <= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60);
        assert!(trusted(), "the test machine has a set clock");
    }
}
