//! Anti-replay window over message counters (RFC 6479, as in WireGuard).
//!
//! A ring of `WORDS` 64-bit words; the window covers the last `WINDOW` counters below the
//! highest one seen. Older counters, and counters already seen, are rejected. Large enough for
//! UDP reordering at high packet rates, unlike a single 64-bit bitmap.

const BITS: u64 = 64;
const WORDS: usize = 32;
/// One word is kept as slack for the ring, so the guaranteed window is a word less.
pub const WINDOW: u64 = (WORDS as u64 - 1) * BITS;

#[derive(Clone)]
pub struct ReplayWindow {
    last: u64,
    bitmap: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow { last: 0, bitmap: [0; WORDS] }
    }
}

impl ReplayWindow {
    fn word(n: u64) -> usize {
        ((n / BITS) % WORDS as u64) as usize
    }

    /// Whether `n` may be accepted. Call before decrypting; call `accept` only after the packet
    /// authenticated, so forged packets cannot move the window.
    pub fn check(&self, n: u64) -> bool {
        if n > self.last {
            return true;
        }
        if self.last - n >= WINDOW {
            return false;
        }
        self.bitmap[Self::word(n)] & (1 << (n % BITS)) == 0
    }

    pub fn accept(&mut self, n: u64) {
        if n > self.last {
            let (cur, new) = (self.last / BITS, n / BITS);
            for i in 1..=(new - cur).min(WORDS as u64) {
                self.bitmap[Self::word((cur + i) * BITS)] = 0;
            }
            self.last = n;
        }
        self.bitmap[Self::word(n)] |= 1 << (n % BITS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn basics() {
        let mut w = ReplayWindow::default();
        assert!(w.check(0));
        w.accept(0);
        assert!(!w.check(0), "replay");
        for n in [1, 5, 3, 2, 4] {
            assert!(w.check(n));
            w.accept(n);
            assert!(!w.check(n));
        }
        w.accept(10_000);
        assert!(!w.check(10_000 - WINDOW), "older than the window");
        assert!(w.check(10_000 - WINDOW + 1));
        assert!(w.check(9_999));
        assert!(w.check(u64::MAX));
    }

    #[test]
    fn jump_clears_stale_bits() {
        let mut w = ReplayWindow::default();
        for n in 0..200 {
            w.accept(n);
        }
        // Jump exactly one ring length ahead: words reused by the ring must not keep old bits.
        let n = 200 + WORDS as u64 * BITS;
        w.accept(n);
        for k in (n - WINDOW + 1)..n {
            assert!(w.check(k), "{k} wrongly marked as seen");
        }
    }

    proptest! {
        /// Model: accept iff unseen and within WINDOW of the highest accepted counter.
        #[test]
        fn matches_model(ops in proptest::collection::vec(0u64..5000, 1..400)) {
            let mut w = ReplayWindow::default();
            let (mut seen, mut last) = (HashSet::new(), 0u64);
            for n in ops {
                let model = !seen.contains(&n) && (n > last || last - n < WINDOW);
                prop_assert_eq!(w.check(n), model, "counter {}", n);
                if model {
                    w.accept(n);
                    seen.insert(n);
                    last = last.max(n);
                }
            }
        }
    }
}
