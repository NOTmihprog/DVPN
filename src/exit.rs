//! Choosing the gateway to the internet (PLAN §8, `exit_v4` / `exit_v6`): the node's `[exit]`
//! lists gateways by priority; the first one that is alive (a direct link or a mesh route) gets
//! the internet routes. When it dies the next one takes over at once; a gateway of higher
//! priority that comes back is taken again only after it stayed alive for `PREEMPT_HOLD`, so a
//! flapping gateway does not move the traffic back and forth (like `choose_gateway` in yggmgr).
//! A gateway alive for the first time (just slower to connect at start) is taken at once.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::identity::NodeId;

pub const PREEMPT_HOLD: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct ExitChooser {
    pub current: Option<NodeId>,
    alive_since: HashMap<NodeId, Instant>,
    /// Gateways that were alive at some point: only those need the hold when they come back.
    seen: HashSet<NodeId>,
}

impl ExitChooser {
    /// The gateway to use now, from `priority` (best first). `alive` says which are reachable.
    pub fn choose(&mut self, priority: &[NodeId], alive: impl Fn(&NodeId) -> bool, now: Instant) -> Option<NodeId> {
        self.alive_since.retain(|g, _| priority.contains(g) && alive(g));
        for g in priority {
            if alive(g) {
                self.alive_since.entry(*g).or_insert(now);
            }
        }
        let best = priority.iter().find(|g| self.alive_since.contains_key(g)).copied();
        let pos = |g: &NodeId| priority.iter().position(|x| x == g);
        self.current = match (self.current, best) {
            (Some(cur), Some(b)) if self.alive_since.contains_key(&cur) && pos(&b) < pos(&cur) => {
                // a better gateway: at once if it just showed up for the first time, else only
                // once it has been stable for a while (it was lost before)
                let stable = !self.seen.contains(&b) || now.duration_since(self.alive_since[&b]) >= PREEMPT_HOLD;
                Some(if stable { b } else { cur })
            }
            (Some(cur), _) if self.alive_since.contains_key(&cur) => Some(cur),
            (_, b) => b,
        };
        self.seen.extend(self.alive_since.keys().copied());
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ids() -> [NodeId; 3] {
        [1u8, 2, 3].map(|i| crate::identity::Identity::from_seed(&[i; 32]).id())
    }

    #[test]
    fn priority_failover_and_hold() {
        let [a, b, c] = ids();
        let prio = [a, b, c];
        let mut ch = ExitChooser::default();
        let t0 = Instant::now();
        let up = |s: &[NodeId]| -> HashSet<NodeId> { s.iter().copied().collect() };

        // at start b connects first, then a: a (better, never seen before) is taken at once
        let alive = up(&[b]);
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0), Some(b));
        let alive = up(&[a, b]);
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0), Some(a), "first alive by priority");
        let alive = up(&[b, c]);
        assert_eq!(
            ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(1)),
            Some(b),
            "a died: next at once"
        );
        // a comes back: stay on b until a is stable
        let alive = up(&[a, b, c]);
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(2)), Some(b));
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(20)), Some(b));
        assert_eq!(
            ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(33)),
            Some(a),
            "a stable: back to it"
        );
        // a flaps: the hold starts over
        let alive = up(&[b]);
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(34)), Some(b));
        let alive = up(&[a, b]);
        assert_eq!(ch.choose(&prio, |g| alive.contains(g), t0 + Duration::from_secs(35)), Some(b));
        // nothing alive: no exit
        assert_eq!(ch.choose(&prio, |_| false, t0 + Duration::from_secs(36)), None);
        // empty list: no exit
        assert_eq!(ExitChooser::default().choose(&[], |_| true, t0), None);
    }
}
