//! Scope-aware rate limiting.
//!
//! The management API distinguishes cheap reads from expensive, stake-affecting
//! writes, so the proxy budgets them separately (`read_per_minute` /
//! `write_per_minute`). Because a request's scope is only known *after* its
//! GraphQL body is classified, limiting happens inside the pipeline rather than
//! as a pre-handler `tower` layer.
//!
//! Each limiter is keyed by principal name, so one noisy caller cannot exhaust
//! another's budget. A configured value of `0` disables limiting for that scope.

use std::num::NonZeroU32;
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::classify::Scope;

pub struct RateLimiters {
    read: Option<DefaultKeyedRateLimiter<String>>,
    write: Option<DefaultKeyedRateLimiter<String>>,
}

impl RateLimiters {
    /// Build read/write limiters from per-minute budgets. `0` means unlimited.
    pub fn new(read_per_minute: u32, write_per_minute: u32) -> Self {
        RateLimiters {
            read: build(read_per_minute),
            write: build(write_per_minute),
        }
    }

    /// Returns `true` if a request of `scope` from `key` is allowed (and consumes
    /// one cell), `false` if it should be rejected with `429`.
    pub fn check(&self, scope: Scope, key: &str) -> bool {
        let limiter = match scope {
            Scope::Read => &self.read,
            Scope::Write => &self.write,
        };
        match limiter {
            Some(l) => l.check_key(&key.to_string()).is_ok(),
            None => true,
        }
    }
}

/// A per-minute budget as a governor quota: burst capacity `n`, fully replenished
/// once per minute. `0` yields `None` (unlimited).
//
// `Quota::new(max_burst, replenish_all_per)` is the correct constructor for
// governor 0.6; its deprecation notice points at `allow_burst`/`per_*` helpers
// that only exist in 0.7+, so we silence the false positive here.
#[allow(deprecated)]
fn build(per_minute: u32) -> Option<DefaultKeyedRateLimiter<String>> {
    let n = NonZeroU32::new(per_minute)?;
    let quota = Quota::new(n, Duration::from_secs(60))?;
    Some(RateLimiter::keyed(quota))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_burst_then_blocks() {
        let limiters = RateLimiters::new(0, 2); // write budget 2/min
        assert!(limiters.check(Scope::Write, "op"));
        assert!(limiters.check(Scope::Write, "op"));
        assert!(!limiters.check(Scope::Write, "op"), "third write blocked");
    }

    #[test]
    fn budgets_are_per_principal() {
        let limiters = RateLimiters::new(0, 1);
        assert!(limiters.check(Scope::Write, "alice"));
        assert!(!limiters.check(Scope::Write, "alice"));
        // bob has his own untouched budget
        assert!(limiters.check(Scope::Write, "bob"));
    }

    #[test]
    fn read_and_write_budgets_are_independent() {
        let limiters = RateLimiters::new(5, 1);
        assert!(limiters.check(Scope::Write, "p"));
        assert!(!limiters.check(Scope::Write, "p"), "write exhausted");
        // reads remain available
        assert!(limiters.check(Scope::Read, "p"));
        assert!(limiters.check(Scope::Read, "p"));
    }

    #[test]
    fn zero_means_unlimited() {
        let limiters = RateLimiters::new(0, 0);
        for _ in 0..1000 {
            assert!(limiters.check(Scope::Write, "p"));
            assert!(limiters.check(Scope::Read, "p"));
        }
    }
}
