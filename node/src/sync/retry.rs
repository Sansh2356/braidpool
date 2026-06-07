use std::time::Duration;

/// Backoff policy governing how IBD re-attempts after a sync request fails, times
/// out, or the sync peer disconnects.
///
/// Single-peer IBD switches sync targets on failure; this policy only decides
/// *how long to wait* before the next attempt and *when to stop counting it as a
/// transient failure*. Peer selection itself is the adapter's (PeerManager's) job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Delay for the first retry; subsequent retries grow exponentially from here.
    base: Duration,
    /// Upper bound on the computed delay.
    max: Duration,
    /// Number of consecutive failed attempts after which the current sync target
    /// is considered exhausted (the adapter should rotate to another peer).
    max_retries: u64,
}

impl RetryPolicy {
    /// Create a policy with an explicit base delay, cap, and retry ceiling.
    pub fn new(base: Duration, max: Duration, max_retries: u64) -> Self {
        Self {
            base,
            max,
            max_retries,
        }
    }

    /// The configured retry ceiling.
    pub fn max_retries(&self) -> u64 {
        self.max_retries
    }

    /// Whether `attempts` consecutive failures have reached the ceiling.
    pub fn is_exhausted(&self, attempts: u64) -> bool {
        attempts >= self.max_retries
    }

    /// Exponential backoff: `base * 2^attempts`, saturating and capped at `max`.
    ///
    /// `attempts == 0` yields `base` (the delay before the first retry).
    pub fn delay(&self, attempts: u64) -> Duration {
        let factor = 1u64.checked_shl(attempts as u32).unwrap_or(u64::MAX);
        let secs = self.base.as_secs().saturating_mul(factor);
        let candidate = Duration::from_secs(secs);
        if candidate > self.max {
            self.max
        } else {
            candidate
        }
    }
}

impl Default for RetryPolicy {
    /// Mirrors the historical IBD constants: a 20s base delay, capped at 5
    /// minutes, with up to 10 attempts against a single sync target.
    fn default() -> Self {
        Self {
            base: Duration::from_secs(20),
            max: Duration::from_secs(300),
            max_retries: 10,
        }
    }
}
