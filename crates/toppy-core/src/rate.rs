use std::time::Duration;

/// Simple token-bucket rate limiter.
///
/// - `capacity` and `refill_per_sec` are expressed in whole tokens.
/// - Internally keeps fixed-point precision (1 token = 1e9 units) to avoid floats.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity_fp: u128,
    tokens_fp: u128,
    refill_per_sec: u64,
    last_refill: Duration,
}

impl TokenBucket {
    const FP_SCALE: u128 = 1_000_000_000;

    /// Creates a new bucket starting full.
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        let capacity_fp = (capacity as u128) * Self::FP_SCALE;
        Self {
            capacity_fp,
            tokens_fp: capacity_fp,
            refill_per_sec,
            last_refill: Duration::ZERO,
        }
    }

    /// Refills tokens based on `now`.
    ///
    /// `now` should be monotonic (e.g. time since process start).
    pub fn refill(&mut self, now: Duration) {
        if now <= self.last_refill {
            return;
        }

        if self.refill_per_sec == 0 {
            self.last_refill = now;
            return;
        }

        let elapsed = now - self.last_refill;
        let elapsed_nanos = elapsed.as_nanos();

        // With FP_SCALE = 1e9, the refill per nanosecond in fp-units is refill_per_sec.
        // increment_fp = elapsed_nanos * refill_per_sec
        let increment_fp = elapsed_nanos.saturating_mul(self.refill_per_sec as u128);
        self.tokens_fp = (self.tokens_fp + increment_fp).min(self.capacity_fp);
        self.last_refill = now;
    }

    /// Returns the number of whole tokens currently available (floored).
    pub fn available(&self) -> u64 {
        (self.tokens_fp / Self::FP_SCALE) as u64
    }

    /// Attempts to take `amount` tokens at time `now`.
    /// Returns `true` if allowed.
    pub fn try_take(&mut self, amount: u64, now: Duration) -> bool {
        self.refill(now);
        let needed_fp = (amount as u128) * Self::FP_SCALE;
        if self.tokens_fp >= needed_fp {
            self.tokens_fp -= needed_fp;
            true
        } else {
            false
        }
    }

    /// Forces the bucket to be empty.
    pub fn clear(&mut self) {
        self.tokens_fp = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_starts_full() {
        let bucket = TokenBucket::new(10, 1);
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn bucket_consumes_and_refills() {
        let mut bucket = TokenBucket::new(10, 2);

        assert!(bucket.try_take(7, Duration::from_secs(0)));
        assert_eq!(bucket.available(), 3);

        // After 2 seconds at 2 tokens/sec => +4 tokens.
        assert!(bucket.try_take(0, Duration::from_secs(2)));
        assert_eq!(bucket.available(), 7);

        // Can't exceed capacity.
        bucket.refill(Duration::from_secs(100));
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn bucket_denies_when_empty() {
        let mut bucket = TokenBucket::new(1, 0);
        assert!(bucket.try_take(1, Duration::from_secs(0)));
        assert!(!bucket.try_take(1, Duration::from_secs(0)));
        assert!(!bucket.try_take(1, Duration::from_secs(100)));
    }

    #[test]
    fn bucket_handles_subsecond_refill() {
        let mut bucket = TokenBucket::new(10, 1);
        bucket.clear();
        assert_eq!(bucket.available(), 0);

        // 500ms at 1 token/sec => 0.5 tokens, should still be 0 whole tokens.
        bucket.refill(Duration::from_millis(500));
        assert_eq!(bucket.available(), 0);

        // Another 500ms => total 1 token.
        bucket.refill(Duration::from_millis(1000));
        assert_eq!(bucket.available(), 1);
    }
}
