//! Token-bucket rate limiting.
//!
//! The bucket has a capacity of `requests_per_minute` tokens and refills
//! continuously over a minute. The async wrapper waits for a token when the
//! wait is bounded by `max_wait_ms`; otherwise it returns
//! [`DecisionError::RateLimited`] without touching the network.

use std::time::Instant;

use tokio::sync::Mutex;

use crate::error::DecisionError;

/// Deterministic, time-injectable token bucket (unit-tested without waiting).
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_refill_ms: i64,
}

impl TokenBucket {
    /// Create a bucket that allows `requests_per_minute` acquisitions per
    /// minute. A capacity of `0` disables limiting (always succeeds).
    pub(crate) fn per_minute(requests_per_minute: u32) -> Self {
        let capacity = requests_per_minute as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: if capacity > 0.0 {
                capacity / 60_000.0
            } else {
                0.0
            },
            last_refill_ms: 0,
        }
    }

    /// True when this bucket never blocks.
    pub(crate) fn is_unlimited(&self) -> bool {
        self.capacity <= 0.0
    }

    fn refill(&mut self, now_ms: i64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let elapsed = (now_ms - self.last_refill_ms) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.last_refill_ms = now_ms;
    }

    /// Try to take one token. On failure returns the earliest retry delay.
    pub(crate) fn try_acquire(&mut self, now_ms: i64) -> Result<(), u64> {
        if self.is_unlimited() {
            return Ok(());
        }
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(self.retry_after_ms(now_ms))
        }
    }

    /// Milliseconds until at least one token is available.
    pub(crate) fn retry_after_ms(&self, now_ms: i64) -> u64 {
        if self.is_unlimited() || self.refill_per_ms <= 0.0 {
            return 0;
        }
        let mut tokens = self.tokens;
        let last = self.last_refill_ms;
        if now_ms > last {
            tokens = (tokens + (now_ms - last) as f64 * self.refill_per_ms).min(self.capacity);
        }
        if tokens >= 1.0 {
            return 0;
        }
        (((1.0 - tokens) / self.refill_per_ms).ceil() as u64).max(1)
    }

    /// Tokens currently available (after refill); used by unit tests.
    #[cfg(test)]
    pub(crate) fn available_tokens(&mut self, now_ms: i64) -> f64 {
        if self.is_unlimited() {
            return f64::INFINITY;
        }
        self.refill(now_ms);
        self.tokens
    }
}

/// Async wrapper used by providers.
pub(crate) struct AsyncRateLimiter {
    bucket: Mutex<TokenBucket>,
    start: Instant,
    max_wait_ms: u64,
}

impl AsyncRateLimiter {
    pub(crate) fn new(requests_per_minute: u32, max_wait_ms: u64) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::per_minute(requests_per_minute)),
            start: Instant::now(),
            max_wait_ms,
        }
    }

    fn now_ms(&self) -> i64 {
        self.start.elapsed().as_millis().min(i64::MAX as u128) as i64
    }

    /// Acquire one token, waiting at most `max_wait_ms` for a refill.
    pub(crate) async fn acquire(&self) -> Result<(), DecisionError> {
        loop {
            let retry_after_ms = {
                let mut bucket = self.bucket.lock().await;
                bucket.try_acquire(self.now_ms())
            };
            match retry_after_ms {
                Ok(()) => return Ok(()),
                Err(retry_after_ms) => {
                    if self.max_wait_ms == 0 || retry_after_ms > self.max_wait_ms {
                        return Err(DecisionError::RateLimited { retry_after_ms });
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(retry_after_ms)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_capacity_then_limits() {
        let mut bucket = TokenBucket::per_minute(3);
        assert!(bucket.try_acquire(0).is_ok());
        assert!(bucket.try_acquire(0).is_ok());
        assert!(bucket.try_acquire(0).is_ok());
        let retry = bucket.try_acquire(0).unwrap_err();
        // 1 token per 20_000 ms with capacity 3.
        assert_eq!(retry, 20_000);
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut bucket = TokenBucket::per_minute(2); // 1 token per 30 s
        assert_eq!(bucket.available_tokens(0), 2.0);
        assert!(bucket.try_acquire(0).is_ok());
        assert!(bucket.try_acquire(0).is_ok());
        assert_eq!(bucket.available_tokens(0), 0.0);
        assert!(bucket.try_acquire(0).is_err());
        assert!((bucket.available_tokens(15_000) - 0.5).abs() < 1e-9);
        assert!(bucket.try_acquire(15_000).is_err());
        assert!(bucket.try_acquire(30_000).is_ok());
        assert!(bucket.try_acquire(30_000).is_err());
        assert!(bucket.try_acquire(60_000).is_ok());
    }

    #[test]
    fn zero_capacity_is_unlimited() {
        let mut bucket = TokenBucket::per_minute(0);
        for _ in 0..100 {
            assert!(bucket.try_acquire(0).is_ok());
        }
        assert!(bucket.is_unlimited());
    }

    #[test]
    fn retry_after_never_zero_when_blocked() {
        let mut bucket = TokenBucket::per_minute(1);
        assert!(bucket.try_acquire(0).is_ok());
        let retry = bucket.try_acquire(0).unwrap_err();
        assert_eq!(retry, 60_000);
        let retry = bucket.try_acquire(59_999).unwrap_err();
        assert_eq!(retry, 1);
    }

    #[tokio::test]
    async fn async_limiter_returns_error_when_wait_exceeds_budget() {
        let limiter = AsyncRateLimiter::new(1, 0);
        assert!(limiter.acquire().await.is_ok());
        let err = limiter.acquire().await.unwrap_err();
        assert!(matches!(err, DecisionError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn async_limiter_waits_when_budget_allows() {
        let limiter = AsyncRateLimiter::new(60, 5_000); // refill after 1s
        assert!(limiter.acquire().await.is_ok());
        assert!(limiter.acquire().await.is_ok());
    }
}
