//! Daily cost accumulation with a hard limit.
//!
//! The provider checks the tracker *before* every network call; once the
//! accumulated cost for the current UTC day reaches `daily_cost_limit_usd` the
//! call is rejected with [`DecisionError::CostLimitExceeded`] and no request is
//! made. A limit of `0` disables the check.

use crate::error::DecisionError;

/// Milliseconds per UTC day.
const DAY_MS: i64 = 86_400_000;

/// Daily cost accumulator (time-injectable for tests).
#[derive(Debug, Clone)]
pub(crate) struct CostTracker {
    limit_usd: f64,
    day_index: i64,
    spent_usd: f64,
}

impl CostTracker {
    /// Create a tracker with the given daily limit in USD.
    pub(crate) fn new(limit_usd: f64) -> Self {
        Self {
            limit_usd: if limit_usd.is_finite() && limit_usd > 0.0 {
                limit_usd
            } else {
                0.0
            },
            day_index: i64::MIN,
            spent_usd: 0.0,
        }
    }

    /// True when no limit is configured.
    pub(crate) fn is_unlimited(&self) -> bool {
        self.limit_usd <= 0.0
    }

    fn roll_day(&mut self, now_ms: i64) {
        let day = now_ms.div_euclid(DAY_MS);
        if day != self.day_index {
            // A new (or first) day starts with zero accumulated cost.
            self.day_index = day;
            self.spent_usd = 0.0;
        }
    }

    /// Reject the call when the daily limit has been reached.
    pub(crate) fn check(&mut self, now_ms: i64) -> Result<(), DecisionError> {
        self.roll_day(now_ms);
        if self.is_unlimited() || self.spent_usd < self.limit_usd {
            Ok(())
        } else {
            Err(DecisionError::CostLimitExceeded)
        }
    }

    /// Record the provider-reported cost of a completed call.
    pub(crate) fn record(&mut self, now_ms: i64, cost_usd: Option<f64>) {
        self.roll_day(now_ms);
        if let Some(cost) = cost_usd {
            if cost.is_finite() && cost > 0.0 {
                self.spent_usd += cost;
            }
        }
    }

    /// Cost accumulated for the current day (used by unit tests).
    #[cfg(test)]
    pub(crate) fn spent_usd(&mut self, now_ms: i64) -> f64 {
        self.roll_day(now_ms);
        self.spent_usd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_until_limit_then_blocks() {
        let mut tracker = CostTracker::new(0.001);
        assert!(tracker.check(0).is_ok());
        tracker.record(0, Some(0.0006));
        assert!(tracker.check(0).is_ok());
        tracker.record(0, Some(0.0006));
        assert_eq!(
            tracker.check(0).unwrap_err(),
            DecisionError::CostLimitExceeded
        );
        assert!((tracker.spent_usd(0) - 0.0012).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_limit_is_unlimited() {
        let mut tracker = CostTracker::new(0.0);
        tracker.record(0, Some(100.0));
        assert!(tracker.check(0).is_ok());
        assert!(tracker.is_unlimited());
    }

    #[test]
    fn resets_on_new_day() {
        let mut tracker = CostTracker::new(0.001);
        tracker.record(0, Some(0.002));
        assert!(tracker.check(0).is_err());
        assert!(tracker.check(DAY_MS + 1).is_ok());
        assert_eq!(tracker.spent_usd(DAY_MS + 1), 0.0);
    }

    #[test]
    fn ignores_invalid_costs() {
        let mut tracker = CostTracker::new(1.0);
        tracker.record(0, Some(f64::NAN));
        tracker.record(0, Some(-5.0));
        tracker.record(0, None);
        assert_eq!(tracker.spent_usd(0), 0.0);
    }
}
