//! TTL cache for decision results, keyed by a stable hash of the redacted state.
//!
//! The cache key ignores `eventId` and `timestampMs`: those identify a specific
//! record, not the security semantics, and excluding them lets two identical
//! observations share one decision without a second cloud call.

use std::collections::HashMap;

use security_core::{DecisionResult, SecurityEventState};

/// Default time-to-live for cached decisions (10 minutes).
pub(crate) const DEFAULT_CACHE_TTL_MS: i64 = 10 * 60 * 1000;

/// Upper bound on cached entries; the entry closest to expiry is evicted first.
const MAX_CACHE_ENTRIES: usize = 512;

#[derive(Debug, Clone)]
struct CacheEntry {
    decision: DecisionResult,
    expires_at_ms: i64,
}

/// TTL cache with an injected clock so tests do not sleep.
#[derive(Debug)]
pub(crate) struct DecisionCache {
    ttl_ms: i64,
    entries: HashMap<u64, CacheEntry>,
}

impl DecisionCache {
    /// Create a cache with the given TTL in milliseconds.
    pub(crate) fn new(ttl_ms: i64) -> Self {
        Self {
            ttl_ms: ttl_ms.max(0),
            entries: HashMap::new(),
        }
    }

    /// Look up a decision, dropping it when expired.
    pub(crate) fn get(&mut self, key: u64, now_ms: i64) -> Option<DecisionResult> {
        match self.entries.get(&key) {
            Some(entry) if entry.expires_at_ms > now_ms => Some(entry.decision.clone()),
            Some(_) => {
                self.entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Insert a decision, purging expired entries first.
    pub(crate) fn insert(&mut self, key: u64, decision: DecisionResult, now_ms: i64) {
        self.purge(now_ms);
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(key, _)| *key)
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                decision,
                expires_at_ms: now_ms.saturating_add(self.ttl_ms),
            },
        );
    }

    /// Drop expired entries.
    pub(crate) fn purge(&mut self, now_ms: i64) {
        self.entries.retain(|_, entry| entry.expires_at_ms > now_ms);
    }

    /// Number of live entries (used by unit tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Stable FNV-1a 64 hash (process- and version-stable, unlike `DefaultHasher`).
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Cache key for a *redacted* state.
pub(crate) fn state_cache_key(state: &SecurityEventState) -> u64 {
    let mut normalized = state.clone();
    normalized.event_id = String::new();
    normalized.timestamp_ms = 0;
    match serde_json::to_vec(&normalized) {
        Ok(bytes) => fnv1a64(&bytes),
        Err(_) => fnv1a64(b"unserializable-state"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_decision;

    #[test]
    fn insert_get_and_expire() {
        let mut cache = DecisionCache::new(1_000);
        let key = 42;
        cache.insert(key, sample_decision("mock"), 10_000);
        assert!(cache.get(key, 10_500).is_some());
        assert_eq!(cache.len(), 1);
        assert!(cache.get(key, 11_000).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn purge_removes_expired_entries() {
        let mut cache = DecisionCache::new(100);
        cache.insert(1, sample_decision("mock"), 0);
        cache.insert(2, sample_decision("mock"), 150);
        cache.purge(200);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(2, 200).is_some());
        assert!(cache.get(1, 200).is_none());
    }

    #[test]
    fn key_is_stable_and_identity_insensitive() {
        let mut first = crate::test_support::sample_state(50.0);
        let second = first.clone();
        first.event_id = "evt_a".into();
        first.timestamp_ms = 1;
        let mut third = second.clone();
        third.event_id = "evt_b".into();
        third.timestamp_ms = 999_999;
        assert_eq!(state_cache_key(&first), state_cache_key(&third));

        third.deterministic.score = 80.0;
        assert_ne!(state_cache_key(&first), state_cache_key(&third));
    }
}
