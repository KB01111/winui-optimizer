//! Deterministic, network-free decision provider for tests and demos.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use security_core::{DecisionCategory, DecisionResult, SecurityEventState};

use crate::error::DecisionError;
use crate::providers::DecisionProvider;
use crate::types::{now_ms, ProviderHealth, ProviderStatus};

/// Boolean flags returned by [`MockDecisionProvider`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MockFlags {
    pub requires_investigation: bool,
    pub persistence: bool,
    pub credential_theft: bool,
    pub ransomware: bool,
}

/// Configurable mock decision provider. Never touches the network.
///
/// Without overrides it derives a plausible decision deterministically from
/// `state.deterministic.score` and the behavior flags.
pub struct MockDecisionProvider {
    category: Option<DecisionCategory>,
    confidence: Option<f32>,
    probabilities: Option<BTreeMap<String, f32>>,
    flags: Option<MockFlags>,
    failure: Option<DecisionError>,
    latency_ms: u64,
    model: String,
    calls: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
}

impl Default for MockDecisionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDecisionProvider {
    /// Create a deterministic mock provider.
    pub fn new() -> Self {
        Self {
            category: None,
            confidence: None,
            probabilities: None,
            flags: None,
            failure: None,
            latency_ms: 0,
            model: "mock-decision-v1".to_string(),
            calls: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Force a category (defaults to a score-derived one).
    pub fn with_category(mut self, category: DecisionCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Force a confidence value.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Force an explicit probability distribution.
    pub fn with_probabilities(mut self, probabilities: BTreeMap<String, f32>) -> Self {
        self.probabilities = Some(probabilities);
        self
    }

    /// Force the boolean flags.
    pub fn with_flags(mut self, flags: MockFlags) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Always fail with the given error (router failure-path tests).
    pub fn with_error(mut self, error: DecisionError) -> Self {
        self.failure = Some(error);
        self
    }

    /// Reported latency in the mock result.
    pub fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Reported model id.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Number of `classify` calls observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }
}

fn score_derived(score: f32) -> (DecisionCategory, f32, MockFlags) {
    if score >= 70.0 {
        (
            DecisionCategory::LikelyMalicious,
            0.85,
            MockFlags {
                requires_investigation: true,
                ..MockFlags::default()
            },
        )
    } else if score >= 40.0 {
        (
            DecisionCategory::Suspicious,
            0.72,
            MockFlags {
                requires_investigation: true,
                ..MockFlags::default()
            },
        )
    } else if score >= 15.0 {
        (DecisionCategory::Suspicious, 0.58, MockFlags::default())
    } else if score > 0.0 {
        (DecisionCategory::Unknown, 0.5, MockFlags::default())
    } else {
        (DecisionCategory::Benign, 0.9, MockFlags::default())
    }
}

fn category_name(category: DecisionCategory) -> &'static str {
    match category {
        DecisionCategory::Benign => "benign",
        DecisionCategory::Suspicious => "suspicious",
        DecisionCategory::LikelyMalicious => "likely_malicious",
        DecisionCategory::Unknown => "unknown",
    }
}

fn default_probabilities(category: DecisionCategory, confidence: f32) -> BTreeMap<String, f32> {
    let confidence = confidence.clamp(0.0, 1.0);
    let rest = (1.0 - confidence).max(0.0) / 3.0;
    let mut map = BTreeMap::new();
    for name in ["benign", "suspicious", "likely_malicious", "unknown"] {
        let value = if name == category_name(category) {
            confidence
        } else {
            rest
        };
        map.insert(name.to_string(), value);
    }
    map
}

#[async_trait]
impl DecisionProvider for MockDecisionProvider {
    fn provider_name(&self) -> &'static str {
        "mock"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn is_configured(&self) -> bool {
        true
    }

    async fn classify(&self, state: &SecurityEventState) -> Result<DecisionResult, DecisionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = &self.failure {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return Err(error.clone());
        }

        let score = state.deterministic.score;
        let (default_category, default_confidence, default_flags) = score_derived(score);
        let category = self.category.unwrap_or(default_category);
        let confidence = self.confidence.unwrap_or(default_confidence);
        let flags = self.flags.unwrap_or_else(|| MockFlags {
            persistence: state.behavior.persistence_attempt,
            credential_theft: state.behavior.credential_access,
            ransomware: state.behavior.ransomware,
            ..default_flags
        });
        let probabilities = self
            .probabilities
            .clone()
            .unwrap_or_else(|| default_probabilities(category, confidence));

        let evidence = vec![
            "deterministic mock decision provider (no network access)".to_string(),
            format!(
                "derived from deterministic score {score:.1} ({}); model answer was deterministic",
                category_name(category)
            ),
            "synthetic probabilities: uncalibrated model probabilities placeholder".to_string(),
        ];

        Ok(DecisionResult {
            id: security_core::new_id("dec"),
            provider: "mock".to_string(),
            model: self.model.clone(),
            model_version: None,
            category,
            probabilities,
            confidence,
            requires_investigation: flags.requires_investigation,
            suspicious_persistence: flags.persistence,
            credential_theft: flags.credential_theft,
            ransomware: flags.ransomware,
            latency_ms: self.latency_ms,
            timestamp_ms: now_ms(),
            evidence,
            cost_usd: Some(0.0),
            escalated: false,
        })
    }

    async fn health(&self) -> ProviderHealth {
        let calls = self.calls();
        let failures = self.failure_count();
        let status = if calls == 0 {
            ProviderStatus::Unknown
        } else if failures == calls {
            ProviderStatus::Unavailable
        } else if failures > 0 {
            ProviderStatus::Degraded
        } else {
            ProviderStatus::Healthy
        };
        ProviderHealth {
            provider: self.provider_name().to_string(),
            model: self.model.clone(),
            status,
            successes: calls.saturating_sub(failures),
            failures,
            last_latency_ms: Some(self.latency_ms),
            last_error: None,
            total_cost_usd: 0.0,
            requests: calls,
            checked_at_ms: now_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_state;

    #[tokio::test]
    async fn derives_category_from_deterministic_score() {
        let provider = MockDecisionProvider::new();
        let high = provider.classify(&sample_state(85.0)).await.unwrap();
        assert_eq!(high.category, DecisionCategory::LikelyMalicious);
        assert!(high.requires_investigation);
        assert_eq!(high.provider, "mock");
        assert_eq!(high.model, "mock-decision-v1");
        assert!(!high.escalated);
        assert_eq!(high.cost_usd, Some(0.0));
        assert!(high.evidence.iter().any(|line| line.contains("no network")));

        let clean = provider.classify(&sample_state(0.0)).await.unwrap();
        assert_eq!(clean.category, DecisionCategory::Benign);
    }

    #[tokio::test]
    async fn mirrors_behavior_flags() {
        let mut state = sample_state(80.0);
        state.behavior.credential_access = true;
        state.behavior.ransomware = false;
        let result = MockDecisionProvider::new().classify(&state).await.unwrap();
        assert!(result.credential_theft);
        assert!(!result.ransomware);
    }

    #[tokio::test]
    async fn overrides_are_respected() {
        let mut probabilities = BTreeMap::new();
        probabilities.insert("benign".to_string(), 0.9);
        let provider = MockDecisionProvider::new()
            .with_category(DecisionCategory::Benign)
            .with_confidence(0.9)
            .with_probabilities(probabilities)
            .with_flags(MockFlags {
                requires_investigation: false,
                persistence: true,
                credential_theft: true,
                ransomware: true,
            })
            .with_latency_ms(7)
            .with_model("mock-custom");
        let result = provider.classify(&sample_state(90.0)).await.unwrap();
        assert_eq!(result.category, DecisionCategory::Benign);
        assert_eq!(result.probabilities.len(), 1);
        assert_eq!(result.model, "mock-custom");
        assert_eq!(result.latency_ms, 7);
        assert!(result.suspicious_persistence);
        assert!(result.credential_theft);
        assert!(result.ransomware);
        assert!(!result.requires_investigation);
    }

    #[tokio::test]
    async fn propagates_configured_failure() {
        let provider = MockDecisionProvider::new().with_error(DecisionError::Timeout);
        let error = provider.classify(&sample_state(50.0)).await.unwrap_err();
        assert_eq!(error, DecisionError::Timeout);
        assert_eq!(provider.calls(), 1);
        let health = provider.health().await;
        assert_eq!(health.status, ProviderStatus::Unavailable);
        assert_eq!(health.failures, 1);
    }

    #[tokio::test]
    async fn health_starts_unknown_and_becomes_healthy() {
        let provider = MockDecisionProvider::new();
        assert_eq!(provider.health().await.status, ProviderStatus::Unknown);
        let _ = provider.classify(&sample_state(50.0)).await;
        let health = provider.health().await;
        assert_eq!(health.status, ProviderStatus::Healthy);
        assert_eq!(health.successes, 1);
        assert_eq!(health.requests, 1);
    }

    #[test]
    fn probabilities_are_a_distribution() {
        let map = default_probabilities(DecisionCategory::Suspicious, 0.7);
        let sum: f32 = map.values().sum();
        assert!((sum - 1.0).abs() < 1e-3, "sum was {sum}");
        assert_eq!(map["suspicious"], 0.7);
    }
}
