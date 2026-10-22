//! Provider router: deterministic policy gate, primary model, escalation model.
//!
//! Routing rules (per contract):
//! 1. Deterministic rules first: a score below `investigate_min_score`
//!    (default 15.0) is answered with [`DecisionRoute::SkippedByPolicy`] and no
//!    network activity.
//! 2. The primary provider (Mercury Decide) triages everything else.
//! 3. When the primary answer is uncertain (confidence < 0.7, category
//!    `unknown`/`suspicious`, or `requires_investigation`) the escalation
//!    provider (Jev) is consulted and its answer becomes the final result.
//! 4. Failures never propagate: a failed primary call produces
//!    [`DecisionRoute::FailedClosed`] with `deterministic_only = true`. A failed
//!    *escalation* keeps the successful primary answer
//!    ([`DecisionRoute::PrimaryOnly`]) and records the failure in provider
//!    health; it never blocks scanning.

use security_core::{DecisionCategory, DecisionResult, RiskAssessment, SecurityEventState};

use crate::error::DecisionError;
use crate::providers::mock::MockDecisionProvider;
use crate::providers::openrouter::{JevProvider, MercuryDecideProvider, ProviderConfig};
use crate::providers::DecisionProvider;
use crate::types::{models, AiConfig, AiMode, DecisionRoute, ProviderHealth, RoutedDecision};

/// Default minimum deterministic score before AI classification is attempted.
pub const DEFAULT_INVESTIGATE_MIN_SCORE: f32 = 15.0;

/// Routes classification between the deterministic policy, the primary
/// provider and the escalation provider.
pub struct ProviderRouter {
    config: AiConfig,
    primary: Option<Box<dyn DecisionProvider>>,
    escalation: Option<Box<dyn DecisionProvider>>,
    investigate_min_score: f32,
}

impl ProviderRouter {
    /// Build the default router from configuration: Mercury Decide as primary,
    /// Jev as escalation. In `AiMode::Offline` no providers are constructed.
    pub fn new(config: AiConfig) -> Result<Self, DecisionError> {
        let mut router = Self {
            config: config.clone(),
            primary: None,
            escalation: None,
            investigate_min_score: DEFAULT_INVESTIGATE_MIN_SCORE,
        };
        if config.mode != AiMode::Offline {
            let primary_model = model_or(&config.primary_model, models::MERCURY_DECIDE);
            let escalation_model = model_or(&config.escalation_model, models::JEV);
            router.primary = Some(Box::new(MercuryDecideProvider::with_config(
                ProviderConfig::from_ai_config(&config, primary_model),
            )));
            router.escalation = Some(Box::new(JevProvider::with_config(
                ProviderConfig::from_ai_config(&config, escalation_model),
            )));
        }
        Ok(router)
    }

    /// Build a router with a single injected provider as primary (no
    /// escalation slot). Used for mocks and embedding.
    pub fn with_provider(
        config: AiConfig,
        provider: Box<dyn DecisionProvider>,
    ) -> Result<Self, DecisionError> {
        Ok(Self {
            config,
            primary: Some(provider),
            escalation: None,
            investigate_min_score: DEFAULT_INVESTIGATE_MIN_SCORE,
        })
    }

    /// Build a router with explicit primary and escalation providers.
    pub fn with_providers(
        config: AiConfig,
        primary: Box<dyn DecisionProvider>,
        escalation: Option<Box<dyn DecisionProvider>>,
    ) -> Result<Self, DecisionError> {
        Ok(Self {
            config,
            primary: Some(primary),
            escalation,
            investigate_min_score: DEFAULT_INVESTIGATE_MIN_SCORE,
        })
    }

    /// A router that never calls any provider.
    pub fn offline(config: AiConfig) -> Self {
        let mut config = config;
        config.mode = AiMode::Offline;
        Self {
            config,
            primary: None,
            escalation: None,
            investigate_min_score: DEFAULT_INVESTIGATE_MIN_SCORE,
        }
    }

    /// Override the deterministic score threshold for AI classification.
    pub fn with_investigate_min_score(mut self, threshold: f32) -> Self {
        self.investigate_min_score = threshold;
        self
    }

    /// Effective configuration (API key redacted in `Debug`).
    pub fn config(&self) -> &AiConfig {
        &self.config
    }

    /// Effective AI mode.
    pub fn mode(&self) -> AiMode {
        self.config.mode
    }

    /// Health snapshot for the primary and escalation slots.
    pub async fn provider_health(&self) -> Vec<ProviderHealth> {
        let mut health = Vec::new();
        if let Some(primary) = &self.primary {
            health.push(primary.health().await);
        }
        if let Some(escalation) = &self.escalation {
            health.push(escalation.health().await);
        }
        health
    }

    /// Classify one redacted state. This never returns an error for provider
    /// failures; it fails closed instead so scanning is never blocked.
    pub async fn classify(
        &self,
        state: &SecurityEventState,
        assessment: &RiskAssessment,
    ) -> Result<RoutedDecision, DecisionError> {
        if self.config.mode == AiMode::Offline {
            return Ok(RoutedDecision::skipped(DecisionRoute::SkippedOffline));
        }
        if !assessment.score.is_finite() || assessment.score < self.investigate_min_score {
            tracing::debug!(
                score = assessment.score,
                threshold = self.investigate_min_score,
                "deterministic score below the AI threshold; skipping classification"
            );
            return Ok(RoutedDecision::skipped(DecisionRoute::SkippedByPolicy));
        }

        let Some(primary) = &self.primary else {
            return Ok(RoutedDecision::skipped(DecisionRoute::SkippedOffline));
        };
        if !primary.is_configured() {
            tracing::debug!(
                provider = primary.provider_name(),
                "primary decision provider is not configured; skipping classification"
            );
            return Ok(RoutedDecision::skipped(DecisionRoute::SkippedOffline));
        }

        let primary_result = match primary.classify(state).await {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(
                    provider = primary.provider_name(),
                    error = %error,
                    "primary decision provider failed; failing closed to deterministic results"
                );
                return Ok(RoutedDecision::skipped(DecisionRoute::FailedClosed));
            }
        };

        if is_uncertain(&primary_result) {
            if let Some(escalation) = &self.escalation {
                if escalation.is_configured() {
                    match escalation.classify(state).await {
                        Ok(mut escalated) => {
                            escalated.escalated = true;
                            escalated.evidence.push(format!(
                                "escalated from {} ({}) after uncertain primary result",
                                primary.provider_name(),
                                primary.model()
                            ));
                            return Ok(RoutedDecision {
                                primary: Some(primary_result),
                                escalation: Some(escalated.clone()),
                                final_result: Some(escalated),
                                route: DecisionRoute::Escalated,
                                deterministic_only: false,
                            });
                        }
                        Err(error) => {
                            tracing::warn!(
                                provider = escalation.provider_name(),
                                error = %error,
                                "escalation provider failed; keeping the primary decision"
                            );
                            let mut degraded = primary_result;
                            degraded.evidence.push(format!(
                                "escalation provider failed ({error}); using primary decision"
                            ));
                            return Ok(RoutedDecision {
                                primary: Some(degraded.clone()),
                                escalation: None,
                                final_result: Some(degraded),
                                route: DecisionRoute::PrimaryOnly,
                                deterministic_only: false,
                            });
                        }
                    }
                }
            }
        }

        Ok(RoutedDecision {
            primary: Some(primary_result.clone()),
            escalation: None,
            final_result: Some(primary_result),
            route: DecisionRoute::PrimaryOnly,
            deterministic_only: false,
        })
    }
}

/// True when the primary answer should be escalated to the stronger model.
pub fn is_uncertain(result: &DecisionResult) -> bool {
    result.confidence < 0.7
        || matches!(
            result.category,
            DecisionCategory::Unknown | DecisionCategory::Suspicious
        )
        || result.requires_investigation
}

fn model_or<'a>(configured: &'a str, default_model: &'a str) -> &'a str {
    if configured.trim().is_empty() {
        default_model
    } else {
        configured
    }
}

/// Convenience constructor used by the service layer: a router that always
/// answers with the deterministic mock provider (never the network).
pub fn mock_router(config: AiConfig) -> Result<ProviderRouter, DecisionError> {
    ProviderRouter::with_provider(config, Box::new(MockDecisionProvider::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assessment_with_score, sample_state};
    use security_core::RiskLevel;

    fn cloud_config() -> AiConfig {
        AiConfig {
            mode: AiMode::Cloud,
            api_key: Some("sk-test-key".into()),
            ..Default::default()
        }
    }

    fn mock(category: DecisionCategory, confidence: f32) -> Box<dyn DecisionProvider> {
        // Explicit flags keep the mock's score-derived `requires_investigation`
        // from interfering with routing assertions.
        Box::new(
            MockDecisionProvider::new()
                .with_category(category)
                .with_confidence(confidence)
                .with_flags(crate::providers::mock::MockFlags {
                    requires_investigation: false,
                    ..Default::default()
                }),
        )
    }

    #[tokio::test]
    async fn skips_low_scores_by_policy() {
        let provider = MockDecisionProvider::new();
        let router = ProviderRouter::with_provider(cloud_config(), Box::new(provider)).unwrap();
        let decision = router
            .classify(&sample_state(5.0), &assessment_with_score(5.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedByPolicy);
        assert!(decision.deterministic_only);
        assert!(decision.final_result.is_none());
    }

    #[tokio::test]
    async fn threshold_boundary_is_inclusive() {
        let router = mock_router(cloud_config()).unwrap();
        let decision = router
            .classify(&sample_state(15.0), &assessment_with_score(15.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::PrimaryOnly);

        let router = mock_router(cloud_config()).unwrap();
        let decision = router
            .classify(&sample_state(14.9), &assessment_with_score(14.9))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedByPolicy);
        assert!(decision.deterministic_only);
    }

    #[tokio::test]
    async fn offline_mode_never_calls_providers() {
        let provider = MockDecisionProvider::new();
        let mut config = cloud_config();
        config.mode = AiMode::Offline;
        let router = ProviderRouter::with_provider(config, Box::new(provider)).unwrap();
        let decision = router
            .classify(&sample_state(90.0), &assessment_with_score(90.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedOffline);
        assert!(decision.deterministic_only);

        let offline = ProviderRouter::offline(cloud_config());
        let decision = offline
            .classify(&sample_state(90.0), &assessment_with_score(90.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedOffline);

        let default_router = ProviderRouter::new(AiConfig::default()).unwrap();
        let decision = default_router
            .classify(&sample_state(90.0), &assessment_with_score(90.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedOffline);
    }

    #[tokio::test]
    async fn unconfigured_provider_is_skipped_not_failed() {
        let router = ProviderRouter::new(cloud_config_without_key()).unwrap();
        assert!(router.primary.is_some());
        let decision = router
            .classify(&sample_state(90.0), &assessment_with_score(90.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedOffline);
        assert!(decision.deterministic_only);
    }

    fn cloud_config_without_key() -> AiConfig {
        AiConfig {
            mode: AiMode::Cloud,
            api_key: None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn confident_primary_stays_primary_only() {
        let router = ProviderRouter::with_providers(
            cloud_config(),
            mock(DecisionCategory::LikelyMalicious, 0.9),
            Some(mock(DecisionCategory::Benign, 0.99)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(85.0), &assessment_with_score(85.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::PrimaryOnly);
        assert!(decision.escalation.is_none());
        assert!(!decision.deterministic_only);
        let primary = decision.primary.unwrap();
        assert_eq!(primary.category, DecisionCategory::LikelyMalicious);
        assert!(!primary.escalated);
        assert_eq!(decision.final_result.unwrap().id, primary.id);
    }

    #[tokio::test]
    async fn low_confidence_escalates() {
        let router = ProviderRouter::with_providers(
            cloud_config(),
            mock(DecisionCategory::LikelyMalicious, 0.6),
            Some(mock(DecisionCategory::LikelyMalicious, 0.95)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(85.0), &assessment_with_score(85.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::Escalated);
        let final_result = decision.final_result.clone().unwrap();
        assert!(final_result.escalated);
        assert!((final_result.confidence - 0.95).abs() < 1e-6);
        assert!(decision.escalation.is_some());
        assert!(final_result
            .evidence
            .iter()
            .any(|line| line.contains("escalated from")));
    }

    #[tokio::test]
    async fn suspicious_category_escalates_even_with_high_confidence() {
        let router = ProviderRouter::with_providers(
            cloud_config(),
            mock(DecisionCategory::Suspicious, 0.9),
            Some(mock(DecisionCategory::LikelyMalicious, 0.9)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(50.0), &assessment_with_score(50.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::Escalated);
        assert_eq!(
            decision.final_result.unwrap().category,
            DecisionCategory::LikelyMalicious
        );
    }

    #[tokio::test]
    async fn investigation_flag_escalates() {
        let primary = MockDecisionProvider::new()
            .with_category(DecisionCategory::Benign)
            .with_confidence(0.95)
            .with_flags(crate::providers::mock::MockFlags {
                requires_investigation: true,
                ..Default::default()
            });
        let router = ProviderRouter::with_providers(
            cloud_config(),
            Box::new(primary),
            Some(mock(DecisionCategory::Benign, 0.99)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(20.0), &assessment_with_score(20.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::Escalated);
    }

    #[tokio::test]
    async fn uncertain_primary_without_escalation_stays_primary_only() {
        let provider = MockDecisionProvider::new();
        let router = ProviderRouter::with_provider(cloud_config(), Box::new(provider)).unwrap();
        let decision = router
            .classify(&sample_state(85.0), &assessment_with_score(85.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::PrimaryOnly);
    }

    #[tokio::test]
    async fn primary_failure_fails_closed_without_error() {
        let primary = MockDecisionProvider::new().with_error(DecisionError::Timeout);
        let router = ProviderRouter::with_providers(
            cloud_config(),
            Box::new(primary),
            Some(mock(DecisionCategory::Benign, 0.99)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(85.0), &assessment_with_score(85.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::FailedClosed);
        assert!(decision.deterministic_only);
        assert!(decision.primary.is_none());
        assert!(decision.escalation.is_none());
        assert!(decision.final_result.is_none());
    }

    #[tokio::test]
    async fn escalation_failure_degrades_to_primary_only() {
        let primary = MockDecisionProvider::new()
            .with_category(DecisionCategory::Suspicious)
            .with_confidence(0.5);
        let escalation = MockDecisionProvider::new()
            .with_error(DecisionError::ProviderError(500, "boom".into()));
        let router = ProviderRouter::with_providers(
            cloud_config(),
            Box::new(primary),
            Some(Box::new(escalation)),
        )
        .unwrap();
        let decision = router
            .classify(&sample_state(50.0), &assessment_with_score(50.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::PrimaryOnly);
        assert!(!decision.deterministic_only);
        let final_result = decision.final_result.unwrap();
        assert_eq!(final_result.category, DecisionCategory::Suspicious);
        assert!(final_result
            .evidence
            .iter()
            .any(|line| line.contains("escalation provider failed")));
    }

    #[tokio::test]
    async fn cost_limit_failure_fails_closed() {
        let primary = MockDecisionProvider::new().with_error(DecisionError::CostLimitExceeded);
        let router =
            ProviderRouter::with_providers(cloud_config(), Box::new(primary), None).unwrap();
        let decision = router
            .classify(&sample_state(85.0), &assessment_with_score(85.0))
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::FailedClosed);
        assert!(decision.deterministic_only);
    }

    #[tokio::test]
    async fn non_finite_scores_skip_classification() {
        let router = mock_router(cloud_config()).unwrap();
        let mut assessment = assessment_with_score(0.0);
        assessment.score = f32::NAN;
        assessment.level = RiskLevel::Unknown;
        let decision = router
            .classify(&sample_state(0.0), &assessment)
            .await
            .unwrap();
        assert_eq!(decision.route, DecisionRoute::SkippedByPolicy);
    }

    #[test]
    fn uncertainty_rules() {
        let base = security_core::DecisionResult {
            id: "dec_x".into(),
            provider: "mock".into(),
            model: "m".into(),
            model_version: None,
            category: DecisionCategory::LikelyMalicious,
            probabilities: Default::default(),
            confidence: 0.9,
            requires_investigation: false,
            suspicious_persistence: false,
            credential_theft: false,
            ransomware: false,
            latency_ms: 0,
            timestamp_ms: 0,
            evidence: vec![],
            cost_usd: None,
            escalated: false,
        };
        assert!(!is_uncertain(&base));
        let mut low = base.clone();
        low.confidence = 0.69;
        assert!(is_uncertain(&low));
        let mut suspicious = base.clone();
        suspicious.category = DecisionCategory::Suspicious;
        assert!(is_uncertain(&suspicious));
        let mut unknown = base.clone();
        unknown.category = DecisionCategory::Unknown;
        assert!(is_uncertain(&unknown));
        let mut investigate = base.clone();
        investigate.requires_investigation = true;
        assert!(is_uncertain(&investigate));
    }
}
