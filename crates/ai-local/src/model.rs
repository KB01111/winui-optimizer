//! Local decision model interface and the deterministic mock model.
//!
//! The frozen `ai-local` manifest has no `async-trait` dependency, so the
//! contract's `#[async_trait]` trait is expressed with the equivalent manual
//! boxed-future form. It stays object-safe (`Box<dyn LocalDecisionModel>`
//! works), which is how the service layer stores local models.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use security_core::{DecisionCategory, DecisionResult, SecurityEventState};

use crate::error::LocalAiError;

/// A local (on-device) decision model. No runtime is bundled: implement this
/// trait when a validated ONNX/NPU runtime becomes available.
pub trait LocalDecisionModel: Send + Sync {
    /// Stable model name.
    fn name(&self) -> &str;

    /// True when the model and its runtime are usable on this machine.
    fn is_available(&self) -> bool;

    /// Classify a (already redacted) security event state.
    fn classify<'a>(
        &'a self,
        state: &'a SecurityEventState,
    ) -> Pin<Box<dyn Future<Output = Result<DecisionResult, LocalAiError>> + Send + 'a>>;
}

/// Deterministic, always-available local model used when no real local runtime
/// exists. Provider is clearly `local-mock`; output is a heuristic derived from
/// the deterministic assessment, never pseudo-inference.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockLocalDecisionModel;

impl MockLocalDecisionModel {
    /// Create the mock model.
    pub fn new() -> Self {
        Self
    }

    /// Stable model id reported on results.
    pub const MODEL_ID: &'static str = "local-mock-heuristic-v1";
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn heuristic(score: f32, known_malware_hash: bool) -> (DecisionCategory, f32) {
    if known_malware_hash || score >= 70.0 {
        (DecisionCategory::LikelyMalicious, 0.8)
    } else if score >= 40.0 {
        (DecisionCategory::Suspicious, 0.65)
    } else if score >= 15.0 {
        (DecisionCategory::Unknown, 0.5)
    } else {
        (DecisionCategory::Benign, 0.85)
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

fn distribution(category: DecisionCategory, confidence: f32) -> BTreeMap<String, f32> {
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

impl LocalDecisionModel for MockLocalDecisionModel {
    fn name(&self) -> &str {
        "local-mock"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn classify<'a>(
        &'a self,
        state: &'a SecurityEventState,
    ) -> Pin<Box<dyn Future<Output = Result<DecisionResult, LocalAiError>> + Send + 'a>> {
        Box::pin(async move {
            let score = state.deterministic.score;
            if !score.is_finite() {
                return Err(LocalAiError::InvalidInput(
                    "deterministic score is not finite".to_string(),
                ));
            }
            let (category, confidence) = heuristic(score, state.detections.known_malware_hash);
            let evidence = vec![
                "local mock model: deterministic heuristic, no model weights and no network access"
                    .to_string(),
                format!(
                    "derived category '{}' from deterministic score {score:.1}",
                    category_name(category)
                ),
                "local probabilities are synthetic placeholders (uncalibrated model probabilities)"
                    .to_string(),
            ];
            Ok(DecisionResult {
                id: security_core::new_id("dec"),
                provider: "local-mock".to_string(),
                model: MockLocalDecisionModel::MODEL_ID.to_string(),
                model_version: None,
                category,
                probabilities: distribution(category, confidence),
                confidence,
                requires_investigation: score >= 40.0,
                suspicious_persistence: state.behavior.persistence_attempt,
                credential_theft: state.behavior.credential_access,
                ransomware: state.behavior.ransomware,
                latency_ms: 0,
                timestamp_ms: now_ms(),
                evidence,
                cost_usd: Some(0.0),
                escalated: false,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use security_core::{
        BehaviorState, DetectionState, DeterministicSummary, RiskLevel, SecurityEventState,
    };

    fn state_with(score: f32) -> SecurityEventState {
        SecurityEventState {
            event_id: "evt_local".to_string(),
            event_type: "process_created".to_string(),
            timestamp_ms: 0,
            process: None,
            file: None,
            behavior: BehaviorState {
                persistence_attempt: true,
                credential_access: true,
                ransomware: false,
                ..Default::default()
            },
            detections: DetectionState::default(),
            deterministic: DeterministicSummary {
                score,
                level: RiskLevel::from_score(score),
                reasons: vec![],
            },
        }
    }

    #[test]
    fn mock_classifies_proportionally_to_the_score() {
        let model = MockLocalDecisionModel::new();
        assert!(model.is_available());
        assert_eq!(model.name(), "local-mock");

        let high = block_on(model.classify(&state_with(85.0))).unwrap();
        assert_eq!(high.category, DecisionCategory::LikelyMalicious);
        assert_eq!(high.provider, "local-mock");
        assert_eq!(high.model, MockLocalDecisionModel::MODEL_ID);
        assert!(high.requires_investigation);
        assert_eq!(high.cost_usd, Some(0.0));
        assert!(!high.escalated);
        assert!(high
            .evidence
            .iter()
            .any(|line| line.contains("uncalibrated model probabilities")));

        let medium = block_on(model.classify(&state_with(50.0))).unwrap();
        assert_eq!(medium.category, DecisionCategory::Suspicious);

        let clean = block_on(model.classify(&state_with(0.0))).unwrap();
        assert_eq!(clean.category, DecisionCategory::Benign);
    }

    #[test]
    fn mock_mirrors_behavior_flags() {
        let result = block_on(MockLocalDecisionModel::new().classify(&state_with(80.0))).unwrap();
        assert!(result.suspicious_persistence);
        assert!(result.credential_theft);
        assert!(!result.ransomware);
    }

    #[test]
    fn probabilities_form_a_distribution() {
        let result = block_on(MockLocalDecisionModel::new().classify(&state_with(50.0))).unwrap();
        assert_eq!(result.probabilities.len(), 4);
        let sum: f32 = result.probabilities.values().sum();
        assert!((sum - 1.0).abs() < 1e-3, "sum was {sum}");
    }

    #[test]
    fn mock_is_object_safe() {
        let model: Box<dyn LocalDecisionModel> = Box::new(MockLocalDecisionModel);
        let result = block_on(model.classify(&state_with(20.0))).unwrap();
        assert_eq!(result.provider, "local-mock");
    }

    #[test]
    fn non_finite_scores_are_rejected() {
        let error =
            block_on(MockLocalDecisionModel::new().classify(&state_with(f32::NAN))).unwrap_err();
        assert!(matches!(error, LocalAiError::InvalidInput(_)));
    }
}
