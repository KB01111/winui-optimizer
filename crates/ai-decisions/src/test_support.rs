//! Shared test fixtures and an injectable transport. Test builds only.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use security_core::{
    BehaviorState, DecisionCategory, DecisionResult, DetectionState, DeterministicSummary,
    FileState, ProcessState, RiskAssessment, RiskLevel, RiskSignals, SecurityEventState,
};

use crate::error::DecisionError;
use crate::transport::{Transport, TransportRequest, TransportResponse};

/// A realistic redacted-looking state with sensitive fields filled in, so
/// redaction tests have something to remove.
pub(crate) fn sample_state(score: f32) -> SecurityEventState {
    SecurityEventState {
        event_id: "evt_sample".to_string(),
        event_type: "process_created".to_string(),
        timestamp_ms: 1_700_000_000_000,
        process: Some(ProcessState {
            name: "evil.exe".to_string(),
            signed: Some(false),
            parent: Some("powershell.exe".to_string()),
            command_line_redacted: Some(
                r"C:\Users\someuser\AppData\Local\Temp\evil.exe -stager http://example.invalid"
                    .to_string(),
            ),
        }),
        file: Some(FileState {
            name: "evil.exe".to_string(),
            extension: Some("exe".to_string()),
            size: 42_000,
            sha256_prefix: Some("deadbeef".to_string()),
            in_temp: true,
            in_startup: false,
        }),
        behavior: BehaviorState {
            persistence_attempt: true,
            credential_access: false,
            ..Default::default()
        },
        detections: DetectionState {
            known_malware_hash: false,
            yara_matches: vec![],
            heuristic_flags: vec![],
        },
        deterministic: DeterministicSummary {
            score,
            level: RiskLevel::from_score(score),
            reasons: vec![],
        },
    }
}

/// Minimal decision result for cache/unit tests.
pub(crate) fn sample_decision(provider: &str) -> DecisionResult {
    DecisionResult {
        id: "dec_sample".to_string(),
        provider: provider.to_string(),
        model: "sample-model".to_string(),
        model_version: None,
        category: DecisionCategory::Suspicious,
        probabilities: BTreeMap::new(),
        confidence: 0.5,
        requires_investigation: true,
        suspicious_persistence: false,
        credential_theft: false,
        ransomware: false,
        latency_ms: 12,
        timestamp_ms: 0,
        evidence: vec![],
        cost_usd: Some(0.0),
        escalated: false,
    }
}

/// Assessment with an exact score (signals left default).
pub(crate) fn assessment_with_score(score: f32) -> RiskAssessment {
    RiskAssessment {
        score,
        level: RiskLevel::from_score(score),
        signals: RiskSignals::default(),
        reasons: vec![],
        deterministic: true,
    }
}

/// `choice` answer fixture: suspicious with numeric `noul` answers.
pub(crate) const RESPONSE_CHOICE_SUSPICIOUS: &str = r#"{
  "id": "gen-test-1",
  "model": "inception/mercury-decide",
  "provider": "Together",
  "answers": {
    "classification": { "type": "choice", "choice": "suspicious", "confidence": 0.75,
      "probabilities": { "benign": 0.1, "suspicious": 0.75, "likely_malicious": 0.1, "unknown": 0.05 } },
    "requires_investigation": { "type": "noul", "noul": 0.96 },
    "persistence": { "type": "noul", "noul": 0.2 },
    "credential_theft": { "type": "noul", "noul": 0.1 },
    "ransomware": { "type": "noul", "noul": 0.05 }
  },
  "usage": { "input_tokens": 812, "output_tokens": 120, "cost": 0.00042 }
}"#;

/// `noul` answer fixture mixing booleans, numbers and strings.
pub(crate) const RESPONSE_NOUL_BOOLEAN: &str = r#"{
  "id": "gen-test-2",
  "model": "inception/mercury-decide",
  "provider": "Inception",
  "answers": {
    "classification": { "type": "choice", "choice": "likely_malicious", "confidence": 0.88,
      "probabilities": { "benign": 0.02, "suspicious": 0.1, "likely_malicious": 0.88, "unknown": 0.0 } },
    "requires_investigation": { "type": "noul", "noul": 0.91 },
    "persistence": { "type": "noul", "noul": true },
    "credential_theft": { "type": "noul", "noul": 0.2 },
    "ransomware": { "type": "noul", "noul": "no" }
  },
  "usage": { "input_tokens": 900, "output_tokens": 140, "cost": 0.00051 }
}"#;

/// Fixture with an extra `score` answer including probabilities and legend.
pub(crate) const RESPONSE_MIXED_SCORE_AND_CHOICE: &str = r#"{
  "id": "gen-test-3",
  "answers": {
    "classification": { "type": "choice", "choice": "benign", "confidence": 0.82 },
    "requires_investigation": { "type": "noul", "noul": 0.05 },
    "persistence": { "type": "noul", "noul": 0.1 },
    "credential_theft": { "type": "noul", "noul": 0.02 },
    "ransomware": { "type": "noul", "noul": 0.01 },
    "risk_score": { "type": "score", "score": 1.99, "confidence": 0.99,
      "probabilities": { "0": 0.01, "1": 0.05, "2": 0.9, "3": 0.03, "4": 0.01 },
      "legend": { "0": "benign", "1": "low", "2": "medium", "3": "high", "4": "critical" } }
  }
}"#;

/// One scripted transport step.
pub(crate) enum ScriptedStep {
    Respond {
        status: u16,
        body: String,
        retry_after_ms: Option<u64>,
    },
    Fail(DecisionError),
}

impl ScriptedStep {
    /// A 200 response with the given JSON body.
    pub(crate) fn json(body: &str) -> Self {
        Self::Respond {
            status: 200,
            body: body.to_string(),
            retry_after_ms: None,
        }
    }

    /// A non-200 response.
    pub(crate) fn status(status: u16, body: &str) -> Self {
        Self::Respond {
            status,
            body: body.to_string(),
            retry_after_ms: None,
        }
    }

    /// A 429 with a `Retry-After` value.
    pub(crate) fn rate_limited(retry_after_ms: u64) -> Self {
        Self::Respond {
            status: 429,
            body: r#"{"error":{"message":"rate limited"}}"#.to_string(),
            retry_after_ms: Some(retry_after_ms),
        }
    }
}

/// Deterministic transport double: replays scripted steps in order and records
/// every request for assertions.
pub(crate) struct ScriptedTransport {
    steps: Mutex<Vec<ScriptedStep>>,
    requests: Mutex<Vec<TransportRequest>>,
}

impl ScriptedTransport {
    pub(crate) fn new(steps: Vec<ScriptedStep>) -> Self {
        Self {
            steps: Mutex::new(steps),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub(crate) fn last_request(&self) -> Option<TransportRequest> {
        self.requests.lock().unwrap().last().cloned()
    }

    pub(crate) fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[async_trait]
impl Transport for ScriptedTransport {
    async fn post_json(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse, DecisionError> {
        self.requests.lock().unwrap().push(request);
        let step = {
            let mut steps = self.steps.lock().unwrap();
            if steps.is_empty() {
                None
            } else {
                Some(steps.remove(0))
            }
        };
        match step {
            Some(ScriptedStep::Respond {
                status,
                body,
                retry_after_ms,
            }) => Ok(TransportResponse {
                status,
                retry_after_ms,
                body,
            }),
            Some(ScriptedStep::Fail(error)) => Err(error),
            None => Err(DecisionError::ProviderError(
                0,
                "scripted transport exhausted".to_string(),
            )),
        }
    }
}
