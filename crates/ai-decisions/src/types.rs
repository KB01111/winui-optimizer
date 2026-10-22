//! Configuration and value types for the decision router.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Well-known OpenRouter model identifiers used by the default providers.
pub mod models {
    /// Primary decision model (fast triage).
    pub const MERCURY_DECIDE: &str = "inception/mercury-decide";
    /// Free tier of the primary decision model.
    pub const MERCURY_DECIDE_FREE: &str = "inception/mercury-decide:free";
    /// Escalation decision model used when the primary answer is uncertain.
    pub const JEV: &str = "typesafe/jev-1.14";
}

/// Milliseconds since the Unix epoch (UTC).
pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Overall AI operating mode. The engine is fully functional in `Offline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AiMode {
    /// No cloud calls at all; deterministic rules only.
    #[default]
    Offline,
    /// Cloud decision providers only.
    Cloud,
    /// Cloud decision providers when policy allows, deterministic fallback.
    Hybrid,
}

impl AiMode {
    /// Stable string form used in logs and reasons.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Cloud => "cloud",
            Self::Hybrid => "hybrid",
        }
    }
}

/// Effective decision-provider configuration owned by the service layer.
///
/// The API key is never serialized and never logged; `Debug` prints it as
/// `"<redacted>"`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfig {
    /// Operating mode.
    #[serde(default)]
    pub mode: AiMode,
    /// OpenRouter API key. Skipped by `Serialize` on purpose.
    #[serde(skip_serializing, default)]
    pub api_key: Option<String>,
    /// Primary (triage) model id.
    #[serde(default = "default_primary_model")]
    pub primary_model: String,
    /// Escalation model id, used when the primary answer is uncertain.
    #[serde(default = "default_escalation_model")]
    pub escalation_model: String,
    /// Per-request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Number of retries after the initial attempt (0 disables retries).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Local token-bucket rate limit per minute (0 disables local limiting).
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    /// Daily cost ceiling in USD (0 disables the check).
    #[serde(default = "default_daily_cost_limit")]
    pub daily_cost_limit_usd: f64,
    /// When false, the structured state is withheld from cloud providers.
    #[serde(default = "default_true")]
    pub allow_cloud_state: bool,
}

fn default_primary_model() -> String {
    models::MERCURY_DECIDE.to_string()
}

fn default_escalation_model() -> String {
    models::JEV.to_string()
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_max_retries() -> u32 {
    2
}

fn default_requests_per_minute() -> u32 {
    20
}

fn default_daily_cost_limit() -> f64 {
    1.0
}

fn default_true() -> bool {
    true
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            mode: AiMode::Offline,
            api_key: None,
            primary_model: default_primary_model(),
            escalation_model: default_escalation_model(),
            timeout_ms: default_timeout_ms(),
            max_retries: default_max_retries(),
            requests_per_minute: default_requests_per_minute(),
            daily_cost_limit_usd: default_daily_cost_limit(),
            allow_cloud_state: true,
        }
    }
}

impl fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiConfig")
            .field("mode", &self.mode)
            .field(
                "api_key",
                &self.api_key.as_ref().map(|_| "<redacted>".to_string()),
            )
            .field("primary_model", &self.primary_model)
            .field("escalation_model", &self.escalation_model)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("daily_cost_limit_usd", &self.daily_cost_limit_usd)
            .field("allow_cloud_state", &self.allow_cloud_state)
            .finish()
    }
}

impl AiConfig {
    /// True when a non-empty API key is present.
    pub fn has_api_key(&self) -> bool {
        self.api_key
            .as_deref()
            .map(|key| !key.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Coarse health state of a decision provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    /// Never called.
    Unknown,
    /// Last call succeeded.
    Healthy,
    /// Succeeded before but is currently failing.
    Degraded,
    /// Never succeeded.
    Unavailable,
    /// AI is disabled (`AiMode::Offline`).
    Offline,
}

/// Per-provider counters exposed to the UI (persisted by `security-storage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderHealth {
    /// Provider implementation name, e.g. `openrouter` or `mock`.
    pub provider: String,
    /// Effective model id.
    pub model: String,
    /// Derived status.
    pub status: ProviderStatus,
    /// Successful classifications.
    pub successes: u64,
    /// Failed classifications (after retries).
    pub failures: u64,
    /// Latency of the last completed HTTP attempt.
    pub last_latency_ms: Option<u64>,
    /// Last error message (sanitized, never contains the API key).
    pub last_error: Option<String>,
    /// Accumulated provider-reported cost in USD since process start.
    pub total_cost_usd: f64,
    /// HTTP attempts made (including retries).
    pub requests: u64,
    /// When this snapshot was taken.
    pub checked_at_ms: i64,
}

/// Routing outcome of a single decision request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRoute {
    /// Deterministic score was too low; no AI call was made.
    SkippedByPolicy,
    /// AI mode is offline or no provider is configured; no AI call was made.
    SkippedOffline,
    /// Only the primary provider produced a decision.
    PrimaryOnly,
    /// Primary was uncertain; the escalation provider was used.
    Escalated,
    /// No AI decision is available; use deterministic results only.
    FailedClosed,
}

impl DecisionRoute {
    /// Stable string form for logs and UI.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SkippedByPolicy => "skipped_by_policy",
            Self::SkippedOffline => "skipped_offline",
            Self::PrimaryOnly => "primary_only",
            Self::Escalated => "escalated",
            Self::FailedClosed => "failed_closed",
        }
    }
}

/// Result of [`crate::ProviderRouter::classify`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutedDecision {
    /// Primary provider decision, when one was produced.
    pub primary: Option<security_core::DecisionResult>,
    /// Escalation provider decision, when escalation happened successfully.
    pub escalation: Option<security_core::DecisionResult>,
    /// The decision the caller should use (escalation result when escalated).
    pub final_result: Option<security_core::DecisionResult>,
    /// Routing outcome.
    pub route: DecisionRoute,
    /// True when no AI result exists and only deterministic signals may be used.
    pub deterministic_only: bool,
}

impl RoutedDecision {
    /// A skipped route with no AI result.
    pub(crate) fn skipped(route: DecisionRoute) -> Self {
        Self {
            primary: None,
            escalation: None,
            final_result: None,
            route,
            deterministic_only: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_config_debug_and_serialize_redact_key() {
        let config = AiConfig {
            mode: AiMode::Cloud,
            api_key: Some("sk-or-v1-supersecret".into()),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("supersecret"), "{debug}");
        assert!(debug.contains("<redacted>"));
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("supersecret"), "{json}");
        assert!(!json.contains("apiKey"), "{json}");
    }

    #[test]
    fn ai_config_deserializes_camel_case_with_defaults() {
        let config: AiConfig =
            serde_json::from_str(r#"{"mode":"hybrid","apiKey":"sk-test","allowCloudState":false}"#)
                .unwrap();
        assert_eq!(config.mode, AiMode::Hybrid);
        assert!(config.has_api_key());
        assert_eq!(config.primary_model, models::MERCURY_DECIDE);
        assert_eq!(config.escalation_model, models::JEV);
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.max_retries, 2);
        assert!(!config.allow_cloud_state);
    }

    #[test]
    fn route_and_mode_strings_are_stable() {
        assert_eq!(DecisionRoute::SkippedByPolicy.as_str(), "skipped_by_policy");
        assert_eq!(DecisionRoute::FailedClosed.as_str(), "failed_closed");
        assert_eq!(AiMode::Offline.as_str(), "offline");
    }
}
