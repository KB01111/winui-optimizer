//! Serialized types exchanged between the Rust backend and the React
//! dashboard. Field names are camelCase to match `security-core`.

use ai_local::{HardwareProfile, InferenceRoute};
use security_core::{DecisionResult, PolicyDecision, ProviderHealth, SecurityEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineState {
    pub running: bool,
    pub started_at_ms: Option<i64>,
    pub uptime_secs: u64,
    pub telemetry_source: String,
    pub telemetry_available: bool,
    pub monitoring_is_preventive: bool,
    pub events_processed: u64,
    pub correlated_chains: u64,
    pub detections: u64,
    pub scans_completed: u64,
    pub dropped_events: u64,
    pub mode: String,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            running: false,
            started_at_ms: None,
            uptime_secs: 0,
            telemetry_source: "windows-toolhelp32".into(),
            telemetry_available: cfg!(windows),
            monitoring_is_preventive: false,
            events_processed: 0,
            correlated_chains: 0,
            detections: 0,
            scans_completed: 0,
            dropped_events: 0,
            mode: "embedded".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub available: bool,
    pub pipe_name: String,
    pub connected: bool,
    pub version: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalModelInfo {
    pub name: String,
    pub available: bool,
    pub runtime: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAiStatus {
    pub hardware: HardwareProfile,
    pub route: InferenceRoute,
    pub model: LocalModelInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiStatus {
    pub mode: String,
    pub configured: bool,
    pub primary_model: String,
    pub escalation_model: String,
    pub allow_cloud_state: bool,
    pub offline_capable: bool,
    pub providers: Vec<ProviderHealth>,
    pub local: LocalAiStatus,
    pub total_cost_usd: f64,
    pub requests: u64,
    pub failures: u64,
    pub avg_latency_ms: Option<u64>,
    pub last_request_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfigInput {
    pub mode: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub clear_api_key: bool,
    pub primary_model: String,
    pub escalation_model: String,
    pub timeout_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    pub requests_per_minute: u32,
    pub daily_cost_limit_usd: f64,
    pub allow_cloud_state: bool,
}

fn default_max_retries() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderTestResult {
    pub model: String,
    pub ok: bool,
    pub latency_ms: u64,
    pub category: Option<String>,
    pub confidence: Option<f32>,
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventDetail {
    pub event: SecurityEvent,
    pub related: Vec<SecurityEvent>,
    pub decisions: Vec<DecisionResult>,
    pub policy: Option<PolicyDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyState {
    pub cloud_ai_enabled: bool,
    pub store_raw_paths: bool,
    pub telemetry_local_only: bool,
    pub notifications_enabled: bool,
    pub auto_quarantine_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    pub product_name: String,
    pub version: String,
    pub package_identity: windows_integration::PackageIdentityInfo,
    pub windows: windows_integration::WindowsVersion,
    pub execution: windows_integration::ExecutionContext,
    pub defender: windows_integration::DefenderStatus,
    pub engine: EngineState,
    pub ai: AiStatus,
    pub hardware: HardwareProfile,
    pub service: ServiceStatus,
    pub privacy: PrivacyState,
    pub storage: security_storage::StorageStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanPathArgs {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

/// Default application settings. Every privacy-impacting option defaults to the
/// strict value.
pub fn default_settings() -> serde_json::Value {
    serde_json::json!({
        "policy": {
            "autoQuarantineEnabled": false,
            "autoQuarantineRequiresKnownHash": true,
            "autoQuarantineMinScore": 90.0,
            "investigateMinScore": 40.0,
            "alertMinScore": 70.0
        },
        "privacy": {
            "cloudAiEnabled": false,
            "storeRawPaths": true,
            "telemetryLocalOnly": true,
            "notificationsEnabled": true,
            "autoQuarantineEnabled": false
        },
        "scanner": {
            "maxFileSizeMb": 128,
            "yaraTimeoutMs": 5000,
            "exclusions": []
        },
        "ai": {
            "mode": "offline",
            "primaryModel": "inception/mercury-decide",
            "escalationModel": "typesafe/jev-1.14",
            "timeoutMs": 15000,
            "requestsPerMinute": 30,
            "dailyCostLimitUsd": 0.50,
            "allowCloudState": false
        },
        "engine": {
            "pollIntervalMs": 3000,
            "eventRetentionDays": 30,
            "autoStartMonitoring": true
        }
    })
}
