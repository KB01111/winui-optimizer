//! Desktop-side AI configuration and routing service.
//!
//! Security properties:
//! - API keys are stored with DPAPI (`windows-integration::protect_secret`) and
//!   are never returned to the frontend.
//! - Cloud state sharing requires both `mode != offline` and
//!   `allowCloudState == true`; otherwise the router refuses to send state.
//! - Provider failures are counted and degrade health, but never interrupt
//!   deterministic scanning.

use crate::types::{AiConfigInput, AiStatus, LocalAiStatus, LocalModelInfo, ProviderTestResult};
use ai_decisions::{
    build_decision_state, AiConfig, AiMode, DecisionProvider, JevProvider,
    MercuryDecideFreeProvider, MercuryDecideProvider, MockDecisionProvider, ProviderConfig,
    ProviderRouter,
};
use ai_local::{
    detect_hardware, select_route, AiMode as LocalAiMode, HardwareProfile, LocalDecisionModel,
    MockLocalDecisionModel, PowerMode, RuntimeKind,
};
use security_core::{
    DecisionResult, ProviderHealth, ProviderStatus, RiskAssessment, SecurityEvent,
    SecurityEventState, TimestampMs,
};
use security_storage::{Database, StorageError};
use std::sync::Arc;
use std::time::Instant;

const SETTING_AI_CONFIG: &str = "ai.config";
const SETTING_AI_KEY: &str = "ai.apiKeyProtected";

pub struct AiService {
    config: AiConfig,
    router: Option<Arc<ProviderRouter>>,
    mock: MockDecisionProvider,
    local_model: MockLocalDecisionModel,
}

impl AiService {
    /// Load configuration from storage, protecting against a missing or
    /// undecryptable key by falling back to offline mode.
    pub fn load(db: &Database) -> Self {
        let mut config = default_ai_config();
        if let Ok(Some(json)) = db.get_setting(SETTING_AI_CONFIG) {
            if let Ok(stored) = serde_json::from_str::<AiConfig>(&json) {
                config = stored;
            }
        }
        if config.mode != AiMode::Offline {
            match load_api_key(db) {
                Ok(Some(key)) => {
                    config.api_key = Some(key);
                }
                _ => {
                    tracing::warn!("AI API key missing or undecryptable; staying offline");
                    config.mode = AiMode::Offline;
                    config.api_key = None;
                }
            }
        }
        let mut service = Self {
            router: None,
            mock: MockDecisionProvider::new(),
            local_model: MockLocalDecisionModel::new(),
            config,
        };
        service.rebuild_router();
        service
    }

    fn rebuild_router(&mut self) {
        self.router = match ProviderRouter::new(self.config.clone()) {
            Ok(router) => Some(Arc::new(router)),
            Err(error) => {
                tracing::warn!(%error, "AI router unavailable; deterministic-only mode");
                None
            }
        };
    }

    pub fn config(&self) -> &AiConfig {
        &self.config
    }

    pub fn is_cloud_enabled(&self) -> bool {
        matches!(self.config.mode, AiMode::Cloud | AiMode::Hybrid)
            && self.config.api_key.is_some()
            && self.config.allow_cloud_state
    }

    pub fn configure(&mut self, input: AiConfigInput, db: &Database) -> Result<(), String> {
        let mode = match input.mode.as_str() {
            "offline" => AiMode::Offline,
            "cloud" => AiMode::Cloud,
            "hybrid" => AiMode::Hybrid,
            other => return Err(format!("unknown AI mode: {other}")),
        };
        if matches!(mode, AiMode::Cloud | AiMode::Hybrid) {
            if input.clear_api_key {
                delete_api_key(db).map_err(|e| e.to_string())?;
            }
            if let Some(key) = input.api_key.as_deref() {
                if !key.trim().is_empty() {
                    store_api_key(db, key.trim()).map_err(|e| e.to_string())?;
                }
            }
            let has_key = load_api_key(db)
                .map_err(|e| e.to_string())?
                .map(|k| !k.is_empty())
                .unwrap_or(false);
            if !has_key {
                return Err("cloud and hybrid modes require an OpenRouter API key".into());
            }
        }
        self.config = AiConfig {
            mode,
            api_key: if mode == AiMode::Offline {
                None
            } else {
                load_api_key(db).map_err(|e| e.to_string())?
            },
            primary_model: input.primary_model,
            escalation_model: input.escalation_model,
            timeout_ms: input.timeout_ms.clamp(1000, 120_000),
            max_retries: input.max_retries.clamp(0, 5),
            requests_per_minute: input.requests_per_minute.clamp(1, 600),
            daily_cost_limit_usd: input.daily_cost_limit_usd.clamp(0.0, 100.0),
            allow_cloud_state: input.allow_cloud_state,
        };
        let json = serde_json::to_string(&self.config).map_err(|e| e.to_string())?;
        db.set_setting(SETTING_AI_CONFIG, &json)
            .map_err(|e| e.to_string())?;
        self.rebuild_router();
        Ok(())
    }

    /// Immediate local kill switch for cloud AI. Drops to offline mode,
    /// clears the in-memory key and persists the offline configuration. The
    /// DPAPI-protected key is retained so re-enabling does not require
    /// re-entering it (the user can clear it explicitly).
    pub fn disable_cloud(&mut self, db: &Database) -> Result<(), String> {
        if self.config.mode == AiMode::Offline {
            return Ok(());
        }
        self.config.mode = AiMode::Offline;
        self.config.api_key = None;
        let json = serde_json::to_string(&self.config).map_err(|e| e.to_string())?;
        db.set_setting(SETTING_AI_CONFIG, &json)
            .map_err(|e| e.to_string())?;
        self.rebuild_router();
        Ok(())
    }

    /// Classify an event with deterministic-first routing. Returns `None` when
    /// no cloud provider applies (offline mode or deterministic score low).
    pub async fn classify(
        &self,
        event: &SecurityEvent,
        assessment: &RiskAssessment,
        db: &Database,
    ) -> Result<Option<DecisionResult>, String> {
        let state = build_decision_state(event, assessment);
        let Some(router) = &self.router else {
            return Ok(None);
        };
        let started = Instant::now();
        match router.classify(&state, assessment).await {
            Ok(routed) => {
                let latency = started.elapsed().as_millis() as u64;
                let result = routed.final_result.clone();
                if let Some(result) = &result {
                    self.record_success(db, result, latency);
                }
                if let Some(primary) = &routed.primary {
                    db.insert_decision(Some(&event.id), primary)
                        .map_err(|e| e.to_string())?;
                }
                if let Some(escalation) = &routed.escalation {
                    db.insert_decision(Some(&event.id), escalation)
                        .map_err(|e| e.to_string())?;
                }
                Ok(result)
            }
            Err(error) => {
                let latency = started.elapsed().as_millis() as u64;
                self.record_failure(db, &error.to_string(), latency);
                Err(error.to_string())
            }
        }
    }

    /// Test one provider/model pair with a synthetic state. Used by the AI
    /// Intelligence page; never sends real system data.
    pub async fn test_model(&self, model: &str) -> ProviderTestResult {
        let Some(api_key) = self.config.api_key.clone() else {
            return ProviderTestResult {
                model: model.into(),
                ok: false,
                latency_ms: 0,
                category: None,
                confidence: None,
                cost_usd: None,
                error: Some("no API key configured".into()),
            };
        };
        let provider: Box<dyn DecisionProvider> = if model.starts_with("typesafe/") {
            Box::new(JevProvider::with_config(ProviderConfig::new(
                model.to_string(),
                Some(api_key),
            )))
        } else if model.contains("mercury-decide:free") {
            Box::new(MercuryDecideFreeProvider::new(api_key))
        } else {
            Box::new(MercuryDecideProvider::with_config(ProviderConfig::new(
                model.to_string(),
                Some(api_key),
            )))
        };

        let state = synthetic_state();
        let started = Instant::now();
        match provider.classify(&state).await {
            Ok(decision) => ProviderTestResult {
                model: model.into(),
                ok: true,
                latency_ms: started.elapsed().as_millis() as u64,
                category: Some(format!("{:?}", decision.category).to_lowercase()),
                confidence: Some(decision.confidence),
                cost_usd: decision.cost_usd,
                error: None,
            },
            Err(error) => ProviderTestResult {
                model: model.into(),
                ok: false,
                latency_ms: started.elapsed().as_millis() as u64,
                category: None,
                confidence: None,
                cost_usd: None,
                error: Some(error.to_string()),
            },
        }
    }

    fn record_success(&self, db: &Database, result: &DecisionResult, latency_ms: u64) {
        let mut health = existing_health(db, &result.provider, &result.model);
        health.successes += 1;
        health.requests += 1;
        health.total_cost_usd += result.cost_usd.unwrap_or(0.0);
        health.last_latency_ms = Some(latency_ms);
        health.last_error = None;
        health.status = if health.failures == 0 {
            ProviderStatus::Healthy
        } else {
            ProviderStatus::Degraded
        };
        health.checked_at_ms = now_ms();
        let _ = db.upsert_provider_health(&health);
    }

    fn record_failure(&self, db: &Database, error: &str, latency_ms: u64) {
        // Failures are attributed to the configured primary model.
        let model = self.config.primary_model.clone();
        let provider = provider_name_for(&model);
        let mut health = existing_health(db, &provider, &model);
        health.failures += 1;
        health.requests += 1;
        health.last_latency_ms = Some(latency_ms);
        health.last_error = Some(error.to_string());
        health.status = if health.successes == 0 {
            ProviderStatus::Unavailable
        } else {
            ProviderStatus::Degraded
        };
        health.checked_at_ms = now_ms();
        let _ = db.upsert_provider_health(&health);
    }

    pub fn status(&self, db: &Database, hardware: &HardwareProfile) -> AiStatus {
        let providers = db.provider_health().unwrap_or_default();
        let (requests, failures, total_cost, latency_samples) = providers.iter().fold(
            (0u64, 0u64, 0.0f64, Vec::new()),
            |(r, f, c, mut l), health| {
                if let Some(latency) = health.last_latency_ms {
                    l.push(latency);
                }
                (
                    r + health.requests,
                    f + health.failures,
                    c + health.total_cost_usd,
                    l,
                )
            },
        );
        let avg_latency = if latency_samples.is_empty() {
            None
        } else {
            Some(latency_samples.iter().sum::<u64>() / latency_samples.len() as u64)
        };
        let power = PowerMode::from_battery(&hardware.battery);
        let route = select_route(hardware, power, local_mode(self.config.mode));
        let local_available = self.local_model.is_available();
        let last_request_at_ms = providers.iter().map(|p| p.checked_at_ms).max();
        AiStatus {
            mode: mode_name(self.config.mode),
            configured: self.config.api_key.is_some(),
            primary_model: self.config.primary_model.clone(),
            escalation_model: self.config.escalation_model.clone(),
            allow_cloud_state: self.config.allow_cloud_state,
            offline_capable: true,
            providers,
            local: LocalAiStatus {
                hardware: hardware.clone(),
                model: LocalModelInfo {
                    name: self.local_model.name().to_string(),
                    available: local_available,
                    runtime: runtime_name(route.primary),
                    note: route.reason.clone(),
                },
                route,
            },
            total_cost_usd: total_cost,
            requests,
            failures,
            avg_latency_ms: avg_latency,
            last_request_at_ms,
        }
    }

    /// Offline-only classification used as a fallback for the UI preview.
    pub async fn classify_local(
        &self,
        event: &SecurityEvent,
        assessment: &RiskAssessment,
    ) -> Result<DecisionResult, String> {
        let state = build_decision_state(event, assessment);
        self.local_model
            .classify(&state)
            .await
            .map_err(|e| e.to_string())
    }
}

impl Default for AiService {
    fn default() -> Self {
        Self {
            config: default_ai_config(),
            router: None,
            mock: MockDecisionProvider::new(),
            local_model: MockLocalDecisionModel::new(),
        }
    }
}

fn local_mode(mode: AiMode) -> LocalAiMode {
    match mode {
        AiMode::Offline => LocalAiMode::Offline,
        AiMode::Cloud => LocalAiMode::Cloud,
        AiMode::Hybrid => LocalAiMode::Hybrid,
    }
}

fn default_ai_config() -> AiConfig {
    AiConfig {
        mode: AiMode::Offline,
        api_key: None,
        primary_model: "inception/mercury-decide".into(),
        escalation_model: "typesafe/jev-1.14".into(),
        timeout_ms: 15_000,
        max_retries: 2,
        requests_per_minute: 30,
        daily_cost_limit_usd: 0.50,
        allow_cloud_state: false,
    }
}

impl AiService {
    #[allow(dead_code)]
    pub fn mock(&self) -> &MockDecisionProvider {
        &self.mock
    }
}

pub fn hardware_now() -> HardwareProfile {
    detect_hardware()
}

fn mode_name(mode: AiMode) -> String {
    match mode {
        AiMode::Offline => "offline",
        AiMode::Cloud => "cloud",
        AiMode::Hybrid => "hybrid",
    }
    .into()
}

fn runtime_name(runtime: RuntimeKind) -> String {
    match runtime {
        RuntimeKind::Cpu => "cpu",
        RuntimeKind::Npu => "npu",
        RuntimeKind::IntegratedGpu => "igpu",
        RuntimeKind::DiscreteGpu => "dgpu",
        RuntimeKind::Cloud => "cloud",
    }
    .into()
}

fn provider_name_for(model: &str) -> String {
    model
        .split('/')
        .next()
        .unwrap_or("unknown")
        .trim_start_matches('~')
        .to_string()
}

/// Load the accumulated health row for a provider/model pair, or start a new
/// counters row from neutral values.
fn existing_health(db: &Database, provider: &str, model: &str) -> ProviderHealth {
    db.provider_health()
        .ok()
        .and_then(|rows| {
            rows.into_iter()
                .find(|health| health.provider == provider && health.model == model)
        })
        .unwrap_or_else(|| ProviderHealth {
            provider: provider.to_string(),
            model: model.to_string(),
            status: ProviderStatus::Unknown,
            successes: 0,
            failures: 0,
            last_latency_ms: None,
            last_error: None,
            total_cost_usd: 0.0,
            requests: 0,
            checked_at_ms: now_ms(),
        })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn synthetic_state() -> SecurityEventState {
    SecurityEventState {
        event_id: "provider-test".into(),
        event_type: "provider_test".into(),
        timestamp_ms: now_ms(),
        process: None,
        file: None,
        behavior: Default::default(),
        detections: Default::default(),
        deterministic: security_core::DeterministicSummary {
            score: 0.0,
            level: security_core::RiskLevel::Clean,
            reasons: vec![],
        },
    }
}

fn store_api_key(db: &Database, key: &str) -> Result<(), StorageError> {
    #[cfg(windows)]
    {
        let protected = windows_integration::protect_secret(key.as_bytes())
            .map_err(|e| StorageError::Migration(e.to_string()))?;
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, protected);
        db.set_setting(SETTING_AI_KEY, &encoded)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (db, key);
        Err(StorageError::Migration(
            "secret storage requires Windows DPAPI".into(),
        ))
    }
}

fn load_api_key(db: &Database) -> Result<Option<String>, StorageError> {
    #[cfg(windows)]
    {
        let Some(encoded) = db.get_setting(SETTING_AI_KEY)? else {
            return Ok(None);
        };
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|e| StorageError::Migration(e.to_string()))?;
        let plaintext = windows_integration::unprotect_secret(&bytes)
            .map_err(|e| StorageError::Migration(e.to_string()))?;
        Ok(Some(String::from_utf8_lossy(&plaintext).to_string()))
    }
    #[cfg(not(windows))]
    {
        let _ = db;
        Ok(None)
    }
}

fn delete_api_key(db: &Database) -> Result<(), StorageError> {
    db.set_setting(SETTING_AI_KEY, "")
}

#[allow(dead_code)]
pub fn default_hardware_status() -> (HardwareProfile, TimestampMs) {
    let profile = detect_hardware();
    (profile, now_ms())
}
