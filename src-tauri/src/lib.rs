//! AI Antivirus desktop application.
//!
//! This crate wires the deterministic security engine (`security-*` crates) and
//! the optional AI decision layer (`ai-decisions`) into a Tauri 2 desktop app
//! with a Fluent UI dashboard.
//!
//! Architectural notes:
//! - The engine runs embedded (unprivileged) while the UI is open. The optional
//!   background service (`security-service`) provides 24/7 monitoring and is
//!   installed separately because MSIX packaging cannot register services.
//! - Package identity is preserved from the Microsoft `winappCli` Tauri sample
//!   and is required for toast notifications.
//! - AI providers never gate deterministic policy. See `docs/CONTRACTS.md`.

mod ai_service;
mod engine;
mod notify;
mod types;

use ai_service::AiService;
use engine::Engine;
use parking_lot::Mutex;
use security_core::{
    DecisionResult, FileScanReport, QuarantineRecord, RestoreResult, RiskAssessment,
    ScanJobSummary, SecurityEvent, Severity,
};
use security_policy::PolicyConfig;
use security_scanner::{QuarantineVault, ScannerConfig};
use security_storage::{Database, EventFilter, EventPage, StorageStats};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use types::{
    AiConfigInput, AiStatus, EngineState, PrivacyState, ProviderTestResult, ScanPathArgs,
    SecurityEventDetail, ServiceStatus, SystemStatus,
};

pub const PRODUCT_NAME: &str = "AI Antivirus";
pub const SETTINGS_KEY: &str = "app.settings";

/// Resolved on-disk locations for the desktop instance.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub vault_dir: PathBuf,
}

impl Paths {
    pub fn resolve() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("AiAntivirus");
        Self {
            data_dir: base.clone(),
            db_path: base.join("security.db"),
            vault_dir: base.join("quarantine"),
        }
    }
}

/// Shared application state managed by Tauri.
pub struct AppState {
    pub db: Arc<Database>,
    pub engine: Arc<Engine>,
    pub ai: tokio::sync::RwLock<AiService>,
    pub vault: Arc<QuarantineVault>,
    pub paths: Paths,
    pub hardware: Mutex<Option<(ai_local::HardwareProfile, Instant)>>,
    pub defender: Mutex<Option<(windows_integration::DefenderStatus, Instant)>>,
    pub event_log: Mutex<Option<security_telemetry::EventLogReader>>,
    settings_cache: Mutex<Option<(serde_json::Value, Instant)>>,
}

impl AppState {
    pub fn new(db: Arc<Database>, paths: Paths) -> Result<Arc<Self>, String> {
        let settings = merged_settings(&db);
        let engine = Engine::new(
            scanner_config_from(&settings),
            policy_config_from(&settings),
        )?;
        let vault = QuarantineVault::new(paths.vault_dir.clone())
            .map_err(|e| format!("could not create quarantine vault: {e}"))?;
        let event_log = if cfg!(windows) {
            security_telemetry::EventLogReader::new().ok()
        } else {
            None
        };
        let ai = AiService::load(&db);
        Ok(Arc::new(Self {
            db,
            engine,
            ai: tokio::sync::RwLock::new(ai),
            vault: Arc::new(vault),
            paths,
            hardware: Mutex::new(None),
            defender: Mutex::new(None),
            event_log: Mutex::new(event_log),
            settings_cache: Mutex::new(None),
        }))
    }

    pub fn hardware_cached(&self) -> ai_local::HardwareProfile {
        const TTL: Duration = Duration::from_secs(30);
        {
            let cache = self.hardware.lock();
            if let Some((profile, at)) = cache.as_ref() {
                if at.elapsed() < TTL {
                    return profile.clone();
                }
            }
        }
        let profile = ai_service::hardware_now();
        *self.hardware.lock() = Some((profile.clone(), Instant::now()));
        profile
    }

    pub fn settings(&self) -> serde_json::Value {
        const TTL: Duration = Duration::from_secs(2);
        {
            let cache = self.settings_cache.lock();
            if let Some((value, at)) = cache.as_ref() {
                if at.elapsed() < TTL {
                    return value.clone();
                }
            }
        }
        let merged = merged_settings(&self.db);
        *self.settings_cache.lock() = Some((merged.clone(), Instant::now()));
        merged
    }

    pub fn settings_bool(&self, dotted_path: &str, default: bool) -> bool {
        dotted_path_value(&self.settings(), dotted_path)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    }

    pub fn settings_u64(&self, dotted_path: &str, default: u64) -> u64 {
        dotted_path_value(&self.settings(), dotted_path)
            .and_then(|v| v.as_u64())
            .unwrap_or(default)
    }

    pub fn settings_f64(&self, dotted_path: &str, default: f64) -> f64 {
        dotted_path_value(&self.settings(), dotted_path)
            .and_then(|v| v.as_f64())
            .unwrap_or(default)
    }

    /// Apply a partial settings patch (deep-merged over existing overrides)
    /// and return the fully merged settings.
    pub fn merge_settings(&self, patch: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut current = serde_json::from_str::<serde_json::Value>(
            &self
                .db
                .get_setting(SETTINGS_KEY)
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "{}".into()),
        )
        .unwrap_or_else(|_| serde_json::json!({}));
        deep_merge(&mut current, patch);
        self.db
            .set_setting(
                SETTINGS_KEY,
                &serde_json::to_string(&current).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        let merged = self.settings();
        *self.settings_cache.lock() = Some((merged.clone(), Instant::now()));
        Ok(merged)
    }

    /// Apply the local privacy preference to an event before it is persisted
    /// or emitted. When `privacy.storeRawPaths` is false, directories, command
    /// lines and usernames are removed while file/process names are retained.
    pub fn sanitize_event(&self, event: &mut SecurityEvent) {
        if self.settings_bool("privacy.storeRawPaths", true) {
            return;
        }
        if let Some(file) = &mut event.file {
            file.path = file.name.clone();
        }
        if let Some(process) = &mut event.process {
            process.path = None;
            process.command_line = None;
            process.user = None;
        }
        if let Some(evidence) = event.evidence.as_object_mut() {
            evidence.remove("path");
            evidence.remove("commandLine");
            evidence.remove("restoredPath");
        }
    }

    /// Delete security events older than `engine.eventRetentionDays`.
    /// Quarantine records, scan jobs and settings are never pruned here.
    pub fn prune_old_events(&self) {
        let days = self
            .settings_u64("engine.eventRetentionDays", 30)
            .clamp(1, 3650);
        let cutoff = engine::now_ms() - (days as i64) * 86_400_000;
        if let Err(error) = self.db.purge_events_older_than(cutoff) {
            tracing::warn!(%error, "event retention purge failed");
        }
    }
}

fn dotted_path_value<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Deep-merge `patch` over `base`. Objects merge recursively; everything else
/// is replaced.
fn deep_merge(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(patch_map)) => {
            for (key, value) in patch_map {
                match base_map.get_mut(key) {
                    Some(existing) => deep_merge(existing, value),
                    None => {
                        base_map.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base_slot, patch_value) => {
            *base_slot = patch_value.clone();
        }
    }
}

fn merged_settings(db: &Database) -> serde_json::Value {
    let mut merged = types::default_settings();
    if let Ok(Some(stored)) = db.get_setting(SETTINGS_KEY) {
        if let Ok(overrides) = serde_json::from_str::<serde_json::Value>(&stored) {
            deep_merge(&mut merged, &overrides);
        }
    }
    merged
}

fn scanner_config_from(settings: &serde_json::Value) -> ScannerConfig {
    let max_file_size =
        dotted_path_value(settings, "scanner.maxFileSizeMb").and_then(|v| v.as_u64());
    let yara_timeout =
        dotted_path_value(settings, "scanner.yaraTimeoutMs").and_then(|v| v.as_u64());
    let mut config = ScannerConfig::default();
    if let Some(mb) = max_file_size {
        config.max_file_size = mb.saturating_mul(1024 * 1024);
    }
    if let Some(ms) = yara_timeout {
        config.yara_timeout_ms = ms.clamp(100, 120_000);
    }
    if let Some(values) =
        dotted_path_value(settings, "scanner.exclusions").and_then(|v| v.as_array())
    {
        config.exclusions = values
            .iter()
            .filter_map(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect();
    }
    config
}

fn policy_config_from(settings: &serde_json::Value) -> PolicyConfig {
    let mut config = PolicyConfig::default();
    if let Some(v) =
        dotted_path_value(settings, "policy.autoQuarantineEnabled").and_then(|v| v.as_bool())
    {
        config.auto_quarantine_enabled = v;
    }
    if let Some(v) = dotted_path_value(settings, "policy.autoQuarantineRequiresKnownHash")
        .and_then(|v| v.as_bool())
    {
        config.auto_quarantine_requires_known_hash = v;
    }
    if let Some(v) =
        dotted_path_value(settings, "policy.autoQuarantineMinScore").and_then(|v| v.as_f64())
    {
        config.auto_quarantine_min_score = v as f32;
    }
    if let Some(v) =
        dotted_path_value(settings, "policy.investigateMinScore").and_then(|v| v.as_f64())
    {
        config.investigate_min_score = v as f32;
    }
    if let Some(v) = dotted_path_value(settings, "policy.alertMinScore").and_then(|v| v.as_f64()) {
        config.alert_min_score = v as f32;
    }
    config
}

async fn defender_status_cached(state: &Arc<AppState>) -> windows_integration::DefenderStatus {
    const TTL: Duration = Duration::from_secs(60);
    {
        let cache = state.defender.lock();
        if let Some((status, at)) = cache.as_ref() {
            if at.elapsed() < TTL {
                return status.clone();
            }
        }
    }
    let stale = state
        .defender
        .lock()
        .as_ref()
        .map(|(status, _)| status.clone());
    match tauri::async_runtime::spawn_blocking(windows_integration::defender_status).await {
        Ok(status) => {
            *state.defender.lock() = Some((status.clone(), Instant::now()));
            status
        }
        Err(error) => {
            let mut fallback = stale.unwrap_or_else(windows_integration::defender_status);
            fallback.available = false;
            fallback.query_error = Some(format!("defender query task failed: {error}"));
            fallback
        }
    }
}

async fn service_status() -> ServiceStatus {
    let pipe_name = security_ipc::IPC_PIPE_NAME.to_string();
    let exists = security_ipc::pipe::pipe_available(&pipe_name);
    if !exists {
        return ServiceStatus {
            available: false,
            pipe_name,
            connected: false,
            version: None,
            last_error: None,
        };
    }
    let name = pipe_name.clone();
    let call = tauri::async_runtime::spawn_blocking(move || {
        security_ipc::pipe::call_pipe(&name, &security_ipc::ClientRequest::Ping)
    });
    match tokio::time::timeout(Duration::from_millis(800), call).await {
        Ok(Ok(Ok(security_ipc::ServerResponse::Pong { version, .. }))) => ServiceStatus {
            available: true,
            pipe_name,
            connected: true,
            version: Some(version),
            last_error: None,
        },
        Ok(Ok(Ok(_))) => ServiceStatus {
            available: true,
            pipe_name,
            connected: true,
            version: None,
            last_error: Some("unexpected response to ping".into()),
        },
        Ok(Ok(Err(error))) => ServiceStatus {
            available: true,
            pipe_name,
            connected: false,
            version: None,
            last_error: Some(error.to_string()),
        },
        Ok(Err(error)) => ServiceStatus {
            available: true,
            pipe_name,
            connected: false,
            version: None,
            last_error: Some(error.to_string()),
        },
        Err(_) => ServiceStatus {
            available: true,
            pipe_name,
            connected: false,
            version: None,
            last_error: Some("service ping timed out".into()),
        },
    }
}

// ---------------------------------------------------------------- commands

#[tauri::command]
async fn get_system_status(state: State<'_, Arc<AppState>>) -> Result<SystemStatus, String> {
    let state = state.inner().clone();
    let hardware = state.hardware_cached();
    let defender = defender_status_cached(&state).await;
    let service = service_status().await;
    let ai = state.ai.read().await.status(&state.db, &hardware);
    let storage = state.db.stats().unwrap_or(StorageStats {
        events: 0,
        detections: 0,
        quarantined: 0,
        scans: 0,
    });
    let privacy = PrivacyState {
        cloud_ai_enabled: ai.mode != "offline",
        store_raw_paths: state.settings_bool("privacy.storeRawPaths", true),
        telemetry_local_only: state.settings_bool("privacy.telemetryLocalOnly", true),
        notifications_enabled: state.settings_bool("privacy.notificationsEnabled", true),
        auto_quarantine_enabled: state.settings_bool("policy.autoQuarantineEnabled", false),
    };
    Ok(SystemStatus {
        product_name: PRODUCT_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        package_identity: windows_integration::package_identity(),
        windows: windows_integration::windows_version(),
        execution: windows_integration::execution_context(),
        defender,
        engine: state.engine.state(),
        ai,
        hardware,
        service,
        privacy,
        storage,
    })
}

#[tauri::command]
async fn get_hardware_profile(
    state: State<'_, Arc<AppState>>,
) -> Result<ai_local::HardwareProfile, String> {
    Ok(state.hardware_cached())
}

#[tauri::command]
async fn get_engine_state(state: State<'_, Arc<AppState>>) -> Result<EngineState, String> {
    Ok(state.engine.state())
}

#[tauri::command]
async fn start_monitoring(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<EngineState, String> {
    let engine_state = state.engine.start();
    let _ = state.merge_settings(&serde_json::json!({
        "engine": { "autoStartMonitoring": true }
    }));
    let _ = app.emit("engine://status", &engine_state);
    Ok(engine_state)
}

#[tauri::command]
async fn stop_monitoring(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<EngineState, String> {
    let engine_state = state.engine.stop();
    let _ = state.merge_settings(&serde_json::json!({
        "engine": { "autoStartMonitoring": false }
    }));
    let _ = app.emit("engine://status", &engine_state);
    Ok(engine_state)
}

#[tauri::command]
async fn scan_path(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    request: ScanPathArgs,
) -> Result<ScanJobSummary, String> {
    let path = std::path::Path::new(&request.path);
    if !path.exists() {
        return Err(format!("path does not exist: {}", request.path));
    }
    let state = state.inner().clone();
    let job = state.engine.spawn_scan(app, state.clone(), request)?;
    Ok(job)
}

#[tauri::command]
async fn cancel_scan(state: State<'_, Arc<AppState>>, job_id: String) -> Result<bool, String> {
    Ok(state.engine.cancel_scan(&job_id))
}

#[tauri::command]
async fn get_scan_results(
    state: State<'_, Arc<AppState>>,
    job_id: String,
    limit: u32,
) -> Result<Vec<FileScanReport>, String> {
    state
        .db
        .scan_results_for_job(&job_id, limit)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_scan_jobs(
    state: State<'_, Arc<AppState>>,
    limit: u32,
) -> Result<Vec<ScanJobSummary>, String> {
    state.db.list_scan_jobs(limit).map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_events(
    state: State<'_, Arc<AppState>>,
    filter: EventFilter,
) -> Result<EventPage, String> {
    state.db.query_events(&filter).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_event(
    state: State<'_, Arc<AppState>>,
    event_id: String,
) -> Result<SecurityEventDetail, String> {
    let event = state
        .db
        .get_event(&event_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("event not found: {event_id}"))?;
    let related = match &event.correlation_id {
        Some(correlation_id) => state
            .db
            .events_by_correlation(correlation_id)
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let decisions = state.db.decisions_for_event(&event_id).unwrap_or_default();
    let policy = Some(state.engine.policy().evaluate_event(&event));
    Ok(SecurityEventDetail {
        event,
        related,
        decisions,
        policy,
    })
}

#[tauri::command]
async fn list_quarantine(state: State<'_, Arc<AppState>>) -> Result<Vec<QuarantineRecord>, String> {
    state.db.list_quarantine(1000).map_err(|e| e.to_string())
}

#[tauri::command]
async fn quarantine_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    path: String,
    reason: String,
) -> Result<QuarantineRecord, String> {
    let file = std::path::Path::new(&path);
    if !file.exists() {
        return Err(format!("file does not exist: {path}"));
    }
    let state = state.inner().clone();
    let record = state
        .vault
        .quarantine(file, &reason, None)
        .map_err(|e| e.to_string())?;
    state
        .db
        .insert_quarantine(&record)
        .map_err(|e| e.to_string())?;
    let mut event = SecurityEvent::new(
        security_core::SecurityEventKind::PolicyDecision,
        Severity::High,
        security_core::TelemetrySource::Engine,
        format!("Manually quarantined {}", record.original_name),
    );
    event.description = reason;
    event.labels = vec!["policy".into(), "quarantine".into(), "manual".into()];
    event.evidence = serde_json::json!({ "quarantineId": record.id });
    let _ = state.db.insert_event(&event);
    let _ = app.emit("engine://event", &event);
    Ok(record)
}

#[tauri::command]
async fn restore_quarantine(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<RestoreResult, String> {
    let state = state.inner().clone();
    let result = state.vault.restore(&id).map_err(|e| e.to_string())?;
    if result.success {
        let _ = state.db.update_quarantine_status(
            &id,
            security_core::QuarantineStatus::Restored,
            Some(engine::now_ms()),
        );
        let mut event = SecurityEvent::new(
            security_core::SecurityEventKind::PolicyDecision,
            Severity::Medium,
            security_core::TelemetrySource::Engine,
            "Quarantine restored".to_string(),
        );
        event.description = if state.settings_bool("privacy.storeRawPaths", true) {
            result
                .restored_path
                .clone()
                .unwrap_or_else(|| "restore completed".into())
        } else {
            "restore completed".into()
        };
        event.labels = vec!["policy".into(), "restore".into()];
        event.evidence = serde_json::json!({ "quarantineId": id });
        let _ = state.db.insert_event(&event);
        let _ = app.emit("engine://event", &event);
    }
    Ok(result)
}

#[tauri::command]
async fn delete_quarantine(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<bool, String> {
    let state = state.inner().clone();
    if state
        .db
        .get_quarantine(&id)
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err(format!("quarantine record not found: {id}"));
    }
    state.vault.delete(&id).map_err(|e| e.to_string())?;
    state
        .db
        .update_quarantine_status(&id, security_core::QuarantineStatus::Deleted, None)
        .map_err(|e| e.to_string())?;
    let mut event = SecurityEvent::new(
        security_core::SecurityEventKind::PolicyDecision,
        Severity::Medium,
        security_core::TelemetrySource::Engine,
        "Quarantined copy deleted".to_string(),
    );
    event.description =
        "The user permanently deleted the vault copy. The original file location is not touched."
            .into();
    event.labels = vec!["policy".into(), "quarantine".into(), "delete".into()];
    event.evidence = serde_json::json!({ "quarantineId": id });
    let _ = state.db.insert_event(&event);
    let _ = app.emit("engine://event", &event);
    Ok(true)
}

#[tauri::command]
async fn get_ai_status(state: State<'_, Arc<AppState>>) -> Result<AiStatus, String> {
    let hardware = state.hardware_cached();
    Ok(state.ai.read().await.status(&state.db, &hardware))
}

#[tauri::command]
async fn configure_ai(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    config: AiConfigInput,
) -> Result<AiStatus, String> {
    let cloud_enabled = config.mode != "offline";
    {
        let mut ai = state.ai.write().await;
        ai.configure(config, &state.db)?;
    }
    // Keep the privacy summary in sync with the actual AI mode so the
    // dashboard never shows "cloud disabled" while egress is active (or the
    // reverse).
    state.merge_settings(&serde_json::json!({
        "privacy": { "cloudAiEnabled": cloud_enabled }
    }))?;
    let hardware = state.hardware_cached();
    let status = state.ai.read().await.status(&state.db, &hardware);
    for health in &status.providers {
        let _ = app.emit("engine://provider-health", health);
    }
    Ok(status)
}

#[tauri::command]
async fn test_ai_provider(
    state: State<'_, Arc<AppState>>,
    model: String,
) -> Result<ProviderTestResult, String> {
    let result = state.ai.read().await.test_model(&model).await;
    Ok(result)
}

#[tauri::command]
async fn classify_event(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    event_id: String,
) -> Result<Option<DecisionResult>, String> {
    let event = state
        .db
        .get_event(&event_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("event not found: {event_id}"))?;
    let assessment = event
        .assessment
        .clone()
        .unwrap_or_else(|| RiskAssessment::from_signals(Default::default()));

    let decision = {
        let ai = state.ai.read().await;
        if ai.is_cloud_enabled() {
            ai.classify(&event, &assessment, &state.db).await?
        } else {
            Some(ai.classify_local(&event, &assessment).await?)
        }
    };

    if let Some(decision) = &decision {
        let _ = state.db.insert_decision(Some(&event_id), decision);
        let mut ai_event = SecurityEvent::new(
            security_core::SecurityEventKind::AiDecision,
            Severity::Info,
            security_core::TelemetrySource::Engine,
            format!("AI decision: {}", decision.model),
        );
        ai_event.description = decision.evidence.join("; ");
        ai_event.correlation_id = event.correlation_id.clone();
        ai_event.labels = vec![
            "ai".into(),
            format!("{:?}", decision.category).to_lowercase(),
        ];
        ai_event.evidence = serde_json::json!({
            "eventId": event_id,
            "decisionId": decision.id,
            "model": decision.model,
            "provider": decision.provider,
            "confidence": decision.confidence,
            "uncalibrated": true,
        });
        let _ = state.db.insert_event(&ai_event);
        let _ = app.emit("engine://event", &ai_event);
    }
    Ok(decision)
}

#[tauri::command]
async fn get_settings(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    Ok(state.settings())
}

#[tauri::command]
async fn update_settings(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    patch: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let merged = state.merge_settings(&patch)?;
    state
        .engine
        .reconfigure(scanner_config_from(&merged), policy_config_from(&merged));

    // Turning the cloud privacy switch off is an immediate, local kill switch:
    // drop to offline mode and discard the in-memory API key.
    let cloud_disabled = dotted_path_value(&merged, "privacy.cloudAiEnabled")
        .and_then(|value| value.as_bool())
        == Some(false);
    if cloud_disabled {
        let mut ai = state.ai.write().await;
        ai.disable_cloud(&state.db)?;
    }

    let _ = app.emit("engine://status", &state.engine.state());
    Ok(merged)
}

#[tauri::command]
async fn send_test_notification() -> Result<windows_integration::NotificationOutcome, String> {
    Ok(notify::notify(
        "AI Antivirus",
        "This is a test notification from your security dashboard.",
        "test",
    ))
}

#[tauri::command]
async fn get_service_status() -> Result<ServiceStatus, String> {
    Ok(service_status().await)
}

// -------------------------------------------------------------------- setup

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tauri_app_lib=info,warn".into()),
        )
        .try_init();

    tauri::Builder::default()
        .setup(|app| {
            let paths = Paths::resolve();
            let db = Arc::new(
                Database::open(&paths.db_path)
                    .map_err(|e| format!("could not open database at {:?}: {e}", paths.db_path))?,
            );
            let state = AppState::new(db, paths)?;
            app.manage(state.clone());
            state.prune_old_events();

            let handle = app.handle().clone();
            let monitor_interval = Duration::from_millis(
                state
                    .settings_u64("engine.pollIntervalMs", 3000)
                    .clamp(1000, 15_000),
            );
            tauri::async_runtime::spawn(engine::run_monitor_loop(
                handle.clone(),
                state.clone(),
                monitor_interval,
            ));

            // Start monitoring on launch unless the user explicitly stopped it.
            if state.settings_bool("engine.autoStartMonitoring", true) {
                let engine_state = state.engine.start();
                let _ = handle.emit("engine://status", &engine_state);
            }

            // Log engine startup context (no PII) for diagnostics.
            let identity = windows_integration::package_identity();
            tracing::info!(
                packaged = identity.available,
                version = env!("CARGO_PKG_VERSION"),
                "AI Antivirus desktop engine initialized"
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_system_status,
            get_hardware_profile,
            get_engine_state,
            start_monitoring,
            stop_monitoring,
            scan_path,
            cancel_scan,
            get_scan_results,
            list_scan_jobs,
            list_events,
            get_event,
            list_quarantine,
            quarantine_file,
            restore_quarantine,
            delete_quarantine,
            get_ai_status,
            configure_ai,
            test_ai_provider,
            classify_event,
            get_settings,
            update_settings,
            send_test_notification,
            get_service_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
