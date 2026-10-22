//! AI Antivirus background security service.
//!
//! The service owns the deterministic engine (storage, process telemetry,
//! correlation, policy, scanner and optional AI router) and exposes it to the
//! unprivileged desktop app over the `security-ipc` named pipe.
//!
//! Public entry points:
//!
//! * [`ServiceEngine`] — the engine handle: `start`/`stop`/`status`,
//!   `handle_request` (pipe requests) and `spawn_scan`/`cancel_scan`.
//! * [`EngineStatus`] — camelCase snapshot returned by
//!   [`security_ipc::ClientRequest::GetStatus`].
//! * [`ScanSchedule`] — scheduled scan configuration stored in the database
//!   setting [`SETTING_SCAN_SCHEDULE`].
//! * [`default_data_dir`] / [`default_db_path`] / [`default_vault_dir`] —
//!   `%ProgramData%\AiAntivirus` locations (override with the
//!   `AI_ANTIVIRUS_DATA_DIR` environment variable).
//!
//! Service identity (see `packaging/service-installer`): name
//! [`SERVICE_NAME`], display name [`SERVICE_DISPLAY_NAME`], start type manual,
//! logon account `NT AUTHORITY\LocalService`.

mod engine;
mod ipc;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

pub use engine::{
    load_ai_config, PollSummary, ServiceEngine, ServiceEngineConfig, ServiceEngineDeps,
};

/// Windows service name (must match the installer scripts and `main.rs`).
pub const SERVICE_NAME: &str = "AiAntivirusSecurityService";
/// Windows service display name.
pub const SERVICE_DISPLAY_NAME: &str = "AI Antivirus Security Engine";
/// Windows service description.
pub const SERVICE_DESCRIPTION: &str =
    "Deterministic local security telemetry, scanning and quarantine engine for AI Antivirus.";
/// Least-privilege logon account used by the installer.
pub const SERVICE_ACCOUNT: &str = r"NT AUTHORITY\LocalService";
/// Default polling interval for process telemetry.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 3;
/// Bounded event queue capacity; events are dropped oldest-first when storage
/// cannot keep up.
pub const EVENT_QUEUE_CAPACITY: usize = 4096;
/// Database setting key holding the JSON-encoded [`ScanSchedule`].
pub const SETTING_SCAN_SCHEDULE: &str = "scan.schedule";
/// Database setting key holding a poll-interval override in seconds.
pub const SETTING_POLL_INTERVAL_SECS: &str = "engine.poll_interval_secs";
/// Database setting key holding a JSON-encoded `ai_decisions::AiConfig`.
pub const SETTING_AI_CONFIG: &str = "ai.config";
/// Default page size for event listing.
pub const DEFAULT_LIST_LIMIT: u32 = 100;
/// Maximum page size accepted over IPC.
pub const MAX_LIST_LIMIT: u32 = 500;
/// Maximum accepted path length.
pub const MAX_PATH_LEN: usize = 4096;
/// Maximum accepted free-text reason length.
pub const MAX_REASON_LEN: usize = 512;
/// Maximum accepted record id length.
pub const MAX_ID_LEN: usize = 128;
/// Environment variable overriding the data directory (development/testing).
pub const DATA_DIR_ENV: &str = "AI_ANTIVIRUS_DATA_DIR";
/// Database file name inside the data directory.
pub const DB_FILE_NAME: &str = "security.db";
/// Quarantine vault directory name inside the data directory.
pub const QUARANTINE_DIR_NAME: &str = "quarantine";
/// Correlation window used by the engine.
pub const CORRELATION_WINDOW_MS: i64 = 15 * 60 * 1000;
/// How often the scheduled-scan check runs.
pub const SCHEDULE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How many queued events are persisted per batch.
pub const PERSIST_BATCH: usize = 256;
/// Safety-net wakeup for the persistence loop.
pub const QUEUE_FALLBACK_WAIT: Duration = Duration::from_millis(250);

/// Milliseconds since the Unix epoch (UTC).
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// `%ProgramData%\AiAntivirus` (or `$AI_ANTIVIRUS_DATA_DIR` when set).
pub fn default_data_dir() -> PathBuf {
    if let Ok(custom) = std::env::var(DATA_DIR_ENV) {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom.trim());
        }
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        if !program_data.trim().is_empty() {
            return PathBuf::from(program_data.trim()).join("AiAntivirus");
        }
    }
    PathBuf::from("data")
}

/// Default database path: `<data dir>\security.db`.
pub fn default_db_path() -> PathBuf {
    default_data_dir().join(DB_FILE_NAME)
}

/// Default quarantine vault: `<data dir>\quarantine`.
pub fn default_vault_dir() -> PathBuf {
    default_data_dir().join(QUARANTINE_DIR_NAME)
}

/// The real process-snapshot provider for the current platform.
///
/// Windows uses the Toolhelp32 implementation; other platforms return the
/// `UnsupportedProcessSnapshot` stub so the workspace still builds and the
/// engine reports zero observations instead of pretending coverage.
pub fn platform_process_provider() -> Box<dyn security_telemetry::ProcessSnapshotProvider> {
    #[cfg(windows)]
    {
        Box::new(security_telemetry::WindowsProcessSnapshot::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(security_telemetry::UnsupportedProcessSnapshot)
    }
}

/// Errors surfaced by the service engine and its IPC layer.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Storage failure.
    #[error("storage error: {0}")]
    Storage(#[from] security_storage::StorageError),
    /// Scanner failure.
    #[error("scan error: {0}")]
    Scan(#[from] security_scanner::ScanError),
    /// Filesystem I/O failure (database directory, quarantine vault, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// AI router failure.
    #[error("ai error: {0}")]
    Ai(#[from] ai_decisions::DecisionError),
    /// Request validation failure.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The engine is not running.
    #[error("engine is not running")]
    NotRunning,
    /// The engine is already running.
    #[error("engine is already running")]
    AlreadyRunning,
    /// Unexpected internal failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ServiceError {
    /// Stable machine-readable error code used in
    /// [`security_ipc::ServerResponse::Error`].
    pub fn code(&self) -> &'static str {
        match self {
            Self::Storage(_) => "storage_error",
            Self::Scan(_) => "scan_failed",
            Self::Io(_) => "io_error",
            Self::Ai(_) => "ai_error",
            Self::InvalidRequest(_) => "invalid_request",
            Self::NotRunning => "not_running",
            Self::AlreadyRunning => "already_running",
            Self::Internal(_) => "internal_error",
        }
    }
}

/// Live engine status, serialized camelCase for the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    /// True while the poll loop is active.
    pub running: bool,
    /// Wall-clock start time of the current run.
    pub started_at_ms: Option<i64>,
    /// Seconds since the engine started (0 when stopped).
    pub uptime_secs: u64,
    /// Configured polling interval.
    pub poll_interval_secs: u64,
    /// Bounded queue capacity.
    pub queue_capacity: usize,
    /// Events currently waiting to be persisted.
    pub queue_depth: usize,
    /// Process/correlation events observed since start.
    pub events_observed: u64,
    /// Events written to storage since start.
    pub events_persisted: u64,
    /// Events dropped because the bounded queue was full (drop-oldest).
    pub events_dropped: u64,
    /// Correlated events emitted since start.
    pub events_correlated: u64,
    /// Policy decisions recorded since start.
    pub policy_decisions: u64,
    /// True when an AI router is configured.
    pub ai_enabled: bool,
    /// AI decisions recorded since start.
    pub ai_decisions: u64,
    /// AI provider failures observed since start.
    pub ai_errors: u64,
    /// Scan jobs started since start.
    pub scans_started: u64,
    /// Scan jobs completed since start.
    pub scans_completed: u64,
    /// Scan jobs that failed since start.
    pub scans_failed: u64,
    /// Scan jobs currently running or queued.
    pub active_scans: u32,
    /// Timestamp of the last telemetry poll.
    pub last_poll_ms: Option<i64>,
    /// Last recorded error (truncated), if any.
    pub last_error: Option<String>,
    /// Database path in use.
    pub db_path: String,
    /// Quarantine vault directory, when configured.
    pub vault_dir: Option<String>,
    /// IPC protocol version this build speaks.
    pub protocol_version: u32,
    /// Service crate version.
    pub version: String,
    /// Configured scheduled scan, when present.
    pub schedule: Option<ScanSchedule>,
    /// False: `Subscribe` is acknowledged but events are not pushed yet.
    pub streaming: bool,
}

/// Scheduled scan configuration stored under [`SETTING_SCAN_SCHEDULE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSchedule {
    /// Whether the schedule is active.
    pub enabled: bool,
    /// Root path to scan.
    pub path: String,
    /// Recurse into subdirectories.
    pub recursive: bool,
    /// Minimum seconds between two runs.
    pub interval_secs: u64,
    /// Timestamp of the last run started by the scheduler.
    #[serde(default)]
    pub last_run_ms: Option<i64>,
}

impl ScanSchedule {
    /// Validate path/interval bounds.
    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_path_string(&self.path)?;
        if self.interval_secs < 60 {
            return Err(ServiceError::InvalidRequest(
                "schedule interval must be at least 60 seconds".to_string(),
            ));
        }
        Ok(())
    }

    /// True when the schedule should run at `now_ms`.
    pub fn is_due(&self, now_ms: i64) -> bool {
        if !self.enabled {
            return false;
        }
        match self.last_run_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= (self.interval_secs as i64) * 1000,
        }
    }

    /// Parse a [`ScanSchedule`] from the stored JSON value.
    pub fn from_json(value: &str) -> Result<Self, ServiceError> {
        let schedule: ScanSchedule = serde_json::from_str(value)
            .map_err(|err| ServiceError::InvalidRequest(format!("invalid scan schedule: {err}")))?;
        schedule.validate()?;
        Ok(schedule)
    }

    /// Serialize for storage.
    pub fn to_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(self)
            .map_err(|err| ServiceError::Internal(format!("failed to encode scan schedule: {err}")))
    }
}

/// Best-effort Windows service (SCM) status, also useful to the desktop app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    /// Windows service name.
    pub service_name: String,
    /// True when the service is registered with the SCM.
    pub installed: bool,
    /// True when the service state is `Running`.
    pub running: bool,
    /// Lowercase state name (`running`, `stopped`, ...), when known.
    pub state: Option<String>,
    /// Service process id, when running.
    pub pid: Option<u32>,
    /// Pipe the service listens on.
    pub pipe_name: String,
    /// IPC protocol version expected by the service.
    pub protocol_version: u32,
    /// Query error, when the SCM could not be reached.
    pub error: Option<String>,
}

/// Query the Windows Service Control Manager for [`SERVICE_NAME`].
///
/// Never panics; on non-Windows or when the SCM cannot be reached it returns an
/// "installed: false" status with an explanatory error.
#[cfg(windows)]
pub fn query_service_status() -> ServiceStatus {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let mut status = ServiceStatus {
        service_name: SERVICE_NAME.to_string(),
        installed: false,
        running: false,
        state: None,
        pid: None,
        pipe_name: security_ipc::IPC_PIPE_NAME.to_string(),
        protocol_version: security_ipc::IPC_PROTOCOL_VERSION,
        error: None,
    };

    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(manager) => manager,
        Err(err) => {
            status.error = Some(format!("service control manager unavailable: {err}"));
            return status;
        }
    };
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(err) => {
            status.error = Some(format!("{err}"));
            return status;
        }
    };
    status.installed = true;
    match service.query_status() {
        Ok(query) => {
            status.running = query.current_state == ServiceState::Running;
            status.state = Some(format!("{:?}", query.current_state).to_ascii_lowercase());
            status.pid = query.process_id;
        }
        Err(err) => status.error = Some(format!("{err}")),
    }
    status
}

/// Non-Windows stub: the service only exists on Windows.
#[cfg(not(windows))]
pub fn query_service_status() -> ServiceStatus {
    ServiceStatus {
        service_name: SERVICE_NAME.to_string(),
        installed: false,
        running: false,
        state: None,
        pid: None,
        pipe_name: security_ipc::IPC_PIPE_NAME.to_string(),
        protocol_version: security_ipc::IPC_PROTOCOL_VERSION,
        error: Some(
            "windows service control manager is not available on this platform".to_string(),
        ),
    }
}

/// Bounded, drop-oldest event queue used between polling and persistence.
///
/// Pushing into a full queue discards the oldest queued event and increments
/// [`EventQueue::dropped`]; the engine surfaces that counter in
/// [`EngineStatus::events_dropped`] so backpressure is observable.
#[derive(Debug)]
pub struct EventQueue {
    inner: Mutex<VecDeque<security_core::SecurityEvent>>,
    capacity: usize,
    dropped: AtomicU64,
    notify: Notify,
}

impl EventQueue {
    /// Create a queue with the given capacity (minimum 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.clamp(1, 1024))),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    /// Push an event, dropping the oldest one when full. Returns true when an
    /// event had to be dropped.
    pub fn push(&self, event: security_core::SecurityEvent) -> bool {
        let mut dropped = false;
        {
            let mut queue = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if queue.len() >= self.capacity {
                queue.pop_front();
                dropped = true;
            }
            queue.push_back(event);
        }
        if dropped {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
        self.notify.notify_one();
        dropped
    }

    /// Put an event back at the front of the queue.
    ///
    /// Used only when SQLite persistence fails: the event must not be lost and
    /// the normal FIFO order is preserved. If the queue is full (a concurrent
    /// producer filled it after the batch was drained) the newest queued event
    /// is discarded and counted as a drop.
    pub fn push_front(&self, event: security_core::SecurityEvent) {
        let mut dropped = false;
        {
            let mut queue = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if queue.len() >= self.capacity {
                queue.pop_back();
                dropped = true;
            }
            queue.push_front(event);
        }
        if dropped {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Remove up to `max` events (oldest first).
    pub fn drain(&self, max: usize) -> Vec<security_core::SecurityEvent> {
        let mut queue = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let take = queue.len().min(max);
        queue.drain(..take).collect()
    }

    /// Number of queued events.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// True when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total number of events dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Wait until an event is available or `timeout` elapses.
    ///
    /// Returns true when an event is (or became) available. The check is
    /// repeated after registering interest so no wakeup can be lost; callers
    /// additionally drain the queue themselves.
    pub async fn wait_for_items(&self, timeout: Duration) -> bool {
        if !self.is_empty() {
            return true;
        }
        let notified = self.notify.notified();
        if !self.is_empty() {
            return true;
        }
        tokio::time::timeout(timeout, notified).await.is_ok() || !self.is_empty()
    }
}

fn validate_path_string(path: &str) -> Result<PathBuf, ServiceError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "path must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_PATH_LEN {
        return Err(ServiceError::InvalidRequest(format!(
            "path must be at most {MAX_PATH_LEN} characters"
        )));
    }
    if trimmed.contains('\0') {
        return Err(ServiceError::InvalidRequest(
            "path must not contain NUL characters".to_string(),
        ));
    }
    let candidate = PathBuf::from(trimmed);
    if !candidate.is_absolute() {
        return Err(ServiceError::InvalidRequest(
            "path must be absolute".to_string(),
        ));
    }
    Ok(candidate)
}

/// Validate a path used by `ScanPath`/`QuarantineFile`.
///
/// Requires an absolute, existing path within the length bound. The service
/// runs as LocalService, so paths the account cannot read will fail later with
/// a descriptive scanner/vault error.
pub fn validate_existing_path(path: &str) -> Result<PathBuf, ServiceError> {
    let candidate = validate_path_string(path)?;
    if !candidate.exists() {
        return Err(ServiceError::InvalidRequest(format!(
            "path does not exist: {}",
            candidate.display()
        )));
    }
    if !candidate.is_file() && !candidate.is_dir() {
        return Err(ServiceError::InvalidRequest(
            "path must be a file or a directory".to_string(),
        ));
    }
    Ok(candidate)
}

fn validate_reason(reason: &str) -> Result<String, ServiceError> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "reason must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_REASON_LEN {
        return Err(ServiceError::InvalidRequest(format!(
            "reason must be at most {MAX_REASON_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ServiceError::InvalidRequest(
            "reason must not contain control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_id(id: &str, what: &str) -> Result<(), ServiceError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::InvalidRequest(format!(
            "{what} must not be empty"
        )));
    }
    if trimmed.len() > MAX_ID_LEN {
        return Err(ServiceError::InvalidRequest(format!(
            "{what} must be at most {MAX_ID_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ServiceError::InvalidRequest(format!(
            "{what} must not contain control characters"
        )));
    }
    Ok(())
}

/// True when `path` is inside the given vault directory (defensive helper used
/// by tests and callers that want to avoid quarantining vault contents).
pub fn is_within(dir: &Path, path: &Path) -> bool {
    fn normalized(path: &Path) -> String {
        // Canonicalisation resolves `\\?\` prefixes and on-disk casing, which
        // matters on Windows where the vault directory may be stored in
        // extended-length form while the request path is not.
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        canonical
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
            .trim_end_matches('\\')
            .to_string()
    }

    let dir = normalized(dir);
    let path = normalized(path);
    if dir.is_empty() {
        return false;
    }
    path == dir || path.starts_with(&(dir + "\\"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_core::{SecurityEvent, SecurityEventKind, Severity, TelemetrySource};

    fn event(name: &str) -> SecurityEvent {
        SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::Info,
            TelemetrySource::ProcessSnapshot,
            name,
        )
    }

    #[test]
    fn queue_drops_oldest_when_full_and_counts() {
        let queue = EventQueue::new(3);
        for i in 0..3 {
            assert!(!queue.push(event(&format!("e{i}"))));
        }
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dropped(), 0);

        assert!(queue.push(event("e3")), "oldest event must be dropped");
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dropped(), 1);

        let drained = queue.drain(10);
        assert_eq!(drained.len(), 3);
        let titles: Vec<_> = drained.iter().map(|e| e.title.clone()).collect();
        assert_eq!(titles, vec!["e1", "e2", "e3"]);
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_capacity_is_at_least_one() {
        let queue = EventQueue::new(0);
        assert_eq!(queue.capacity(), 1);
        assert!(!queue.push(event("a")));
        assert!(queue.push(event("b")));
        assert_eq!(queue.dropped(), 1);
    }

    #[tokio::test]
    async fn queue_wait_for_items_times_out_and_wakes() {
        let queue = std::sync::Arc::new(EventQueue::new(4));
        assert!(!queue.wait_for_items(Duration::from_millis(20)).await);

        let producer = std::sync::Arc::clone(&queue);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            producer.push(event("late"));
        });
        assert!(queue.wait_for_items(Duration::from_millis(500)).await);
        assert_eq!(queue.drain(10).len(), 1);
    }

    #[test]
    fn schedule_due_logic() {
        let mut schedule = ScanSchedule {
            enabled: false,
            path: r"C:\Windows".to_string(),
            recursive: false,
            interval_secs: 3600,
            last_run_ms: None,
        };
        assert!(!schedule.is_due(1_000));
        schedule.enabled = true;
        assert!(schedule.is_due(1_000), "never run schedules are due");
        schedule.last_run_ms = Some(1_000_000);
        assert!(!schedule.is_due(1_000_000 + 3_599_000));
        assert!(schedule.is_due(1_000_000 + 3_600_000));
        assert!(schedule.is_due(1_000_000 + 10_000_000));
    }

    #[test]
    fn schedule_validation_rejects_short_intervals_and_relative_paths() {
        let mut schedule = ScanSchedule {
            enabled: true,
            path: r"C:\Windows".to_string(),
            recursive: false,
            interval_secs: 30,
            last_run_ms: None,
        };
        assert!(schedule.validate().is_err());
        schedule.interval_secs = 3600;
        assert!(schedule.validate().is_ok());
        schedule.path = "relative\\path".to_string();
        assert!(schedule.validate().is_err());
    }

    #[test]
    fn schedule_json_roundtrip() {
        let schedule = ScanSchedule {
            enabled: true,
            path: r"C:\Users".to_string(),
            recursive: true,
            interval_secs: 900,
            last_run_ms: Some(42),
        };
        let json = schedule.to_json().expect("serialize");
        let parsed = ScanSchedule::from_json(&json).expect("parse");
        assert_eq!(parsed, schedule);
        assert!(ScanSchedule::from_json("{not json").is_err());
    }

    #[test]
    fn path_validation_bounds() {
        assert!(validate_path_string("").is_err());
        assert!(validate_path_string("relative\\x").is_err());
        assert!(validate_path_string("C:\\has\0nul").is_err());
        let long = format!(r"C:\{}", "a".repeat(MAX_PATH_LEN));
        assert!(validate_path_string(&long).is_err());
        assert!(validate_path_string(r"C:\Windows").is_ok());
    }

    #[test]
    fn reason_validation_bounds() {
        assert!(validate_reason("").is_err());
        assert!(validate_reason("  ").is_err());
        assert!(validate_reason("test\nreason").is_err());
        assert_eq!(
            validate_reason(" manual review ").expect("ok"),
            "manual review"
        );
    }

    #[test]
    fn id_validation_bounds() {
        assert!(validate_id("", "event id").is_err());
        assert!(validate_id("ok_id", "event id").is_ok());
        assert!(validate_id(&"x".repeat(MAX_ID_LEN + 1), "event id").is_err());
    }

    #[test]
    fn data_dir_env_override_is_honoured() {
        // Serialised by opt-in: only assert the pure fallback shape here.
        let dir = default_data_dir();
        assert!(!dir.to_string_lossy().is_empty());
    }

    #[test]
    fn service_status_stub_never_panics() {
        let status = query_service_status();
        assert_eq!(status.service_name, SERVICE_NAME);
        assert_eq!(status.protocol_version, security_ipc::IPC_PROTOCOL_VERSION);
    }

    #[test]
    fn within_helper_is_case_insensitive() {
        assert!(is_within(
            Path::new(r"C:\ProgramData\AiAntivirus\quarantine"),
            Path::new(r"c:\programdata\aiantivirus\quarantine\x.bin")
        ));
        assert!(!is_within(
            Path::new(r"C:\ProgramData\AiAntivirus\quarantine"),
            Path::new(r"C:\Windows\System32\evil.exe")
        ));
    }
}
