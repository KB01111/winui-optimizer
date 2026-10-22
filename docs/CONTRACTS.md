# AI Antivirus — Shared Contracts (v1.0)

This document is the coordination contract for every workstream. Do not change
types or signatures in this document without updating the orchestrator first.

## Ground rules

- Shared domain types live in `crates/security-core`. **Nobody except the
  orchestrator edits `security-core` after this point.**
- Crate `Cargo.toml` manifests are frozen. Add code and tests only; if a
  dependency is missing, report it to the orchestrator instead of editing the
  root `Cargo.toml`.
- Never weaken Defender, Tamper Protection, or existing Windows security.
- The engine must remain fully functional with **no AI provider configured**.
- AI can never call quarantine or any destructive operation directly. Only
  `security-policy` decides outcomes, from deterministic signals.
- All data shown in the UI must be real. Empty states are acceptable; fake rows
  are not.
- No `.unwrap()` in production paths for untrusted input. Tests may unwrap.

## Dependency direction

```text
security-core
  ^   ^   ^   ^   ^   ^   ^
  |   |   |   |   |   |   |
policy scanner telemetry storage ai-decisions ai-local windows-integration security-ipc
                                   ^
                       security-service (all crates)
                                   ^
                              src-tauri (desktop)
```

No crate other than `security-service` may depend on more than one leaf crate
without orchestrator approval.

## security-core (frozen)

Key types (all serde `camelCase`):

- `Severity { Info, Low, Medium, High, Critical }`
- `RiskLevel { Unknown, Clean, Low, Medium, High, Critical }`
- `SecurityEventKind`, `TelemetrySource`, `DetectionSource`, `ScanSource`,
  `ScanState`, `PolicyOutcome`, `DecisionCategory`, `QuarantineStatus`
- `ProcessRef`, `FileRef`, `PeMetadata`, `SignatureInfo`, `Detection`
- `RiskSignals` with `deterministic_score() -> f32` in `[0,100]` and
  `RiskAssessment::from_signals()`
- `SecurityEventState` + `ProcessState`, `FileState`, `BehaviorState`,
  `DetectionState`, `DeterministicSummary` — the redacted payload sent to AI
- `SecurityEvent`, `FileScanReport`, `ScanJobSummary`, `ScanProgress`
- `DecisionResult`, `PolicyDecision`, `QuarantineRecord`, `RestoreResult`

`new_id(prefix)` creates record ids.

## Required public APIs per crate

### security-policy
```rust
pub struct PolicyConfig {
    pub auto_quarantine_enabled: bool,          // default: false
    pub auto_quarantine_min_score: f32,         // default: 90.0
    pub auto_quarantine_requires_known_hash: bool, // default: true
    pub investigate_min_score: f32,             // default: 40.0
    pub alert_min_score: f32,                   // default: 70.0
}
pub struct PolicyEngine { /* config */ }
impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self;
    pub fn config(&self) -> &PolicyConfig;
    pub fn evaluate_event(&self, event: &SecurityEvent) -> PolicyDecision;
    pub fn evaluate_scan(&self, report: &FileScanReport, ai: Option<&DecisionResult>) -> PolicyDecision;
    /// AI-only input can never produce Quarantine.
    pub fn evaluate_ai_only(&self, ai: &DecisionResult, assessment: &RiskAssessment) -> PolicyDecision;
}
```
Behavioral invariants that MUST have tests:
1. `evaluate_ai_only` never returns `Quarantine`, for any input.
2. `evaluate_scan` returns `Quarantine` only when the deterministic hash/YARA
   rules match and `auto_quarantine_enabled` is true.
3. Known-malware hash => at least `Alert` even with auto-quarantine disabled.
4. Reason strings and matched rule ids are stable, auditable strings.

### security-scanner
```rust
pub struct ScannerConfig {
    pub max_file_size: u64,        // default 128 MiB
    pub max_hash_size: u64,        // default 512 MiB
    pub yara_timeout_ms: u64,      // default 5000
    pub follow_symlinks: bool,     // default false
    pub extra_yara_rules: Option<String>,
}
pub struct Scanner { /* ... */ }
impl Scanner {
    pub fn new(config: ScannerConfig) -> Result<Self, ScanError>;
    pub fn scan_file(&self, path: &std::path::Path, source: ScanSource) -> Result<FileScanReport, ScanError>;
    pub fn scan_path(&self, root: &std::path::Path, recursive: bool, cancel: &std::sync::atomic::AtomicBool, progress: &dyn Fn(ScanProgress)) -> ScanSummary;
}
pub struct ScanSummary { pub files_scanned: u64, pub detections: u64, pub errors: u64, pub reports: Vec<FileScanReport>, pub cancelled: bool }
pub fn compute_sha256(path: &std::path::Path) -> std::io::Result<String>;
pub fn shannon_entropy(data: &[u8]) -> f32;
pub fn analyze_pe(data: &[u8]) -> Option<PeMetadata>;
pub fn default_yara_rules() -> &'static str;
```

Quarantine vault:
```rust
pub struct QuarantineVault { /* ... */ }
impl QuarantineVault {
    pub fn new(vault_dir: impl Into<std::path::PathBuf>) -> std::io::Result<Self>;
    pub fn quarantine(&self, path: &std::path::Path, reason: &str, detection_id: Option<String>) -> Result<QuarantineRecord, ScanError>;
    pub fn restore(&self, id: &str) -> Result<RestoreResult, ScanError>;
    pub fn list(&self) -> Vec<QuarantineRecord>;
    /// Explicit, user-initiated permanent deletion of a quarantined copy.
    pub fn delete(&self, id: &str) -> Result<(), ScanError>;
}
```
Vault invariants: reject symlinks/reparse points, verify SHA-256 before
quarantine and again before restore, collision-safe stored names
(`<sha256-prefix>-<timestamp>-<name>`), never touch files outside the vault on
restore except the recorded original path, never delete originals automatically.

### security-telemetry
```rust
pub trait ProcessSnapshotProvider: Send + Sync {
    fn snapshot(&self) -> Result<Vec<ProcessRef>, TelemetryError>;
}
pub struct WindowsProcessSnapshot; // Toolhelp32-based, cfg(windows)
pub struct SyntheticProcessSnapshot; // test-only provider

pub struct ProcessMonitor { /* diffs snapshots, emits ProcessCreated/Terminated */ }
impl ProcessMonitor {
    pub fn new(provider: Box<dyn ProcessSnapshotProvider>) -> Self;
    pub fn poll(&mut self) -> Vec<SecurityEvent>; // never panics on provider errors
}

pub struct EventLogReader; // cfg(windows); reads PowerShell operational log 4104 + Defender system events
impl EventLogReader {
    pub fn new() -> Result<Self, TelemetryError>;
    pub fn available(&self) -> bool;
    /// Returns at most `max` events newer than `since_ms`.
    pub fn poll(&self, since_ms: i64, max: usize) -> Result<Vec<SecurityEvent>, TelemetryError>;
}

pub struct CorrelationEngine { /* ... */ }
impl CorrelationEngine {
    /// Feed every observed event; returns zero or more correlated events.
    pub fn ingest(&mut self, event: &SecurityEvent) -> Vec<SecurityEvent>;
    pub fn chains(&self) -> Vec<ProcessChain>; // for the UI
}
pub struct ProcessChain {
    pub root_pid: u32,
    pub events: Vec<String>, // event ids
    pub signals: RiskSignals,
    pub correlation_id: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}
```
Correlation rules must be deterministic and unit-tested with synthetic events,
for example: unsigned executable -> spawns script host -> writes startup
persistence -> fractional score crosses the alerting threshold.

### security-storage
SQLite via `rusqlite` (bundled). Owned by the orchestrator.

```rust
pub struct Database { /* Connection behind Mutex */ }
impl Database {
    pub fn open(path: &std::path::Path) -> Result<Self, StorageError>;
    pub fn open_in_memory() -> Result<Self, StorageError>;
    pub fn schema_version(&self) -> Result<u32, StorageError>;
    pub fn insert_event(&self, event: &SecurityEvent) -> Result<(), StorageError>;
    pub fn get_event(&self, id: &str) -> Result<Option<SecurityEvent>, StorageError>;
    pub fn query_events(&self, filter: &EventFilter) -> Result<EventPage, StorageError>;
    pub fn insert_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError>;
    pub fn update_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError>;
    pub fn list_scan_jobs(&self, limit: u32) -> Result<Vec<ScanJobSummary>, StorageError>;
    pub fn insert_scan_result(&self, job_id: &str, report: &FileScanReport) -> Result<(), StorageError>;
    pub fn find_cached_report(&self, sha256: &str, size: u64) -> Result<Option<FileScanReport>, StorageError>;
    pub fn insert_decision(&self, event_id: Option<&str>, decision: &DecisionResult) -> Result<(), StorageError>;
    pub fn decisions_for_event(&self, event_id: &str) -> Result<Vec<DecisionResult>, StorageError>;
    pub fn insert_quarantine(&self, record: &QuarantineRecord) -> Result<(), StorageError>;
    pub fn update_quarantine_status(&self, id: &str, status: QuarantineStatus, restored_at_ms: Option<i64>) -> Result<(), StorageError>;
    pub fn list_quarantine(&self, limit: u32) -> Result<Vec<QuarantineRecord>, StorageError>;
    pub fn upsert_provider_health(&self, health: &ProviderHealth) -> Result<(), StorageError>;
    pub fn provider_health(&self) -> Result<Vec<ProviderHealth>, StorageError>;
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError>;
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StorageError>;
    pub fn purge_events_older_than(&self, timestamp_ms: i64) -> Result<u64, StorageError>;
}
pub struct EventFilter { pub limit: u32, pub offset: u32, pub severity: Option<Severity>, pub kind: Option<SecurityEventKind>, pub search: Option<String>, pub correlation_id: Option<String>, pub since_ms: Option<i64> }
pub struct EventPage { pub items: Vec<SecurityEvent>, pub total: u64, pub next_offset: Option<u32> }
pub struct ProviderHealth { /* see ai-decisions */ } // re-exported here
```
Required tables: `security_events`, `processes`, `process_relationships`,
`files`, `scan_results`, `detections`, `decision_results`, `quarantine_records`,
`scan_jobs`, `application_settings`, `provider_health`, `schema_migrations`.
Use `PRAGMA user_version` for explicit schema versions. Tests must cover
migrations and each query path with an in-memory DB.

### ai-decisions
```rust
#[async_trait]
pub trait DecisionProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn model(&self) -> &str;
    fn is_configured(&self) -> bool;
    async fn classify(&self, state: &SecurityEventState) -> Result<DecisionResult, DecisionError>;
    async fn health(&self) -> ProviderHealth;
}

pub struct JevProvider;                // typesafe/jev-1.14
pub struct MercuryDecideProvider;      // inception/mercury-decide
pub struct MercuryDecideFreeProvider;  // inception/mercury-decide:free
pub struct MockDecisionProvider;       // never touches the network

pub enum AiMode { Offline, Cloud, Hybrid }
pub struct AiConfig { pub mode: AiMode, pub api_key: Option<String>, pub primary_model: String, pub escalation_model: String, pub timeout_ms: u64, pub max_retries: u32, pub requests_per_minute: u32, pub daily_cost_limit_usd: f64, pub allow_cloud_state: bool }
pub struct ProviderHealth { pub provider: String, pub model: String, pub status: ProviderStatus, pub successes: u64, pub failures: u64, pub last_latency_ms: Option<u64>, pub last_error: Option<String>, pub total_cost_usd: f64, pub requests: u64, pub checked_at_ms: i64 }
pub enum ProviderStatus { Unknown, Healthy, Degraded, Unavailable, Offline }

pub struct ProviderRouter { /* ... */ }
impl ProviderRouter {
    pub fn new(config: AiConfig) -> Result<Self, DecisionError>;
    pub fn with_provider(config: AiConfig, provider: Box<dyn DecisionProvider>) -> Result<Self, DecisionError>;
    pub fn offline(config: AiConfig) -> Self;
    /// Routing: deterministic rules -> primary (Mercury) -> escalation (Jev) when uncertain.
    pub async fn classify(&self, state: &SecurityEventState, assessment: &RiskAssessment) -> Result<RoutedDecision, DecisionError>;
}
pub struct RoutedDecision { pub primary: Option<DecisionResult>, pub escalation: Option<DecisionResult>, pub final_result: Option<DecisionResult>, pub route: DecisionRoute, pub deterministic_only: bool }
pub enum DecisionRoute { SkippedByPolicy, SkippedOffline, PrimaryOnly, Escalated, FailedClosed }
pub fn redact_state(state: &SecurityEventState) -> SecurityEventState;
pub fn build_decision_state(event: &SecurityEvent, assessment: &RiskAssessment) -> SecurityEventState;
```

OpenRouter Decisions API (verified 2026-10-19):
- `POST https://openrouter.ai/api/alpha/decisions`
- Headers: `Authorization: Bearer <key>`, `Content-Type: application/json`
- Body: `{ "model": "...", "state": <string|object|array>, "questions": { "<name>": { "type": "noul"|"choice"|"score"|"box", "instructions": "...", "criteria": ... } } }`
- Response: `{ "id", "model", "provider", "answers": { "<name>": { "type": "noul", "noul": 0.96 } | { "type": "choice", "choice": "x", "confidence": 0.75, "probabilities": {...} } | { "type": "score", "score": 1.99, "confidence": 0.99, "probabilities": {...}, "legend": {...} } }, "usage": { "input_tokens", "output_tokens", "cost" } }`
- Required questions: `classification` (choice: benign/suspicious/likely_malicious/unknown),
  `requires_investigation` (noul), `persistence` (noul), `credential_theft` (noul),
  `ransomware` (noul).
- Never use chat completions for these models.
- Redaction must be applied when `allow_cloud_state` is true but still removes
  usernames, absolute paths, command lines, and full hashes (a short prefix is
  allowed).
- Retry with exponential backoff on 429/5xx, honor timeouts, enforce rate limit
  and daily cost limit, cache by state hash (TTL 10 min), and fail closed to
  `DecisionRoute::FailedClosed` without blocking scanning.

### ai-local
```rust
pub struct HardwareProfile { pub cpu_arch: String, pub cpu_name: Option<String>, pub logical_cores: u32, pub physical_cores: Option<u32>, pub total_ram_mb: u64, pub available_ram_mb: u64, pub gpus: Vec<GpuAdapter>, pub npu: Option<NpuInfo>, pub battery: BatteryState }
pub struct GpuAdapter { pub name: String, pub vendor: String, pub dedicated_vram_mb: u64, pub is_discrete: bool, pub is_software: bool }
pub struct NpuInfo { pub name: String, pub available: bool, pub driver_hint: Option<String> }
pub struct BatteryState { pub present: bool, pub percent: Option<u8>, pub ac_online: bool, pub charging: bool }
pub fn detect_hardware() -> HardwareProfile; // never panics; unknown fields are None
pub enum PowerMode { Battery, Ac }
pub enum RuntimeKind { Cpu, Npu, IntegratedGpu, DiscreteGpu, Cloud }
pub struct InferenceRoute { pub primary: RuntimeKind, pub fallback: RuntimeKind, pub reason: String, pub allow_discrete_gpu: bool }
pub fn select_route(profile: &HardwareProfile, mode: PowerMode, ai: AiMode) -> InferenceRoute;
#[async_trait]
pub trait LocalDecisionModel: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    async fn classify(&self, state: &SecurityEventState) -> Result<DecisionResult, LocalAiError>;
}
pub struct MockLocalDecisionModel;
```
Hard rule: on battery, never choose `DiscreteGpu` for routine background
analysis. NPU must only be selected when a validated compatible runtime is
present; otherwise route to CPU and say so in `reason`.

### windows-integration
```rust
pub struct PackageIdentityInfo { pub available: bool, pub family_name: Option<String>, pub full_name: Option<String>, pub publisher: Option<String>, pub version: Option<String>, pub install_location: Option<String>, pub app_user_model_id: Option<String> }
pub fn package_identity() -> PackageIdentityInfo;
pub struct WindowsVersion { pub major: u32, pub minor: u32, pub build: u32, pub revision: u32, pub display_version: String, pub edition: String, pub architecture: String, pub is_windows_11: bool }
pub fn windows_version() -> WindowsVersion;
pub struct ExecutionContext { pub packaged: bool, pub elevated: bool, pub user_sid: Option<String>, pub username_redacted: Option<String>, pub process_id: u32, pub session_id: Option<u32> }
pub fn execution_context() -> ExecutionContext;

pub struct DefenderStatus { pub available: bool, pub query_error: Option<String>, pub realtime_enabled: bool, pub antivirus_enabled: bool, pub antispyware_enabled: bool, pub tamper_protected: bool, pub engine_version: Option<String>, pub signature_version: Option<String>, pub signature_age_days: Option<u32>, pub last_quick_scan_ms: Option<i64>, pub last_full_scan_ms: Option<i64>, pub threats_detected: Option<u64>, pub definition_status: Option<String>, pub checked_at_ms: i64 }
pub fn defender_status() -> DefenderStatus; // read-only via Get-MpComputerStatus, never modifies

pub enum NotificationOutcome { Sent, NoPackageIdentity, Unsupported, Failed(String) }
pub fn notifications_supported() -> bool;
pub fn show_notification(title: &str, body: &str, tag: &str) -> NotificationOutcome;

pub fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError>;   // DPAPI
pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError>;
```
Notifications must only be attempted when package identity exists; the Rust
function returns `NoPackageIdentity` instead of throwing. Defender query must
use `-NonInteractive -NoProfile`, a timeout, and must never modify settings.

### security-ipc
```rust
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\ai-antivirus-security";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub enum ClientRequest {
    Ping,
    GetStatus,
    ScanPath { path: String, recursive: bool },
    CancelScan { job_id: String },
    ListEvents { limit: u32, offset: u32 },
    GetEvent { event_id: String },
    ListQuarantine,
    QuarantineFile { path: String, reason: String },
    RestoreQuarantine { id: String },
    Subscribe,
}
pub enum ServerResponse {
    Pong { version: String, uptime_secs: u64 },
    Status(serde_json::Value),
    ScanAccepted { job_id: String },
    Cancelled { job_id: String, cancelled: bool },
    Events(serde_json::Value),
    Event(serde_json::Value),
    Quarantine(Vec<serde_json::Value>),
    QuarantineRecord(serde_json::Value),
    Restore(serde_json::Value),
    Subscribed,
    Error { code: String, message: String },
}
pub fn encode_frame(message: &impl Serialize) -> Result<Vec<u8>, IpcError>;
pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, IpcError>;
pub struct RateLimiter { /* token bucket */ }
```
Pipe DACL must grant the interactive user, SYSTEM and Administrators only.
Enforce frame size, JSON validation, per-client rate limits, and log security
relevant rejections. Test framing and limits without requiring a live pipe.

### security-service
- `security_service::ServiceEngine`: owns storage + monitor + correlation +
  policy + scanner + optional AI router.
- Pipe handlers implement `security-ipc::ClientRequest`.
- `security-service.exe --console` runs in the foreground for development;
  default runs as a Windows service (`windows-service` crate) named
  `AiAntivirusSecurityService`, display name "AI Antivirus Security Engine",
  start type manual by default.
- `packaging/service-installer/install-service.ps1` / `uninstall-service.ps1`
  register the service with least privilege (LocalService) and document that
  MSIX cannot install privileged services; service installation requires an
  elevated signed-installer step.

## Desktop Tauri command contract

Events emitted by the backend (payload types from `security-core`):

| Event name | Payload |
| --- | --- |
| `engine://event` | `SecurityEvent` |
| `engine://scan-progress` | `ScanProgress` |
| `engine://provider-health` | `ProviderHealth` |
| `engine://status` | `EngineState` |

Commands (all return `Result<T, String>` where errors are printable):

| Command | Args | Returns |
| --- | --- | --- |
| `get_system_status` | — | `SystemStatus` |
| `get_hardware_profile` | — | `HardwareProfile` |
| `get_engine_state` | — | `EngineState` |
| `start_monitoring` | — | `EngineState` |
| `stop_monitoring` | — | `EngineState` |
| `scan_path` | `{ request: { path, recursive } }` | `ScanJobSummary` |
| `cancel_scan` | `{ jobId }` | `bool` |
| `get_scan_results` | `{ jobId, limit }` | `Vec<FileScanReport>` |
| `list_scan_jobs` | `{ limit }` | `Vec<ScanJobSummary>` |
| `list_events` | `{ filter: EventFilter }` | `EventPage` |
| `get_event` | `{ eventId }` | `SecurityEventDetail` |
| `list_quarantine` | — | `Vec<QuarantineRecord>` |
| `quarantine_file` | `{ path, reason }` | `QuarantineRecord` |
| `restore_quarantine` | `{ id }` | `RestoreResult` |
| `delete_quarantine` | `{ id }` | `bool` |
| `get_ai_status` | — | `AiStatus` |
| `configure_ai` | `{ config: AiConfigInput }` | `AiStatus` |
| `test_ai_provider` | `{ model }` | `ProviderTestResult` |
| `classify_event` | `{ eventId }` | `Option<DecisionResult>` |
| `get_settings` | — | `serde_json::Value` |
| `update_settings` | `{ patch: serde_json::Value }` | `serde_json::Value` |
| `send_test_notification` | — | `NotificationOutcome` |
| `get_service_status` | — | `ServiceStatus` |

`SystemStatus` (camelCase):
```ts
{
  productName: string; version: string;
  packageIdentity: PackageIdentityInfo;
  windows: WindowsVersion;
  execution: ExecutionContext;
  defender: DefenderStatus;
  engine: EngineState;
  ai: AiStatus;
  hardware: HardwareProfile;
  service: ServiceStatus;
  privacy: { cloudAiEnabled: boolean; storeRawPaths: boolean; telemetryLocalOnly: boolean };
}
```

Dashboard TypeScript types must mirror these serialized structs. If a type is
missing, request it from the orchestrator instead of inventing a shape.
