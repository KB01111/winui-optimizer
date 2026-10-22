//! Shared domain contracts for the AI Antivirus engine.
//!
//! This crate intentionally contains no platform code and no I/O. Every other
//! crate in the workspace depends on these types so that the scanner, policy
//! engine, AI providers, storage layer and UI all speak the same vocabulary.
//!
//! All serialized types use `camelCase` field names so they can be consumed
//! directly by the React/TypeScript dashboard.

use serde::{Deserialize, Serialize};

/// Milliseconds since the Unix epoch (UTC).
pub type TimestampMs = i64;

/// Stable identifier for a stored event, detection or decision.
pub type RecordId = String;

/// Create a new random record id with a human-readable prefix.
pub fn new_id(prefix: &str) -> RecordId {
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}

/// Severity attached to events, detections and alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Numeric weight used by deterministic scoring.
    pub fn weight(&self) -> f32 {
        match self {
            Self::Info => 0.0,
            Self::Low => 10.0,
            Self::Medium => 25.0,
            Self::High => 55.0,
            Self::Critical => 85.0,
        }
    }
}

/// Coarse risk bucket derived from a numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Unknown,
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 90.0 => Self::Critical,
            s if s >= 70.0 => Self::High,
            s if s >= 40.0 => Self::Medium,
            s if s >= 15.0 => Self::Low,
            s if s <= 0.0 => Self::Clean,
            _ => Self::Unknown,
        }
    }
}

/// What kind of security observation an event represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    ProcessCreated,
    ProcessTerminated,
    FileCreated,
    FileModified,
    PersistenceIndicator,
    ScriptActivity,
    NetworkActivity,
    DefenderStatus,
    ScanStarted,
    ScanCompleted,
    Detection,
    PolicyDecision,
    AiDecision,
    ProviderHealth,
    Correlation,
    EngineStatus,
}

impl SecurityEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessCreated => "process_created",
            Self::ProcessTerminated => "process_terminated",
            Self::FileCreated => "file_created",
            Self::FileModified => "file_modified",
            Self::PersistenceIndicator => "persistence_indicator",
            Self::ScriptActivity => "script_activity",
            Self::NetworkActivity => "network_activity",
            Self::DefenderStatus => "defender_status",
            Self::ScanStarted => "scan_started",
            Self::ScanCompleted => "scan_completed",
            Self::Detection => "detection",
            Self::PolicyDecision => "policy_decision",
            Self::AiDecision => "ai_decision",
            Self::ProviderHealth => "provider_health",
            Self::Correlation => "correlation",
            Self::EngineStatus => "engine_status",
        }
    }
}

/// Where a telemetry observation came from. Documented so the UI can be
/// explicit about which data is directly observed versus inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetrySource {
    /// Windows Toolhelp process snapshot diffing.
    ProcessSnapshot,
    /// Windows Event Log (for example PowerShell operational log).
    WindowsEventLog,
    /// A user-requested or scheduled file scan.
    FileScanner,
    /// Correlation of two or more observed events.
    Correlation,
    /// Microsoft Defender status query (read-only).
    Defender,
    /// The application's own lifecycle.
    Engine,
}

/// Process identity captured from a snapshot or event payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub signed: Option<bool>,
    pub signer: Option<String>,
    pub sha256: Option<String>,
    pub user: Option<String>,
    pub started_at_ms: Option<TimestampMs>,
}

/// File metadata captured during a scan. File contents are never stored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRef {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub entropy: Option<f32>,
    pub is_pe: bool,
    pub pe: Option<PeMetadata>,
    pub signature: Option<SignatureInfo>,
    pub created_at_ms: Option<TimestampMs>,
    pub modified_at_ms: Option<TimestampMs>,
}

/// A subset of the PE header that is useful for triage.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeMetadata {
    pub machine: String,
    pub subsystem: String,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub timestamp: Option<u32>,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<String>,
    pub entry_point: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f32,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeImport {
    pub dll: String,
    pub functions: Vec<String>,
}

/// Authenticode signature metadata. We report what Windows reports; we do not
/// claim to validate trust beyond the reported status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub present: bool,
    pub status: String,
    pub signer: Option<String>,
    pub issuer: Option<String>,
    pub thumbprint: Option<String>,
}

/// A single deterministic detection produced by the Rust engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub id: RecordId,
    pub rule_id: String,
    pub rule_name: String,
    pub source: DetectionSource,
    pub severity: Severity,
    pub description: String,
    pub score_contribution: f32,
    pub evidence: Vec<String>,
    pub created_at_ms: TimestampMs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    Yara,
    KnownHash,
    PeHeuristic,
    BehaviorRule,
    Policy,
    Defender,
}

/// Feature signals extracted deterministically and fed to the policy engine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSignals {
    pub known_malware_hash: bool,
    pub yara_matches: u32,
    pub unsigned_executable: bool,
    pub invalid_signature: bool,
    pub suspicious_imports: bool,
    pub persistence_attempt: bool,
    pub obfuscated_script: bool,
    pub unusual_network_activity: bool,
    pub suspicious_parent: bool,
    pub high_entropy: bool,
    pub writable_executable_section: bool,
    pub credential_access_indicator: bool,
    pub ransomware_indicator: bool,
    pub startup_folder_write: bool,
    pub temp_execution: bool,
    pub living_off_the_land_binary: bool,
}

impl RiskSignals {
    /// Deterministic score in `[0, 100]`. Every weight is explicit and tested;
    /// AI output is never part of this calculation.
    pub fn deterministic_score(&self) -> f32 {
        let mut score: f32 = 0.0;
        if self.known_malware_hash {
            return 100.0;
        }
        if self.yara_matches > 0 {
            score += 45.0 + (self.yara_matches.min(4) as f32 - 1.0) * 5.0;
        }
        if self.credential_access_indicator {
            score += 18.0;
        }
        if self.ransomware_indicator {
            score += 25.0;
        }
        if self.persistence_attempt {
            score += 12.0;
        }
        if self.startup_folder_write {
            score += 10.0;
        }
        if self.obfuscated_script {
            score += 10.0;
        }
        if self.unusual_network_activity {
            score += 8.0;
        }
        if self.suspicious_imports {
            score += 10.0;
        }
        if self.writable_executable_section {
            score += 10.0;
        }
        if self.high_entropy {
            score += 5.0;
        }
        if self.unsigned_executable {
            score += 6.0;
        }
        if self.invalid_signature {
            score += 12.0;
        }
        if self.suspicious_parent {
            score += 6.0;
        }
        if self.temp_execution {
            score += 6.0;
        }
        if self.living_off_the_land_binary {
            score += 4.0;
        }
        score.min(100.0)
    }
}

/// Deterministic risk assessment, including the human-readable reasons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub score: f32,
    pub level: RiskLevel,
    pub signals: RiskSignals,
    pub reasons: Vec<String>,
    /// True when the score came only from deterministic rules.
    pub deterministic: bool,
}

impl RiskAssessment {
    pub fn from_signals(signals: RiskSignals) -> Self {
        let score = signals.deterministic_score();
        Self {
            score,
            level: RiskLevel::from_score(score),
            reasons: signals.explain(),
            signals,
            deterministic: true,
        }
    }
}

impl RiskSignals {
    /// Human readable explanations for every active signal.
    pub fn explain(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.known_malware_hash {
            reasons.push("SHA-256 matches a known malicious sample identifier".into());
        }
        if self.yara_matches > 0 {
            reasons.push(format!("{} YARA rule match(es)", self.yara_matches));
        }
        if self.unsigned_executable {
            reasons.push("Executable is not Authenticode signed".into());
        }
        if self.invalid_signature {
            reasons.push("Authenticode signature is present but not valid".into());
        }
        if self.suspicious_imports {
            reasons.push("Imports include APIs commonly abused by malware".into());
        }
        if self.persistence_attempt {
            reasons.push("Process attempted a persistence mechanism".into());
        }
        if self.obfuscated_script {
            reasons.push("Script content shows obfuscation indicators".into());
        }
        if self.unusual_network_activity {
            reasons.push("Unusual outbound network activity observed".into());
        }
        if self.suspicious_parent {
            reasons.push("Parent process is a script host or uncommon launcher".into());
        }
        if self.high_entropy {
            reasons.push("File or section entropy is unusually high".into());
        }
        if self.writable_executable_section {
            reasons.push("PE section is both writable and executable".into());
        }
        if self.credential_access_indicator {
            reasons.push("Behavior consistent with credential access".into());
        }
        if self.ransomware_indicator {
            reasons.push("Behavior consistent with ransomware activity".into());
        }
        if self.startup_folder_write {
            reasons.push("Write to a startup persistence location".into());
        }
        if self.temp_execution {
            reasons.push("Executable launched from a temporary directory".into());
        }
        if self.living_off_the_land_binary {
            reasons.push("Known built-in Windows binary used in an unusual context".into());
        }
        reasons
    }
}

/// Decision categories returned by decision models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionCategory {
    Benign,
    Suspicious,
    LikelyMalicious,
    Unknown,
}

/// Output of a decision provider (Jev, Mercury Decide, local mock).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionResult {
    pub id: RecordId,
    pub provider: String,
    pub model: String,
    pub model_version: Option<String>,
    pub category: DecisionCategory,
    pub probabilities: std::collections::BTreeMap<String, f32>,
    pub confidence: f32,
    pub requires_investigation: bool,
    pub suspicious_persistence: bool,
    pub credential_theft: bool,
    pub ransomware: bool,
    pub latency_ms: u64,
    pub timestamp_ms: TimestampMs,
    pub evidence: Vec<String>,
    pub cost_usd: Option<f64>,
    pub escalated: bool,
}

/// Structured state sent to a decision model. Redaction happens before this is
/// serialized for a cloud provider; see `ai-decisions::redaction`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventState {
    pub event_id: RecordId,
    pub event_type: String,
    pub timestamp_ms: TimestampMs,
    pub process: Option<ProcessState>,
    pub file: Option<FileState>,
    pub behavior: BehaviorState,
    pub detections: DetectionState,
    pub deterministic: DeterministicSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessState {
    pub name: String,
    pub signed: Option<bool>,
    pub parent: Option<String>,
    pub command_line_redacted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileState {
    pub name: String,
    pub extension: Option<String>,
    pub size: u64,
    pub sha256_prefix: Option<String>,
    pub in_temp: bool,
    pub in_startup: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorState {
    pub persistence_attempt: bool,
    pub obfuscated_script: bool,
    pub unusual_network_activity: bool,
    pub credential_access: bool,
    pub ransomware: bool,
    pub spawned_script_host: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionState {
    pub known_malware_hash: bool,
    pub yara_matches: Vec<String>,
    pub heuristic_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeterministicSummary {
    pub score: f32,
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

impl From<&RiskAssessment> for DeterministicSummary {
    fn from(value: &RiskAssessment) -> Self {
        Self {
            score: value.score,
            level: value.level,
            reasons: value.reasons.clone(),
        }
    }
}

/// One observed security event, stored immutably.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: RecordId,
    pub timestamp_ms: TimestampMs,
    pub kind: SecurityEventKind,
    pub severity: Severity,
    pub source: TelemetrySource,
    pub title: String,
    pub description: String,
    pub process: Option<ProcessRef>,
    pub file: Option<FileRef>,
    pub detections: Vec<Detection>,
    pub assessment: Option<RiskAssessment>,
    pub correlation_id: Option<RecordId>,
    pub labels: Vec<String>,
    /// Bounded, structured evidence. Never contains file contents.
    pub evidence: serde_json::Value,
}

impl SecurityEvent {
    pub fn new(
        kind: SecurityEventKind,
        severity: Severity,
        source: TelemetrySource,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: new_id("evt"),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            kind,
            severity,
            source,
            title: title.into(),
            description: String::new(),
            process: None,
            file: None,
            detections: Vec::new(),
            assessment: None,
            correlation_id: None,
            labels: Vec::new(),
            evidence: serde_json::Value::Null,
        }
    }
}

/// A report produced for a single file scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileScanReport {
    pub id: RecordId,
    pub file: FileRef,
    pub detections: Vec<Detection>,
    pub assessment: RiskAssessment,
    pub source: ScanSource,
    pub duration_ms: u64,
    pub scanned_at_ms: TimestampMs,
    pub cache_hit: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSource {
    Manual,
    Scheduled,
    Realtime,
}

/// Lifecycle of a scan job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Summary of a scan job, safe to send to the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobSummary {
    pub id: RecordId,
    pub path: String,
    pub recursive: bool,
    pub state: ScanState,
    pub started_at_ms: TimestampMs,
    pub finished_at_ms: Option<TimestampMs>,
    pub files_scanned: u64,
    pub detections: u64,
    pub errors: u64,
    pub current_path: Option<String>,
    pub cancelled: bool,
}

/// Lifecycle of a quarantined file. Deletion is only performed on explicit
/// user request; automated flows always keep the copied original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
}

/// Auditable quarantine record. The original bytes are stored in a restricted
/// vault directory with collision-safe naming; the original path is preserved
/// for restore and never deleted automatically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineRecord {
    pub id: RecordId,
    pub original_path: String,
    pub original_name: String,
    pub stored_path: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at_ms: TimestampMs,
    pub status: QuarantineStatus,
    pub restored_at_ms: Option<TimestampMs>,
    pub detection_id: Option<RecordId>,
    pub reason: String,
    pub identity_verified: bool,
}

/// Result of a restore attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub id: RecordId,
    pub restored_path: Option<String>,
    pub success: bool,
    pub message: String,
}

/// Progress notification emitted while a scan is running.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub job_id: RecordId,
    pub state: ScanState,
    pub files_scanned: u64,
    pub current_path: Option<String>,
    pub detections: u64,
    pub errors: u64,
}

/// Health of one decision provider/model pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Unknown,
    Healthy,
    Degraded,
    Unavailable,
    Offline,
}

/// Provider health snapshot persisted by the storage layer and surfaced in the
/// AI Intelligence dashboard page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderHealth {
    pub provider: String,
    pub model: String,
    pub status: ProviderStatus,
    pub successes: u64,
    pub failures: u64,
    pub last_latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub total_cost_usd: f64,
    pub requests: u64,
    pub checked_at_ms: TimestampMs,
}

/// Error type shared by engine crates that do not need finer granularity.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("not supported: {0}")]
    Unsupported(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Supported security policy outcomes, ordered from least to most impactful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Observe,
    Investigate,
    Alert,
    Quarantine,
}

/// Result of evaluating deterministic policy. AI cannot set this directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub id: RecordId,
    pub outcome: PolicyOutcome,
    pub reason: String,
    pub matched_rules: Vec<String>,
    pub requires_human_approval: bool,
    pub quarantine_allowed: bool,
    pub deterministic: bool,
    pub created_at_ms: TimestampMs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hash_forces_critical_score() {
        let signals = RiskSignals {
            known_malware_hash: true,
            ..Default::default()
        };
        assert_eq!(signals.deterministic_score(), 100.0);
        assert_eq!(RiskLevel::from_score(100.0), RiskLevel::Critical);
    }

    #[test]
    fn empty_signals_are_clean() {
        let assessment = RiskAssessment::from_signals(RiskSignals::default());
        assert_eq!(assessment.score, 0.0);
        assert_eq!(assessment.level, RiskLevel::Clean);
        assert!(assessment.reasons.is_empty());
        assert!(assessment.deterministic);
    }

    #[test]
    fn score_is_bounded() {
        let signals = RiskSignals {
            yara_matches: 10,
            unsigned_executable: true,
            invalid_signature: true,
            suspicious_imports: true,
            persistence_attempt: true,
            obfuscated_script: true,
            unusual_network_activity: true,
            suspicious_parent: true,
            high_entropy: true,
            writable_executable_section: true,
            credential_access_indicator: true,
            ransomware_indicator: true,
            startup_folder_write: true,
            temp_execution: true,
            living_off_the_land_binary: true,
            known_malware_hash: false,
        };
        let score = signals.deterministic_score();
        assert!(score > 90.0 && score <= 100.0, "score was {score}");
    }

    #[test]
    fn events_serialize_camel_case() {
        let event = SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::Info,
            TelemetrySource::ProcessSnapshot,
            "Process created",
        );
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("timestampMs").is_some());
        assert_eq!(value["kind"], "process_created");
    }
}
