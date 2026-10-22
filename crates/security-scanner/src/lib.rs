//! AI Antivirus file analysis engine.
//!
//! Public surface:
//!
//! - [`Scanner`]: hashes files, parses PE headers, runs bundled and optional
//!   YARA-X rules, and assembles deterministic [`security_core::RiskSignals`]
//!   into a [`security_core::FileScanReport`].
//! - [`compute_sha256`], [`shannon_entropy`], [`analyze_pe`],
//!   [`default_yara_rules`]: standalone analysis primitives.
//! - [`QuarantineVault`]: copy-based quarantine store with verified hashes and
//!   JSON sidecar metadata.
//!
//! Everything is designed to be safe on hostile input: no panics on malformed
//! files, bounded memory, and per-file error notes instead of aborted scans.

mod authenticode;
mod hashing;
mod pe;
mod quarantine;
mod yara_rules;

pub use authenticode::{read_authenticode, read_authenticode_with_timeout, AUTHENTICODE_TIMEOUT};
pub use hashing::{compute_sha256, shannon_entropy};
pub use pe::analyze_pe;
pub use quarantine::QuarantineVault;
pub use yara_rules::default_yara_rules;

use std::fmt;
use std::fs::Metadata;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use security_core::{
    new_id, Detection, DetectionSource, FileRef, FileScanReport, PeMetadata, RiskAssessment,
    RiskSignals, ScanProgress, ScanSource, ScanState, Severity, SignatureInfo,
};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

/// High-entropy threshold (bits per byte) for the `high_entropy` signal.
pub const ENTROPY_HIGH_THRESHOLD: f32 = 7.2;
/// Files smaller than this are never considered high entropy.
pub const ENTROPY_MIN_FILE_BYTES: u64 = 4096;
/// PE sections must be at least this large (raw) to contribute `high_entropy`.
pub const ENTROPY_SECTION_MIN_RAW_BYTES: u32 = 1024;
/// Byte sample used for entropy estimation on files too large to read fully.
pub const ENTROPY_SAMPLE_BYTES: u64 = 1024 * 1024;
/// Number of distinct high-signal imports before `suspicious_imports` is set.
pub const SUSPICIOUS_IMPORT_MIN: usize = 2;

/// Errors produced by the scanner and the quarantine vault.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The configuration was rejected.
    #[error("invalid scanner configuration: {0}")]
    Invalid(String),
    /// The file is not a regular file (directory, device, ...).
    #[error("not a regular file: {0}")]
    NotAFile(PathBuf),
    /// The file is a symlink or reparse point and `follow_symlinks` is false.
    #[error("symlink or reparse point rejected: {0}")]
    SymlinkRejected(PathBuf),
    /// YARA rule compilation failed.
    #[error("yara rule compilation failed: {0}")]
    Rules(String),
    /// SHA-256 verification failed.
    #[error("hash verification failed for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        /// Path whose hash was verified.
        path: String,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },
    /// A quarantine record or stored copy could not be found.
    #[error("quarantine record not found: {0}")]
    NotFound(String),
    /// Any other quarantine failure (missing copy, invalid sidecar, ...).
    #[error("quarantine error: {0}")]
    Quarantine(String),
}

/// Configuration for [`Scanner`].
///
/// Defaults: 128 MiB full-read/PE cap, 512 MiB hashing cap, 5000 ms YARA
/// timeout, symlinks not followed, no extra rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScannerConfig {
    /// Files larger than this are not read into memory: PE parsing is skipped
    /// and YARA scans at most this many leading bytes via a memory-mapped
    /// read. Must be greater than zero.
    pub max_file_size: u64,
    /// Files larger than this are not hashed. Must be greater than zero.
    pub max_hash_size: u64,
    /// YARA scan timeout in milliseconds; `0` disables the timeout.
    ///
    /// yara-x enforces timeouts with an internal ~1 second heartbeat, so the
    /// effective granularity is about one second.
    pub yara_timeout_ms: u64,
    /// Follow symlinks. When `false`, symlink/reparse-point files are rejected
    /// and symlinked directories are never traversed.
    pub follow_symlinks: bool,
    /// Paths that are never traversed or scanned. Directory entries are
    /// matched by path prefix with component boundaries; files are matched
    /// exactly. Empty by default.
    pub exclusions: Vec<String>,
    /// Additional YARA source compiled together with the bundled rules.
    pub extra_yara_rules: Option<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 128 * 1024 * 1024,
            max_hash_size: 512 * 1024 * 1024,
            yara_timeout_ms: 5000,
            follow_symlinks: false,
            exclusions: Vec::new(),
            extra_yara_rules: None,
        }
    }
}

/// Aggregate result of [`Scanner::scan_path`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    /// Number of files that were scanned successfully.
    pub files_scanned: u64,
    /// Total number of detections across all scanned files.
    pub detections: u64,
    /// Number of per-file errors (failed scans, skipped symlinks, walk
    /// errors).
    pub errors: u64,
    /// Reports for every successfully scanned file.
    pub reports: Vec<FileScanReport>,
    /// True when the scan stopped because the cancellation flag was set.
    pub cancelled: bool,
}

/// File scanner: hashing, PE analysis, YARA-X matching, Authenticode
/// metadata, risk signal assembly.
pub struct Scanner {
    config: ScannerConfig,
    rules: yara_x::Rules,
    exclusions: Vec<std::path::PathBuf>,
}

impl fmt::Debug for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("config", &self.config)
            .field("rules", &"<yara-x Rules>")
            .finish()
    }
}

impl Scanner {
    /// Creates a scanner and compiles the bundled (plus optional extra) YARA
    /// rules. Invalid configuration or unparsable extra rules are rejected
    /// here, not at scan time.
    pub fn new(config: ScannerConfig) -> Result<Self, ScanError> {
        if config.max_file_size == 0 {
            return Err(ScanError::Invalid(
                "max_file_size must be greater than zero".to_string(),
            ));
        }
        if config.max_hash_size == 0 {
            return Err(ScanError::Invalid(
                "max_hash_size must be greater than zero".to_string(),
            ));
        }
        let rules = yara_rules::compile_rules(&config)?;
        let exclusions = config
            .exclusions
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| normalize_lexical(Path::new(value)))
            .collect();
        Ok(Self {
            config,
            rules,
            exclusions,
        })
    }

    /// True when `path` is inside a user-configured exclusion. Comparisons use
    /// absolute, case-insensitive paths with component boundaries, so
    /// excluding `C:\Foo` does not exclude `C:\Foobar`.
    fn is_excluded(&self, path: &Path) -> bool {
        if self.exclusions.is_empty() {
            return false;
        }
        let candidate = path_text(&normalize_lexical(path));
        self.exclusions.iter().any(|excluded| {
            let base = path_text(excluded);
            if base.is_empty() {
                return false;
            }
            candidate == base
                || candidate
                    .strip_prefix(&base)
                    .is_some_and(|rest| rest.starts_with('\\'))
        })
    }

    /// The active configuration.
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Scans a single file.
    ///
    /// Memory is bounded: files up to `max_file_size` are read once into a
    /// buffer (used for hashing, entropy, PE parsing and YARA); larger files
    /// are hashed in chunks, entropy-sampled, PE-skipped and YARA-scanned at
    /// most `max_file_size` leading bytes. Authenticode metadata is queried
    /// best-effort; failures become entries in [`FileScanReport::errors`].
    pub fn scan_file(&self, path: &Path, source: ScanSource) -> Result<FileScanReport, ScanError> {
        let started = Instant::now();
        let mut errors: Vec<String> = Vec::new();

        let symlink_metadata = std::fs::symlink_metadata(path)?;
        if !self.config.follow_symlinks && is_symlink_or_reparse(&symlink_metadata) {
            return Err(ScanError::SymlinkRejected(path.to_path_buf()));
        }
        let metadata = if self.config.follow_symlinks {
            std::fs::metadata(path)?
        } else {
            symlink_metadata
        };
        if !metadata.is_file() {
            return Err(ScanError::NotAFile(path.to_path_buf()));
        }
        let size = metadata.len();

        let mut detections: Vec<Detection> = Vec::new();

        // Read the whole file only when it fits the configured cap.
        let mut full_data: Option<Vec<u8>> = None;
        if size <= self.config.max_file_size {
            let data = read_at_most(path, self.config.max_file_size)?;
            if (data.len() as u64) <= self.config.max_file_size {
                full_data = Some(data);
            }
        }

        let (sha256, entropy, pe) = match &full_data {
            Some(data) => {
                let sha256 = if size <= self.config.max_hash_size {
                    Some(hashing::sha256_hex(data))
                } else {
                    errors.push(format!(
                        "sha256 skipped: file exceeds max_hash_size ({} bytes)",
                        self.config.max_hash_size
                    ));
                    None
                };
                let entropy = Some(shannon_entropy(data));
                let pe = analyze_pe(data);
                let outcome = yara_rules::scan_buffer(
                    &self.rules,
                    data,
                    self.config.yara_timeout_ms,
                    usize_cap(self.config.max_file_size),
                );
                detections.extend(outcome.detections);
                errors.extend(outcome.errors);
                (sha256, entropy, pe)
            }
            None => {
                let sha256 = match hashing::hash_file_limited(path, self.config.max_hash_size)? {
                    Some((hash, _)) => Some(hash),
                    None => {
                        errors.push(format!(
                            "sha256 skipped: file exceeds max_hash_size ({} bytes)",
                            self.config.max_hash_size
                        ));
                        None
                    }
                };
                let sample = read_at_most(path, ENTROPY_SAMPLE_BYTES)?;
                let entropy = Some(shannon_entropy(&sample));
                errors.push(format!(
                    "pe analysis skipped: file exceeds max_file_size ({} bytes)",
                    self.config.max_file_size
                ));
                let outcome = yara_rules::scan_file(
                    &self.rules,
                    path,
                    self.config.yara_timeout_ms,
                    usize_cap(self.config.max_file_size),
                );
                detections.extend(outcome.detections);
                errors.extend(outcome.errors);
                (sha256, entropy, None)
            }
        };

        // Known-hash detection from the (small, deterministic) seed list.
        if let Some(hash) = sha256.as_deref() {
            if let Some((rule_id, description)) = yara_rules::known_hash_entry(hash) {
                detections.push(Detection {
                    id: new_id("det"),
                    rule_id: rule_id.to_string(),
                    rule_name: "Known malware hash".to_string(),
                    source: DetectionSource::KnownHash,
                    severity: Severity::Critical,
                    description: description.to_string(),
                    score_contribution: 100.0,
                    evidence: vec![format!("sha256={hash}")],
                    created_at_ms: now_ms(),
                });
            }
        }

        // Authenticode metadata is only meaningful for PE files; run the
        // read-only query best-effort and record failures as error notes.
        let mut signature: Option<SignatureInfo> = None;
        if pe.is_some() {
            match read_authenticode(path) {
                Ok(Some(info)) => signature = Some(info),
                Ok(None) => {}
                Err(note) => errors.push(format!("authenticode: {note}")),
            }
        }

        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| absolute.to_string_lossy().into_owned());

        let yara_count = detections
            .iter()
            .filter(|detection| detection.source == DetectionSource::Yara)
            .count()
            .min(u32::MAX as usize) as u32;
        let signals = assemble_signals(SignalInputs {
            path,
            file_name: &name,
            size,
            sha256: sha256.as_deref(),
            entropy,
            pe: pe.as_ref(),
            yara_matches: yara_count,
            signature: signature.as_ref(),
        });
        let assessment = RiskAssessment::from_signals(signals);

        let file = FileRef {
            path: absolute.to_string_lossy().into_owned(),
            name,
            size,
            sha256,
            entropy,
            is_pe: pe.is_some(),
            pe,
            signature,
            created_at_ms: system_time_ms(metadata.created()),
            modified_at_ms: system_time_ms(metadata.modified()),
        };

        Ok(FileScanReport {
            id: new_id("fsr"),
            file,
            detections,
            assessment,
            source,
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            scanned_at_ms: now_ms(),
            cache_hit: false,
            errors,
        })
    }

    /// Scans a file or directory tree.
    ///
    /// `recursive` controls the walk depth. The cancellation flag is checked
    /// before every entry; per-file failures increment the error count and do
    /// not stop the scan. `progress` is invoked for every processed entry and
    /// once at the end with `Completed` or `Cancelled`.
    pub fn scan_path(
        &self,
        root: &Path,
        recursive: bool,
        cancel: &AtomicBool,
        progress: &dyn Fn(ScanProgress),
    ) -> ScanSummary {
        let job_id = new_id("scan");
        let mut summary = ScanSummary::default();
        let max_depth = if recursive { usize::MAX } else { 1 };
        let walker = WalkDir::new(root)
            .follow_links(self.config.follow_symlinks)
            .max_depth(max_depth)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| !self.is_excluded(entry.path()));

        let mut cancelled = false;
        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    summary.errors = summary.errors.saturating_add(1);
                    let path = err
                        .path()
                        .map(|value| value.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    progress(progress_update(&job_id, &summary, Some(path)));
                    continue;
                }
            };

            let file_type = entry.file_type();
            if file_type.is_symlink() && !self.config.follow_symlinks {
                // walkdir does not traverse these; count the explicit skip so
                // the summary stays auditable.
                summary.errors = summary.errors.saturating_add(1);
                progress(progress_update(
                    &job_id,
                    &summary,
                    Some(entry.path().to_string_lossy().into_owned()),
                ));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let path = entry.path().to_path_buf();
            match self.scan_file(&path, ScanSource::Manual) {
                Ok(report) => {
                    summary.files_scanned = summary.files_scanned.saturating_add(1);
                    summary.detections = summary
                        .detections
                        .saturating_add(report.detections.len() as u64);
                    progress(progress_update(
                        &job_id,
                        &summary,
                        Some(report.file.path.clone()),
                    ));
                    summary.reports.push(report);
                }
                Err(err) => {
                    summary.errors = summary.errors.saturating_add(1);
                    tracing::debug!(
                        target: "security_scanner",
                        path = %path.display(),
                        error = %err,
                        "scan_path: file scan failed"
                    );
                    progress(progress_update(
                        &job_id,
                        &summary,
                        Some(path.to_string_lossy().into_owned()),
                    ));
                }
            }
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
            }
        }

        summary.cancelled = cancelled || cancel.load(Ordering::Relaxed);
        let state = if summary.cancelled {
            ScanState::Cancelled
        } else {
            ScanState::Completed
        };
        progress(ScanProgress {
            job_id,
            state,
            files_scanned: summary.files_scanned,
            current_path: None,
            detections: summary.detections,
            errors: summary.errors,
        });
        summary
    }
}

fn progress_update(
    job_id: &str,
    summary: &ScanSummary,
    current_path: Option<String>,
) -> ScanProgress {
    ScanProgress {
        job_id: job_id.to_string(),
        state: ScanState::Running,
        files_scanned: summary.files_scanned,
        current_path,
        detections: summary.detections,
        errors: summary.errors,
    }
}

/// Everything [`assemble_signals`] needs to derive deterministic risk signals.
struct SignalInputs<'a> {
    path: &'a Path,
    file_name: &'a str,
    size: u64,
    sha256: Option<&'a str>,
    entropy: Option<f32>,
    pe: Option<&'a PeMetadata>,
    yara_matches: u32,
    signature: Option<&'a SignatureInfo>,
}

/// Assembles deterministic risk signals from all analysis results.
fn assemble_signals(inputs: SignalInputs<'_>) -> RiskSignals {
    let SignalInputs {
        path,
        file_name,
        size,
        sha256,
        entropy,
        pe,
        yara_matches,
        signature,
    } = inputs;
    let lower_path = path.to_string_lossy().to_ascii_lowercase();
    let lower_name = file_name.to_ascii_lowercase();
    let is_pe = pe.is_some();

    let known_malware_hash = sha256
        .map(|hash| yara_rules::known_hash_entry(hash).is_some())
        .unwrap_or(false);

    let high_entropy = entropy
        .map(|value| value >= ENTROPY_HIGH_THRESHOLD && size >= ENTROPY_MIN_FILE_BYTES)
        .unwrap_or(false)
        || pe
            .map(|metadata| {
                metadata.sections.iter().any(|section| {
                    section.raw_size >= ENTROPY_SECTION_MIN_RAW_BYTES
                        && section.entropy >= ENTROPY_HIGH_THRESHOLD
                })
            })
            .unwrap_or(false);

    let writable_executable_section = pe
        .map(|metadata| {
            metadata
                .sections
                .iter()
                .any(|section| section.executable && section.writable)
        })
        .unwrap_or(false);

    let suspicious_imports = pe
        .map(|metadata| count_high_signal_imports(metadata) >= SUSPICIOUS_IMPORT_MIN)
        .unwrap_or(false);

    let unsigned_executable = is_pe && signature.map(|info| !info.present).unwrap_or(false);
    let invalid_signature = signature
        .map(|info| info.present && !info.status.eq_ignore_ascii_case("Valid"))
        .unwrap_or(false);

    let temp_execution = is_pe && is_under_temp_dir(&lower_path);
    let startup_folder_write = is_pe && is_startup_path(&lower_path);
    let living_off_the_land_binary =
        is_pe && is_lolbin_name(&lower_name) && !is_windows_system_path(&lower_path);

    RiskSignals {
        known_malware_hash,
        yara_matches,
        unsigned_executable,
        invalid_signature,
        suspicious_imports,
        persistence_attempt: false,
        obfuscated_script: false,
        unusual_network_activity: false,
        suspicious_parent: false,
        high_entropy,
        writable_executable_section,
        credential_access_indicator: false,
        ransomware_indicator: false,
        startup_folder_write,
        temp_execution,
        living_off_the_land_binary,
    }
}

/// APIs that are commonly abused by malware, matched case-insensitively.
const HIGH_SIGNAL_APIS: &[&str] = &[
    "writeprocessmemory",
    "createremotethread",
    "setwindowshookexa",
    "setwindowshookexw",
    "queueuserapc",
    "virtualallocex",
    "ntunmapviewofsection",
    "adjusttokenprivileges",
    "createprocesswithtokenw",
    "minidumpwritedump",
    "credenumerate",
    "cryptencrypt",
    "cryptdecrypt",
    "virtualprotect",
    "rtlmovememory",
];

/// Binaries that are legitimate on their own but frequently used by attackers
/// when they run from outside the Windows directories.
const LOLBIN_NAMES: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "msbuild.exe",
    "installutil.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "cscript.exe",
    "wscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "msiexec.exe",
    "forfiles.exe",
];

fn count_high_signal_imports(pe: &PeMetadata) -> usize {
    let mut count = 0;
    for import in &pe.imports {
        for function in &import.functions {
            let lower = function.to_ascii_lowercase();
            if HIGH_SIGNAL_APIS.contains(&lower.as_str()) {
                count += 1;
            }
        }
    }
    count
}

fn is_under_temp_dir(lower_path: &str) -> bool {
    let mut temp = std::env::temp_dir().to_string_lossy().to_ascii_lowercase();
    if !temp.is_empty() {
        if !temp.ends_with('\\') && !temp.ends_with('/') {
            temp.push(std::path::MAIN_SEPARATOR);
        }
        if lower_path.starts_with(&temp) {
            return true;
        }
    }
    lower_path.contains("\\appdata\\local\\temp\\") || lower_path.contains("/tmp/")
}

fn is_startup_path(lower_path: &str) -> bool {
    lower_path.contains("\\start menu\\programs\\startup\\")
        || lower_path.contains("/start menu/programs/startup/")
        || lower_path.contains("\\microsoft\\windows\\startup\\")
}

fn is_windows_system_path(lower_path: &str) -> bool {
    lower_path.contains("\\windows\\system32\\")
        || lower_path.contains("\\windows\\syswow64\\")
        || lower_path.contains("\\windows\\winsxs\\")
        || lower_path.contains("\\windows\\servicing\\")
}

fn is_lolbin_name(lower_name: &str) -> bool {
    LOLBIN_NAMES.contains(&lower_name)
}

/// True for symlinks and Windows reparse points (junctions, mount points,
/// cloud placeholders).
pub(crate) fn is_symlink_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Reads at most `limit` bytes from `path` (does not fail when the file is
/// larger).
fn read_at_most(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(limit);
    let capacity = usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .min(1024 * 1024);
    let mut buffer = Vec::with_capacity(capacity);
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn usize_cap(value: u64) -> Option<usize> {
    usize::try_from(value).ok().filter(|value| *value > 0)
}

fn system_time_ms(value: std::io::Result<SystemTime>) -> Option<i64> {
    let value = value.ok()?;
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).ok(),
        Err(_) => None,
    }
}

/// Current UTC time in milliseconds since the epoch (0 if the clock is
/// before the epoch).
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Best-effort absolute path without requiring the file to exist.
fn normalize_lexical(path: &Path) -> std::path::PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Lowercased, backslash-normalized path text for Windows-style comparisons.
fn path_text(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
