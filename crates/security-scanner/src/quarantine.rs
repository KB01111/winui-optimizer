//! Quarantine vault.
//!
//! Invariants enforced here:
//!
//! - Symlinks and reparse points are rejected, both when quarantining and
//!   when restoring.
//! - The SHA-256 of the original is verified before copying and the vault copy
//!   is verified again; restore verifies the stored copy before writing.
//! - Stored names are collision-safe:
//!   `<sha256-prefix>-<utc-timestamp>-<sanitized-name>.quarantine`.
//! - Originals are **never** deleted automatically: quarantine copies.
//! - Restore only ever writes to the recorded original path, recreates parent
//!   directories, and refuses to overwrite an existing file.
//! - Deletion of a stored copy happens only through the explicit
//!   [`QuarantineVault::delete`] call.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use security_core::{new_id, QuarantineRecord, QuarantineStatus, RestoreResult, TimestampMs};

use crate::hashing::{hash_file_limited, CHUNK_SIZE};
use crate::{is_symlink_or_reparse, now_ms, ScanError};

/// Extension of stored quarantine copies.
const QUARANTINE_EXTENSION: &str = "quarantine";
/// Extension of the JSON sidecar next to a stored copy.
const SIDECAR_EXTENSION: &str = "quarantine.json";
/// Upper bound on the sanitized original name inside a stored file name.
const NAME_LIMIT: usize = 64;
/// Upper bound on collision-avoidance attempts for a stored name.
const COLLISION_ATTEMPTS: usize = 1000;

/// Default upper bound on the number of bytes read while hashing a file that
/// is about to be copied into (or out of) the vault.
///
/// This mirrors `ScannerConfig::max_hash_size` (512 MiB) so that a single
/// enormous file cannot turn a quarantine action into an unbounded read.
pub const DEFAULT_MAX_HASH_SIZE: u64 = 512 * 1024 * 1024;

/// A restricted directory that holds quarantined file copies and their
/// JSON metadata sidecars.
#[derive(Debug, Clone)]
pub struct QuarantineVault {
    dir: PathBuf,
    max_hash_size: u64,
}

impl QuarantineVault {
    /// Creates (or opens) the vault directory.
    ///
    /// Permissions are hardened on a best-effort basis: on Windows the
    /// inherited ACL is replaced with the current user, SYSTEM and
    /// Administrators via `icacls`; on other platforms the directory mode is
    /// set to `0o700`. Failures are logged, never fatal.
    pub fn new(vault_dir: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_max_hash_size(vault_dir, DEFAULT_MAX_HASH_SIZE)
    }

    /// Like [`QuarantineVault::new`], with an explicit hashing bound.
    ///
    /// `max_hash_size` is the maximum number of bytes read while verifying a
    /// file's SHA-256. `0` disables the bound (not recommended).
    pub fn with_max_hash_size(
        vault_dir: impl Into<PathBuf>,
        max_hash_size: u64,
    ) -> io::Result<Self> {
        let dir = vault_dir.into();
        fs::create_dir_all(&dir)?;
        harden_vault_permissions(&dir);
        let dir = fs::canonicalize(&dir).unwrap_or(dir);
        Ok(Self { dir, max_hash_size })
    }

    /// The canonicalized vault directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Copies `path` into the vault and writes an audit record.
    ///
    /// The original file is left untouched. The copy is verified against the
    /// SHA-256 of the source before the record is written; on any failure the
    /// partial copy is removed.
    pub fn quarantine(
        &self,
        path: &Path,
        reason: &str,
        detection_id: Option<String>,
    ) -> Result<QuarantineRecord, ScanError> {
        let symlink_metadata = fs::symlink_metadata(path)?;
        if is_symlink_or_reparse(&symlink_metadata) {
            return Err(ScanError::SymlinkRejected(path.to_path_buf()));
        }
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(ScanError::NotAFile(path.to_path_buf()));
        }
        let size = metadata.len();

        let (sha256, hashed_bytes) =
            hash_file_limited(path, self.max_hash_size)?.ok_or_else(|| {
                ScanError::Quarantine(format!(
                    "source is larger than the vault hashing limit ({} bytes)",
                    self.max_hash_size
                ))
            })?;
        if hashed_bytes != size {
            // The file changed while it was being hashed; refuse rather than
            // store an inconsistent copy.
            return Err(ScanError::Quarantine(format!(
                "source changed while hashing ({hashed_bytes} bytes read, metadata said {size})"
            )));
        }

        let original_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unnamed".to_string());

        let stored_path = self.allocate_stored_path(&sha256, &original_name)?;
        self.copy_verified(path, &stored_path, &sha256)?;

        let record = QuarantineRecord {
            id: new_id("qtn"),
            original_path: absolute_display(path),
            original_name,
            stored_path: stored_path.to_string_lossy().into_owned(),
            sha256,
            size,
            quarantined_at_ms: now_ms(),
            status: QuarantineStatus::Quarantined,
            restored_at_ms: None,
            detection_id,
            reason: reason.to_string(),
            identity_verified: true,
        };
        if let Err(err) = self.write_sidecar(&record) {
            let _ = fs::remove_file(&stored_path);
            return Err(err);
        }

        tracing::info!(
            target: "security_scanner",
            quarantine_id = %record.id,
            stored = %record.stored_path,
            "quarantined file copy"
        );
        Ok(record)
    }

    /// Restores a quarantined copy to its recorded original path.
    ///
    /// Returns `Ok(RestoreResult { success: false, .. })` when the restore is
    /// refused (for example the original path already exists); returns `Err`
    /// for missing records or integrity failures.
    pub fn restore(&self, id: &str) -> Result<RestoreResult, ScanError> {
        let Some(record) = self.find_record(id)? else {
            return Err(ScanError::NotFound(id.to_string()));
        };
        let stored = PathBuf::from(&record.stored_path);
        if !self.owns_stored_path(&stored) {
            return Err(ScanError::Quarantine(format!(
                "stored path is outside the vault: {}",
                stored.display()
            )));
        }

        let symlink_metadata = match fs::symlink_metadata(&stored) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(ScanError::Quarantine(format!(
                    "stored copy is missing: {}",
                    stored.display()
                )));
            }
            Err(err) => return Err(err.into()),
        };
        if is_symlink_or_reparse(&symlink_metadata) {
            return Err(ScanError::SymlinkRejected(stored));
        }

        let stored_hash = hash_file_limited(&stored, self.max_hash_size)?
            .ok_or_else(|| {
                ScanError::Quarantine(format!(
                    "stored copy is larger than the vault hashing limit ({} bytes)",
                    self.max_hash_size
                ))
            })?
            .0;
        if stored_hash != record.sha256 {
            return Err(ScanError::HashMismatch {
                path: stored.to_string_lossy().into_owned(),
                expected: record.sha256.clone(),
                actual: stored_hash,
            });
        }

        let target = PathBuf::from(&record.original_path);
        if target.exists() {
            return Ok(refusal(
                &record.id,
                format!("refusing to overwrite existing file: {}", target.display()),
            ));
        }
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let output = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                return Ok(refusal(
                    &record.id,
                    format!("refusing to overwrite existing file: {}", target.display()),
                ));
            }
            Err(err) => return Err(err.into()),
        };
        copy_stream(&stored, output)?;

        let restored_hash = hash_file_limited(&target, self.max_hash_size)?
            .ok_or_else(|| {
                ScanError::Quarantine(format!(
                    "restored file is larger than the vault hashing limit ({} bytes)",
                    self.max_hash_size
                ))
            })?
            .0;
        if restored_hash != record.sha256 {
            let _ = fs::remove_file(&target);
            return Err(ScanError::HashMismatch {
                path: target.to_string_lossy().into_owned(),
                expected: record.sha256.clone(),
                actual: restored_hash,
            });
        }

        let mut updated = record.clone();
        updated.status = QuarantineStatus::Restored;
        updated.restored_at_ms = Some(now_ms());
        if let Err(err) = self.write_sidecar(&updated) {
            tracing::warn!(
                target: "security_scanner",
                quarantine_id = %record.id,
                error = %err,
                "restored file but failed to update the quarantine sidecar"
            );
        }

        tracing::info!(
            target: "security_scanner",
            quarantine_id = %record.id,
            restored = %target.display(),
            "restored quarantined file"
        );
        Ok(RestoreResult {
            id: record.id,
            restored_path: Some(target.to_string_lossy().into_owned()),
            success: true,
            message: format!("restored {} bytes to {}", updated.size, target.display()),
        })
    }

    /// Lists all quarantine records, newest first.
    ///
    /// Unreadable or corrupt sidecars are skipped with a warning; listing is
    /// best-effort and never panics.
    pub fn list(&self) -> Vec<QuarantineRecord> {
        let mut records = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return records;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_sidecar_path(&path) {
                continue;
            }
            match read_sidecar(&path) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {}
                Err(err) => tracing::warn!(
                    target: "security_scanner",
                    sidecar = %path.display(),
                    error = %err,
                    "skipping unreadable quarantine sidecar"
                ),
            }
        }
        records.sort_by(|a, b| {
            b.quarantined_at_ms
                .cmp(&a.quarantined_at_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        records
    }

    /// Explicitly removes a stored copy and its sidecar.
    ///
    /// This is the only path that deletes quarantine data; it is never called
    /// automatically.
    pub fn delete(&self, id: &str) -> Result<(), ScanError> {
        let Some((record, sidecar)) = self.find_record_with_sidecar(id)? else {
            return Err(ScanError::NotFound(id.to_string()));
        };
        let stored = PathBuf::from(&record.stored_path);
        if self.owns_stored_path(&stored) {
            match fs::remove_file(&stored) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        fs::remove_file(&sidecar)?;
        tracing::info!(
            target: "security_scanner",
            quarantine_id = %record.id,
            "deleted quarantined copy"
        );
        Ok(())
    }

    fn allocate_stored_path(
        &self,
        sha256: &str,
        original_name: &str,
    ) -> Result<PathBuf, ScanError> {
        let prefix = sha256.get(..16).unwrap_or(sha256);
        let stamp = format_utc_stamp(now_ms());
        let sanitized = sanitize_component(original_name);
        for attempt in 0..COLLISION_ATTEMPTS {
            let suffix = if attempt == 0 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            let candidate = self.dir.join(format!(
                "{prefix}-{stamp}-{sanitized}{suffix}.{QUARANTINE_EXTENSION}"
            ));
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(ScanError::Quarantine(
            "could not allocate a unique vault file name".to_string(),
        ))
    }

    /// Copies `source` to `destination` (must not exist), then verifies the
    /// SHA-256 of the copy. Removes the copy and returns an error on mismatch.
    fn copy_verified(
        &self,
        source: &Path,
        destination: &Path,
        expected_sha256: &str,
    ) -> Result<(), ScanError> {
        let input = BufReader::new(File::open(source)?);
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        if let Err(err) = copy_stream_from(input, output) {
            let _ = fs::remove_file(destination);
            return Err(err.into());
        }

        let actual = hash_file_limited(destination, self.max_hash_size)?
            .ok_or_else(|| {
                ScanError::Quarantine(format!(
                    "vault copy is larger than the vault hashing limit ({} bytes)",
                    self.max_hash_size
                ))
            })?
            .0;
        if actual != expected_sha256 {
            let _ = fs::remove_file(destination);
            return Err(ScanError::HashMismatch {
                path: destination.to_string_lossy().into_owned(),
                expected: expected_sha256.to_string(),
                actual,
            });
        }
        Ok(())
    }

    fn write_sidecar(&self, record: &QuarantineRecord) -> Result<(), ScanError> {
        let sidecar = sidecar_path_for(Path::new(&record.stored_path));
        let json = serde_json::to_vec_pretty(record)
            .map_err(|err| ScanError::Quarantine(format!("serialize quarantine record: {err}")))?;
        fs::write(&sidecar, json)?;
        Ok(())
    }

    /// True when `path` is a direct child of the vault directory.
    fn owns_stored_path(&self, path: &Path) -> bool {
        match path.parent() {
            Some(parent) => {
                let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                parent == self.dir
            }
            None => false,
        }
    }

    fn find_record(&self, id: &str) -> Result<Option<QuarantineRecord>, ScanError> {
        Ok(self
            .find_record_with_sidecar(id)?
            .map(|(record, _sidecar)| record))
    }

    fn find_record_with_sidecar(
        &self,
        id: &str,
    ) -> Result<Option<(QuarantineRecord, PathBuf)>, ScanError> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Ok(None);
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_sidecar_path(&path) {
                continue;
            }
            match read_sidecar(&path) {
                Ok(Some(record)) if record.id == id => return Ok(Some((record, path))),
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    target: "security_scanner",
                    sidecar = %path.display(),
                    error = %err,
                    "skipping unreadable quarantine sidecar"
                ),
            }
        }
        Ok(None)
    }
}

fn refusal(id: &str, message: String) -> RestoreResult {
    RestoreResult {
        id: id.to_string(),
        restored_path: None,
        success: false,
        message,
    }
}

fn copy_stream(source: &Path, output: File) -> io::Result<()> {
    copy_stream_from(BufReader::new(File::open(source)?), output)
}

fn copy_stream_from(mut input: impl Read, output: File) -> io::Result<()> {
    let mut writer = BufWriter::new(output);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn sidecar_path_for(stored_path: &Path) -> PathBuf {
    stored_path.with_extension(SIDECAR_EXTENSION)
}

fn is_sidecar_path(path: &Path) -> bool {
    path.file_name()
        .map(|name| {
            name.to_string_lossy()
                .ends_with(&format!(".{SIDECAR_EXTENSION}"))
        })
        .unwrap_or(false)
}

fn read_sidecar(path: &Path) -> Result<Option<QuarantineRecord>, ScanError> {
    let text = fs::read_to_string(path)?;
    let record: QuarantineRecord = serde_json::from_str(&text).map_err(|err| {
        ScanError::Quarantine(format!("invalid sidecar {}: {err}", path.display()))
    })?;
    Ok(Some(record))
}

fn absolute_display(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// Sanitizes an original file name for use inside a vault file name.
fn sanitize_component(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if out.len() >= NAME_LIMIT {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    while out.ends_with('.') {
        out.pop();
    }
    if out.is_empty() || out == "." || out == ".." {
        out = "unnamed".to_string();
    }
    out
}

/// Formats epoch milliseconds as a file-name safe UTC timestamp:
/// `YYYYMMDDTHHMMSS.mmmZ`.
pub(crate) fn format_utc_stamp(ms: TimestampMs) -> String {
    let seconds = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}.{millis:03}Z",
        seconds_of_day / 3600,
        (seconds_of_day / 60) % 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (y, m, d).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(windows)]
fn harden_vault_permissions(dir: &Path) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(domain), Ok(name)) if !domain.is_empty() && !name.is_empty() => {
            format!("{domain}\\{name}")
        }
        _ => {
            tracing::warn!(
                target: "security_scanner",
                "could not determine the current user; skipping vault ACL hardening"
            );
            return;
        }
    };

    let dir_arg = dir.to_string_lossy().into_owned();
    let mut child = match Command::new("icacls")
        .args([
            dir_arg.as_str(),
            "/inheritance:r",
            "/grant:r",
            &format!("{user}:(OI)(CI)F"),
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(target: "security_scanner", error = %err, "icacls unavailable; vault ACL not hardened");
            return;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    tracing::warn!(
                        target: "security_scanner",
                        code = ?status.code(),
                        "icacls exited with a non-zero status; vault ACL may still allow inherited access"
                    );
                }
                return;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(target: "security_scanner", "icacls timed out; vault ACL not hardened");
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                tracing::warn!(target: "security_scanner", error = %err, "failed to wait for icacls");
                return;
            }
        }
    }
}

#[cfg(not(windows))]
fn harden_vault_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    match fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
        Ok(()) => {}
        Err(err) => tracing::warn!(
            target: "security_scanner",
            error = %err,
            "failed to set vault directory permissions"
        ),
    }
}
