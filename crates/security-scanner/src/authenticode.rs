//! Best-effort Authenticode signature metadata.
//!
//! On Windows this runs a read-only PowerShell query
//! (`Get-AuthenticodeSignature`, `-NoProfile -NonInteractive`) with a hard
//! timeout. It never modifies security settings. Failures are reported as
//! `Err(String)` so callers can record them as a scan error note instead of
//! failing the scan.

use std::path::Path;
use std::time::Duration;

use security_core::SignatureInfo;

/// Default timeout for the PowerShell query.
pub const AUTHENTICODE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reads Authenticode metadata for `path`.
///
/// - On Windows: `Ok(Some(info))` when Windows reports a status (including
///   `NotSigned`), `Err(note)` when PowerShell could not be queried.
/// - On other platforms: always `Ok(None)`.
pub fn read_authenticode(path: &Path) -> Result<Option<SignatureInfo>, String> {
    read_authenticode_with_timeout(path, AUTHENTICODE_TIMEOUT)
}

/// Like [`read_authenticode`], with an explicit timeout for tests.
pub fn read_authenticode_with_timeout(
    path: &Path,
    timeout: Duration,
) -> Result<Option<SignatureInfo>, String> {
    imp::read(path, timeout)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    /// Do not flash a console window for the helper process.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// Hard bound on captured helper output. The JSON payload is a few
    /// hundred bytes; the bound only exists so a pathological helper cannot
    /// exhaust memory.
    const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;

    pub(super) fn read(path: &Path, timeout: Duration) -> Result<Option<SignatureInfo>, String> {
        let script = build_script(path);
        let encoded = encode_utf16le_base64(&script);
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|err| format!("failed to start PowerShell: {err}"))?;

        // Drain both pipes on their own threads so the helper can never block
        // on a full pipe, and so the captured output stays bounded.
        let stdout_reader = child.stdout.take().map(spawn_bounded_reader);
        let stderr_reader = child.stderr.take().map(spawn_bounded_reader);

        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!(
                            "Get-AuthenticodeSignature timed out after {} ms",
                            timeout.as_millis()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(err) => return Err(format!("failed to wait for PowerShell: {err}")),
            }
        };

        let stdout = join_reader(stdout_reader);
        let stderr = join_reader(stderr_reader);

        if !status.success() {
            return Err(format!(
                "Get-AuthenticodeSignature failed (exit {}): {}",
                status.code().unwrap_or(-1),
                truncate_text(String::from_utf8_lossy(&stderr).trim())
            ));
        }

        parse_signature_json(String::from_utf8_lossy(&stdout).trim())
    }

    /// Reads at most [`MAX_CAPTURE_BYTES`] from `pipe` on a dedicated thread.
    fn spawn_bounded_reader(
        mut pipe: impl Read + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe
                .by_ref()
                .take(MAX_CAPTURE_BYTES)
                .read_to_end(&mut buffer);
            buffer
        })
    }

    fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
        handle
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default()
    }

    /// Builds a read-only PowerShell script. The path is embedded with
    /// single-quote doubling so it cannot break out of the string literal.
    fn build_script(path: &Path) -> String {
        let escaped = path.to_string_lossy().replace('\'', "''");
        format!(
            "$ErrorActionPreference = 'Stop'; \
             $sig = Get-AuthenticodeSignature -LiteralPath '{escaped}'; \
             $signer = $null; $issuer = $null; $thumbprint = $null; \
             if ($sig.SignerCertificate -ne $null) {{ \
               $signer = [string]$sig.SignerCertificate.Subject; \
               $issuer = [string]$sig.SignerCertificate.Issuer; \
               $thumbprint = [string]$sig.SignerCertificate.Thumbprint }}; \
             $out = [ordered]@{{ status = [string]$sig.Status; signer = $signer; issuer = $issuer; thumbprint = $thumbprint }}; \
             ConvertTo-Json -InputObject $out -Compress"
        )
    }

    fn encode_utf16le_base64(script: &str) -> String {
        let mut utf16 = Vec::with_capacity(script.len().saturating_mul(2));
        for unit in script.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        STANDARD.encode(utf16)
    }

    fn parse_signature_json(stdout: &str) -> Result<Option<SignatureInfo>, String> {
        if stdout.is_empty() {
            return Err("Get-AuthenticodeSignature returned no output".to_string());
        }
        let value: serde_json::Value = serde_json::from_str(stdout)
            .map_err(|err| format!("invalid PowerShell JSON output: {err}"))?;
        let status = value
            .get("status")
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "UnknownError".to_string());
        let present = !status.eq_ignore_ascii_case("NotSigned");
        Ok(Some(SignatureInfo {
            present,
            status,
            signer: json_string(&value, "signer"),
            issuer: json_string(&value, "issuer"),
            thumbprint: json_string(&value, "thumbprint"),
        }))
    }

    fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
        value
            .get(key)
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn truncate_text(text: &str) -> String {
        let cleaned: String = text.chars().filter(|ch| !ch.is_control()).collect();
        if cleaned.chars().count() > 240 {
            let truncated: String = cleaned.chars().take(240).collect();
            format!("{truncated}...")
        } else {
            cleaned
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub(super) fn read(_path: &Path, _timeout: Duration) -> Result<Option<SignatureInfo>, String> {
        // Authenticode metadata is a Windows-only concept.
        Ok(None)
    }
}
