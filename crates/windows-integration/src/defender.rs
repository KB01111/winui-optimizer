//! Read-only Microsoft Defender status query.
//!
//! The query shells out to Windows PowerShell with `-NoProfile -NonInteractive`
//! and a 10 second timeout, and only ever calls `Get-*` cmdlets:
//! `Get-MpComputerStatus` and `Get-MpThreatDetection` (for the detection
//! count). Nothing in this module can change Defender, Tamper Protection or
//! any other security setting. On any error the status is reported as
//! `available: false` with a bounded `query_error`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::util::{clean_string, strip_bom, truncate_chars};

/// Hard timeout for the Defender probe.
pub const DEFENDER_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded query error length, so a chatty host cannot bloat the UI payload.
const MAX_ERROR_CHARS: usize = 400;

/// Earliest plausible scan timestamp (2000-01-01T00:00:00Z). Defender reports
/// `1601-01-01` (or `1899-12-30`) for scans that never ran; those are reported
/// as `None` instead of a misleading timestamp.
const MIN_PLAUSIBLE_SCAN_MS: i64 = 946_684_800_000;

/// Read-only status snapshot of Microsoft Defender.
///
/// `available` is true only when the read-only query succeeded and its JSON
/// payload parsed; every field then reflects what Defender reported. On error,
/// `available` is false, `query_error` explains why and the remaining fields
/// keep their neutral defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenderStatus {
    /// True when the read-only query succeeded.
    pub available: bool,
    /// Bounded error description when `available` is false.
    pub query_error: Option<String>,
    /// Real-time protection enabled.
    pub realtime_enabled: bool,
    /// Antivirus component enabled.
    pub antivirus_enabled: bool,
    /// Antispyware component enabled.
    pub antispyware_enabled: bool,
    /// Tamper Protection enabled (`IsTamperProtected`). Read only.
    pub tamper_protected: bool,
    /// Antimalware engine version.
    pub engine_version: Option<String>,
    /// Antivirus security intelligence version.
    pub signature_version: Option<String>,
    /// Age of the security intelligence in days.
    pub signature_age_days: Option<u32>,
    /// End of the last quick scan (Unix milliseconds).
    pub last_quick_scan_ms: Option<i64>,
    /// End of the last full scan (Unix milliseconds).
    pub last_full_scan_ms: Option<i64>,
    /// Number of threat detections reported by `Get-MpThreatDetection`.
    pub threats_detected: Option<u64>,
    /// Heuristic label derived from `signature_age_days`:
    /// `up_to_date` (0-1 days), `aging` (2-6 days), `out_of_date` (7+ days).
    pub definition_status: Option<String>,
    /// When this snapshot was taken (Unix milliseconds).
    pub checked_at_ms: i64,
}

impl DefenderStatus {
    fn unavailable(checked_at_ms: i64, error: impl AsRef<str>) -> Self {
        Self {
            available: false,
            query_error: Some(truncate_chars(error.as_ref().trim(), MAX_ERROR_CHARS)),
            realtime_enabled: false,
            antivirus_enabled: false,
            antispyware_enabled: false,
            tamper_protected: false,
            engine_version: None,
            signature_version: None,
            signature_age_days: None,
            last_quick_scan_ms: None,
            last_full_scan_ms: None,
            threats_detected: None,
            definition_status: None,
            checked_at_ms,
        }
    }
}

/// Query Microsoft Defender status (read-only).
///
/// Never fails and never modifies Defender settings. The call is bounded by
/// [`DEFENDER_QUERY_TIMEOUT`].
pub fn defender_status() -> DefenderStatus {
    let checked_at_ms = chrono::Utc::now().timestamp_millis();
    #[cfg(windows)]
    {
        match query_defender_json() {
            Ok(json) => match parse_defender_payload(&json, checked_at_ms) {
                Ok(status) => status,
                Err(error) => DefenderStatus::unavailable(checked_at_ms, error),
            },
            Err(error) => DefenderStatus::unavailable(checked_at_ms, error),
        }
    }
    #[cfg(not(windows))]
    {
        DefenderStatus::unavailable(checked_at_ms, "not running on Windows")
    }
}

/// Read-only PowerShell probe. `$ErrorActionPreference = 'Stop'` makes
/// non-terminating cmdlet errors surface in the catch block instead of
/// producing a misleading partially-filled object.
const DEFENDER_QUERY_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
  $status = Get-MpComputerStatus
  $quick = $null
  if ($status.QuickScanEndTime -and $status.QuickScanEndTime.Year -gt 1900) { $quick = $status.QuickScanEndTime.ToUniversalTime().ToString('o') }
  $full = $null
  if ($status.FullScanEndTime -and $status.FullScanEndTime.Year -gt 1900) { $full = $status.FullScanEndTime.ToUniversalTime().ToString('o') }
  $age = $null
  if ($null -ne $status.AntivirusSignatureAge) { $age = [int]$status.AntivirusSignatureAge }
  $engine = $null
  if ($status.AMEngineVersion) { $engine = [string]$status.AMEngineVersion }
  $signatures = $null
  if ($status.AntivirusSignatureVersion) { $signatures = [string]$status.AntivirusSignatureVersion }
  $threats = $null
  try { $threats = [int]@(Get-MpThreatDetection).Count } catch { $threats = $null }
  [pscustomobject]@{
    realtimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
    antivirusEnabled = [bool]$status.AntivirusEnabled
    antispywareEnabled = [bool]$status.AntispywareEnabled
    isTamperProtected = [bool]$status.IsTamperProtected
    engineVersion = $engine
    signatureVersion = $signatures
    signatureAgeDays = $age
    lastQuickScan = $quick
    lastFullScan = $full
    threatsDetected = $threats
  } | ConvertTo-Json -Compress
} catch {
  [Console]::Error.WriteLine('defender-query-failed: ' + $_.Exception.Message)
  exit 3
}
"#;

#[cfg(windows)]
fn query_defender_json() -> Result<String, String> {
    use crate::process_util::{run_with_timeout, ProcessRunError};

    let args = [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        DEFENDER_QUERY_SCRIPT,
    ];
    match run_with_timeout("powershell.exe", &args, DEFENDER_QUERY_TIMEOUT) {
        Ok(output) if output.exit_code == 0 => Ok(output.stdout.trim().to_string()),
        Ok(output) => Err(describe_failure(&output)),
        Err(ProcessRunError::Timeout) => Err(format!(
            "Get-MpComputerStatus did not finish within {} seconds and was stopped",
            DEFENDER_QUERY_TIMEOUT.as_secs()
        )),
        Err(error) => Err(error.message().to_string()),
    }
}

#[cfg(windows)]
fn describe_failure(output: &crate::process_util::ProcessOutput) -> String {
    let stderr = clean_string(&output.stderr);
    let stdout = clean_string(&output.stdout);
    match (stderr, stdout) {
        (Some(stderr), _) => stderr,
        (None, Some(stdout)) => format!(
            "Get-MpComputerStatus failed with exit code {}: {stdout}",
            output.exit_code
        ),
        (None, None) => format!(
            "Get-MpComputerStatus failed with exit code {}",
            output.exit_code
        ),
    }
}

/// Parse a `Get-MpComputerStatus` JSON payload. Pure so it can be tested with
/// fixture strings.
pub(crate) fn parse_defender_payload(
    json: &str,
    checked_at_ms: i64,
) -> Result<DefenderStatus, String> {
    let value: Value = serde_json::from_str(strip_bom(json).trim())
        .map_err(|error| format!("could not parse Defender response as JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Defender response was not a JSON object".to_string())?;

    let signature_age_days = opt_u32_field(object, "signatureAgeDays");

    Ok(DefenderStatus {
        available: true,
        query_error: None,
        realtime_enabled: bool_field(object, "realtimeProtectionEnabled"),
        antivirus_enabled: bool_field(object, "antivirusEnabled"),
        antispyware_enabled: bool_field(object, "antispywareEnabled"),
        tamper_protected: bool_field(object, "isTamperProtected"),
        engine_version: opt_string_field(object, "engineVersion"),
        signature_version: opt_string_field(object, "signatureVersion"),
        signature_age_days,
        last_quick_scan_ms: opt_timestamp_field(object, "lastQuickScan"),
        last_full_scan_ms: opt_timestamp_field(object, "lastFullScan"),
        threats_detected: opt_u64_field(object, "threatsDetected"),
        definition_status: definition_label(signature_age_days),
        checked_at_ms,
    })
}

/// Heuristic definition freshness label derived from the signature age.
pub(crate) fn definition_label(signature_age_days: Option<u32>) -> Option<String> {
    signature_age_days.map(|days| match days {
        0..=1 => "up_to_date".to_string(),
        2..=6 => "aging".to_string(),
        _ => "out_of_date".to_string(),
    })
}

fn bool_field(object: &Map<String, Value>, key: &str) -> bool {
    match object.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number.as_i64().map(|value| value != 0).unwrap_or(false),
        Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn opt_string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(clean_string)
}

fn opt_u32_field(object: &Map<String, Value>, key: &str) -> Option<u32> {
    value_as_u64(object.get(key)?).and_then(|value| u32::try_from(value).ok())
}

fn opt_u64_field(object: &Map<String, Value>, key: &str) -> Option<u64> {
    value_as_u64(object.get(key)?)
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().and_then(|value| u64::try_from(value).ok()))
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .map(|value| value as u64)
            }),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn opt_timestamp_field(object: &Map<String, Value>, key: &str) -> Option<i64> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(parse_timestamp_ms)
}

/// Parse an ISO-8601 timestamp (PowerShell `ToString('o')`) into Unix
/// milliseconds. Timestamps before [`MIN_PLAUSIBLE_SCAN_MS`] are treated as
/// "never happened" and return `None`.
pub(crate) fn parse_timestamp_ms(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let milliseconds = chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_millis())
        .or_else(|_| {
            // Defensive fallback for offset-less timestamps.
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|timestamp| timestamp.and_utc().timestamp_millis())
        })
        .ok()?;
    (milliseconds >= MIN_PLAUSIBLE_SCAN_MS).then_some(milliseconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKED_AT: i64 = 1_700_000_000_000;

    const FULL_FIXTURE: &str = r#"{"realtimeProtectionEnabled":true,"antivirusEnabled":true,"antispywareEnabled":true,"isTamperProtected":true,"engineVersion":"1.1.24090.11","signatureVersion":"1.421.1234.0","signatureAgeDays":0,"lastQuickScan":"2024-01-01T00:00:00.0000000Z","lastFullScan":"2024-01-01T01:00:00.0000000+01:00","threatsDetected":2}"#;

    #[test]
    fn parses_full_payload() {
        let status = parse_defender_payload(FULL_FIXTURE, CHECKED_AT).expect("fixture parses");
        assert!(status.available);
        assert_eq!(status.query_error, None);
        assert!(status.realtime_enabled);
        assert!(status.antivirus_enabled);
        assert!(status.antispyware_enabled);
        assert!(status.tamper_protected);
        assert_eq!(status.engine_version.as_deref(), Some("1.1.24090.11"));
        assert_eq!(status.signature_version.as_deref(), Some("1.421.1234.0"));
        assert_eq!(status.signature_age_days, Some(0));
        // 2024-01-01T00:00:00Z == 1_704_067_200_000 ms.
        assert_eq!(status.last_quick_scan_ms, Some(1_704_067_200_000));
        // Same instant expressed with a +01:00 offset.
        assert_eq!(status.last_full_scan_ms, Some(1_704_067_200_000));
        assert_eq!(status.threats_detected, Some(2));
        assert_eq!(status.definition_status.as_deref(), Some("up_to_date"));
        assert_eq!(status.checked_at_ms, CHECKED_AT);
    }

    #[test]
    fn parses_payload_with_nulls_and_missing_fields() {
        let json = r#"{"realtimeProtectionEnabled":null,"antivirusEnabled":false,"antispywareEnabled":false,"isTamperProtected":null,"engineVersion":null,"signatureVersion":null,"signatureAgeDays":null,"lastQuickScan":null,"lastFullScan":null,"threatsDetected":null}"#;
        let status = parse_defender_payload(json, CHECKED_AT).expect("fixture parses");
        assert!(status.available);
        assert!(!status.realtime_enabled);
        assert!(!status.antivirus_enabled);
        assert!(!status.tamper_protected);
        assert_eq!(status.engine_version, None);
        assert_eq!(status.signature_age_days, None);
        assert_eq!(status.last_quick_scan_ms, None);
        assert_eq!(status.threats_detected, None);
        assert_eq!(status.definition_status, None);
    }

    #[test]
    fn empty_strings_are_normalized_to_none() {
        let json = r#"{"engineVersion":"   ","signatureVersion":""}"#;
        let status = parse_defender_payload(json, CHECKED_AT).expect("fixture parses");
        assert_eq!(status.engine_version, None);
        assert_eq!(status.signature_version, None);
    }

    #[test]
    fn mixed_types_do_not_break_parsing() {
        // Numbers-as-strings and 0/1 booleans are tolerated field by field.
        let json = r#"{"realtimeProtectionEnabled":1,"antivirusEnabled":"true","signatureAgeDays":"3","threatsDetected":"7"}"#;
        let status = parse_defender_payload(json, CHECKED_AT).expect("fixture parses");
        assert!(status.realtime_enabled);
        assert!(status.antivirus_enabled);
        assert_eq!(status.signature_age_days, Some(3));
        assert_eq!(status.threats_detected, Some(7));
    }

    #[test]
    fn rejects_invalid_json_before_parsing_fields() {
        assert!(parse_defender_payload("", CHECKED_AT).is_err());
        assert!(parse_defender_payload("not json at all", CHECKED_AT).is_err());
        assert!(parse_defender_payload("[1,2,3]", CHECKED_AT).is_err());
    }

    #[test]
    fn strips_utf8_bom_before_parsing() {
        let json = "\u{feff}{\"antivirusEnabled\":true}";
        let status = parse_defender_payload(json, CHECKED_AT).expect("fixture parses");
        assert!(status.antivirus_enabled);
    }

    #[test]
    fn parses_timestamps_and_drops_implausible_ones() {
        assert_eq!(
            parse_timestamp_ms("2024-01-01T00:00:00.0000000Z"),
            Some(1_704_067_200_000)
        );
        assert_eq!(
            parse_timestamp_ms("2024-01-01T01:00:00.0000000+01:00"),
            Some(1_704_067_200_000)
        );
        // Never-scanned marker from Defender.
        assert_eq!(parse_timestamp_ms("1601-01-01T00:00:00Z"), None);
        assert_eq!(parse_timestamp_ms(""), None);
        assert_eq!(parse_timestamp_ms("not a date"), None);
    }

    #[test]
    fn definition_labels_cross_thresholds() {
        assert_eq!(definition_label(Some(0)).as_deref(), Some("up_to_date"));
        assert_eq!(definition_label(Some(1)).as_deref(), Some("up_to_date"));
        assert_eq!(definition_label(Some(2)).as_deref(), Some("aging"));
        assert_eq!(definition_label(Some(6)).as_deref(), Some("aging"));
        assert_eq!(definition_label(Some(7)).as_deref(), Some("out_of_date"));
        assert_eq!(definition_label(None), None);
    }

    #[test]
    fn unavailable_status_is_neutral_and_bounded() {
        let long_error = "x".repeat(1_000);
        let status = DefenderStatus::unavailable(CHECKED_AT, &long_error);
        assert!(!status.available);
        assert_eq!(status.checked_at_ms, CHECKED_AT);
        assert!(!status.realtime_enabled);
        assert!(!status.tamper_protected);
        assert_eq!(status.signature_age_days, None);
        assert_eq!(status.definition_status, None);
        assert_eq!(
            status.query_error.as_deref().map(str::len),
            Some(MAX_ERROR_CHARS)
        );
    }

    #[test]
    fn serializes_with_camel_case_field_names() {
        let status = DefenderStatus::unavailable(CHECKED_AT, "boom");
        let value = serde_json::to_value(&status).expect("serializes");
        assert!(value.get("queryError").is_some());
        assert!(value.get("realtimeEnabled").is_some());
        assert!(value.get("tamperProtected").is_some());
        assert!(value.get("lastQuickScanMs").is_some());
        assert!(value.get("checkedAtMs").is_some());
        assert!(value.get("query_error").is_none());
    }
}
