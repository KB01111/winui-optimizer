//! Bundled YARA-X rules, compilation, and match-to-`Detection` mapping.

use std::path::Path;
use std::time::Duration;

use security_core::{new_id, Detection, DetectionSource, Severity};
use yara_x::{Compiler, MetaValue, Rule, Rules, ScanResults, Scanner as YaraScanner};

use crate::{now_ms, ScanError, ScannerConfig};

/// Bundled default rules, embedded at compile time.
///
/// The rules are deliberately conservative: the EICAR test string, a
/// PowerShell download cradle, and a writable+executable PE section marker.
pub fn default_yara_rules() -> &'static str {
    include_str!("../rules/default.yar")
}

/// Compiles the bundled rules plus optional extra rules from the config.
pub(crate) fn compile_rules(config: &ScannerConfig) -> Result<Rules, ScanError> {
    let mut compiler = Compiler::new();
    compiler
        .add_source(default_yara_rules())
        .map_err(|err| ScanError::Rules(format!("bundled rules: {err}")))?;
    if let Some(extra) = config.extra_yara_rules.as_deref() {
        if !extra.trim().is_empty() {
            compiler
                .add_source(extra)
                .map_err(|err| ScanError::Rules(format!("extra rules: {err}")))?;
        }
    }
    Ok(compiler.build())
}

/// Known malware SHA-256 seed list: `(sha256, rule_id, description)`.
///
/// This is intentionally tiny and deterministic. The seed entry is the
/// harmless EICAR anti-malware test file; production threat intel is expected
/// to merge in additional hashes from elsewhere.
pub(crate) const KNOWN_MALWARE_SHA256: &[(&str, &str, &str)] = &[(
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "hash.eicar_test",
    "EICAR standard anti-malware test file",
)];

/// Returns `(rule_id, description)` when the hash is a known malicious sample.
///
/// The comparison is case-insensitive and trims surrounding whitespace.
pub(crate) fn known_hash_entry(hash: &str) -> Option<(&'static str, &'static str)> {
    let normalized = hash.trim().to_ascii_lowercase();
    KNOWN_MALWARE_SHA256
        .iter()
        .find(|(known, _, _)| *known == normalized)
        .map(|(_, rule_id, description)| (*rule_id, *description))
}

/// Result of a YARA scan: detections plus non-fatal error notes.
#[derive(Debug, Default)]
pub(crate) struct YaraOutcome {
    pub detections: Vec<Detection>,
    pub errors: Vec<String>,
}

/// Scans an in-memory buffer.
pub(crate) fn scan_buffer(
    rules: &Rules,
    data: &[u8],
    timeout_ms: u64,
    max_scan_bytes: Option<usize>,
) -> YaraOutcome {
    let mut scanner = YaraScanner::new(rules);
    configure(&mut scanner, timeout_ms, max_scan_bytes);
    match scanner.scan(data) {
        Ok(results) => outcome_from_results(&results),
        Err(err) => YaraOutcome {
            detections: Vec::new(),
            errors: vec![scan_error_note(&err, timeout_ms)],
        },
    }
}

/// Scans a file from disk (mmap-backed inside yara-x, so peak memory stays
/// bounded even for very large files).
pub(crate) fn scan_file(
    rules: &Rules,
    path: &Path,
    timeout_ms: u64,
    max_scan_bytes: Option<usize>,
) -> YaraOutcome {
    let mut scanner = YaraScanner::new(rules);
    configure(&mut scanner, timeout_ms, max_scan_bytes);
    match scanner.scan_file(path) {
        Ok(results) => outcome_from_results(&results),
        Err(err) => YaraOutcome {
            detections: Vec::new(),
            errors: vec![scan_error_note(&err, timeout_ms)],
        },
    }
}

fn configure(scanner: &mut YaraScanner<'_>, timeout_ms: u64, max_scan_bytes: Option<usize>) {
    if timeout_ms > 0 {
        scanner.set_timeout(Duration::from_millis(timeout_ms));
    }
    if let Some(max) = max_scan_bytes {
        if max > 0 {
            scanner.max_scan_size(max);
        }
    }
}

fn scan_error_note(err: &yara_x::ScanError, timeout_ms: u64) -> String {
    match err {
        // yara-x enforces timeouts with an internal ~1 second heartbeat, so
        // the effective granularity of `yara_timeout_ms` is about one second.
        yara_x::ScanError::Timeout => format!(
            "yara scan timed out after {timeout_ms} ms (yara-x timeout granularity is about one second)"
        ),
        other => format!("yara scan failed: {other}"),
    }
}

fn outcome_from_results(results: &ScanResults<'_, '_>) -> YaraOutcome {
    let mut detections: Vec<Detection> = Vec::new();
    for rule in results.matching_rules() {
        detections.push(detection_for_rule(&rule));
    }
    detections.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    YaraOutcome {
        detections,
        errors: Vec::new(),
    }
}

fn detection_for_rule(rule: &Rule<'_, '_>) -> Detection {
    let identifier = rule.identifier().to_string();
    let mut rule_name = identifier.clone();
    let mut description = format!("YARA rule `{identifier}` matched");
    let mut severity = Severity::Medium;
    let mut score = 45.0_f32;

    for (key, value) in rule.metadata() {
        match (key, value) {
            ("name", MetaValue::String(value)) => rule_name = value.to_string(),
            ("description", MetaValue::String(value)) => description = value.to_string(),
            ("severity", MetaValue::String(value)) => {
                severity = severity_from_name(value);
            }
            ("score", MetaValue::Integer(value)) => {
                score = (value as f32).clamp(0.0, 100.0);
            }
            ("score", MetaValue::Float(value)) if value.is_finite() => {
                score = (value as f32).clamp(0.0, 100.0);
            }
            _ => {}
        }
    }

    let mut evidence = Vec::new();
    for pattern in rule.patterns() {
        let pattern_id = pattern.identifier().to_string();
        if let Some(found) = pattern.matches().next() {
            let range = found.range();
            evidence.push(format!(
                "{pattern_id} at 0x{:x}..0x{:x}",
                range.start, range.end
            ));
        }
        if evidence.len() >= 8 {
            break;
        }
    }

    Detection {
        id: new_id("det"),
        rule_id: identifier,
        rule_name,
        source: DetectionSource::Yara,
        severity,
        description,
        score_contribution: score,
        evidence,
        created_at_ms: now_ms(),
    }
}

fn severity_from_name(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}
