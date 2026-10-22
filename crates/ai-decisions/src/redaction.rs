//! Redaction of security event state before it can leave the machine.
//!
//! This is defense in depth: it runs even when the user allowed cloud state
//! sharing (`allow_cloud_state = true`) and again inside every provider.
//! Removed or shortened: user profile paths and user names, absolute paths
//! (reduced to the file name), full SHA-256 hashes (reduced to 8 characters)
//! and known environment user names (including `DOMAIN\user`).

use security_core::{
    BehaviorState, DetectionSource, DetectionState, DeterministicSummary, FileState, ProcessState,
    RiskAssessment, SecurityEvent, SecurityEventState,
};

/// One-line note appended to provider evidence describing probability quality.
pub(crate) const CALIBRATION_NOTE: &str =
    "uncalibrated model probabilities: raw provider output, not calibrated to measured accuracy";

/// Redact a state object. Idempotent.
pub fn redact_state(state: &SecurityEventState) -> SecurityEventState {
    let mut redacted = state.clone();

    if let Some(process) = redacted.process.as_mut() {
        process.name = scrub_file_name(&process.name);
        process.parent = process.parent.as_deref().map(scrub_file_name);
        process.command_line_redacted = process.command_line_redacted.as_deref().map(scrub_text);
    }

    if let Some(file) = redacted.file.as_mut() {
        file.name = scrub_file_name(&file.name);
        file.extension = file
            .extension
            .as_deref()
            .map(|ext| ext.trim_start_matches('.').to_ascii_lowercase())
            .filter(|ext| {
                !ext.is_empty() && ext.len() <= 16 && ext.chars().all(|c| c.is_ascii_alphanumeric())
            });
        file.sha256_prefix = file
            .sha256_prefix
            .as_deref()
            .map(|hash| hash.chars().take(8).collect::<String>())
            .filter(|prefix| !prefix.is_empty());
    }

    redacted.detections.yara_matches = redacted
        .detections
        .yara_matches
        .iter()
        .map(|rule| scrub_text(rule))
        .collect();
    redacted.detections.heuristic_flags = redacted
        .detections
        .heuristic_flags
        .iter()
        .map(|flag| scrub_text(flag))
        .collect();
    redacted.deterministic.reasons = redacted
        .deterministic
        .reasons
        .iter()
        .map(|reason| scrub_text(reason))
        .collect();

    redacted
}

/// Build the structured, redacted state for an event and its assessment.
pub fn build_decision_state(
    event: &SecurityEvent,
    assessment: &RiskAssessment,
) -> SecurityEventState {
    let process = event.process.as_ref().map(|process| ProcessState {
        name: process.name.clone(),
        signed: process.signed,
        parent: process.parent_name.clone(),
        command_line_redacted: process.command_line.clone(),
    });

    let file = event.file.as_ref().map(|file| FileState {
        name: if file.name.is_empty() {
            file_name_of(&file.path)
        } else {
            file.name.clone()
        },
        extension: extension_of(&file.name).or_else(|| extension_of(&file.path)),
        size: file.size,
        sha256_prefix: file
            .sha256
            .as_deref()
            .map(|hash| hash.chars().take(8).collect()),
        in_temp: path_is_temp(&file.path),
        in_startup: path_is_startup(&file.path),
    });

    let mut known_malware_hash = assessment.signals.known_malware_hash;
    let mut yara_matches = Vec::new();
    let mut heuristic_flags = Vec::new();
    for detection in &event.detections {
        match detection.source {
            DetectionSource::Yara => yara_matches.push(detection.rule_id.clone()),
            DetectionSource::KnownHash => known_malware_hash = true,
            DetectionSource::PeHeuristic
            | DetectionSource::BehaviorRule
            | DetectionSource::Policy
            | DetectionSource::Defender => heuristic_flags.push(detection.rule_id.clone()),
        }
    }

    let spawned_script_host = event
        .labels
        .iter()
        .any(|label| label == "spawned_script_host")
        || event
            .process
            .as_ref()
            .and_then(|process| process.parent_name.as_deref())
            .map(is_script_host)
            .unwrap_or(false);

    let state = SecurityEventState {
        event_id: event.id.clone(),
        event_type: event.kind.as_str().to_string(),
        timestamp_ms: event.timestamp_ms,
        process,
        file,
        behavior: BehaviorState {
            persistence_attempt: assessment.signals.persistence_attempt,
            obfuscated_script: assessment.signals.obfuscated_script,
            unusual_network_activity: assessment.signals.unusual_network_activity,
            credential_access: assessment.signals.credential_access_indicator,
            ransomware: assessment.signals.ransomware_indicator,
            spawned_script_host,
        },
        detections: DetectionState {
            known_malware_hash,
            yara_matches,
            heuristic_flags,
        },
        deterministic: DeterministicSummary::from(assessment),
    };

    redact_state(&state)
}

// ---------------------------------------------------------------------------
// Text scrubbing
// ---------------------------------------------------------------------------

/// Scrub one command line, path, rule name or reason string.
pub(crate) fn scrub_text(input: &str) -> String {
    let masked = mask_segment_after_marker(input, "\\users\\");
    let masked = mask_segment_after_marker(&masked, "\\documents and settings\\");
    let tokens: Vec<String> = split_tokens(&masked)
        .into_iter()
        .map(|token| reduce_path_token(&token))
        .collect();
    let mut result = tokens.join(" ");
    for username in environment_usernames() {
        result = replace_ignore_case_ascii(&result, &username, "<user>");
    }
    result = replace_ignore_case_ascii(&result, "%username%", "<user>");
    truncate_hex_runs(&result)
}

/// Reduce a possibly-absolute name to its last path component (file name only).
pub(crate) fn scrub_file_name(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"');
    let base = trimmed
        .rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .unwrap_or(trimmed);
    scrub_text(base)
}

fn file_name_of(path: &str) -> String {
    scrub_file_name(path)
}

fn extension_of(name: &str) -> Option<String> {
    std::path::Path::new(name)
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
}

fn is_script_host(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "powershell.exe"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "cmd.exe"
            | "mshta.exe"
            | "wmic.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
    )
}

/// True when the path points into any temporary directory.
pub(crate) fn path_is_temp(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.ends_with("\\temp")
        || lower.contains("\\appdata\\local\\temp")
}

/// True when the path points into a startup persistence location.
pub(crate) fn path_is_startup(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    lower.contains("\\startup\\") || lower.contains("\\start menu\\programs\\startup")
}

/// Replace the segment following a marker (for example `\users\`) with `<user>`.
fn mask_segment_after_marker(text: &str, marker_lower: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while let Some(position) = lower[cursor..].find(marker_lower) {
        let marker_start = cursor + position;
        let segment_start = marker_start + marker_lower.len();
        result.push_str(&text[cursor..segment_start]);
        let mut segment_end = segment_start;
        for (offset, ch) in text[segment_start..].char_indices() {
            if ch == '\\' || ch == '/' {
                break;
            }
            segment_end = segment_start + offset + ch.len_utf8();
        }
        if segment_end > segment_start {
            result.push_str("<user>");
        }
        cursor = segment_end;
    }
    result.push_str(&text[cursor..]);
    result
}

/// Whitespace tokenizer that keeps quoted segments together.
fn split_tokens(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in input.chars() {
        match quote {
            Some(open) => {
                current.push(ch);
                if ch == open {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch.is_whitespace() {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(ch);
                }
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Reduce a token to its file name when it looks like an absolute path.
fn reduce_path_token(token: &str) -> String {
    let trimmed = token.trim_matches(|ch| ch == '"' || ch == '\'');
    if let Some(eq) = trimmed.find('=') {
        let (key, value) = trimmed.split_at(eq + 1);
        return format!("{key}{}", reduce_path_token(value));
    }
    if trimmed.contains('\\') {
        if let Some(component) = last_component(trimmed, '\\') {
            return component.to_string();
        }
    }
    if trimmed.len() > 1 && trimmed.starts_with('/') && trimmed[1..].contains('/') {
        if let Some(component) = last_component(trimmed, '/') {
            return component.to_string();
        }
    }
    trimmed.to_string()
}

fn last_component(value: &str, separator: char) -> Option<&str> {
    let mut end = value.len();
    while end > 0 {
        match value[..end].chars().next_back() {
            Some(ch) if ch == separator => end -= ch.len_utf8(),
            _ => break,
        }
    }
    let value = &value[..end];
    if value.is_empty() {
        return None;
    }
    match value.rfind(separator) {
        Some(index) => {
            let component = &value[index + 1..];
            if component.is_empty() {
                None
            } else {
                Some(component)
            }
        }
        None => Some(value),
    }
}

/// Truncate hex runs of 16+ characters (MD5/SHA-1/SHA-256 and similar) to their
/// first 8 characters.
fn truncate_hex_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            run.push(ch);
            continue;
        }
        flush_hex_run(&mut run, &mut out);
        out.push(ch);
    }
    flush_hex_run(&mut run, &mut out);
    out
}

fn flush_hex_run(run: &mut String, out: &mut String) {
    if run.chars().count() >= 16 {
        out.extend(run.chars().take(8));
        out.push_str("[…]");
    } else {
        out.push_str(run);
    }
    run.clear();
}

fn environment_usernames() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(user) = std::env::var("USERNAME") {
        let user = user.trim().to_string();
        if user.len() >= 2 {
            if let Ok(domain) = std::env::var("USERDOMAIN") {
                let domain = domain.trim();
                if !domain.is_empty() {
                    names.push(format!("{domain}\\{user}"));
                }
            }
            names.push(user);
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if let Some(component) = profile.rsplit(['\\', '/']).find(|part| !part.is_empty()) {
            let component = component.to_string();
            if component.len() >= 2 && !names.iter().any(|n| n.eq_ignore_ascii_case(&component)) {
                names.push(component);
            }
        }
    }
    names
}

fn replace_ignore_case_ascii(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let haystack_lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(position) = haystack_lower[cursor..].find(&needle_lower) {
        let start = cursor + position;
        out.push_str(&haystack[cursor..start]);
        out.push_str(replacement);
        cursor = start + needle.len();
    }
    out.push_str(&haystack[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_core::{
        Detection, RiskAssessment, RiskSignals, SecurityEventKind, Severity, TelemetrySource,
    };

    fn sample_event() -> SecurityEvent {
        let mut event = SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::High,
            TelemetrySource::ProcessSnapshot,
            "suspicious process",
        );
        event.id = "evt_redaction".into();
        event.process = Some(security_core::ProcessRef {
            pid: 4242,
            name: r"C:\Users\someuser\AppData\Local\Temp\evil.exe".into(),
            parent_name: Some("powershell.exe".into()),
            command_line: Some(
                r#""C:\Users\someuser\AppData\Local\Temp\evil.exe" -stager http://example.invalid"#
                    .into(),
            ),
            signed: Some(false),
            ..Default::default()
        });
        event.file = Some(security_core::FileRef {
            path: r"C:\Users\someuser\AppData\Local\Temp\payload.bin".into(),
            name: "payload.bin".into(),
            size: 4096,
            sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()),
            ..Default::default()
        });
        event.detections.push(Detection {
            id: "det_1".into(),
            rule_id: "yara_test_rule".into(),
            rule_name: "yara_test_rule".into(),
            source: DetectionSource::Yara,
            severity: Severity::High,
            description: String::new(),
            score_contribution: 45.0,
            evidence: vec![],
            created_at_ms: 0,
        });
        event.detections.push(Detection {
            id: "det_2".into(),
            rule_id: "pe_high_entropy".into(),
            rule_name: "pe_high_entropy".into(),
            source: DetectionSource::PeHeuristic,
            severity: Severity::Medium,
            description: String::new(),
            score_contribution: 5.0,
            evidence: vec![],
            created_at_ms: 0,
        });
        event
    }

    #[test]
    fn redacts_usernames_and_absolute_paths_in_command_lines() {
        let state = build_decision_state(
            &sample_event(),
            &RiskAssessment::from_signals(RiskSignals::default()),
        );
        let command_line = state
            .process
            .as_ref()
            .and_then(|process| process.command_line_redacted.as_deref())
            .unwrap_or_default();
        assert!(!command_line.contains("someuser"), "{command_line}");
        assert!(!command_line.contains("AppData"), "{command_line}");
        assert!(command_line.contains("evil.exe"), "{command_line}");
        assert!(
            command_line.contains("http://example.invalid"),
            "{command_line}"
        );
        assert_eq!(
            state.process.as_ref().map(|p| p.name.as_str()),
            Some("evil.exe")
        );
    }

    #[test]
    fn truncates_hashes_to_eight_characters() {
        let state = build_decision_state(
            &sample_event(),
            &RiskAssessment::from_signals(RiskSignals::default()),
        );
        assert_eq!(
            state.file.as_ref().and_then(|f| f.sha256_prefix.as_deref()),
            Some("01234567")
        );
        assert!(state.file.as_ref().map(|f| f.in_temp).unwrap_or(false));
    }

    #[test]
    fn scrubs_hashes_and_paths_in_reasons_and_rule_names() {
        let mut state = build_decision_state(
            &sample_event(),
            &RiskAssessment::from_signals(RiskSignals::default()),
        );
        state.detections.yara_matches = vec![r"rule C:\Users\someuser\rules\test.yar".to_string()];
        state.deterministic.reasons = vec![
            "SHA-256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef matches"
                .to_string(),
        ];
        let redacted = redact_state(&state);
        let yara = &redacted.detections.yara_matches[0];
        assert!(!yara.contains("someuser"), "{yara}");
        assert!(yara.contains("test.yar"), "{yara}");
        let reason = &redacted.deterministic.reasons[0];
        assert!(
            !reason.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(
            reason.contains("01234567[") || reason.contains("01234567…"),
            "{reason}"
        );
    }

    #[test]
    fn build_state_maps_detections_and_behavior() {
        let signals = RiskSignals {
            persistence_attempt: true,
            credential_access_indicator: true,
            ransomware_indicator: true,
            unusual_network_activity: true,
            ..Default::default()
        };
        let assessment = RiskAssessment::from_signals(signals);
        let state = build_decision_state(&sample_event(), &assessment);
        assert!(state.behavior.persistence_attempt);
        assert!(state.behavior.credential_access);
        assert!(state.behavior.ransomware);
        assert!(state.behavior.spawned_script_host);
        assert_eq!(
            state.detections.yara_matches,
            vec!["yara_test_rule".to_string()]
        );
        assert_eq!(
            state.detections.heuristic_flags,
            vec!["pe_high_entropy".to_string()]
        );
        assert!(!state.detections.known_malware_hash);
        assert_eq!(state.event_type, "process_created");
        assert_eq!(state.deterministic.score, assessment.score);
    }

    #[test]
    fn extension_is_normalized() {
        let mut state = build_decision_state(
            &sample_event(),
            &RiskAssessment::from_signals(RiskSignals::default()),
        );
        if let Some(file) = state.file.as_mut() {
            file.extension = Some(".BIN".into());
        }
        let redacted = redact_state(&state);
        assert_eq!(
            redacted.file.and_then(|f| f.extension),
            Some("bin".to_string())
        );
    }

    #[test]
    fn user_profile_segments_are_masked_even_without_env_username() {
        let scrubbed = scrub_text(r"copy C:\Users\someuser\secrets.txt D:\backup\");
        assert!(!scrubbed.contains("someuser"), "{scrubbed}");
        assert!(scrubbed.contains("secrets.txt"), "{scrubbed}");
    }
}
