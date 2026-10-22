//! Security regression tests for the invariants the product promises.
//!
//! This file is owned by the `security-qa` reviewer role. It contains **new**
//! tests only; no implementation file is modified. Every test documents the
//! security invariant it protects in a comment directly above it.
//!
//! Scope:
//! * `security-policy` — the "AI output can never trigger a destructive
//!   action" invariant and the deterministic-basis requirement.
//! * `security-scanner` — quarantine vault safety (symlinks, restore
//!   overwrite, delete scope).
//! * `security-ipc` — frame size limits and truncation handling.
//! * `ai-decisions` — secret handling (API key never serialized/debug-printed).
//!
//! The tests do not touch the network, do not execute scanned files and do
//! not require Windows package identity. Windows-only behaviour is guarded
//! with `#[cfg(windows)]` and degrades to a documented skip.

use std::collections::BTreeMap;

use ai_decisions::{AiConfig, AiMode, ProviderConfig};
use security_core::{
    DecisionCategory, DecisionResult, Detection, DetectionSource, FileRef, FileScanReport,
    PolicyOutcome, RiskAssessment, RiskSignals, ScanSource, SecurityEvent, SecurityEventKind,
    Severity, TelemetrySource,
};
use security_ipc::{decode_frame, encode_frame, ClientRequest, IpcError, MAX_FRAME_BYTES};
use security_policy::{PolicyConfig, PolicyEngine};
use security_scanner::{QuarantineVault, ScanError};

// ---------------------------------------------------------------- helpers

/// The most aggressive decision a (hostile or malfunctioning) AI provider
/// could possibly return: maximum confidence, malicious category and every
/// high-impact flag raised.
fn maximally_aggressive_ai_decision() -> DecisionResult {
    DecisionResult {
        id: security_core::new_id("dec"),
        provider: "adversarial-provider".into(),
        model: "adversarial-model".into(),
        model_version: None,
        category: DecisionCategory::LikelyMalicious,
        probabilities: BTreeMap::from([("likely_malicious".to_string(), 1.0_f32)]),
        confidence: 1.0,
        requires_investigation: true,
        suspicious_persistence: true,
        credential_theft: true,
        ransomware: true,
        latency_ms: 0,
        timestamp_ms: 0,
        evidence: vec!["adversarial input".to_string()],
        cost_usd: None,
        escalated: true,
    }
}

/// The most permissive policy the product could ever be configured with:
/// auto-quarantine enabled, no known-hash requirement and every threshold at
/// its lowest legal value. If AI could quarantine under *this* configuration it
/// could quarantine under any configuration.
fn most_permissive_policy() -> PolicyConfig {
    PolicyConfig {
        auto_quarantine_enabled: true,
        auto_quarantine_min_score: 0.0,
        auto_quarantine_requires_known_hash: false,
        investigate_min_score: 0.0,
        alert_min_score: 0.0,
    }
}

/// A policy matrix that spans the shipped defaults through the most permissive
/// configuration the settings UI can produce.
fn policy_matrix() -> Vec<(&'static str, PolicyConfig)> {
    vec![
        ("default", PolicyConfig::default()),
        (
            "auto-quarantine on, known hash required",
            PolicyConfig {
                auto_quarantine_enabled: true,
                ..PolicyConfig::default()
            },
        ),
        (
            "auto-quarantine on, hash requirement waived",
            PolicyConfig {
                auto_quarantine_enabled: true,
                auto_quarantine_requires_known_hash: false,
                ..PolicyConfig::default()
            },
        ),
        ("most permissive", most_permissive_policy()),
    ]
}

fn report_with(signals: RiskSignals) -> FileScanReport {
    FileScanReport {
        id: security_core::new_id("fsr"),
        file: FileRef {
            path: r"C:\audit\fixture.bin".to_string(),
            name: "fixture.bin".to_string(),
            size: 64,
            ..Default::default()
        },
        detections: Vec::new(),
        assessment: RiskAssessment::from_signals(signals),
        source: ScanSource::Manual,
        duration_ms: 1,
        scanned_at_ms: 0,
        cache_hit: false,
        errors: Vec::new(),
    }
}

fn known_hash_signals() -> RiskSignals {
    RiskSignals {
        known_malware_hash: true,
        ..Default::default()
    }
}

// ------------------------------------------------------------- policy tests

/// Invariant: **AI output can never trigger quarantine or any destructive
/// action.** A maximally aggressive, fully untrusted `DecisionResult` fed into
/// `PolicyEngine::evaluate_ai_only` must never produce `Quarantine`, and
/// `quarantine_allowed` must always be `false`, for every policy
/// configuration — including the most permissive one.
#[test]
fn ai_decision_can_never_trigger_quarantine_in_any_policy_configuration() {
    let ai = maximally_aggressive_ai_decision();
    let assessments = [
        (
            "clean",
            RiskAssessment::from_signals(RiskSignals::default()),
        ),
        (
            "known hash",
            RiskAssessment::from_signals(known_hash_signals()),
        ),
        (
            "yara heavy",
            RiskAssessment::from_signals(RiskSignals {
                yara_matches: 4,
                ransomware_indicator: true,
                credential_access_indicator: true,
                ..Default::default()
            }),
        ),
    ];

    for (config_name, config) in policy_matrix() {
        let engine = PolicyEngine::new(config);
        for (assessment_name, assessment) in &assessments {
            let decision = engine.evaluate_ai_only(&ai, assessment);
            assert_ne!(
                decision.outcome,
                PolicyOutcome::Quarantine,
                "AI-only evaluation produced a quarantine outcome \
                 (config={config_name}, assessment={assessment_name})"
            );
            assert!(
                !decision.quarantine_allowed,
                "quarantine_allowed must be false for AI-only input \
                 (config={config_name}, assessment={assessment_name})"
            );
            assert!(
                decision.outcome <= PolicyOutcome::Alert,
                "AI-only evaluation must be capped at Alert \
                 (config={config_name}, assessment={assessment_name})"
            );
            assert!(
                !decision.deterministic,
                "an AI-only decision is never marked deterministic \
                 (config={config_name}, assessment={assessment_name})"
            );
        }
    }
}

/// Invariant: **auto-quarantine requires a deterministic basis.** A scan
/// report whose only "evidence" is an AI decision (no known hash, no YARA
/// match) must not reach `Quarantine`, even when auto-quarantine is enabled
/// and the known-hash requirement is waived.
#[test]
fn auto_quarantine_requires_a_deterministic_hash_or_yara_basis() {
    let engine = PolicyEngine::new(most_permissive_policy());
    let ai = maximally_aggressive_ai_decision();

    // Behavioural / PE heuristics only: no known hash, no YARA match.
    let heuristic_only = report_with(RiskSignals {
        unsigned_executable: true,
        high_entropy: true,
        suspicious_imports: true,
        writable_executable_section: true,
        ..Default::default()
    });
    assert!(
        !heuristic_only.assessment.signals.known_malware_hash,
        "fixture must not carry a known-hash signal"
    );
    assert_eq!(
        heuristic_only.assessment.signals.yara_matches, 0,
        "fixture must not carry a YARA signal"
    );

    let decision = engine.evaluate_scan(&heuristic_only, Some(&ai));
    assert_ne!(
        decision.outcome,
        PolicyOutcome::Quarantine,
        "AI output alone must never reach a quarantine outcome"
    );
    assert!(
        !decision.quarantine_allowed,
        "AI output alone must never set quarantine_allowed"
    );

    // Control: the same policy *does* quarantine when a deterministic
    // known-hash basis is present. Without this the assertion above could
    // pass for the wrong reason.
    let deterministic = engine.evaluate_scan(&report_with(known_hash_signals()), Some(&ai));
    assert_eq!(
        deterministic.outcome,
        PolicyOutcome::Quarantine,
        "control case: a known hash must still quarantine under this policy"
    );
    assert!(deterministic.quarantine_allowed);
}

/// Invariant: **behaviour-only events are capped at `Alert`.** No combination
/// of behavioural labels, a critical severity and even a known-hash assessment
/// attached to an *event* may produce a quarantine outcome — quarantine is
/// only ever decided from a file scan report.
#[test]
fn event_evaluation_is_capped_at_alert() {
    let engine = PolicyEngine::new(most_permissive_policy());

    let mut event = SecurityEvent::new(
        SecurityEventKind::Correlation,
        Severity::Critical,
        TelemetrySource::Correlation,
        "adversarial behaviour chain",
    );
    event.labels = vec![
        "ransomware".to_string(),
        "credential_access".to_string(),
        "persistence".to_string(),
        "startup_folder_write".to_string(),
        "obfuscated_script".to_string(),
        "unusual_network".to_string(),
        "suspicious_parent".to_string(),
        "high_entropy".to_string(),
        "suspicious_imports".to_string(),
        "writable_executable_section".to_string(),
        "unsigned_executable".to_string(),
        "invalid_signature".to_string(),
        "temp_execution".to_string(),
        "lolbin".to_string(),
    ];
    event.detections.push(Detection {
        id: security_core::new_id("det"),
        rule_id: "hash.known_malicious".to_string(),
        rule_name: "known malicious sample".to_string(),
        source: DetectionSource::KnownHash,
        severity: Severity::Critical,
        description: "adversarial fixture".to_string(),
        score_contribution: 100.0,
        evidence: Vec::new(),
        created_at_ms: 0,
    });
    event.assessment = Some(RiskAssessment::from_signals(known_hash_signals()));

    let decision = engine.evaluate_event(&event);
    assert_ne!(
        decision.outcome,
        PolicyOutcome::Quarantine,
        "an event must never produce a quarantine outcome"
    );
    assert!(
        decision.outcome <= PolicyOutcome::Alert,
        "event evaluation must be capped at Alert, got {:?}",
        decision.outcome
    );
    assert!(
        !decision.quarantine_allowed,
        "event evaluation must never set quarantine_allowed"
    );
}

// ---------------------------------------------------------- quarantine tests

/// Invariant: **the quarantine vault never overwrites an existing file on
/// restore.** After a successful restore, a second restore attempt for the
/// same record must be refused and must leave the on-disk file untouched.
#[test]
fn quarantine_restore_never_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = QuarantineVault::new(dir.path().join("vault")).expect("vault");
    let original = dir.path().join("restore-target.bin");
    let payload = b"quarantine restore overwrite fixture".to_vec();
    std::fs::write(&original, &payload).expect("write fixture");

    let record = vault
        .quarantine(&original, "security audit", None)
        .expect("quarantine");

    // Quarantine is copy-only: the original is still present, so the first
    // restore is refused. Remove it to model "the user cleaned up the file".
    assert!(original.exists());
    std::fs::remove_file(&original).expect("remove original");

    let first = vault.restore(&record.id).expect("first restore");
    assert!(
        first.success,
        "first restore must succeed: {}",
        first.message
    );
    assert_eq!(
        std::fs::read(&original).expect("read restored file"),
        payload,
        "restored bytes must match the quarantined copy"
    );

    // Now mutate the restored file. A second restore must be refused and
    // must not clobber the newer content.
    let newer = b"newer user content that must survive".to_vec();
    std::fs::write(&original, &newer).expect("replace restored file");

    let second = vault.restore(&record.id).expect("second restore attempt");
    assert!(
        !second.success,
        "a second restore must be refused, got: {}",
        second.message
    );
    assert!(
        second.restored_path.is_none(),
        "a refused restore must not report a restored path"
    );
    assert!(
        second.message.contains("refusing to overwrite"),
        "unexpected refusal message: {}",
        second.message
    );
    assert_eq!(
        std::fs::read(&original).expect("read file after refused restore"),
        newer,
        "the refused restore must not overwrite the existing file"
    );
}

/// Invariant: **the quarantine vault rejects symlinks and reparse points.**
/// A symlink must never be copied into the vault, because the copy would
/// point at a target outside the vault.
#[cfg(windows)]
#[test]
fn quarantine_vault_rejects_symlinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = QuarantineVault::new(dir.path().join("vault")).expect("vault");
    let target = dir.path().join("symlink-target.bin");
    let payload = b"symlink target payload".to_vec();
    std::fs::write(&target, &payload).expect("write target");

    let link = dir.path().join("symlink-link.bin");
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        eprintln!("skipping symlink test: creating symlinks is not permitted on this system");
        return;
    }

    let error = vault
        .quarantine(&link, "security audit", None)
        .expect_err("a symlink must never be quarantined");
    assert!(
        matches!(error, ScanError::SymlinkRejected(_)),
        "unexpected error for a symlink source: {error:?}"
    );

    assert!(
        vault.list().is_empty(),
        "a rejected symlink must not create a vault record"
    );
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        payload,
        "the symlink target must be untouched"
    );
}

/// Invariant: **deleting a quarantine record touches only the vault copy.**
/// The original file must survive with byte-identical content; only the copy
/// inside the vault and its sidecar may be removed.
#[test]
fn quarantine_delete_touches_only_the_vault_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = QuarantineVault::new(dir.path().join("vault")).expect("vault");
    let original = dir.path().join("delete-scope.bin");
    let payload = b"delete scope fixture".to_vec();
    std::fs::write(&original, &payload).expect("write fixture");

    let record = vault
        .quarantine(&original, "security audit", None)
        .expect("quarantine");
    let stored = std::path::PathBuf::from(&record.stored_path);
    assert!(stored.exists(), "the vault copy must exist before deletion");
    assert!(original.exists(), "the original must exist before deletion");

    vault.delete(&record.id).expect("delete");

    assert!(
        !stored.exists(),
        "the vault copy must be removed by an explicit delete"
    );
    assert!(
        vault.list().is_empty(),
        "the sidecar must be removed by an explicit delete"
    );
    assert!(
        original.exists(),
        "the original file must survive an explicit vault delete"
    );
    assert_eq!(
        std::fs::read(&original).expect("read original after delete"),
        payload,
        "the original bytes must be unchanged by an explicit vault delete"
    );
}

// ----------------------------------------------------------------- ipc tests

/// Invariant: **the IPC transport enforces a hard frame size limit and
/// rejects truncated frames.** A peer must not be able to make the service
/// allocate or interpret an oversized payload, nor to smuggle a partial frame
/// past the length prefix.
#[test]
fn ipc_rejects_oversized_and_truncated_frames() {
    // A frame whose declared payload length exceeds the limit is rejected
    // before any allocation happens.
    let mut oversized_payload = br#"{"type":"ping"}"#.to_vec();
    oversized_payload.resize(MAX_FRAME_BYTES + 1, b' ');
    let mut oversized_frame = (oversized_payload.len() as u32).to_le_bytes().to_vec();
    oversized_frame.extend_from_slice(&oversized_payload);
    assert!(
        matches!(
            decode_frame::<ClientRequest>(&oversized_frame),
            Err(IpcError::FrameTooLarge { .. })
        ),
        "a frame larger than MAX_FRAME_BYTES must be rejected"
    );

    // A frame that is exactly at the limit is still accepted (the limit is
    // inclusive), which proves the rejection above is the limit and not an
    // unrelated parse failure.
    let mut at_limit_payload = br#"{"type":"ping"}"#.to_vec();
    at_limit_payload.resize(MAX_FRAME_BYTES, b' ');
    let mut at_limit_frame = (at_limit_payload.len() as u32).to_le_bytes().to_vec();
    at_limit_frame.extend_from_slice(&at_limit_payload);
    let decoded = decode_frame::<ClientRequest>(&at_limit_frame)
        .expect("a frame exactly at MAX_FRAME_BYTES must decode");
    assert_eq!(decoded, ClientRequest::Ping);

    // A truncated frame is rejected instead of being partially interpreted.
    let frame = encode_frame(&ClientRequest::GetStatus).expect("encode");
    let truncated = &frame[..frame.len() - 3];
    assert!(
        matches!(
            decode_frame::<ClientRequest>(truncated),
            Err(IpcError::TruncatedFrame { .. })
        ),
        "a truncated frame must be rejected"
    );

    // A short header is rejected before the length prefix can be read.
    assert!(
        matches!(
            decode_frame::<ClientRequest>(&[0, 0, 0]),
            Err(IpcError::HeaderTooShort { .. })
        ),
        "a frame shorter than the length prefix must be rejected"
    );
}

// -------------------------------------------------------------- secret tests

/// Invariant: **the OpenRouter API key never reaches the React layer, the
/// event log or a persisted configuration file.** `AiConfig` is the exact type
/// the desktop layer serializes into the `ai.config` settings row and derives
/// the UI status from, so both its `Serialize` and its `Debug` implementations
/// must drop the key entirely.
#[test]
fn api_key_is_never_serialized_or_debug_printed() {
    let secret = "sk-or-v1-AUDITKEY-must-never-leak-0123456789";
    let config = AiConfig {
        mode: AiMode::Cloud,
        api_key: Some(secret.to_string()),
        allow_cloud_state: true,
        ..AiConfig::default()
    };

    let json = serde_json::to_string(&config).expect("config serializes");
    assert!(
        !json.contains("AUDITKEY"),
        "the serialized configuration must not contain the API key: {json}"
    );
    assert!(
        !json.contains("apiKey"),
        "the serialized configuration must not contain an apiKey field: {json}"
    );

    let debug = format!("{config:?}");
    assert!(
        !debug.contains("AUDITKEY"),
        "the Debug output must not contain the API key: {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "the Debug output must mark the key as redacted: {debug}"
    );

    // The provider-level configuration is the other object that holds the key
    // and is logged on provider errors.
    let provider = ProviderConfig::new("typesafe/jev-1.14", Some(secret.to_string()));
    let provider_debug = format!("{provider:?}");
    assert!(
        !provider_debug.contains("AUDITKEY"),
        "the provider Debug output must not contain the API key: {provider_debug}"
    );
    assert!(
        provider_debug.contains("<redacted>"),
        "the provider Debug output must mark the key as redacted: {provider_debug}"
    );
}
