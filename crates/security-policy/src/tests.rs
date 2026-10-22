//! Unit tests for the deterministic policy engine.
//!
//! Invariants covered here are the ones that the rest of the product relies
//! on: AI can never quarantine, auto-quarantine obeys its configuration, a
//! known hash always alerts, and rule ids / reason strings are stable.

use super::*;
use security_core::{
    DecisionCategory, DecisionResult, Detection, FileRef, FileScanReport, ScanSource,
    SecurityEventKind, TelemetrySource,
};

fn report_with(signals: RiskSignals) -> FileScanReport {
    report_scored(RiskAssessment::from_signals(signals))
}

fn report_scored(assessment: RiskAssessment) -> FileScanReport {
    FileScanReport {
        id: security_core::new_id("fsr"),
        file: FileRef {
            path: "C:\\test\\sample.bin".to_string(),
            name: "sample.bin".to_string(),
            size: 42,
            ..Default::default()
        },
        detections: Vec::new(),
        assessment,
        source: ScanSource::Manual,
        duration_ms: 1,
        scanned_at_ms: 0,
        cache_hit: false,
        errors: Vec::new(),
    }
}

fn ai_decision(category: DecisionCategory, confidence: f32) -> DecisionResult {
    DecisionResult {
        id: security_core::new_id("dec"),
        provider: "mock-provider".to_string(),
        model: "mock-model".to_string(),
        model_version: None,
        category,
        probabilities: Default::default(),
        confidence,
        requires_investigation: false,
        suspicious_persistence: false,
        credential_theft: false,
        ransomware: false,
        latency_ms: 1,
        timestamp_ms: 0,
        evidence: Vec::new(),
        cost_usd: None,
        escalated: false,
    }
}

fn event(kind: SecurityEventKind, severity: Severity) -> SecurityEvent {
    SecurityEvent::new(kind, severity, TelemetrySource::FileScanner, "test event")
}

fn known_hash_signals() -> RiskSignals {
    RiskSignals {
        known_malware_hash: true,
        ..Default::default()
    }
}

/// YARA-heavy signals whose deterministic score is 100 without a known hash.
fn strong_yara_signals() -> RiskSignals {
    RiskSignals {
        yara_matches: 4,
        ransomware_indicator: true,
        credential_access_indicator: true,
        ..Default::default()
    }
}

fn assert_contains_rule(decision: &PolicyDecision, rule: &str) {
    assert!(
        decision.matched_rules.iter().any(|value| value == rule),
        "expected rule {rule} in {:?}",
        decision.matched_rules
    );
}

#[test]
fn defaults_match_contract() {
    let config = PolicyConfig::default();
    assert!(!config.auto_quarantine_enabled);
    assert_eq!(config.auto_quarantine_min_score, 90.0);
    assert!(config.auto_quarantine_requires_known_hash);
    assert_eq!(config.investigate_min_score, 40.0);
    assert_eq!(config.alert_min_score, 70.0);
    assert_eq!(config.validate(), Ok(()));

    let engine = PolicyEngine::new(PolicyConfig::default());
    assert_eq!(engine.config(), &config);
}

#[test]
fn config_serializes_camel_case() {
    let value = serde_json::to_value(PolicyConfig::default()).expect("config serializes");
    assert_eq!(value["autoQuarantineEnabled"], false);
    assert_eq!(value["autoQuarantineMinScore"], 90.0);
    assert_eq!(value["autoQuarantineRequiresKnownHash"], true);
    assert_eq!(value["investigateMinScore"], 40.0);
    assert_eq!(value["alertMinScore"], 70.0);
}

#[test]
fn invalid_config_is_sanitized_and_validated() {
    let bad = PolicyConfig {
        alert_min_score: f32::NAN,
        investigate_min_score: -5.0,
        auto_quarantine_min_score: 500.0,
        ..Default::default()
    };
    assert!(bad.validate().is_err());
    let engine = PolicyEngine::new(bad);
    assert_eq!(engine.config().alert_min_score, 70.0, "NaN falls back");
    assert_eq!(engine.config().investigate_min_score, 0.0, "clamped up");
    assert_eq!(
        engine.config().auto_quarantine_min_score,
        100.0,
        "clamped down"
    );

    let reversed = PolicyConfig {
        investigate_min_score: 80.0,
        alert_min_score: 70.0,
        ..Default::default()
    };
    assert!(matches!(
        reversed.validate(),
        Err(PolicyConfigError::ThresholdOrder { .. })
    ));
    let engine = PolicyEngine::new(reversed);
    assert_eq!(engine.config().investigate_min_score, 40.0);
    assert_eq!(engine.config().alert_min_score, 70.0);

    assert!(matches!(
        PolicyConfig {
            alert_min_score: f32::INFINITY,
            ..Default::default()
        }
        .validate(),
        Err(PolicyConfigError::InvalidThreshold { .. })
    ));
}

#[test]
fn auto_quarantine_gating_matrix() {
    let scenarios: &[(bool, bool, RiskSignals, PolicyOutcome)] = &[
        // enabled, requires_known_hash, signals, expected outcome
        (false, true, known_hash_signals(), PolicyOutcome::Alert),
        (false, false, known_hash_signals(), PolicyOutcome::Alert),
        (true, true, known_hash_signals(), PolicyOutcome::Quarantine),
        (true, false, known_hash_signals(), PolicyOutcome::Quarantine),
        (true, true, strong_yara_signals(), PolicyOutcome::Alert),
        (
            true,
            false,
            strong_yara_signals(),
            PolicyOutcome::Quarantine,
        ),
        (
            true,
            false,
            RiskSignals {
                yara_matches: 1,
                ..Default::default()
            },
            PolicyOutcome::Investigate,
        ),
        (
            true,
            true,
            RiskSignals {
                yara_matches: 1,
                ..Default::default()
            },
            PolicyOutcome::Investigate,
        ),
        (true, false, RiskSignals::default(), PolicyOutcome::Allow),
    ];

    for (enabled, requires_hash, signals, expected) in scenarios {
        let engine = PolicyEngine::new(PolicyConfig {
            auto_quarantine_enabled: *enabled,
            auto_quarantine_requires_known_hash: *requires_hash,
            ..Default::default()
        });
        let decision = engine.evaluate_scan(&report_with(signals.clone()), None);
        assert_eq!(
            decision.outcome, *expected,
            "enabled={enabled} requires_hash={requires_hash} signals={signals:?} -> {:?}",
            decision.outcome
        );
        assert_eq!(
            decision.quarantine_allowed,
            *expected == PolicyOutcome::Quarantine,
            "quarantine_allowed must track the Quarantine outcome"
        );
        if *expected == PolicyOutcome::Quarantine {
            assert!(!decision.requires_human_approval);
            if signals.known_malware_hash {
                assert_contains_rule(&decision, rule_ids::AUTO_QUARANTINE_KNOWN_HASH);
            } else {
                assert_contains_rule(&decision, rule_ids::AUTO_QUARANTINE_YARA_THRESHOLD);
            }
        }
        if *expected == PolicyOutcome::Alert && signals.known_malware_hash {
            assert_contains_rule(&decision, rule_ids::KNOWN_MALWARE_HASH);
        }
    }
}

#[test]
fn known_hash_is_at_least_alert_when_auto_quarantine_disabled() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: false,
        auto_quarantine_requires_known_hash: true,
        ..Default::default()
    });
    let decision = engine.evaluate_scan(&report_with(known_hash_signals()), None);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert!(decision.outcome >= PolicyOutcome::Alert);
    assert!(!decision.quarantine_allowed);
    assert!(decision.requires_human_approval);
    assert_contains_rule(&decision, rule_ids::KNOWN_MALWARE_HASH);
    assert_contains_rule(&decision, rule_ids::AUTO_QUARANTINE_DISABLED);
}

#[test]
fn quarantine_yara_path_requires_score_threshold() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        auto_quarantine_requires_known_hash: false,
        ..Default::default()
    });
    let signals = RiskSignals {
        yara_matches: 1,
        ..Default::default()
    };
    let mut assessment = RiskAssessment::from_signals(signals);
    assessment.score = 89.9;
    let below = engine.evaluate_scan(&report_scored(assessment.clone()), None);
    assert_ne!(below.outcome, PolicyOutcome::Quarantine);

    assessment.score = 90.0;
    let at_threshold = engine.evaluate_scan(&report_scored(assessment), None);
    assert_eq!(at_threshold.outcome, PolicyOutcome::Quarantine);
    assert_contains_rule(&at_threshold, rule_ids::AUTO_QUARANTINE_YARA_THRESHOLD);
}

#[test]
fn non_finite_scores_cannot_mask_known_hash() {
    let engine = PolicyEngine::default();
    let mut assessment = RiskAssessment::from_signals(known_hash_signals());
    assessment.score = f32::NAN;
    let decision = engine.evaluate_scan(&report_scored(assessment), None);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);

    // NaN reported score on a clean report stays clean.
    let mut clean = RiskAssessment::from_signals(RiskSignals::default());
    clean.score = f32::NAN;
    let decision = engine.evaluate_scan(&report_scored(clean), None);
    assert_eq!(decision.outcome, PolicyOutcome::Allow);
}

#[test]
fn unsigned_executable_is_observe_only() {
    let engine = PolicyEngine::default();
    let decision = engine.evaluate_scan(
        &report_with(RiskSignals {
            unsigned_executable: true,
            ..Default::default()
        }),
        None,
    );
    assert_eq!(decision.outcome, PolicyOutcome::Observe);
    assert!(!decision.requires_human_approval);
    assert!(!decision.quarantine_allowed);
}

#[test]
fn ai_escalation_thresholds() {
    let engine = PolicyEngine::default();
    let clean = RiskAssessment::from_signals(RiskSignals::default());

    let mut ai = ai_decision(DecisionCategory::LikelyMalicious, 0.49);
    assert_eq!(
        engine.evaluate_ai_only(&ai, &clean).outcome,
        PolicyOutcome::Allow
    );
    ai.confidence = 0.5;
    assert_eq!(
        engine.evaluate_ai_only(&ai, &clean).outcome,
        PolicyOutcome::Alert
    );

    let mut suspicious = ai_decision(DecisionCategory::Suspicious, 0.5);
    assert_eq!(
        engine.evaluate_ai_only(&suspicious, &clean).outcome,
        PolicyOutcome::Investigate
    );
    suspicious.confidence = 0.2;
    assert_eq!(
        engine.evaluate_ai_only(&suspicious, &clean).outcome,
        PolicyOutcome::Allow
    );

    let mut investigate = ai_decision(DecisionCategory::Unknown, 0.29);
    investigate.requires_investigation = true;
    assert_eq!(
        engine.evaluate_ai_only(&investigate, &clean).outcome,
        PolicyOutcome::Allow
    );
    investigate.confidence = 0.3;
    assert_eq!(
        engine.evaluate_ai_only(&investigate, &clean).outcome,
        PolicyOutcome::Investigate
    );

    let mut ransomware = ai_decision(DecisionCategory::Benign, 0.9);
    ransomware.ransomware = true;
    let decision = engine.evaluate_ai_only(&ransomware, &clean);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert_contains_rule(&decision, rule_ids::AI_HIGH_IMPACT);
    assert!(!decision.quarantine_allowed);
}

#[test]
fn evaluate_ai_only_never_quarantines() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        ..Default::default()
    });
    let assessments = [
        RiskAssessment::from_signals(RiskSignals::default()),
        RiskAssessment::from_signals(known_hash_signals()),
        RiskAssessment::from_signals(strong_yara_signals()),
    ];
    let categories = [
        DecisionCategory::Benign,
        DecisionCategory::Suspicious,
        DecisionCategory::LikelyMalicious,
        DecisionCategory::Unknown,
    ];
    let confidences = [0.0_f32, 0.25, 0.5, 0.9, 1.0, f32::NAN, f32::INFINITY];
    let flags = [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (true, true, true),
    ];

    for assessment in &assessments {
        for category in categories {
            for confidence in confidences {
                for (requires_investigation, ransomware, credential_theft) in flags {
                    let mut ai = ai_decision(category, confidence);
                    ai.requires_investigation = requires_investigation;
                    ai.ransomware = ransomware;
                    ai.credential_theft = credential_theft;
                    let decision = engine.evaluate_ai_only(&ai, assessment);
                    assert_ne!(
                        decision.outcome,
                        PolicyOutcome::Quarantine,
                        "AI-only input must never quarantine: {category:?}/{confidence}"
                    );
                    assert!(!decision.quarantine_allowed);
                    assert!(!decision.deterministic);
                    assert!(decision.id.starts_with("pol_"));
                }
            }
        }
    }
}

#[test]
fn ai_cannot_quarantine_a_clean_scan() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        ..Default::default()
    });
    let ai = ai_decision(DecisionCategory::LikelyMalicious, 0.99);
    let decision = engine.evaluate_scan(&report_with(RiskSignals::default()), Some(&ai));
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert!(!decision.quarantine_allowed);
    assert!(!decision.deterministic);
    assert!(decision.requires_human_approval);
    assert_contains_rule(&decision, rule_ids::AI_LIKELY_MALICIOUS);
}

#[test]
fn ai_cannot_lower_a_deterministic_quarantine() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        ..Default::default()
    });
    let ai = ai_decision(DecisionCategory::Benign, 0.99);
    let decision = engine.evaluate_scan(&report_with(known_hash_signals()), Some(&ai));
    assert_eq!(decision.outcome, PolicyOutcome::Quarantine);
    assert!(decision.quarantine_allowed);
    assert!(decision.deterministic, "AI did not change the outcome");
    assert!(!decision.requires_human_approval);
}

#[test]
fn ai_cannot_lower_alert_when_quarantine_disabled() {
    let engine = PolicyEngine::default();
    let ai = ai_decision(DecisionCategory::Benign, 1.0);
    let decision = engine.evaluate_scan(&report_with(known_hash_signals()), Some(&ai));
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert!(!decision.quarantine_allowed);
}

#[test]
fn rule_ids_and_reasons_are_stable() {
    assert_eq!(rule_ids::KNOWN_MALWARE_HASH, "policy.known_malware_hash.v1");
    assert_eq!(rule_ids::YARA_MATCH, "policy.yara_match.v1");
    assert_eq!(rule_ids::SCORE_ALERT, "policy.score.alert.v1");
    assert_eq!(rule_ids::SCORE_INVESTIGATE, "policy.score.investigate.v1");
    assert_eq!(
        rule_ids::AUTO_QUARANTINE_KNOWN_HASH,
        "policy.auto_quarantine.known_hash.v1"
    );
    assert_eq!(
        rule_ids::AUTO_QUARANTINE_YARA_THRESHOLD,
        "policy.auto_quarantine.yara_threshold.v1"
    );
    assert_eq!(
        rule_ids::AUTO_QUARANTINE_DISABLED,
        "policy.auto_quarantine.disabled.v1"
    );

    let engine = PolicyEngine::default();
    let decision = engine.evaluate_scan(&report_with(known_hash_signals()), None);
    assert_eq!(
        decision.matched_rules,
        vec![
            rule_ids::KNOWN_MALWARE_HASH.to_string(),
            rule_ids::SCORE_ALERT.to_string(),
            rule_ids::AUTO_QUARANTINE_DISABLED.to_string(),
        ]
    );
    assert!(
        decision
            .reason
            .starts_with("deterministic score 100.0 (critical)"),
        "unexpected reason: {}",
        decision.reason
    );
    assert!(
        decision
            .reason
            .contains("SHA-256 matches a known malicious sample identifier"),
        "unexpected reason: {}",
        decision.reason
    );
    assert!(
        decision.reason.contains("auto-quarantine is disabled"),
        "unexpected reason: {}",
        decision.reason
    );
    assert!(decision.id.starts_with("pol_"));
    assert!(decision.created_at_ms > 0);
}

#[test]
fn event_severity_floors_and_never_quarantines() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        ..Default::default()
    });
    let cases = [
        (Severity::Info, PolicyOutcome::Allow),
        (Severity::Low, PolicyOutcome::Allow),
        (Severity::Medium, PolicyOutcome::Observe),
        (Severity::High, PolicyOutcome::Investigate),
        (Severity::Critical, PolicyOutcome::Alert),
    ];
    for (severity, expected) in cases {
        let decision = engine.evaluate_event(&event(SecurityEventKind::ProcessCreated, severity));
        assert_eq!(decision.outcome, expected, "severity {severity:?}");
        assert!(!decision.quarantine_allowed);
        assert!(decision.deterministic);
        assert_ne!(decision.outcome, PolicyOutcome::Quarantine);
    }

    let critical = engine.evaluate_event(&event(SecurityEventKind::Detection, Severity::Critical));
    assert_contains_rule(&critical, rule_ids::EVENT_SEVERITY_CRITICAL);
}

#[test]
fn event_known_hash_detection_is_at_least_alert() {
    let engine = PolicyEngine::default();
    let mut observed = event(SecurityEventKind::Detection, Severity::Info);
    observed.detections.push(Detection {
        id: security_core::new_id("det"),
        rule_id: "hash.eicar_test".to_string(),
        rule_name: "EICAR test string".to_string(),
        source: DetectionSource::KnownHash,
        severity: Severity::Critical,
        description: "known hash".to_string(),
        score_contribution: 100.0,
        evidence: vec![],
        created_at_ms: 0,
    });
    let decision = engine.evaluate_event(&observed);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert!(!decision.quarantine_allowed);
    assert_contains_rule(&decision, rule_ids::KNOWN_MALWARE_HASH);
    assert!(decision.requires_human_approval);
}

#[test]
fn event_labels_map_to_deterministic_signals() {
    let engine = PolicyEngine::default();
    let mut observed = event(SecurityEventKind::ScriptActivity, Severity::Info);
    observed.labels = vec![
        "ransomware".to_string(),
        "credential_access".to_string(),
        "persistence".to_string(),
    ];
    let decision = engine.evaluate_event(&observed);
    assert_eq!(decision.outcome, PolicyOutcome::Investigate);
    assert_contains_rule(&decision, rule_ids::RANSOMWARE_INDICATOR);
    assert_contains_rule(&decision, rule_ids::CREDENTIAL_ACCESS_INDICATOR);
    assert_contains_rule(&decision, rule_ids::PERSISTENCE_ATTEMPT);
    assert!(!decision.quarantine_allowed);
}

#[test]
fn event_qualified_quarantine_is_deferred_to_scan() {
    let engine = PolicyEngine::new(PolicyConfig {
        auto_quarantine_enabled: true,
        ..Default::default()
    });
    let mut observed = event(SecurityEventKind::Detection, Severity::Critical);
    observed.assessment = Some(RiskAssessment::from_signals(known_hash_signals()));
    let decision = engine.evaluate_event(&observed);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert!(!decision.quarantine_allowed);
    assert_contains_rule(&decision, rule_ids::QUARANTINE_REQUIRES_SCAN);
}

#[test]
fn event_uses_stored_assessment_score() {
    let engine = PolicyEngine::default();
    let mut observed = event(SecurityEventKind::Correlation, Severity::Low);
    let mut assessment = RiskAssessment::from_signals(RiskSignals::default());
    assessment.score = 75.0;
    observed.assessment = Some(assessment);
    let decision = engine.evaluate_event(&observed);
    assert_eq!(decision.outcome, PolicyOutcome::Alert);
    assert_contains_rule(&decision, rule_ids::SCORE_ALERT);
}
