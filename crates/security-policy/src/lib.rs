//! Deterministic security policy engine.
//!
//! Design rules that this crate enforces:
//!
//! - Only deterministic signals (`RiskSignals`, known hashes, YARA match
//!   counts) can raise an outcome to `Quarantine`.
//! - AI output (`DecisionResult`) may escalate an outcome toward
//!   `Investigate`/`Alert`, but it can never lower the deterministic outcome
//!   and it can never produce `Quarantine`.
//! - `evaluate_ai_only` never returns `Quarantine` for any input.
//! - Every outcome carries stable rule ids ([`rule_ids`]) and reason strings
//!   so the audit log and UI can be correlated across releases.
//!
//! The engine performs no I/O and never panics on untrusted input: scores and
//! identifiers coming from reports, events or AI providers are sanitized
//! before use.

use chrono::Utc;
use security_core::{
    DecisionCategory, DecisionResult, DetectionSource, FileScanReport, PolicyDecision,
    PolicyOutcome, RiskAssessment, RiskLevel, RiskSignals, SecurityEvent, Severity,
};
use serde::{Deserialize, Serialize};

/// Stable, auditable rule identifiers.
///
/// The `.v1` suffix is intentional: rule ids and their meaning are part of the
/// audit trail and must never change silently. Add a new version instead.
pub mod rule_ids {
    /// SHA-256 matches a known malicious sample identifier.
    pub const KNOWN_MALWARE_HASH: &str = "policy.known_malware_hash.v1";
    /// At least one YARA rule matched.
    pub const YARA_MATCH: &str = "policy.yara_match.v1";
    /// Deterministic score reached the configured alert threshold.
    pub const SCORE_ALERT: &str = "policy.score.alert.v1";
    /// Deterministic score reached the configured investigate threshold.
    pub const SCORE_INVESTIGATE: &str = "policy.score.investigate.v1";
    /// Deterministic score was non-zero but below the investigate threshold.
    pub const SCORE_OBSERVE: &str = "policy.score.observe.v1";
    /// Event severity (`critical`) raised the outcome.
    pub const EVENT_SEVERITY_CRITICAL: &str = "policy.event.severity_critical.v1";
    /// Event severity (`high`) raised the outcome.
    pub const EVENT_SEVERITY_HIGH: &str = "policy.event.severity_high.v1";
    /// Event severity (`medium`) raised the outcome.
    pub const EVENT_SEVERITY_MEDIUM: &str = "policy.event.severity_medium.v1";
    /// Quarantine is only decided from file scan reports.
    pub const QUARANTINE_REQUIRES_SCAN: &str = "policy.quarantine.requires_scan.v1";
    /// Known-malware hash satisfies the auto-quarantine rules.
    pub const AUTO_QUARANTINE_KNOWN_HASH: &str = "policy.auto_quarantine.known_hash.v1";
    /// YARA evidence plus score satisfies the auto-quarantine rules.
    pub const AUTO_QUARANTINE_YARA_THRESHOLD: &str = "policy.auto_quarantine.yara_threshold.v1";
    /// Deterministic evidence qualifies, but auto-quarantine is disabled.
    pub const AUTO_QUARANTINE_DISABLED: &str = "policy.auto_quarantine.disabled.v1";
    /// Signal: credential access indicator observed.
    pub const CREDENTIAL_ACCESS_INDICATOR: &str = "policy.signal.credential_access.v1";
    /// Signal: ransomware indicator observed.
    pub const RANSOMWARE_INDICATOR: &str = "policy.signal.ransomware.v1";
    /// Signal: persistence attempt observed.
    pub const PERSISTENCE_ATTEMPT: &str = "policy.signal.persistence_attempt.v1";
    /// Signal: startup folder write observed.
    pub const STARTUP_FOLDER_WRITE: &str = "policy.signal.startup_folder_write.v1";
    /// Signal: obfuscated script observed.
    pub const OBFUSCATED_SCRIPT: &str = "policy.signal.obfuscated_script.v1";
    /// Signal: unusual network activity observed.
    pub const UNUSUAL_NETWORK_ACTIVITY: &str = "policy.signal.unusual_network.v1";
    /// Signal: suspicious imports observed.
    pub const SUSPICIOUS_IMPORTS: &str = "policy.signal.suspicious_imports.v1";
    /// Signal: writable and executable PE section observed.
    pub const WRITABLE_EXECUTABLE_SECTION: &str = "policy.signal.writable_executable_section.v1";
    /// Signal: high entropy observed.
    pub const HIGH_ENTROPY: &str = "policy.signal.high_entropy.v1";
    /// Signal: unsigned executable observed.
    pub const UNSIGNED_EXECUTABLE: &str = "policy.signal.unsigned_executable.v1";
    /// Signal: invalid Authenticode signature observed.
    pub const INVALID_SIGNATURE: &str = "policy.signal.invalid_signature.v1";
    /// Signal: suspicious parent process observed.
    pub const SUSPICIOUS_PARENT: &str = "policy.signal.suspicious_parent.v1";
    /// Signal: executable launched from a temporary directory.
    pub const TEMP_EXECUTION: &str = "policy.signal.temp_execution.v1";
    /// Signal: built-in Windows binary used in an unusual context.
    pub const LIVING_OFF_THE_LAND: &str = "policy.signal.living_off_the_land.v1";
    /// AI requested further investigation.
    pub const AI_REQUIRES_INVESTIGATION: &str = "policy.ai.requires_investigation.v1";
    /// AI classified the sample as suspicious.
    pub const AI_SUSPICIOUS: &str = "policy.ai.suspicious.v1";
    /// AI classified the sample as likely malicious.
    pub const AI_LIKELY_MALICIOUS: &str = "policy.ai.likely_malicious.v1";
    /// AI reported credential-theft or ransomware indicators.
    pub const AI_HIGH_IMPACT: &str = "policy.ai.high_impact.v1";
}

/// Minimum AI confidence before `suspicious`/`likely_malicious` categories or
/// high-impact flags can raise the policy outcome.
pub const AI_MIN_CONFIDENCE: f32 = 0.5;

/// Minimum AI confidence before `requires_investigation` raises the outcome.
pub const AI_INVESTIGATE_MIN_CONFIDENCE: f32 = 0.3;

/// Configuration for the deterministic policy engine.
///
/// Defaults are part of the public contract:
/// auto-quarantine is disabled, auto-quarantine needs a known hash and a score
/// of at least 90, investigation starts at 40 and alerts start at 70.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyConfig {
    /// Enable automatic quarantine decisions from scan reports.
    pub auto_quarantine_enabled: bool,
    /// Minimum deterministic score before auto-quarantine qualifies.
    pub auto_quarantine_min_score: f32,
    /// When true, auto-quarantine also requires a known malware hash.
    pub auto_quarantine_requires_known_hash: bool,
    /// Minimum deterministic score for an `Investigate` outcome.
    pub investigate_min_score: f32,
    /// Minimum deterministic score for an `Alert` outcome.
    pub alert_min_score: f32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            auto_quarantine_enabled: false,
            auto_quarantine_min_score: 90.0,
            auto_quarantine_requires_known_hash: true,
            investigate_min_score: 40.0,
            alert_min_score: 70.0,
        }
    }
}

/// Validation error for [`PolicyConfig`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PolicyConfigError {
    /// A threshold was not finite or outside `[0, 100]`.
    #[error("threshold `{field}` must be finite and within [0, 100], got {value}")]
    InvalidThreshold {
        /// Name of the offending field.
        field: &'static str,
        /// Offending value.
        value: f32,
    },
    /// `investigate_min_score` must not exceed `alert_min_score`.
    #[error(
        "threshold order invalid: investigate_min_score ({investigate}) must not exceed alert_min_score ({alert})"
    )]
    ThresholdOrder {
        /// Configured investigate threshold.
        investigate: f32,
        /// Configured alert threshold.
        alert: f32,
    },
}

impl PolicyConfig {
    /// Validates the configuration without modifying it.
    pub fn validate(&self) -> Result<(), PolicyConfigError> {
        for (field, value) in [
            ("auto_quarantine_min_score", self.auto_quarantine_min_score),
            ("investigate_min_score", self.investigate_min_score),
            ("alert_min_score", self.alert_min_score),
        ] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                return Err(PolicyConfigError::InvalidThreshold { field, value });
            }
        }
        if self.investigate_min_score > self.alert_min_score {
            return Err(PolicyConfigError::ThresholdOrder {
                investigate: self.investigate_min_score,
                alert: self.alert_min_score,
            });
        }
        Ok(())
    }

    /// Returns a copy with non-finite or out-of-range thresholds replaced by
    /// the documented defaults. [`PolicyEngine::new`] applies this so an
    /// invalid settings file can never disable alerting silently.
    pub fn sanitized(&self) -> Self {
        let defaults = Self::default();
        let mut config = *self;
        config.auto_quarantine_min_score = finite_threshold(
            self.auto_quarantine_min_score,
            defaults.auto_quarantine_min_score,
        );
        config.investigate_min_score =
            finite_threshold(self.investigate_min_score, defaults.investigate_min_score);
        config.alert_min_score = finite_threshold(self.alert_min_score, defaults.alert_min_score);
        if config.investigate_min_score > config.alert_min_score {
            config.investigate_min_score = defaults.investigate_min_score;
            config.alert_min_score = defaults.alert_min_score;
        }
        config
    }
}

fn finite_threshold(value: f32, fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 100.0)
    } else {
        fallback
    }
}

/// The deterministic policy engine. Cheap to clone; contains only config.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl PolicyEngine {
    /// Creates an engine. Invalid thresholds (NaN, infinities, reversed
    /// investigate/alert order) fall back to the documented defaults; call
    /// [`PolicyConfig::validate`] first if you want to reject them loudly.
    pub fn new(config: PolicyConfig) -> Self {
        let sanitized = config.sanitized();
        if sanitized != config {
            tracing::warn!(
                target: "security_policy",
                "policy config contained invalid thresholds; defaults were applied for those fields"
            );
        }
        Self { config: sanitized }
    }

    /// Returns the (sanitized) active configuration.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Evaluates a single observation event.
    ///
    /// Events are behavioral observations, never the quarantine input: the
    /// outcome is capped at [`PolicyOutcome::Alert`] and `quarantine_allowed`
    /// is always `false`. Use [`PolicyEngine::evaluate_scan`] for file
    /// quarantine decisions.
    pub fn evaluate_event(&self, event: &SecurityEvent) -> PolicyDecision {
        let derived = signals_from_event(event);
        let assessment = match &event.assessment {
            Some(existing) => {
                let mut signals = existing.signals.clone();
                merge_signals(&mut signals, &derived);
                let mut rebuilt = RiskAssessment::from_signals(signals);
                // Preserve a stored score that is higher than what the
                // signals reproduce (for example a correlation score).
                if existing.score.is_finite() {
                    rebuilt.score = existing.score.clamp(0.0, 100.0).max(rebuilt.score);
                    rebuilt.level = RiskLevel::from_score(rebuilt.score);
                }
                rebuilt
            }
            None => RiskAssessment::from_signals(derived),
        };

        let score = effective_score(assessment.score, &assessment.signals);
        let level = RiskLevel::from_score(score);
        let mut rules = deterministic_signal_rules(&assessment.signals);
        let mut notes: Vec<String> = Vec::new();
        let mut outcome = self.outcome_for_score(score, &mut rules, &mut notes);

        if let Some((floor, rule, note)) = severity_floor(event.severity) {
            if floor > outcome {
                outcome = floor;
            }
            rules.push(rule);
            notes.push(note.to_string());
        }
        if assessment.signals.known_malware_hash && outcome < PolicyOutcome::Alert {
            outcome = PolicyOutcome::Alert;
            notes.push("known-malware hash forces at least an alert".to_string());
        }
        if self
            .quarantine_qualification(&assessment.signals, score)
            .is_some()
        {
            rules.push(rule_ids::QUARANTINE_REQUIRES_SCAN);
            notes.push(
                "quarantine is only decided from file scan reports; event decisions stop at alert"
                    .to_string(),
            );
        }
        // Defensive: events never produce quarantine even if future rules
        // assign a stronger outcome.
        if outcome >= PolicyOutcome::Quarantine {
            outcome = PolicyOutcome::Alert;
        }

        tracing::debug!(
            target: "security_policy",
            event_id = %event.id,
            outcome = ?outcome,
            score,
            "evaluated event"
        );

        self.finish(
            outcome,
            score,
            level,
            rules,
            assessment.signals.explain(),
            notes,
            true,
        )
    }

    /// Evaluates a completed file scan report, optionally with an AI decision.
    ///
    /// `Quarantine` is returned only when all of the following hold:
    ///
    /// 1. `auto_quarantine_enabled` is true,
    /// 2. the deterministic evidence is a known-malware hash or a YARA match
    ///    whose deterministic score reaches `auto_quarantine_min_score`,
    /// 3. when `auto_quarantine_requires_known_hash` is true, a known hash is
    ///    present.
    ///
    /// A known-malware hash always yields at least `Alert`, even when
    /// auto-quarantine is disabled.
    pub fn evaluate_scan(
        &self,
        report: &FileScanReport,
        ai: Option<&DecisionResult>,
    ) -> PolicyDecision {
        let signals = &report.assessment.signals;
        let score = effective_score(report.assessment.score, signals);
        let level = RiskLevel::from_score(score);

        let mut rules = deterministic_signal_rules(signals);
        let mut notes: Vec<String> = Vec::new();
        let mut outcome = self.outcome_for_score(score, &mut rules, &mut notes);

        if signals.known_malware_hash && outcome < PolicyOutcome::Alert {
            outcome = PolicyOutcome::Alert;
            notes.push("known-malware hash forces at least an alert".to_string());
        }

        let mut deterministic = true;
        if let Some(ai) = ai {
            let (floor, ai_rules, ai_notes) = ai_escalation(ai);
            if floor > outcome {
                outcome = floor;
                deterministic = false;
            }
            rules.extend(ai_rules);
            notes.extend(ai_notes);
        }

        // AI escalation is capped at Alert; only the deterministic
        // qualification below can reach Quarantine.
        if outcome >= PolicyOutcome::Quarantine {
            outcome = PolicyOutcome::Alert;
            deterministic = false;
        }

        match self.quarantine_qualification(signals, score) {
            Some((rule, note)) if self.config.auto_quarantine_enabled => {
                outcome = PolicyOutcome::Quarantine;
                rules.push(rule);
                notes.push(note);
            }
            Some(_) => {
                rules.push(rule_ids::AUTO_QUARANTINE_DISABLED);
                notes.push(
                    "deterministic evidence meets auto-quarantine rules but auto-quarantine is disabled; human approval required"
                        .to_string(),
                );
            }
            None => {}
        }

        tracing::debug!(
            target: "security_policy",
            report_id = %report.id,
            outcome = ?outcome,
            score,
            ai = ai.is_some(),
            "evaluated scan report"
        );

        self.finish(
            outcome,
            score,
            level,
            rules,
            signals.explain(),
            notes,
            deterministic,
        )
    }

    /// Evaluates AI output plus a deterministic assessment in isolation.
    ///
    /// Invariant: the returned decision is **never** `Quarantine`, for any
    /// input. This path exists for replaying or testing AI decisions without a
    /// file report.
    pub fn evaluate_ai_only(
        &self,
        ai: &DecisionResult,
        assessment: &RiskAssessment,
    ) -> PolicyDecision {
        let signals = &assessment.signals;
        // The deterministic floor for this path deliberately ignores
        // auto-quarantine eligibility: AI input alone can never quarantine.
        let score = effective_score(assessment.score, signals);
        let level = RiskLevel::from_score(score);

        let mut rules = deterministic_signal_rules(signals);
        let mut notes: Vec<String> = Vec::new();
        let mut outcome = self.outcome_for_score(score, &mut rules, &mut notes);
        if signals.known_malware_hash && outcome < PolicyOutcome::Alert {
            outcome = PolicyOutcome::Alert;
            notes.push("known-malware hash forces at least an alert".to_string());
        }

        let (floor, ai_rules, ai_notes) = ai_escalation(ai);
        if floor > outcome {
            outcome = floor;
        }
        rules.extend(ai_rules);
        notes.extend(ai_notes);

        // Hard invariant: AI-only evaluation can never return Quarantine.
        if outcome >= PolicyOutcome::Quarantine {
            outcome = PolicyOutcome::Alert;
            notes.push(
                "quarantine requires a deterministic file scan decision; capped at alert"
                    .to_string(),
            );
        }
        if self.quarantine_qualification(signals, score).is_some()
            && !notes.iter().any(|n| n.contains("quarantine requires"))
        {
            rules.push(rule_ids::QUARANTINE_REQUIRES_SCAN);
            notes.push(
                "quarantine requires a deterministic file scan decision; capped at alert"
                    .to_string(),
            );
        }

        tracing::debug!(
            target: "security_policy",
            ai_id = %ai.id,
            outcome = ?outcome,
            score,
            "evaluated ai-only decision"
        );

        self.finish(
            outcome,
            score,
            level,
            rules,
            signals.explain(),
            notes,
            false,
        )
    }

    /// Deterministic qualification for auto-quarantine.
    fn quarantine_qualification(
        &self,
        signals: &RiskSignals,
        score: f32,
    ) -> Option<(&'static str, String)> {
        let yara_evidence = signals.yara_matches > 0;
        if !(signals.known_malware_hash || yara_evidence) {
            return None;
        }
        if self.config.auto_quarantine_requires_known_hash && !signals.known_malware_hash {
            return None;
        }
        if score < self.config.auto_quarantine_min_score {
            return None;
        }
        if signals.known_malware_hash {
            Some((
                rule_ids::AUTO_QUARANTINE_KNOWN_HASH,
                format!(
                    "known-malware SHA-256 with deterministic score {score:.1} >= auto-quarantine threshold {:.1}",
                    self.config.auto_quarantine_min_score
                ),
            ))
        } else {
            Some((
                rule_ids::AUTO_QUARANTINE_YARA_THRESHOLD,
                format!(
                    "{} YARA match(es) with deterministic score {score:.1} >= auto-quarantine threshold {:.1}",
                    signals.yara_matches, self.config.auto_quarantine_min_score
                ),
            ))
        }
    }

    fn outcome_for_score(
        &self,
        score: f32,
        rules: &mut Vec<&'static str>,
        notes: &mut Vec<String>,
    ) -> PolicyOutcome {
        let config = &self.config;
        if score >= config.alert_min_score {
            rules.push(rule_ids::SCORE_ALERT);
            notes.push(format!(
                "deterministic score {score:.1} >= alert threshold {:.1}",
                config.alert_min_score
            ));
            PolicyOutcome::Alert
        } else if score >= config.investigate_min_score {
            rules.push(rule_ids::SCORE_INVESTIGATE);
            notes.push(format!(
                "deterministic score {score:.1} >= investigate threshold {:.1}",
                config.investigate_min_score
            ));
            PolicyOutcome::Investigate
        } else if score > 0.0 {
            rules.push(rule_ids::SCORE_OBSERVE);
            notes.push(format!(
                "deterministic score {score:.1} is below the investigate threshold {:.1}",
                config.investigate_min_score
            ));
            PolicyOutcome::Observe
        } else {
            PolicyOutcome::Allow
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        outcome: PolicyOutcome,
        score: f32,
        level: RiskLevel,
        rules: Vec<&'static str>,
        signal_reasons: Vec<String>,
        notes: Vec<String>,
        deterministic: bool,
    ) -> PolicyDecision {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!(
            "deterministic score {score:.1} ({})",
            level_name(level)
        ));
        parts.extend(signal_reasons.into_iter().take(3));
        parts.extend(notes.into_iter().take(3));
        let total = parts.len();
        let mut reason = parts.into_iter().take(6).collect::<Vec<_>>().join("; ");
        if total > 6 {
            reason.push_str(&format!(" (+{} more)", total - 6));
        }

        PolicyDecision {
            id: security_core::new_id("pol"),
            outcome,
            reason,
            matched_rules: dedupe_rules(rules),
            requires_human_approval: outcome >= PolicyOutcome::Alert
                && outcome != PolicyOutcome::Quarantine,
            quarantine_allowed: outcome == PolicyOutcome::Quarantine,
            deterministic,
            created_at_ms: Utc::now().timestamp_millis(),
        }
    }
}

fn level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Unknown => "unknown",
        RiskLevel::Clean => "clean",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn dedupe_rules(rules: Vec<&'static str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(rules.len());
    for rule in rules {
        if !out.iter().any(|existing| existing == rule) {
            out.push(rule.to_string());
        }
    }
    out
}

/// Deterministic score used by the engine: the reported assessment score and
/// the score recomputed from signals, whichever is higher, sanitized to
/// `[0, 100]`. A malformed report can therefore never *lower* the outcome.
fn effective_score(reported: f32, signals: &RiskSignals) -> f32 {
    let reported = if reported.is_finite() {
        reported.clamp(0.0, 100.0)
    } else {
        0.0
    };
    let computed = signals.deterministic_score();
    let computed = if computed.is_finite() {
        computed.clamp(0.0, 100.0)
    } else {
        0.0
    };
    reported.max(computed)
}

fn deterministic_signal_rules(signals: &RiskSignals) -> Vec<&'static str> {
    let mut rules = Vec::new();
    if signals.known_malware_hash {
        rules.push(rule_ids::KNOWN_MALWARE_HASH);
    }
    if signals.yara_matches > 0 {
        rules.push(rule_ids::YARA_MATCH);
    }
    if signals.credential_access_indicator {
        rules.push(rule_ids::CREDENTIAL_ACCESS_INDICATOR);
    }
    if signals.ransomware_indicator {
        rules.push(rule_ids::RANSOMWARE_INDICATOR);
    }
    if signals.persistence_attempt {
        rules.push(rule_ids::PERSISTENCE_ATTEMPT);
    }
    if signals.startup_folder_write {
        rules.push(rule_ids::STARTUP_FOLDER_WRITE);
    }
    if signals.obfuscated_script {
        rules.push(rule_ids::OBFUSCATED_SCRIPT);
    }
    if signals.unusual_network_activity {
        rules.push(rule_ids::UNUSUAL_NETWORK_ACTIVITY);
    }
    if signals.suspicious_imports {
        rules.push(rule_ids::SUSPICIOUS_IMPORTS);
    }
    if signals.writable_executable_section {
        rules.push(rule_ids::WRITABLE_EXECUTABLE_SECTION);
    }
    if signals.high_entropy {
        rules.push(rule_ids::HIGH_ENTROPY);
    }
    if signals.unsigned_executable {
        rules.push(rule_ids::UNSIGNED_EXECUTABLE);
    }
    if signals.invalid_signature {
        rules.push(rule_ids::INVALID_SIGNATURE);
    }
    if signals.suspicious_parent {
        rules.push(rule_ids::SUSPICIOUS_PARENT);
    }
    if signals.temp_execution {
        rules.push(rule_ids::TEMP_EXECUTION);
    }
    if signals.living_off_the_land_binary {
        rules.push(rule_ids::LIVING_OFF_THE_LAND);
    }
    rules
}

/// Severity floor contributed by an event's declared severity.
fn severity_floor(severity: Severity) -> Option<(PolicyOutcome, &'static str, &'static str)> {
    match severity {
        Severity::Critical => Some((
            PolicyOutcome::Alert,
            rule_ids::EVENT_SEVERITY_CRITICAL,
            "event severity is critical",
        )),
        Severity::High => Some((
            PolicyOutcome::Investigate,
            rule_ids::EVENT_SEVERITY_HIGH,
            "event severity is high",
        )),
        Severity::Medium => Some((
            PolicyOutcome::Observe,
            rule_ids::EVENT_SEVERITY_MEDIUM,
            "event severity is medium",
        )),
        Severity::Low | Severity::Info => None,
    }
}

/// Derives risk signals from an event when no assessment is attached.
///
/// Recognized label keys: `persistence`, `credential_access`, `ransomware`,
/// `obfuscated_script`, `unusual_network`, `suspicious_parent`,
/// `startup_folder_write`, `temp_execution`, `lolbin`, `unsigned_executable`,
/// `invalid_signature`, `high_entropy`, `suspicious_imports`,
/// `writable_executable_section`.
fn signals_from_event(event: &SecurityEvent) -> RiskSignals {
    let mut signals = event
        .assessment
        .as_ref()
        .map(|assessment| assessment.signals.clone())
        .unwrap_or_default();

    for detection in &event.detections {
        match detection.source {
            DetectionSource::KnownHash => signals.known_malware_hash = true,
            DetectionSource::Yara => {
                signals.yara_matches = signals.yara_matches.saturating_add(1);
            }
            _ => {}
        }
    }

    for label in &event.labels {
        match label.as_str() {
            "persistence" => signals.persistence_attempt = true,
            "credential_access" => signals.credential_access_indicator = true,
            "ransomware" => signals.ransomware_indicator = true,
            "obfuscated_script" => signals.obfuscated_script = true,
            "unusual_network" => signals.unusual_network_activity = true,
            "suspicious_parent" => signals.suspicious_parent = true,
            "startup_folder_write" => signals.startup_folder_write = true,
            "temp_execution" => signals.temp_execution = true,
            "lolbin" => signals.living_off_the_land_binary = true,
            "unsigned_executable" => signals.unsigned_executable = true,
            "invalid_signature" => signals.invalid_signature = true,
            "high_entropy" => signals.high_entropy = true,
            "suspicious_imports" => signals.suspicious_imports = true,
            "writable_executable_section" => signals.writable_executable_section = true,
            _ => {}
        }
    }

    signals
}

fn merge_signals(base: &mut RiskSignals, other: &RiskSignals) {
    base.known_malware_hash |= other.known_malware_hash;
    base.yara_matches = base.yara_matches.max(other.yara_matches);
    base.unsigned_executable |= other.unsigned_executable;
    base.invalid_signature |= other.invalid_signature;
    base.suspicious_imports |= other.suspicious_imports;
    base.persistence_attempt |= other.persistence_attempt;
    base.obfuscated_script |= other.obfuscated_script;
    base.unusual_network_activity |= other.unusual_network_activity;
    base.suspicious_parent |= other.suspicious_parent;
    base.high_entropy |= other.high_entropy;
    base.writable_executable_section |= other.writable_executable_section;
    base.credential_access_indicator |= other.credential_access_indicator;
    base.ransomware_indicator |= other.ransomware_indicator;
    base.startup_folder_write |= other.startup_folder_write;
    base.temp_execution |= other.temp_execution;
    base.living_off_the_land_binary |= other.living_off_the_land_binary;
}

/// Maps an AI decision to the highest outcome it may contribute (never
/// quarantine) plus auditable rule ids and reason strings.
fn ai_escalation(ai: &DecisionResult) -> (PolicyOutcome, Vec<&'static str>, Vec<String>) {
    let mut rules: Vec<&'static str> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut floor = PolicyOutcome::Allow;

    let confidence = if ai.confidence.is_finite() {
        ai.confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let provider = sanitize_text(&ai.provider);

    if (ai.ransomware || ai.credential_theft) && confidence >= AI_MIN_CONFIDENCE {
        floor = PolicyOutcome::Alert;
        rules.push(rule_ids::AI_HIGH_IMPACT);
        notes.push(format!(
            "AI provider {provider} reported credential-theft or ransomware indicators (confidence {confidence:.2})"
        ));
    }

    match ai.category {
        DecisionCategory::LikelyMalicious if confidence >= AI_MIN_CONFIDENCE => {
            floor = floor.max(PolicyOutcome::Alert);
            rules.push(rule_ids::AI_LIKELY_MALICIOUS);
            notes.push(format!(
                "AI provider {provider} classified the sample as likely malicious (confidence {confidence:.2})"
            ));
        }
        DecisionCategory::Suspicious if confidence >= AI_MIN_CONFIDENCE => {
            floor = floor.max(PolicyOutcome::Investigate);
            rules.push(rule_ids::AI_SUSPICIOUS);
            notes.push(format!(
                "AI provider {provider} classified the sample as suspicious (confidence {confidence:.2})"
            ));
        }
        _ => {}
    }

    if ai.requires_investigation && confidence >= AI_INVESTIGATE_MIN_CONFIDENCE {
        floor = floor.max(PolicyOutcome::Investigate);
        rules.push(rule_ids::AI_REQUIRES_INVESTIGATION);
        notes.push("AI requested further investigation".to_string());
    }

    // Hard invariant: AI can never contribute quarantine.
    if floor >= PolicyOutcome::Quarantine {
        floor = PolicyOutcome::Alert;
    }

    (floor, rules, notes)
}

/// Truncates and strips control characters from provider-supplied text before
/// it is embedded in audit reasons.
fn sanitize_text(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests;
