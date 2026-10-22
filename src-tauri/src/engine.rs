//! Embedded security engine used while the desktop UI is running.
//!
//! The background Windows service (see `services/security-service`) provides
//! the same pipeline when the UI is closed. This embedded engine exists so the
//! application works without requiring an elevated service installation.
//!
//! Monitoring is **observational**: processes are observed by snapshot diffing,
//! not intercepted. Only deterministic policy can quarantine, and automatic
//! quarantine is opt-in and off by default.

use crate::types::{EngineState, ScanPathArgs};
use crate::AppState;
use parking_lot::Mutex;
use security_core::{
    new_id, PolicyDecision, PolicyOutcome, RiskLevel, ScanJobSummary, ScanProgress, ScanSource,
    ScanState, SecurityEvent, SecurityEventKind, Severity, TelemetrySource,
};
use security_policy::{PolicyConfig, PolicyEngine};
use security_scanner::{Scanner, ScannerConfig};
use security_telemetry::{CorrelationEngine, ProcessMonitor, ProcessSnapshotProvider};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

#[cfg(not(windows))]
use security_telemetry::UnsupportedProcessSnapshot;
#[cfg(windows)]
use security_telemetry::WindowsProcessSnapshot;

pub struct Engine {
    runtime: Mutex<EngineRuntime>,
    scanner: Mutex<Arc<Scanner>>,
    policy: Mutex<Arc<PolicyEngine>>,
    cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
    monitor: Mutex<ProcessMonitor>,
    correlation: Mutex<CorrelationEngine>,
}

struct EngineRuntime {
    running: bool,
    started_at_ms: Option<i64>,
    started_instant: Option<Instant>,
    events_processed: u64,
    correlated_chains: u64,
    detections: u64,
    scans_completed: u64,
    last_event_log_ms: i64,
}

impl Engine {
    pub fn new(
        scanner_config: ScannerConfig,
        policy_config: PolicyConfig,
    ) -> Result<Arc<Self>, String> {
        let provider: Box<dyn ProcessSnapshotProvider> = {
            #[cfg(windows)]
            {
                Box::new(WindowsProcessSnapshot::new())
            }
            #[cfg(not(windows))]
            {
                Box::new(UnsupportedProcessSnapshot)
            }
        };
        let scanner = Scanner::new(scanner_config).map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            runtime: Mutex::new(EngineRuntime {
                running: false,
                started_at_ms: None,
                started_instant: None,
                events_processed: 0,
                correlated_chains: 0,
                detections: 0,
                scans_completed: 0,
                last_event_log_ms: chrono::Utc::now().timestamp_millis(),
            }),
            scanner: Mutex::new(Arc::new(scanner)),
            policy: Mutex::new(Arc::new(PolicyEngine::new(policy_config))),
            cancels: Mutex::new(HashMap::new()),
            monitor: Mutex::new(ProcessMonitor::new(provider)),
            correlation: Mutex::new(CorrelationEngine::default()),
        }))
    }

    pub fn scanner(&self) -> Arc<Scanner> {
        self.scanner.lock().clone()
    }

    pub fn policy(&self) -> Arc<PolicyEngine> {
        self.policy.lock().clone()
    }

    /// Apply new policy/scanner configuration after the user changes settings.
    /// A failed scan configuration change keeps the previous scanner intact.
    pub fn reconfigure(&self, scanner_config: ScannerConfig, policy_config: PolicyConfig) {
        if let Ok(scanner) = Scanner::new(scanner_config) {
            *self.scanner.lock() = Arc::new(scanner);
        }
        *self.policy.lock() = Arc::new(PolicyEngine::new(policy_config));
    }

    pub fn start(&self) -> EngineState {
        {
            let mut runtime = self.runtime.lock();
            if !runtime.running {
                runtime.running = true;
                runtime.started_at_ms = Some(now_ms());
                runtime.started_instant = Some(Instant::now());
            }
        }
        self.state()
    }

    pub fn stop(&self) -> EngineState {
        {
            let mut runtime = self.runtime.lock();
            runtime.running = false;
            runtime.started_instant = None;
        }
        self.state()
    }

    pub fn is_running(&self) -> bool {
        self.runtime.lock().running
    }

    pub fn state(&self) -> EngineState {
        let runtime = self.runtime.lock();
        EngineState {
            running: runtime.running,
            started_at_ms: runtime.started_at_ms,
            uptime_secs: runtime
                .started_instant
                .map(|i| i.elapsed().as_secs())
                .unwrap_or(0),
            telemetry_source: self.monitor.lock().provider_name().to_string(),
            telemetry_available: cfg!(windows),
            monitoring_is_preventive: false,
            events_processed: runtime.events_processed,
            correlated_chains: runtime.correlated_chains,
            detections: runtime.detections,
            scans_completed: runtime.scans_completed,
            dropped_events: self.monitor.lock().dropped_observations(),
            mode: "embedded".into(),
        }
    }

    /// One monitoring tick. Returns every event that should be persisted and
    /// streamed to the UI (observed, correlated and policy events).
    pub fn tick(&self, state: &AppState) -> Vec<SecurityEvent> {
        if !self.is_running() {
            return Vec::new();
        }
        let observed = self.monitor.lock().poll();
        let mut output = Vec::new();
        for event in observed {
            output.extend(self.process_observed(state, event));
        }
        output.extend(self.poll_event_log(state));
        if !output.is_empty() {
            let mut runtime = self.runtime.lock();
            runtime.events_processed = runtime.events_processed.saturating_add(output.len() as u64);
            runtime.detections = runtime.detections.saturating_add(
                output
                    .iter()
                    .filter(|e| e.kind == SecurityEventKind::Detection)
                    .count() as u64,
            );
        }
        output
    }

    /// Poll Windows Event Log channels (best effort). Only enabled when the
    /// platform supports the API; missing channels simply return no events.
    fn poll_event_log(&self, state: &AppState) -> Vec<SecurityEvent> {
        let mut reader = state.event_log.lock();
        let Some(reader) = reader.as_mut() else {
            return Vec::new();
        };
        let since = self.runtime.lock().last_event_log_ms;
        match reader.poll(since, 32) {
            Ok(events) => {
                if let Some(latest) = events.iter().map(|e| e.timestamp_ms).max() {
                    self.runtime.lock().last_event_log_ms = latest;
                }
                let mut output = Vec::new();
                for event in events {
                    output.extend(self.process_observed(state, event));
                }
                output
            }
            Err(error) => {
                tracing::debug!(%error, "event log poll failed");
                Vec::new()
            }
        }
    }

    /// Persist and score one observed event, including correlation fan-out.
    pub fn process_observed(&self, state: &AppState, event: SecurityEvent) -> Vec<SecurityEvent> {
        let mut emitted = vec![event.clone()];
        let correlated = self.correlation.lock().ingest(&event);
        if !correlated.is_empty() {
            let count = correlated.len() as u64;
            let mut runtime = self.runtime.lock();
            runtime.correlated_chains = runtime.correlated_chains.saturating_add(count);
        }

        for correlated_event in correlated {
            let policy = self.policy().evaluate_event(&correlated_event);
            emitted.push(correlated_event.clone());
            if policy.outcome >= PolicyOutcome::Investigate {
                emitted.push(policy_event_from(&correlated_event, &policy));
            }
        }

        for event in &mut emitted {
            state.sanitize_event(event);
            if let Err(error) = state.db.insert_event(event) {
                tracing::warn!(%error, "failed to persist security event");
            }
        }
        emitted
    }

    /// Start a scan job on a worker task and return its queued summary.
    /// Progress is emitted through Tauri events; results are persisted before
    /// the job is marked complete.
    pub fn spawn_scan(
        self: &Arc<Self>,
        app: AppHandle,
        state: Arc<AppState>,
        request: ScanPathArgs,
    ) -> Result<ScanJobSummary, String> {
        let job = ScanJobSummary {
            id: new_id("job"),
            path: request.path.clone(),
            recursive: request.recursive,
            state: ScanState::Queued,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            files_scanned: 0,
            detections: 0,
            errors: 0,
            current_path: None,
            cancelled: false,
        };
        state.db.insert_scan_job(&job).map_err(|e| e.to_string())?;

        let cancel = Arc::new(AtomicBool::new(false));
        self.cancels.lock().insert(job.id.clone(), cancel.clone());

        let engine = self.clone();
        let queued = job.clone();
        tauri::async_runtime::spawn(async move {
            let scanner = engine.scanner();
            let root = std::path::PathBuf::from(&job.path);
            let app_for_progress = app.clone();
            let db_for_progress = state.db.clone();
            let progress_gate = Arc::new(Mutex::new(now_ms()));
            let job_for_progress = job.clone();
            let cancel_for_scan = cancel.clone();

            let mut running = job.clone();
            running.state = ScanState::Running;
            let _ = state.db.update_scan_job(&running);
            let _ = app.emit(
                "engine://event",
                engine_status_event(&state, "scan_started", &job.path),
            );

            let summary = scanner.scan_path(
                &root,
                job.recursive,
                cancel_for_scan.as_ref(),
                &|progress: ScanProgress| {
                    let now = now_ms();
                    let mut gate = progress_gate.lock();
                    if now - *gate < 250 && progress.state == ScanState::Running {
                        return;
                    }
                    *gate = now;
                    let mut snapshot = job_for_progress.clone();
                    snapshot.state = ScanState::Running;
                    snapshot.files_scanned = progress.files_scanned;
                    snapshot.detections = progress.detections;
                    snapshot.current_path = progress.current_path.clone();
                    let _ = db_for_progress.update_scan_job(&snapshot);
                    let _ = app_for_progress.emit("engine://scan-progress", &progress);
                },
            );

            // Persist results and emit detection events.
            let investigate_min = engine.policy().config().investigate_min_score;
            let mut ai_candidates = Vec::new();
            for report in &summary.reports {
                if let Err(error) = state.db.insert_scan_result(&job.id, report) {
                    tracing::warn!(%error, "could not persist scan result");
                }
                if report.assessment.score >= investigate_min {
                    ai_candidates.push(report.clone());
                }
                if !report.detections.is_empty() || report.assessment.score >= 40.0 {
                    let mut event = detection_event_from_report(&job.id, report);
                    state.sanitize_event(&mut event);
                    let _ = state.db.insert_event(&event);
                    let _ = app.emit("engine://event", &event);
                }
            }

            // AI review of the highest-scoring files (bounded, best effort).
            ai_candidates.sort_by(|a, b| b.assessment.score.total_cmp(&a.assessment.score));
            ai_candidates.truncate(3);
            for report in ai_candidates {
                let mut event = detection_event_from_report(&job.id, &report);
                state.sanitize_event(&mut event);
                let decision = {
                    let ai = state.ai.read().await;
                    if ai.is_cloud_enabled() {
                        ai.classify(&event, &report.assessment, &state.db)
                            .await
                            .ok()
                            .flatten()
                    } else {
                        None
                    }
                };
                let decision_ref = decision.as_ref();
                let policy = engine.policy().evaluate_scan(&report, decision_ref);
                if policy.outcome >= PolicyOutcome::Investigate {
                    let mut policy_event = policy_event_from(&event, &policy);
                    state.sanitize_event(&mut policy_event);
                    policy_event.evidence = serde_json::json!({
                        "scanJobId": job.id,
                        "reportId": report.id,
                        "score": report.assessment.score,
                        "aiUsed": decision_ref.is_some(),
                    });
                    let _ = state.db.insert_event(&policy_event);
                    let _ = app.emit("engine://event", &policy_event);
                }
                if policy.outcome == PolicyOutcome::Quarantine
                    && engine.policy().config().auto_quarantine_enabled
                    && policy.deterministic
                    && policy.quarantine_allowed
                {
                    match state.vault.quarantine(
                        std::path::Path::new(&report.file.path),
                        &policy.reason,
                        report.detections.first().map(|d| d.id.clone()),
                    ) {
                        Ok(record) => {
                            let _ = state.db.insert_quarantine(&record);
                            let mut quarantine_event = SecurityEvent::new(
                                SecurityEventKind::PolicyDecision,
                                Severity::Critical,
                                TelemetrySource::FileScanner,
                                format!("Quarantined {}", record.original_name),
                            );
                            quarantine_event.description = policy.reason.clone();
                            quarantine_event.file = Some(report.file.clone());
                            quarantine_event.labels = vec!["policy".into(), "quarantine".into()];
                            state.sanitize_event(&mut quarantine_event);
                            let _ = state.db.insert_event(&quarantine_event);
                            let _ = app.emit("engine://event", &quarantine_event);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "quarantine failed");
                        }
                    }
                }
            }

            let mut finished = job.clone();
            finished.state = if summary.cancelled {
                ScanState::Cancelled
            } else {
                ScanState::Completed
            };
            finished.finished_at_ms = Some(now_ms());
            finished.files_scanned = summary.files_scanned;
            finished.detections = summary.detections;
            finished.errors = summary.errors;
            finished.cancelled = summary.cancelled;
            let _ = state.db.update_scan_job(&finished);
            let _ = app.emit(
                "engine://scan-progress",
                &ScanProgress {
                    job_id: finished.id.clone(),
                    state: finished.state,
                    files_scanned: finished.files_scanned,
                    current_path: None,
                    detections: finished.detections,
                    errors: finished.errors,
                },
            );
            let mut completed_event = SecurityEvent::new(
                SecurityEventKind::ScanCompleted,
                if finished.detections > 0 {
                    Severity::Medium
                } else {
                    Severity::Info
                },
                TelemetrySource::FileScanner,
                if state.settings_bool("privacy.storeRawPaths", true) {
                    format!("Scan {} on {}", state_name(finished.state), finished.path)
                } else {
                    format!("Scan {}", state_name(finished.state))
                },
            );
            completed_event.description = format!(
                "{} files scanned, {} detections, {} errors",
                finished.files_scanned, finished.detections, finished.errors
            );
            completed_event.evidence = serde_json::json!({ "jobId": finished.id });
            let _ = state.db.insert_event(&completed_event);
            let _ = app.emit("engine://event", &completed_event);
            state.prune_old_events();

            if finished.state == ScanState::Completed {
                let mut runtime = engine.runtime.lock();
                runtime.scans_completed = runtime.scans_completed.saturating_add(1);
            }

            if state.settings_bool("privacy.notificationsEnabled", true) && finished.detections > 0
            {
                crate::notify::notify_scan_complete(&finished);
            }

            // Release the cancellation flag; completed jobs cannot be cancelled.
            engine.cancels.lock().remove(&job.id);
        });

        Ok(queued)
    }

    pub fn cancel_scan(&self, job_id: &str) -> bool {
        if let Some(flag) = self.cancels.lock().get(job_id) {
            flag.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }
}

fn state_name(state: ScanState) -> &'static str {
    match state {
        ScanState::Queued => "queued",
        ScanState::Running => "running",
        ScanState::Completed => "completed",
        ScanState::Failed => "failed",
        ScanState::Cancelled => "cancelled",
    }
}

fn engine_status_event(state: &AppState, stage: &str, detail: &str) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        SecurityEventKind::EngineStatus,
        Severity::Info,
        TelemetrySource::Engine,
        format!("Engine {stage}"),
    );
    event.description = detail.to_string();
    let _ = state;
    event
}

pub fn detection_event_from_report(
    job_id: &str,
    report: &security_core::FileScanReport,
) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        SecurityEventKind::Detection,
        severity_for_score(report.assessment.score),
        TelemetrySource::FileScanner,
        format!("Detection in {}", report.file.name),
    );
    event.description = if report.assessment.reasons.is_empty() {
        format!("Risk score {:.0}", report.assessment.score)
    } else {
        report.assessment.reasons.join("; ")
    };
    event.file = Some(report.file.clone());
    event.detections = report.detections.clone();
    event.assessment = Some(report.assessment.clone());
    event.evidence = serde_json::json!({
        "scanJobId": job_id,
        "reportId": report.id,
        "source": match report.source {
            ScanSource::Manual => "manual",
            ScanSource::Scheduled => "scheduled",
            ScanSource::Realtime => "realtime",
        },
    });
    event
}

pub fn policy_event_from(event: &SecurityEvent, policy: &PolicyDecision) -> SecurityEvent {
    let mut policy_event = SecurityEvent::new(
        SecurityEventKind::PolicyDecision,
        match policy.outcome {
            PolicyOutcome::Quarantine => Severity::Critical,
            PolicyOutcome::Alert => Severity::High,
            PolicyOutcome::Investigate => Severity::Medium,
            _ => Severity::Info,
        },
        TelemetrySource::Engine,
        format!("Policy: {}", outcome_name(policy.outcome)),
    );
    policy_event.description = policy.reason.clone();
    policy_event.process = event.process.clone();
    policy_event.file = event.file.clone();
    policy_event.correlation_id = event.correlation_id.clone();
    policy_event.labels = vec!["policy".into(), outcome_name(policy.outcome).into()];
    policy_event.evidence = serde_json::json!({
        "policyId": policy.id,
        "matchedRules": policy.matched_rules,
        "requiresHumanApproval": policy.requires_human_approval,
        "quarantineAllowed": policy.quarantine_allowed,
        "deterministic": policy.deterministic,
    });
    policy_event
}

pub fn outcome_name(outcome: PolicyOutcome) -> &'static str {
    match outcome {
        PolicyOutcome::Allow => "allow",
        PolicyOutcome::Observe => "observe",
        PolicyOutcome::Investigate => "investigate",
        PolicyOutcome::Alert => "alert",
        PolicyOutcome::Quarantine => "quarantine",
    }
}

pub fn severity_for_score(score: f32) -> Severity {
    match RiskLevel::from_score(score) {
        RiskLevel::Critical => Severity::Critical,
        RiskLevel::High => Severity::High,
        RiskLevel::Medium => Severity::Medium,
        RiskLevel::Low => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Monitoring loop. The interval is intentionally conservative; snapshots are
/// cheap but the process list changes slowly, and idle CPU must stay low.
pub async fn run_monitor_loop(app: AppHandle, state: Arc<AppState>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        if !state.engine.is_running() {
            continue;
        }
        let events = state.engine.tick(&state);
        for event in &events {
            let _ = app.emit("engine://event", event);
        }
    }
}
