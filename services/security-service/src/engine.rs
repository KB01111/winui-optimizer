//! Engine implementation: telemetry polling, persistence, scans and IPC state.
//!
//! The engine owns one SQLite connection, one process monitor, one correlation
//! engine, the deterministic policy engine, the scanner and an optional AI
//! router. Long-running work is split between:
//!
//! * a dedicated runtime thread running [`EngineInner::run_loop`] (telemetry
//!   polling, bounded-queue persistence and scheduled scans), and
//! * detached per-scan threads (the scanner API is blocking).
//!
//! [`ServiceEngine::handle_request`] is synchronous on purpose: it is called
//! from named-pipe client threads and never needs an async runtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ai_decisions::{
    build_decision_state, AiConfig, DecisionRoute, ProviderRouter, DEFAULT_INVESTIGATE_MIN_SCORE,
};
use security_core::{
    new_id, DecisionResult, FileScanReport, PolicyDecision, PolicyOutcome, QuarantineRecord,
    RestoreResult, ScanJobSummary, ScanProgress, ScanSource, ScanState, SecurityEvent,
    SecurityEventKind, Severity, TelemetrySource,
};
use security_policy::{PolicyConfig, PolicyEngine};
use security_scanner::{QuarantineVault, Scanner, ScannerConfig};
use security_storage::{Database, EventFilter};
use security_telemetry::{CorrelationEngine, ProcessMonitor, ProcessSnapshotProvider};
use serde_json::Value;

use crate::{
    EngineStatus, EventQueue, ScanSchedule, ServiceError, CORRELATION_WINDOW_MS, MAX_LIST_LIMIT,
    PERSIST_BATCH, QUEUE_FALLBACK_WAIT, SETTING_SCAN_SCHEDULE,
};

/// How many files may be scanned between intermediate scan-job writes.
const SCAN_PROGRESS_PERSIST_EVERY: u64 = 32;

/// Configuration for [`ServiceEngine`].
#[derive(Debug, Clone)]
pub struct ServiceEngineConfig {
    /// SQLite path, or `None` for an in-memory database (tests).
    pub db_path: Option<PathBuf>,
    /// Quarantine vault directory, or `None` to disable quarantine.
    pub vault_dir: Option<PathBuf>,
    /// Telemetry polling interval.
    pub poll_interval: Duration,
    /// Bounded queue capacity between polling and SQLite.
    pub queue_capacity: usize,
    /// Scanner configuration used when the caller does not inject a scanner.
    pub scanner: ScannerConfig,
    /// Policy configuration used when the caller does not inject a policy.
    pub policy: PolicyConfig,
}

impl Default for ServiceEngineConfig {
    fn default() -> Self {
        Self {
            db_path: Some(crate::default_db_path()),
            vault_dir: Some(crate::default_vault_dir()),
            poll_interval: Duration::from_secs(crate::DEFAULT_POLL_INTERVAL_SECS),
            queue_capacity: crate::EVENT_QUEUE_CAPACITY,
            scanner: ScannerConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}

/// Fully-injectable engine dependencies.
///
/// Construct this directly in tests to supply an in-memory database, a
/// synthetic snapshot provider or a mock AI router.
pub struct ServiceEngineDeps {
    /// Storage connection (file-backed or in-memory).
    pub database: Database,
    /// Process snapshot monitor.
    pub process_monitor: ProcessMonitor,
    /// Behavior correlation engine.
    pub correlation: CorrelationEngine,
    /// Deterministic policy engine.
    pub policy: PolicyEngine,
    /// File scanner.
    pub scanner: Scanner,
    /// Optional AI router. `None` keeps the engine fully offline.
    pub router: Option<Arc<ProviderRouter>>,
    /// Engine configuration.
    pub config: ServiceEngineConfig,
}

impl ServiceEngineDeps {
    /// Build dependencies with default policy/scanner and an offline engine.
    pub fn new(database: Database, process_monitor: ProcessMonitor) -> Result<Self, ServiceError> {
        Ok(Self {
            database,
            process_monitor,
            correlation: CorrelationEngine::new(CORRELATION_WINDOW_MS),
            policy: PolicyEngine::default(),
            scanner: Scanner::new(ScannerConfig::default())?,
            router: None,
            config: ServiceEngineConfig::default(),
        })
    }

    /// Build dependencies backed by an in-memory database and no vault.
    pub fn in_memory(process_monitor: ProcessMonitor) -> Result<Self, ServiceError> {
        let mut deps = Self::new(Database::open_in_memory()?, process_monitor)?;
        deps.config.db_path = None;
        deps.config.vault_dir = None;
        Ok(deps)
    }

    /// Use a specific AI router.
    pub fn with_router(mut self, router: ProviderRouter) -> Self {
        self.router = Some(Arc::new(router));
        self
    }

    /// Replace the engine configuration.
    pub fn with_config(mut self, config: ServiceEngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Replace the policy engine.
    pub fn with_policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = policy;
        self
    }

    /// Replace the scanner (useful to avoid recompiling YARA rules in tests).
    pub fn with_scanner(mut self, scanner: Scanner) -> Self {
        self.scanner = scanner;
        self
    }
}

/// A running (or stopped) security engine.
///
/// `ServiceEngine` is cheap to clone and can be shared between the named-pipe
/// handler and the service control thread.
#[derive(Clone)]
pub struct ServiceEngine {
    inner: Arc<EngineInner>,
}

impl ServiceEngine {
    /// Create an engine from fully-injected dependencies.
    pub fn new(deps: ServiceEngineDeps) -> Result<Self, ServiceError> {
        if deps.config.poll_interval.is_zero() {
            return Err(ServiceError::InvalidRequest(
                "poll interval must be greater than zero".to_string(),
            ));
        }
        let ServiceEngineDeps {
            database,
            process_monitor,
            correlation,
            policy,
            scanner,
            router,
            config,
        } = deps;

        let vault = match &config.vault_dir {
            Some(dir) => Some(QuarantineVault::new(dir)?),
            None => None,
        };
        let schedule = load_schedule(&database);

        Ok(Self {
            inner: Arc::new(EngineInner {
                db: database,
                monitor: Mutex::new(process_monitor),
                correlation: Mutex::new(correlation),
                policy,
                scanner: Arc::new(scanner),
                router,
                vault,
                queue: EventQueue::new(config.queue_capacity),
                scan_jobs: Mutex::new(HashMap::new()),
                schedule: Mutex::new(schedule),
                config,
                running: AtomicBool::new(false),
                stopping: AtomicBool::new(false),
                started_at_ms: AtomicI64::new(0),
                started_instant: Mutex::new(None),
                stop: tokio::sync::Notify::new(),
                runtime_thread: Mutex::new(None),
                events_observed: AtomicU64::new(0),
                events_persisted: AtomicU64::new(0),
                events_correlated: AtomicU64::new(0),
                policy_decisions: AtomicU64::new(0),
                ai_decisions: AtomicU64::new(0),
                ai_errors: AtomicU64::new(0),
                scans_started: AtomicU64::new(0),
                scans_completed: AtomicU64::new(0),
                scans_failed: AtomicU64::new(0),
                active_scans: AtomicU32::new(0),
                last_poll_ms: AtomicI64::new(0),
                last_error: Mutex::new(None),
            }),
        })
    }

    /// Convenience constructor for tests: in-memory storage, optional mock AI.
    pub fn in_memory(
        provider: Box<dyn ProcessSnapshotProvider>,
        router: Option<ProviderRouter>,
    ) -> Result<Self, ServiceError> {
        let mut deps = ServiceEngineDeps::in_memory(ProcessMonitor::new(provider))?;
        deps.router = router.map(Arc::new);
        Self::new(deps)
    }

    /// Start the polling runtime. Returns [`ServiceError::AlreadyRunning`] when
    /// the engine is already active.
    pub fn start(&self) -> Result<(), ServiceError> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Err(ServiceError::AlreadyRunning);
        }
        self.inner.stopping.store(false, Ordering::SeqCst);
        self.inner
            .started_at_ms
            .store(crate::now_ms(), Ordering::SeqCst);
        if let Ok(mut started) = self.inner.started_instant.lock() {
            *started = Some(Instant::now());
        }

        let inner = Arc::clone(&self.inner);
        let spawned = thread::Builder::new()
            .name("security-engine-runtime".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("security-engine-worker")
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => runtime.block_on(Arc::clone(&inner).run_loop()),
                    Err(err) => {
                        inner.record_error(format!("failed to create the engine runtime: {err}"))
                    }
                }
                inner.running.store(false, Ordering::SeqCst);
            });

        match spawned {
            Ok(handle) => {
                if let Ok(mut slot) = self.inner.runtime_thread.lock() {
                    *slot = Some(handle);
                }
                tracing::info!(
                    interval_secs = self.inner.config.poll_interval.as_secs_f64(),
                    "security engine started"
                );
                Ok(())
            }
            Err(err) => {
                self.inner.running.store(false, Ordering::SeqCst);
                if let Ok(mut started) = self.inner.started_instant.lock() {
                    *started = None;
                }
                self.inner.started_at_ms.store(0, Ordering::SeqCst);
                Err(ServiceError::Internal(format!(
                    "failed to spawn the engine runtime thread: {err}"
                )))
            }
        }
    }

    /// Stop the polling runtime (idempotent).
    pub fn stop(&self) -> Result<(), ServiceError> {
        self.stop_and_wait(Duration::from_secs(10))
    }

    /// Stop the engine and wait up to `timeout` for the runtime thread.
    ///
    /// Pending scans are asked to cancel, their partial state is kept in
    /// SQLite, and the queued telemetry events are flushed to storage before
    /// this returns.
    pub fn stop_and_wait(&self, timeout: Duration) -> Result<(), ServiceError> {
        self.inner.stopping.store(true, Ordering::SeqCst);
        self.inner.stop.notify_waiters();
        self.inner.cancel_all_scans();

        // Wakes a pipe accept loop blocked in ConnectNamedPipe. The call is a
        // no-op on platforms without pipes.
        security_ipc::pipe::request_pipe_shutdown();

        let deadline = Instant::now() + timeout;
        let handle = self
            .inner
            .runtime_thread
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());

        let mut timed_out = false;
        match handle {
            Some(handle) => {
                while !handle.is_finished() {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                if !timed_out {
                    let _ = handle.join();
                }
            }
            None => {
                while self.inner.running.load(Ordering::SeqCst) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                timed_out = self.inner.running.load(Ordering::SeqCst);
            }
        }

        self.inner.running.store(false, Ordering::SeqCst);
        self.inner.started_at_ms.store(0, Ordering::SeqCst);
        if let Ok(mut started) = self.inner.started_instant.lock() {
            *started = None;
        }
        self.inner.persist_queue();

        if timed_out {
            return Err(ServiceError::Internal(format!(
                "engine did not stop within {timeout:?}"
            )));
        }
        tracing::info!("security engine stopped");
        Ok(())
    }

    /// True while the polling runtime is active.
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    /// Snapshot of the engine status exposed over IPC.
    pub fn status(&self) -> EngineStatus {
        self.inner.status()
    }

    /// Handle one IPC request synchronously.
    pub fn handle_request(
        &self,
        request: security_ipc::ClientRequest,
    ) -> security_ipc::ServerResponse {
        crate::ipc::handle_request(self, request)
    }

    /// Bounded event queue (exposed for backpressure tests).
    pub fn queue(&self) -> &EventQueue {
        &self.inner.queue
    }

    /// Storage handle (read-only use is safe; the engine owns writes).
    pub fn database(&self) -> &Database {
        &self.inner.db
    }

    /// Force one telemetry poll (used by tests and diagnostics).
    pub async fn poll_once(&self) -> PollSummary {
        self.inner.poll_events().await
    }

    /// Flush queued events to SQLite now.
    pub fn persist_queue_now(&self) -> u64 {
        self.inner.persist_queue()
    }

    /// Queue an asynchronous scan. Returns the job id.
    pub fn spawn_scan(
        &self,
        path: impl AsRef<Path>,
        recursive: bool,
        source: ScanSource,
    ) -> Result<String, ServiceError> {
        self.inner.spawn_scan(path.as_ref(), recursive, source)
    }

    /// Ask a running scan to cancel. Returns false for unknown/completed jobs.
    pub fn cancel_scan(&self, job_id: &str) -> bool {
        self.inner.cancel_scan(job_id)
    }

    /// Currently configured scan schedule.
    pub fn schedule(&self) -> Option<ScanSchedule> {
        self.inner
            .schedule
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Persist (or clear, with `None`) the scan schedule in application
    /// settings and update the in-memory copy.
    pub fn set_schedule(&self, schedule: Option<ScanSchedule>) -> Result<(), ServiceError> {
        match &schedule {
            Some(schedule) => {
                schedule.validate()?;
                let json = schedule.to_json()?;
                self.inner.db.set_setting(SETTING_SCAN_SCHEDULE, &json)?;
            }
            None => {
                self.inner.db.set_setting(SETTING_SCAN_SCHEDULE, "")?;
            }
        }
        if let Ok(mut guard) = self.inner.schedule.lock() {
            *guard = schedule;
        }
        Ok(())
    }

    /// Uptime in whole seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.inner.uptime_secs()
    }

    /// Access the quarantine vault, when configured.
    pub fn vault(&self) -> Option<&QuarantineVault> {
        self.inner.vault.as_ref()
    }

    /// Last recorded engine error, if any.
    pub fn last_error(&self) -> Option<String> {
        self.inner
            .last_error
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Quarantine one file (validated by the IPC layer) and record it.
    pub(crate) fn quarantine_file(
        &self,
        path: &Path,
        reason: &str,
    ) -> Result<QuarantineRecord, ServiceError> {
        let vault = self.inner.vault.as_ref().ok_or_else(|| {
            ServiceError::InvalidRequest(
                "quarantine is disabled because no vault directory is configured".to_string(),
            )
        })?;
        if crate::is_within(vault.dir(), path) {
            return Err(ServiceError::InvalidRequest(
                "refusing to quarantine a file inside the quarantine vault".to_string(),
            ));
        }
        let record = vault.quarantine(path, reason, None)?;
        self.inner.db.insert_quarantine(&record)?;

        let mut event = SecurityEvent::new(
            SecurityEventKind::Detection,
            Severity::Medium,
            TelemetrySource::Engine,
            format!("File quarantined: {}", record.original_name),
        );
        event.description = reason.to_string();
        event.file = Some(security_core::FileRef {
            path: record.original_path.clone(),
            name: record.original_name.clone(),
            size: record.size,
            sha256: Some(record.sha256.clone()),
            ..Default::default()
        });
        event.evidence = serde_json::json!({
            "action": "quarantine",
            "quarantineId": record.id,
            "storedPath": record.stored_path,
        });
        self.inner.persist_event_direct(&event);
        Ok(record)
    }

    /// Restore one quarantined record by id.
    pub(crate) fn restore_quarantine(&self, id: &str) -> Result<RestoreResult, ServiceError> {
        let vault = self.inner.vault.as_ref().ok_or_else(|| {
            ServiceError::InvalidRequest(
                "quarantine is disabled because no vault directory is configured".to_string(),
            )
        })?;
        let result = vault.restore(id)?;
        if result.success {
            match self.inner.db.update_quarantine_status(
                id,
                security_core::QuarantineStatus::Restored,
                Some(crate::now_ms()),
            ) {
                Ok(()) => {}
                Err(security_storage::StorageError::NotFound(_)) => {
                    tracing::warn!(
                        quarantine_id = id,
                        "restored a vault record that was not present in the database"
                    );
                }
                Err(err) => return Err(err.into()),
            }
            let mut event = SecurityEvent::new(
                SecurityEventKind::PolicyDecision,
                Severity::Low,
                TelemetrySource::Engine,
                format!("Quarantined file restored: {id}"),
            );
            event.description = result.message.clone();
            event.evidence = serde_json::to_value(&result).unwrap_or(Value::Null);
            self.inner.persist_event_direct(&event);
        }
        Ok(result)
    }
}

/// One in-flight scan job.
#[derive(Clone)]
struct ScanJob {
    cancel: Arc<AtomicBool>,
    summary: Arc<Mutex<ScanJobSummary>>,
}

/// Per-poll counters returned by [`ServiceEngine::poll_once`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollSummary {
    /// Events observed (telemetry plus correlated).
    pub observed: u64,
    /// Correlated events emitted.
    pub correlated: u64,
    /// Policy decisions recorded.
    pub policy_decisions: u64,
    /// AI decisions recorded.
    pub ai_decisions: u64,
    /// AI provider failures (including fail-closed routes).
    pub ai_errors: u64,
    /// Queue drops observed during this poll.
    pub queue_dropped: u64,
}

struct EngineInner {
    db: Database,
    monitor: Mutex<ProcessMonitor>,
    correlation: Mutex<CorrelationEngine>,
    policy: PolicyEngine,
    scanner: Arc<Scanner>,
    router: Option<Arc<ProviderRouter>>,
    vault: Option<QuarantineVault>,
    config: ServiceEngineConfig,

    queue: EventQueue,
    scan_jobs: Mutex<HashMap<String, ScanJob>>,
    schedule: Mutex<Option<ScanSchedule>>,

    running: AtomicBool,
    stopping: AtomicBool,
    started_at_ms: AtomicI64,
    started_instant: Mutex<Option<Instant>>,
    stop: tokio::sync::Notify,
    runtime_thread: Mutex<Option<JoinHandle<()>>>,

    events_observed: AtomicU64,
    events_persisted: AtomicU64,
    events_correlated: AtomicU64,
    policy_decisions: AtomicU64,
    ai_decisions: AtomicU64,
    ai_errors: AtomicU64,
    scans_started: AtomicU64,
    scans_completed: AtomicU64,
    scans_failed: AtomicU64,
    active_scans: AtomicU32,
    last_poll_ms: AtomicI64,
    last_error: Mutex<Option<String>>,
}

impl EngineInner {
    async fn run_loop(self: Arc<Self>) {
        let period = self.config.poll_interval.max(Duration::from_millis(10));
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                _ = self.stop.notified() => break,
                _ = interval.tick() => {
                    if self.stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    self.poll_events().await;
                    self.persist_queue();
                    self.maybe_run_scheduled_scan();
                }
                _ = self.queue.wait_for_items(QUEUE_FALLBACK_WAIT) => {
                    self.persist_queue();
                }
            }
        }
        self.persist_queue();
    }

    /// Poll once, evaluate policy and AI, and enqueue telemetry events.
    async fn poll_events(&self) -> PollSummary {
        let before_policy = self.policy_decisions.load(Ordering::Relaxed);
        let before_ai = self.ai_decisions.load(Ordering::Relaxed);
        let before_errors = self.ai_errors.load(Ordering::Relaxed);
        let before_dropped = self.queue.dropped();

        let events = {
            let mut monitor = lock_unpoisoned(&self.monitor);
            monitor.poll()
        };
        self.last_poll_ms.store(crate::now_ms(), Ordering::Relaxed);

        let mut summary = PollSummary::default();
        for event in events {
            summary.observed = summary.observed.saturating_add(1);
            self.events_observed.fetch_add(1, Ordering::Relaxed);

            let correlated = {
                let mut correlation = lock_unpoisoned(&self.correlation);
                correlation.ingest(&event)
            };
            self.process_event(event).await;

            for correlated_event in correlated {
                summary.correlated = summary.correlated.saturating_add(1);
                summary.observed = summary.observed.saturating_add(1);
                self.events_observed.fetch_add(1, Ordering::Relaxed);
                self.events_correlated.fetch_add(1, Ordering::Relaxed);
                self.process_event(correlated_event).await;
            }
        }

        summary.policy_decisions = self
            .policy_decisions
            .load(Ordering::Relaxed)
            .saturating_sub(before_policy);
        summary.ai_decisions = self
            .ai_decisions
            .load(Ordering::Relaxed)
            .saturating_sub(before_ai);
        summary.ai_errors = self
            .ai_errors
            .load(Ordering::Relaxed)
            .saturating_sub(before_errors);
        summary.queue_dropped = self.queue.dropped().saturating_sub(before_dropped);
        summary
    }

    /// Evaluate one telemetry event, optionally classify it with AI, record the
    /// policy outcome, and enqueue it for persistence.
    async fn process_event(&self, event: SecurityEvent) {
        let mut decision = self.policy.evaluate_event(&event);

        if let (Some(router), Some(assessment)) =
            (self.router.as_deref(), event.assessment.as_ref())
        {
            if assessment.score.is_finite() && assessment.score >= DEFAULT_INVESTIGATE_MIN_SCORE {
                let state = build_decision_state(&event, assessment);
                match router.classify(&state, assessment).await {
                    Ok(routed) => {
                        if routed.route == DecisionRoute::FailedClosed {
                            self.ai_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Some(ai_decision) = routed.final_result.clone() {
                            self.ai_decisions.fetch_add(1, Ordering::Relaxed);
                            self.record_ai_decision(&event, &ai_decision, routed.route);
                            let ai_policy = self.policy.evaluate_ai_only(&ai_decision, assessment);
                            if ai_policy.outcome > decision.outcome {
                                decision = ai_policy;
                            }
                        }
                    }
                    Err(err) => {
                        self.ai_errors.fetch_add(1, Ordering::Relaxed);
                        self.record_error(format!("AI classification failed: {err}"));
                    }
                }
            }
        }

        self.record_policy_decision(&decision, &event);
        self.queue.push(event);
    }

    fn record_policy_decision(&self, decision: &PolicyDecision, source_event: &SecurityEvent) {
        self.policy_decisions.fetch_add(1, Ordering::Relaxed);
        if decision.outcome < PolicyOutcome::Investigate {
            return;
        }

        let severity = match decision.outcome {
            PolicyOutcome::Quarantine | PolicyOutcome::Alert => Severity::High,
            PolicyOutcome::Investigate => Severity::Medium,
            PolicyOutcome::Observe | PolicyOutcome::Allow => Severity::Info,
        };
        let mut event = SecurityEvent::new(
            SecurityEventKind::PolicyDecision,
            severity,
            TelemetrySource::Engine,
            format!(
                "Policy outcome: {}",
                serde_json::to_value(decision.outcome)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_else(|| format!("{:?}", decision.outcome))
            ),
        );
        event.description = decision.reason.clone();
        event.labels = decision.matched_rules.clone();
        event.correlation_id = source_event.correlation_id.clone();
        event.process = source_event.process.clone();
        event.file = source_event.file.clone();
        event.evidence = serde_json::json!({
            "policyDecision": decision,
            "sourceEventId": source_event.id,
        });
        self.persist_event_direct(&event);
    }

    fn record_ai_decision(
        &self,
        source_event: &SecurityEvent,
        decision: &DecisionResult,
        route: DecisionRoute,
    ) {
        if let Err(err) = self.db.insert_decision(Some(&source_event.id), decision) {
            self.record_error(format!("failed to persist AI decision: {err}"));
        }

        let severity = match decision.category {
            security_core::DecisionCategory::LikelyMalicious => Severity::High,
            security_core::DecisionCategory::Suspicious => Severity::Medium,
            security_core::DecisionCategory::Unknown => Severity::Low,
            security_core::DecisionCategory::Benign => Severity::Info,
        };
        let mut event = SecurityEvent::new(
            SecurityEventKind::AiDecision,
            severity,
            TelemetrySource::Engine,
            format!("AI decision: {}", decision.provider),
        );
        event.description = decision.evidence.join("; ");
        event.assessment = source_event.assessment.clone();
        event.correlation_id = source_event.correlation_id.clone();
        event.process = source_event.process.clone();
        event.file = source_event.file.clone();
        event.labels = vec![format!("route:{}", route.as_str())];
        event.evidence = serde_json::json!({
            "decision": decision,
            "sourceEventId": source_event.id,
            "route": route.as_str(),
        });
        self.persist_event_direct(&event);
    }

    /// Drain the bounded queue into SQLite. Returns how many events were saved.
    fn persist_queue(&self) -> u64 {
        let mut persisted = 0u64;
        loop {
            let batch = self.queue.drain(PERSIST_BATCH);
            if batch.is_empty() {
                break;
            }
            let batch_len = batch.len();
            for (index, event) in batch.iter().enumerate() {
                match self.db.insert_event(event) {
                    Ok(()) => {
                        self.events_persisted.fetch_add(1, Ordering::Relaxed);
                        persisted = persisted.saturating_add(1);
                    }
                    Err(err) => {
                        self.record_error(format!("failed to persist event: {err}"));
                        // Put the failed event and anything after it back at the
                        // front of the queue (drop-oldest still bounds memory).
                        for pending in batch.iter().skip(index).rev() {
                            self.queue.push_front(pending.clone());
                        }
                        return persisted;
                    }
                }
            }
            if batch_len < PERSIST_BATCH {
                break;
            }
        }
        persisted
    }

    /// Persist a single event immediately (used for scans and audit events).
    fn persist_event_direct(&self, event: &SecurityEvent) -> bool {
        match self.db.insert_event(event) {
            Ok(()) => {
                self.events_persisted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(err) => {
                self.record_error(format!("failed to persist event: {err}"));
                false
            }
        }
    }

    fn maybe_run_scheduled_scan(self: &Arc<Self>) {
        let mut schedule = match self.schedule.lock() {
            Ok(guard) => match guard.clone() {
                Some(schedule) => schedule,
                None => return,
            },
            Err(poisoned) => match poisoned.into_inner().clone() {
                Some(schedule) => schedule,
                None => return,
            },
        };
        let now = crate::now_ms();
        if !schedule.is_due(now) {
            return;
        }

        let root = PathBuf::from(&schedule.path);
        let result = self.spawn_scan(&root, schedule.recursive, ScanSource::Scheduled);
        if let Err(err) = &result {
            self.record_error(format!("scheduled scan could not start: {err}"));
        }
        // Record the attempt either way so a permanently invalid path does not
        // retry on every poll tick.
        schedule.last_run_ms = Some(now);
        if let Err(err) = self.save_schedule(&schedule) {
            self.record_error(format!("failed to persist scan schedule: {err}"));
        }
    }

    fn save_schedule(&self, schedule: &ScanSchedule) -> Result<(), ServiceError> {
        let json = schedule.to_json()?;
        self.db.set_setting(SETTING_SCAN_SCHEDULE, &json)?;
        if let Ok(mut guard) = self.schedule.lock() {
            *guard = Some(schedule.clone());
        }
        Ok(())
    }

    fn spawn_scan(
        self: &Arc<Self>,
        path: &Path,
        recursive: bool,
        source: ScanSource,
    ) -> Result<String, ServiceError> {
        let path_text = path.to_string_lossy().into_owned();
        let root = crate::validate_existing_path(&path_text)?;
        let job_id = new_id("scan");
        let summary = ScanJobSummary {
            id: job_id.clone(),
            path: root.to_string_lossy().into_owned(),
            recursive,
            state: ScanState::Queued,
            started_at_ms: crate::now_ms(),
            finished_at_ms: None,
            files_scanned: 0,
            detections: 0,
            errors: 0,
            current_path: None,
            cancelled: false,
        };
        self.db.insert_scan_job(&summary)?;

        let summary = Arc::new(Mutex::new(summary));
        let cancel = Arc::new(AtomicBool::new(false));
        if let Ok(mut jobs) = self.scan_jobs.lock() {
            jobs.insert(
                job_id.clone(),
                ScanJob {
                    cancel: Arc::clone(&cancel),
                    summary: Arc::clone(&summary),
                },
            );
        }
        self.scans_started.fetch_add(1, Ordering::Relaxed);
        self.active_scans.fetch_add(1, Ordering::Relaxed);

        let inner = Arc::clone(self);
        let thread_id = job_id.clone();
        let spawned = thread::Builder::new()
            .name(format!("security-scan-{job_id}"))
            .spawn(move || {
                inner.run_scan_job(thread_id, root, recursive, source, summary, cancel);
            });

        if let Err(err) = spawned {
            self.scans_failed.fetch_add(1, Ordering::Relaxed);
            self.active_scans.fetch_sub(1, Ordering::Relaxed);
            if let Ok(mut jobs) = self.scan_jobs.lock() {
                jobs.remove(&job_id);
            }
            self.record_error(format!("failed to spawn scan job: {err}"));
            return Err(ServiceError::Internal(format!(
                "failed to spawn scan job: {err}"
            )));
        }
        Ok(job_id)
    }

    fn cancel_scan(&self, job_id: &str) -> bool {
        let jobs = match self.scan_jobs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match jobs.get(job_id) {
            Some(job) => {
                job.cancel.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    fn run_scan_job(
        &self,
        job_id: String,
        root: PathBuf,
        recursive: bool,
        source: ScanSource,
        summary: Arc<Mutex<ScanJobSummary>>,
        cancel: Arc<AtomicBool>,
    ) {
        {
            let mut job = lock_unpoisoned(&summary);
            job.state = ScanState::Running;
            if let Err(err) = self.db.update_scan_job(&job) {
                self.record_error(format!("failed to persist scan start: {err}"));
            }
        }

        let progress_tick = AtomicU64::new(0);
        let progress = |progress: ScanProgress| {
            let mut job = lock_unpoisoned(&summary);
            job.files_scanned = progress.files_scanned;
            job.detections = progress.detections;
            job.errors = progress.errors;
            job.current_path = progress.current_path;
            if progress.state == ScanState::Cancelled {
                job.cancelled = true;
            }
            let tick = progress_tick.fetch_add(1, Ordering::Relaxed) + 1;
            if tick.is_multiple_of(SCAN_PROGRESS_PERSIST_EVERY) {
                if let Err(err) = self.db.update_scan_job(&job) {
                    self.record_error(format!("failed to persist scan progress: {err}"));
                }
            }
        };

        let scan_summary = self.scanner.scan_path(&root, recursive, &cancel, &progress);
        let state = if scan_summary.cancelled {
            ScanState::Cancelled
        } else {
            ScanState::Completed
        };

        let final_summary = {
            let mut job = lock_unpoisoned(&summary);
            job.state = state;
            job.cancelled = scan_summary.cancelled;
            job.files_scanned = scan_summary.files_scanned;
            job.detections = scan_summary.detections;
            job.errors = scan_summary.errors;
            job.current_path = None;
            job.finished_at_ms = Some(crate::now_ms());
            job.clone()
        };
        if let Err(err) = self.db.update_scan_job(&final_summary) {
            self.record_error(format!("failed to persist scan completion: {err}"));
        }

        let severity = if final_summary.detections > 0 {
            Severity::Medium
        } else {
            Severity::Info
        };
        let mut completed = SecurityEvent::new(
            SecurityEventKind::ScanCompleted,
            severity,
            TelemetrySource::FileScanner,
            format!("Scan completed: {}", final_summary.path),
        );
        completed.description = format!(
            "{} file(s) scanned, {} detection(s), {} error(s){}",
            final_summary.files_scanned,
            final_summary.detections,
            final_summary.errors,
            if final_summary.cancelled {
                ", cancelled"
            } else {
                ""
            }
        );
        completed.labels = vec![format!(
            "scan-source:{}",
            serde_json::to_value(source)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| "manual".to_string())
        )];
        completed.evidence = serde_json::json!({
            "jobId": job_id,
            "path": final_summary.path,
            "filesScanned": final_summary.files_scanned,
            "detections": final_summary.detections,
            "errors": final_summary.errors,
            "cancelled": final_summary.cancelled,
            "source": source,
        });
        self.persist_event_direct(&completed);

        for mut report in scan_summary.reports {
            // `Scanner::scan_path` always labels reports `Manual`; preserve the
            // real source (manual vs scheduled) before persisting.
            report.source = source;
            if let Err(err) = self.db.insert_scan_result(&job_id, &report) {
                self.record_error(format!("failed to persist scan result: {err}"));
                continue;
            }
            self.process_scan_report(&report);
        }

        self.scans_completed.fetch_add(1, Ordering::Relaxed);
        self.active_scans.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut jobs) = self.scan_jobs.lock() {
            jobs.remove(&job_id);
        }
    }

    fn process_scan_report(&self, report: &FileScanReport) {
        let interesting = !report.detections.is_empty() || report.assessment.score > 0.0;
        if interesting {
            let severity = severity_for_score(report.assessment.score);
            let mut event = SecurityEvent::new(
                SecurityEventKind::Detection,
                severity,
                TelemetrySource::FileScanner,
                format!("Scan detection: {}", report.file.name),
            );
            event.description = report.assessment.reasons.join("; ");
            event.file = Some(report.file.clone());
            event.detections = report.detections.clone();
            event.assessment = Some(report.assessment.clone());
            event.labels = vec![format!("scan-id:{}", report.id)];
            event.evidence = serde_json::json!({
                "reportId": report.id,
                "score": report.assessment.score,
                "source": report.source,
                "errors": report.errors,
            });
            self.persist_event_direct(&event);
        }

        let decision = self.policy.evaluate_scan(report, None);
        let mut placeholder = SecurityEvent::new(
            SecurityEventKind::PolicyDecision,
            Severity::Info,
            TelemetrySource::FileScanner,
            "scan policy decision",
        );
        placeholder.file = Some(report.file.clone());
        self.record_policy_decision(&decision, &placeholder);

        if decision.outcome == PolicyOutcome::Quarantine {
            self.auto_quarantine(report, &decision);
        }
    }

    fn auto_quarantine(&self, report: &FileScanReport, decision: &PolicyDecision) {
        let Some(vault) = self.vault.as_ref() else {
            self.record_error(
                "policy requested auto-quarantine but no vault is configured".to_string(),
            );
            return;
        };
        let path = PathBuf::from(&report.file.path);
        if crate::is_within(vault.dir(), &path) {
            self.record_error(format!(
                "refusing to auto-quarantine a vault path: {}",
                path.display()
            ));
            return;
        }
        let detection_id = report.detections.first().map(|d| d.id.clone());
        match vault.quarantine(&path, &decision.reason, detection_id) {
            Ok(record) => {
                if let Err(err) = self.db.insert_quarantine(&record) {
                    self.record_error(format!("failed to persist auto-quarantine record: {err}"));
                }
                let mut event = SecurityEvent::new(
                    SecurityEventKind::Detection,
                    Severity::High,
                    TelemetrySource::FileScanner,
                    format!("Auto-quarantined: {}", record.original_name),
                );
                event.description = decision.reason.clone();
                event.file = Some(report.file.clone());
                event.evidence = serde_json::json!({
                    "action": "auto_quarantine",
                    "quarantineId": record.id,
                    "policyDecisionId": decision.id,
                });
                self.persist_event_direct(&event);
            }
            Err(err) => self.record_error(format!(
                "auto-quarantine failed for {}: {err}",
                path.display()
            )),
        }
    }

    fn cancel_all_scans(&self) {
        let jobs = match self.scan_jobs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for job in jobs.values() {
            job.cancel.store(true, Ordering::SeqCst);
            let mut summary = lock_unpoisoned(&job.summary);
            summary.cancelled = true;
        }
    }

    fn status(&self) -> EngineStatus {
        let started_at = self.started_at_ms.load(Ordering::Relaxed);
        let last_poll = self.last_poll_ms.load(Ordering::Relaxed);
        EngineStatus {
            running: self.running.load(Ordering::SeqCst),
            started_at_ms: (started_at > 0).then_some(started_at),
            uptime_secs: self.uptime_secs(),
            poll_interval_secs: self.config.poll_interval.as_secs().max(1),
            queue_capacity: self.queue.capacity(),
            queue_depth: self.queue.len(),
            events_observed: self.events_observed.load(Ordering::Relaxed),
            events_persisted: self.events_persisted.load(Ordering::Relaxed),
            events_dropped: self.queue.dropped(),
            events_correlated: self.events_correlated.load(Ordering::Relaxed),
            policy_decisions: self.policy_decisions.load(Ordering::Relaxed),
            ai_enabled: self.router.is_some(),
            ai_decisions: self.ai_decisions.load(Ordering::Relaxed),
            ai_errors: self.ai_errors.load(Ordering::Relaxed),
            scans_started: self.scans_started.load(Ordering::Relaxed),
            scans_completed: self.scans_completed.load(Ordering::Relaxed),
            scans_failed: self.scans_failed.load(Ordering::Relaxed),
            active_scans: self.active_scans.load(Ordering::Relaxed),
            last_poll_ms: (last_poll > 0).then_some(last_poll),
            last_error: self
                .last_error
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_else(|poisoned| poisoned.into_inner().clone()),
            db_path: self
                .config
                .db_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| ":memory:".to_string()),
            vault_dir: self
                .vault
                .as_ref()
                .map(|vault| vault.dir().to_string_lossy().into_owned())
                .or_else(|| {
                    self.config
                        .vault_dir
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned())
                }),
            protocol_version: security_ipc::IPC_PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            schedule: self
                .schedule
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_else(|poisoned| poisoned.into_inner().clone()),
            streaming: false,
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started_instant
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map(|started| started.elapsed().as_secs())
            .unwrap_or(0)
    }

    fn record_error(&self, message: impl Into<String>) {
        let message = message.into();
        let truncated: String = message.chars().take(512).collect();
        tracing::warn!(error = %truncated, "security service error");
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = Some(truncated);
        }
    }
}

/// Convenience: read the persisted schedule, treating a missing or invalid
/// value as "no schedule" instead of failing engine startup.
fn load_schedule(db: &Database) -> Option<ScanSchedule> {
    let raw = db.get_setting(SETTING_SCAN_SCHEDULE).ok().flatten()?;
    if raw.trim().is_empty() {
        return None;
    }
    match ScanSchedule::from_json(&raw) {
        Ok(schedule) => Some(schedule),
        Err(err) => {
            tracing::warn!(error = %err, "ignoring invalid persisted scan schedule");
            None
        }
    }
}

fn severity_for_score(score: f32) -> Severity {
    if score >= 90.0 {
        Severity::Critical
    } else if score >= 70.0 {
        Severity::High
    } else if score >= 40.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Search events through the engine database (helper used by IPC handlers).
pub(crate) fn query_events(
    db: &Database,
    limit: u32,
    offset: u32,
) -> Result<security_storage::EventPage, ServiceError> {
    let limit = if limit == 0 {
        crate::DEFAULT_LIST_LIMIT
    } else {
        limit.min(MAX_LIST_LIMIT)
    };
    let filter = EventFilter {
        limit,
        offset,
        ..Default::default()
    }
    .bounded();
    Ok(db.query_events(&filter)?)
}

/// Read the AI configuration from settings. Returns `None` when no
/// configuration is stored.
pub fn load_ai_config(db: &Database) -> Option<AiConfig> {
    let raw = db.get_setting(crate::SETTING_AI_CONFIG).ok().flatten()?;
    if raw.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<AiConfig>(&raw) {
        Ok(config) => Some(config),
        Err(err) => {
            tracing::warn!(error = %err, "ignoring invalid persisted AI configuration");
            None
        }
    }
}
