//! Integration tests for the security engine: lifecycle, backpressure, scan
//! jobs, request validation, schedule persistence and quarantine round-trips.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_decisions::{AiConfig, AiMode};
use security_core::{
    ProcessRef, ScanSource, SecurityEvent, SecurityEventKind, Severity, TelemetrySource,
};
use security_ipc::{ClientRequest, ServerResponse};
use security_service::{ScanSchedule, ServiceEngine, ServiceEngineDeps};
use security_storage::{Database, EventFilter};
use security_telemetry::{ProcessMonitor, ProcessSnapshotProvider, TelemetryError};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// First snapshot primes the monitor; every later snapshot adds a suspicious
/// process so one poll yields a real `ProcessCreated` event.
struct GrowingProvider {
    calls: AtomicUsize,
}

impl GrowingProvider {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

fn base_process() -> ProcessRef {
    ProcessRef {
        pid: 4,
        name: "explorer.exe".to_string(),
        path: Some(r"C:\Windows\explorer.exe".to_string()),
        ..Default::default()
    }
}

fn suspicious_process() -> ProcessRef {
    ProcessRef {
        pid: 4242,
        name: "powershell.exe".to_string(),
        path: Some(r"C:\Users\Public\AppData\Local\Temp\payload.exe".to_string()),
        parent_pid: Some(4),
        parent_name: Some("wscript.exe".to_string()),
        signed: Some(false),
        ..Default::default()
    }
}

impl ProcessSnapshotProvider for GrowingProvider {
    fn snapshot(&self) -> Result<Vec<ProcessRef>, TelemetryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            Ok(vec![base_process()])
        } else {
            Ok(vec![base_process(), suspicious_process()])
        }
    }

    fn source_name(&self) -> &'static str {
        "test-growing"
    }
}

struct StaticProvider {
    processes: Vec<ProcessRef>,
}

impl StaticProvider {
    fn empty() -> Self {
        Self {
            processes: Vec::new(),
        }
    }
}

impl ProcessSnapshotProvider for StaticProvider {
    fn snapshot(&self) -> Result<Vec<ProcessRef>, TelemetryError> {
        Ok(self.processes.clone())
    }

    fn source_name(&self) -> &'static str {
        "test-static"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn engine_with_provider(
    provider: Box<dyn ProcessSnapshotProvider>,
    poll_interval: Duration,
    queue_capacity: usize,
) -> ServiceEngine {
    let mut deps = ServiceEngineDeps::in_memory(ProcessMonitor::new(provider))
        .expect("in-memory dependencies");
    deps.config.poll_interval = poll_interval;
    deps.config.queue_capacity = queue_capacity;
    ServiceEngine::new(deps).expect("engine")
}

fn mock_ai_engine() -> ServiceEngine {
    let router = ai_decisions::mock_router(AiConfig {
        mode: AiMode::Hybrid,
        ..Default::default()
    })
    .expect("mock router");
    let mut deps =
        ServiceEngineDeps::in_memory(ProcessMonitor::new(Box::new(GrowingProvider::new())))
            .expect("in-memory dependencies");
    deps.config.poll_interval = Duration::from_millis(25);
    deps.config.queue_capacity = 16;
    deps.router = Some(Arc::new(router));
    ServiceEngine::new(deps).expect("engine")
}

fn wait_for(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn event(title: &str) -> SecurityEvent {
    SecurityEvent::new(
        SecurityEventKind::ProcessCreated,
        Severity::Info,
        TelemetrySource::ProcessSnapshot,
        title,
    )
}

/// `EventFilter::default()` leaves `limit` at zero (the serde default is only
/// applied when deserializing), and the storage layer clamps that to one row.
/// Tests that need the whole page must set a real limit.
fn event_filter() -> EventFilter {
    EventFilter {
        limit: 100,
        ..Default::default()
    }
}

fn expect_error_code(response: ServerResponse, expected: &str) {
    match response {
        ServerResponse::Error { code, message } => {
            assert_eq!(code, expected, "message: {message}");
        }
        other => panic!("expected error {expected}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn engine_lifecycle_with_synthetic_telemetry_and_mock_ai() {
    let engine = mock_ai_engine();
    engine.start().expect("start");
    assert!(engine.is_running());

    let observed = wait_for(
        || {
            let status = engine.status();
            status.ai_decisions >= 1
                && engine
                    .database()
                    .query_events(&event_filter())
                    .map(|page| {
                        page.items
                            .iter()
                            .any(|event| event.title.contains("powershell.exe"))
                    })
                    .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    assert!(
        wait_for(|| engine.status().queue_depth == 0, Duration::from_secs(5)),
        "engine queue did not drain: {:?}",
        engine.status()
    );
    let status = engine.status();
    if !observed {
        let page = engine
            .database()
            .query_events(&event_filter())
            .expect("query events");
        eprintln!(
            "persisted events: {:?}",
            page.items
                .iter()
                .map(|event| (event.kind, event.title.clone(), event.description.clone()))
                .collect::<Vec<_>>()
        );
    }
    assert!(observed, "engine did not persist an event: {status:?}");
    assert!(status.running);
    assert!(status.started_at_ms.is_some());
    assert_eq!(status.protocol_version, security_ipc::IPC_PROTOCOL_VERSION);
    assert!(status.events_observed >= 1);
    assert!(status.events_persisted >= 1);
    assert!(status.policy_decisions >= 1);
    assert!(status.ai_enabled);
    assert!(status.ai_decisions >= 1);
    assert_eq!(status.ai_errors, 0);
    assert!(status.last_poll_ms.is_some());
    assert_eq!(status.queue_capacity, 16);
    assert_eq!(status.queue_depth, 0);
    assert_eq!(status.db_path, ":memory:");

    match engine.handle_request(ClientRequest::GetStatus) {
        ServerResponse::Status(value) => {
            assert_eq!(value["running"], true);
            assert_eq!(value["aiEnabled"], true);
            assert_eq!(value["protocolVersion"], 1);
        }
        other => panic!("expected status, got {other:?}"),
    }

    match engine.handle_request(ClientRequest::Ping) {
        ServerResponse::Pong {
            version,
            uptime_secs,
        } => {
            assert_eq!(version, security_ipc::IPC_PROTOCOL_VERSION.to_string());
            let _ = uptime_secs;
        }
        other => panic!("expected pong, got {other:?}"),
    }

    match engine.handle_request(ClientRequest::ListEvents {
        limit: 50,
        offset: 0,
    }) {
        ServerResponse::Events(value) => {
            let items = value["items"].as_array().expect("items array");
            assert!(!items.is_empty(), "expected stored events: {value}");
            assert!(value["total"].as_u64().unwrap_or(0) >= 1);
        }
        other => panic!("expected events, got {other:?}"),
    }

    let persisted = engine
        .database()
        .query_events(&event_filter())
        .expect("query events");
    assert!(
        persisted.items.iter().any(|event| {
            event.kind == SecurityEventKind::ProcessCreated
                && event.title.contains("powershell.exe")
        }),
        "persisted events: {:?}",
        persisted
            .items
            .iter()
            .map(|event| (event.kind, event.title.clone()))
            .collect::<Vec<_>>()
    );

    engine.stop().expect("stop");
    assert!(!engine.is_running());
    let stopped = engine.status();
    assert_eq!(stopped.started_at_ms, None);
    assert!(!stopped.running);
    assert!(stopped.events_persisted >= 1);

    // The engine can be restarted after a clean stop.
    engine.start().expect("restart");
    assert!(engine.is_running());
    engine.stop().expect("second stop");
    assert!(!engine.is_running());
}

#[test]
fn bounded_queue_drops_oldest_and_reports_backpressure() {
    let engine = engine_with_provider(Box::new(StaticProvider::empty()), Duration::from_secs(3), 3);
    assert_eq!(engine.queue().capacity(), 3);
    for index in 0..5 {
        engine.queue().push(event(&format!("queued-{index}")));
    }

    assert_eq!(engine.queue().len(), 3);
    assert_eq!(engine.queue().dropped(), 2);
    let status = engine.status();
    assert_eq!(status.queue_depth, 3);
    assert_eq!(status.events_dropped, 2);
    assert!(!status.running);

    let drained = engine.queue().drain(10);
    let titles: Vec<_> = drained.iter().map(|event| event.title.as_str()).collect();
    assert_eq!(titles, vec!["queued-2", "queued-3", "queued-4"]);

    // Pushing one more and flushing exercises the persistence path.
    engine.queue().push(event("queued-5"));
    assert_eq!(engine.persist_queue_now(), 1);
    assert_eq!(engine.status().events_persisted, 1);
    assert_eq!(engine.status().queue_depth, 0);
}

#[test]
fn request_validation_and_unknown_records() {
    let engine = engine_with_provider(Box::new(StaticProvider::empty()), Duration::from_secs(3), 8);

    expect_error_code(
        engine.handle_request(ClientRequest::ScanPath {
            path: "relative\\path".to_string(),
            recursive: false,
        }),
        "invalid_request",
    );
    expect_error_code(
        engine.handle_request(ClientRequest::ScanPath {
            path: r"C:\this\does\not\exist\ai-antivirus".to_string(),
            recursive: true,
        }),
        "invalid_request",
    );
    expect_error_code(
        engine.handle_request(ClientRequest::CancelScan {
            job_id: "   ".to_string(),
        }),
        "invalid_request",
    );
    match engine.handle_request(ClientRequest::CancelScan {
        job_id: "scan_unknown".to_string(),
    }) {
        ServerResponse::Cancelled { cancelled, job_id } => {
            assert!(!cancelled);
            assert_eq!(job_id, "scan_unknown");
        }
        other => panic!("expected cancelled, got {other:?}"),
    }
    expect_error_code(
        engine.handle_request(ClientRequest::GetEvent {
            event_id: " ".to_string(),
        }),
        "invalid_request",
    );
    expect_error_code(
        engine.handle_request(ClientRequest::GetEvent {
            event_id: "evt_missing".to_string(),
        }),
        "not_found",
    );

    match engine.handle_request(ClientRequest::ListEvents {
        limit: 0,
        offset: 0,
    }) {
        ServerResponse::Events(value) => {
            assert_eq!(value["total"], 0);
            assert!(value["items"].as_array().expect("items").is_empty());
        }
        other => panic!("expected events, got {other:?}"),
    }
    match engine.handle_request(ClientRequest::ListQuarantine) {
        ServerResponse::Quarantine(records) => assert!(records.is_empty()),
        other => panic!("expected quarantine, got {other:?}"),
    }
    assert!(matches!(
        engine.handle_request(ClientRequest::Subscribe),
        ServerResponse::Subscribed
    ));

    // Quarantine is disabled when no vault is configured.
    let dir = tempfile::tempdir().expect("temp dir");
    let file = dir.path().join("sample.bin");
    std::fs::write(&file, b"sample").expect("write file");
    expect_error_code(
        engine.handle_request(ClientRequest::QuarantineFile {
            path: file.to_string_lossy().into_owned(),
            reason: "manual review".to_string(),
        }),
        "invalid_request",
    );
}

#[test]
fn scan_job_persists_report_and_completion_event() {
    let dir = tempfile::tempdir().expect("temp dir");
    let file = dir.path().join("hello.txt");
    std::fs::write(&file, b"hello from the scan integration test").expect("write file");

    let engine = engine_with_provider(
        Box::new(StaticProvider::empty()),
        Duration::from_millis(50),
        32,
    );
    engine.start().expect("start");

    let job_id = match engine.handle_request(ClientRequest::ScanPath {
        path: dir.path().to_string_lossy().into_owned(),
        recursive: true,
    }) {
        ServerResponse::ScanAccepted { job_id } => job_id,
        other => panic!("expected scan accepted, got {other:?}"),
    };
    assert!(job_id.starts_with("scan_"));

    let completed = wait_for(
        || engine.status().scans_completed >= 1,
        Duration::from_secs(30),
    );
    let status = engine.status();
    assert!(completed, "scan did not finish: {status:?}");
    assert_eq!(status.scans_started, 1);
    assert_eq!(status.scans_completed, 1);
    assert_eq!(status.active_scans, 0);

    let reports = engine
        .database()
        .scan_results_for_job(&job_id, 10)
        .expect("scan results");
    assert_eq!(reports.len(), 1, "expected one scanned file");
    assert_eq!(reports[0].file.name, "hello.txt");
    assert_eq!(reports[0].source, ScanSource::Manual);

    let page = engine
        .database()
        .query_events(&event_filter())
        .expect("events");
    assert!(page
        .items
        .iter()
        .any(|event| event.kind == SecurityEventKind::ScanCompleted
            && event.evidence["jobId"] == serde_json::json!(job_id)));

    engine.stop().expect("stop");
}

#[test]
fn scheduled_scan_runs_and_updates_last_run() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("note.txt"), b"scheduled scan").expect("write file");

    let engine = engine_with_provider(
        Box::new(StaticProvider::empty()),
        Duration::from_millis(25),
        32,
    );
    engine
        .set_schedule(Some(ScanSchedule {
            enabled: true,
            path: dir.path().to_string_lossy().into_owned(),
            recursive: false,
            interval_secs: 60,
            last_run_ms: None,
        }))
        .expect("set schedule");

    engine.start().expect("start");
    let completed = wait_for(
        || engine.status().scans_completed >= 1,
        Duration::from_secs(30),
    );
    let status = engine.status();
    assert!(completed, "scheduled scan did not run: {status:?}");
    let schedule = status.schedule.expect("schedule");
    assert!(schedule.last_run_ms.is_some());
    assert_eq!(schedule.interval_secs, 60);
    engine.stop().expect("stop");
}

#[test]
fn schedule_is_persisted_in_settings_and_reloaded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("state.db");
    std::fs::write(dir.path().join("scan-me.txt"), b"data").expect("write file");

    let schedule = ScanSchedule {
        enabled: true,
        path: dir.path().to_string_lossy().into_owned(),
        recursive: true,
        interval_secs: 900,
        last_run_ms: Some(1234),
    };

    {
        let db = Database::open(&db_path).expect("open db");
        let mut deps =
            ServiceEngineDeps::new(db, ProcessMonitor::new(Box::new(StaticProvider::empty())))
                .expect("deps");
        deps.config.db_path = Some(db_path.clone());
        deps.config.vault_dir = None;
        let engine = ServiceEngine::new(deps).expect("engine");
        assert!(engine.schedule().is_none());
        engine
            .set_schedule(Some(schedule.clone()))
            .expect("persist schedule");
        assert_eq!(engine.schedule(), Some(schedule.clone()));

        // Invalid schedules are rejected and do not replace the stored value.
        let invalid = ScanSchedule {
            interval_secs: 5,
            ..schedule.clone()
        };
        assert!(engine.set_schedule(Some(invalid)).is_err());
        assert_eq!(engine.schedule(), Some(schedule.clone()));
    }

    let db = Database::open(&db_path).expect("reopen db");
    let mut deps =
        ServiceEngineDeps::new(db, ProcessMonitor::new(Box::new(StaticProvider::empty())))
            .expect("deps");
    deps.config.db_path = Some(db_path);
    deps.config.vault_dir = None;
    let reloaded = ServiceEngine::new(deps).expect("engine");
    assert_eq!(reloaded.schedule(), Some(schedule));
}

#[test]
fn quarantine_and_restore_round_trip() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault_dir = dir.path().join("vault");
    let original = dir.path().join("evil.bin");
    std::fs::write(&original, b"quarantine me").expect("write file");
    let original_text = original.to_string_lossy().into_owned();

    let mut deps =
        ServiceEngineDeps::in_memory(ProcessMonitor::new(Box::new(StaticProvider::empty())))
            .expect("deps");
    deps.config.vault_dir = Some(vault_dir.clone());
    let engine = ServiceEngine::new(deps).expect("engine");

    let record = match engine.handle_request(ClientRequest::QuarantineFile {
        path: original_text.clone(),
        reason: "integration test".to_string(),
    }) {
        ServerResponse::QuarantineRecord(value) => value,
        other => panic!("expected quarantine record, got {other:?}"),
    };
    assert_eq!(record["originalPath"], original_text);
    assert_eq!(record["status"], "quarantined");
    let stored = record["storedPath"].as_str().expect("stored path");
    assert!(std::path::Path::new(stored).is_file());
    assert!(stored.to_ascii_lowercase().contains("vault"));
    assert!(vault_dir.is_dir());

    match engine.handle_request(ClientRequest::ListQuarantine) {
        ServerResponse::Quarantine(records) => assert_eq!(records.len(), 1),
        other => panic!("expected quarantine list, got {other:?}"),
    }

    // Quarantine copies; the original remains until the user deletes it.
    assert!(original.is_file());
    std::fs::remove_file(&original).expect("remove original");
    let id = record["id"].as_str().expect("id").to_string();
    match engine.handle_request(ClientRequest::RestoreQuarantine { id: id.clone() }) {
        ServerResponse::Restore(value) => {
            assert_eq!(value["success"], true, "restore failed: {value}");
            assert_eq!(value["restoredPath"], original_text);
        }
        other => panic!("expected restore result, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(&original).expect("restored file"),
        b"quarantine me"
    );

    // A second restore refuses to overwrite the restored file.
    match engine.handle_request(ClientRequest::RestoreQuarantine { id }) {
        ServerResponse::Restore(value) => {
            assert_eq!(value["success"], false, "unexpected overwrite: {value}");
        }
        other => panic!("expected restore result, got {other:?}"),
    }

    // Files inside the vault are never accepted for quarantine.
    let inside = vault_dir.join("manual.bin");
    let mut handle = std::fs::File::create(&inside).expect("vault file");
    handle.write_all(b"inside").expect("write");
    expect_error_code(
        engine.handle_request(ClientRequest::QuarantineFile {
            path: inside.to_string_lossy().into_owned(),
            reason: "should be rejected".to_string(),
        }),
        "invalid_request",
    );
}
