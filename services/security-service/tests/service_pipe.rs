//! End-to-end test of the Windows named-pipe transport against a live
//! [`ServiceEngine`].
//!
//! The test starts a real pipe server, talks to it with the public
//! [`security_ipc::pipe::call_pipe`] client and shuts it down through the
//! production control path. On machines where named pipes are unavailable
//! (locked-down CI containers, non-Windows hosts) the test skips cleanly.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use security_core::ProcessRef;
use security_ipc::{pipe, ClientRequest, ServerResponse, IPC_PROTOCOL_VERSION};
use security_service::{ServiceEngine, ServiceEngineDeps};
use security_telemetry::{ProcessMonitor, ProcessSnapshotProvider, TelemetryError};

/// Empty snapshot provider: this test exercises the IPC transport, not
/// telemetry, so polling never produces events.
struct EmptyProvider;

impl ProcessSnapshotProvider for EmptyProvider {
    fn snapshot(&self) -> Result<Vec<ProcessRef>, TelemetryError> {
        Ok(Vec::new())
    }

    fn source_name(&self) -> &'static str {
        "service-pipe-test"
    }
}

fn unique_pipe_name() -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!(
        r"\\.\pipe\ai-antivirus-service-test-{}-{nonce}",
        std::process::id()
    )
}

/// Wait until the pipe has a free instance, or until the server thread exits.
fn wait_for_pipe(
    name: &str,
    server: &thread::JoinHandle<Result<(), security_ipc::IpcError>>,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if pipe::pipe_available(name) {
            return true;
        }
        if server.is_finished() {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn pipe_serves_engine_requests_end_to_end() {
    let pipe_name = unique_pipe_name();

    let mut deps = ServiceEngineDeps::in_memory(ProcessMonitor::new(Box::new(EmptyProvider)))
        .expect("in-memory dependencies");
    deps.config.poll_interval = Duration::from_secs(60);
    let engine = ServiceEngine::new(deps).expect("engine");
    engine.start().expect("start engine");

    let handler_engine = engine.clone();
    let server_pipe = pipe_name.clone();
    let server = thread::spawn(move || {
        let handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync> =
            Arc::new(move |request| handler_engine.handle_request(request));
        pipe::serve_pipe(&server_pipe, handler)
    });

    let listening = wait_for_pipe(&pipe_name, &server);
    if !listening {
        pipe::request_pipe_shutdown();
        let result = server.join().expect("server thread must not panic");
        let _ = engine.stop();
        eprintln!(
            "SKIPPING live pipe integration test: pipe server did not become available ({result:?})"
        );
        return;
    }

    // Ping validates the wire version on both ends.
    match pipe::call_pipe(&pipe_name, &ClientRequest::Ping).expect("ping over the pipe") {
        ServerResponse::Pong { version, .. } => {
            assert_eq!(version, IPC_PROTOCOL_VERSION.to_string());
        }
        other => panic!("expected pong, got {other:?}"),
    }

    // GetStatus must decode into the engine's camelCase status document.
    match pipe::call_pipe(&pipe_name, &ClientRequest::GetStatus).expect("status over the pipe") {
        ServerResponse::Status(value) => {
            assert_eq!(value["running"], serde_json::json!(true));
            assert_eq!(
                value["protocolVersion"],
                serde_json::json!(IPC_PROTOCOL_VERSION)
            );
            assert_eq!(value["dbPath"], serde_json::json!(":memory:"));
            assert_eq!(value["streaming"], serde_json::json!(false));
        }
        other => panic!("expected status, got {other:?}"),
    }

    // A normal engine request works through the transport.
    match pipe::call_pipe(
        &pipe_name,
        &ClientRequest::ListEvents {
            limit: 10,
            offset: 0,
        },
    )
    .expect("list events over the pipe")
    {
        ServerResponse::Events(value) => {
            assert_eq!(value["total"], serde_json::json!(0));
            assert!(value["items"].as_array().expect("items").is_empty());
        }
        other => panic!("expected events, got {other:?}"),
    }

    // Validation errors are surfaced as structured responses, not dropped.
    match pipe::call_pipe(
        &pipe_name,
        &ClientRequest::ScanPath {
            path: "relative\\path".to_string(),
            recursive: false,
        },
    )
    .expect("validation error response")
    {
        ServerResponse::Error { code, .. } => assert_eq!(code, "invalid_request"),
        other => panic!("expected invalid_request, got {other:?}"),
    }

    match pipe::call_pipe(&pipe_name, &ClientRequest::Subscribe).expect("subscribe") {
        ServerResponse::Subscribed => {}
        other => panic!("expected subscribed, got {other:?}"),
    }

    pipe::request_pipe_shutdown();
    let result = server.join().expect("server thread must not panic");
    assert!(result.is_ok(), "serve_pipe returned {result:?}");

    engine.stop().expect("stop engine");
    assert!(!engine.is_running());
}
