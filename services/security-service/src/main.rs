//! `security-service` binary: Windows service host plus development console.
//!
//! Modes:
//!
//! * (default) register with the Service Control Manager and run as
//!   [`SERVICE_NAME`], listening on the security named pipe.
//! * `--console` run in the foreground (press Enter or Ctrl+C to stop).
//! * `--install` / `--uninstall` / `--start` / `--stop` manage the SCM entry.
//!
//! The executable never assumes it is elevated: installation fails unless it
//! is run from an elevated shell (or the signed installer).

#![cfg_attr(all(windows, not(test)), allow(dead_code))]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use security_service::{
    default_data_dir, default_db_path, default_vault_dir, load_ai_config,
    platform_process_provider, ServiceEngine, ServiceEngineConfig, ServiceEngineDeps, ServiceError,
    SERVICE_ACCOUNT, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    SETTING_POLL_INTERVAL_SECS,
};
use security_storage::Database;
use security_telemetry::ProcessMonitor;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// How long to wait for the SCM to reach a requested state.
const SCM_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for the named pipe server to start accepting clients.
const PIPE_START_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(windows)]
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(windows)]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
#[cfg(windows)]
use windows_service::{define_windows_service, service_dispatcher};

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

fn main() {
    if let Err(err) = run() {
        eprintln!("security-service: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let argument = std::env::args().nth(1);
    match argument.as_deref() {
        Some("--console") => {
            init_console_logging();
            run_console()
        }
        Some("--install") => {
            init_console_logging();
            install_service()
        }
        Some("--uninstall") => {
            init_console_logging();
            uninstall_service()
        }
        Some("--start") => {
            init_console_logging();
            start_service()
        }
        Some("--stop") => {
            init_console_logging();
            stop_service()
        }
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown argument {other:?}; use --console, --install, --uninstall, --start, --stop or --help"
        )),
        None => run_as_service(),
    }
}

fn print_help() {
    println!(
        "\
{SERVICE_DISPLAY_NAME} ({SERVICE_NAME})

Usage:
  security-service                 run as a Windows service (SCM only)
  security-service --console       run in the foreground for development
  security-service --install       register the service (elevated)
  security-service --uninstall     remove the service, preserving data (elevated)
  security-service --start         start the installed service (elevated)
  security-service --stop          stop the installed service (elevated)
  security-service --help          show this help

Data directory: {}
Quarantine vault: {}
Pipe: {}
",
        default_data_dir().display(),
        default_vault_dir().display(),
        security_ipc::IPC_PIPE_NAME
    );
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn init_console_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

/// Append-only service log. No rotation: the file is intentionally simple and
/// bounded by the operator/installer (documented in the installer README).
fn init_file_logging() {
    let log_dir = default_data_dir().join("logs");
    let path = log_dir.join("security-service.log");
    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "security-service: cannot create log directory {}: {err}",
            log_dir.display()
        );
        init_console_logging();
        return;
    }
    let file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!(
                "security-service: cannot open log file {}: {err}",
                path.display()
            );
            init_console_logging();
            return;
        }
    };
    let writer = Arc::new(Mutex::new(file));
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(true)
        .with_writer(move || LogWriter(Arc::clone(&writer)))
        .try_init();
    if result.is_err() {
        eprintln!("security-service: tracing subscriber was already initialized");
    }
    info!(log = %path.display(), "service logging initialized");
}

struct LogWriter(Arc<Mutex<File>>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.lock() {
            Ok(mut file) => file.write(buf),
            Err(poisoned) => poisoned.into_inner().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.lock() {
            Ok(mut file) => file.flush(),
            Err(poisoned) => poisoned.into_inner().flush(),
        }
    }
}

// ---------------------------------------------------------------------------
// Engine runtime (shared by console and service mode)
// ---------------------------------------------------------------------------

struct EngineRuntime {
    engine: ServiceEngine,
    pipe_thread: Option<std::thread::JoinHandle<()>>,
}

impl EngineRuntime {
    fn start() -> Result<Self, String> {
        let data_dir = default_data_dir();
        std::fs::create_dir_all(&data_dir)
            .map_err(|err| format!("cannot create {}: {err}", data_dir.display()))?;
        let db_path = default_db_path();
        let vault_dir = default_vault_dir();

        let db = Database::open(&db_path)
            .map_err(|err| format!("cannot open {}: {err}", db_path.display()))?;
        let poll_interval = read_poll_interval(&db);
        let router = build_ai_router(&db);

        let mut config = ServiceEngineConfig {
            db_path: Some(db_path.clone()),
            vault_dir: Some(vault_dir.clone()),
            poll_interval,
            ..Default::default()
        };
        config.scanner.follow_symlinks = false;

        let mut deps = ServiceEngineDeps::new(db, ProcessMonitor::new(platform_process_provider()))
            .map_err(|err| format!("cannot initialize the scanner: {err}"))?
            .with_config(config);
        if let Some(router) = router {
            deps.router = Some(router);
        }

        let engine = ServiceEngine::new(deps)
            .map_err(|err| format!("cannot initialize the engine: {err}"))?;
        engine
            .start()
            .map_err(|err| format!("cannot start the engine: {err}"))?;

        let handler_engine = engine.clone();
        let pipe_name = security_ipc::IPC_PIPE_NAME;
        let pipe_thread = std::thread::Builder::new()
            .name("security-ipc-pipe".to_string())
            .spawn(move || {
                let handler = Arc::new(move |request| handler_engine.handle_request(request));
                if let Err(err) = security_ipc::pipe::serve_pipe(pipe_name, handler) {
                    error!(error = %err, "named-pipe server stopped with an error");
                }
            })
            .map_err(|err| format!("cannot spawn the pipe server: {err}"))?;

        // Do not report the service as running until the pipe is accepting.
        let deadline = Instant::now() + PIPE_START_TIMEOUT;
        while Instant::now() < deadline {
            if security_ipc::pipe::pipe_available(pipe_name) {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if !security_ipc::pipe::pipe_available(pipe_name) {
            let _ = engine.stop_and_wait(Duration::from_secs(5));
            security_ipc::pipe::request_pipe_shutdown();
            join_thread(pipe_thread, Duration::from_secs(2));
            return Err(format!(
                "named pipe {pipe_name} did not become available; another process may be holding it"
            ));
        }

        info!(
            pipe = pipe_name,
            db = %db_path.display(),
            vault = %vault_dir.display(),
            "security service runtime started"
        );
        Ok(Self {
            engine,
            pipe_thread: Some(pipe_thread),
        })
    }

    fn shutdown(mut self) {
        if let Err(err) = self.engine.stop_and_wait(Duration::from_secs(10)) {
            warn!(error = %err, "engine shutdown was not clean");
        }
        security_ipc::pipe::request_pipe_shutdown();
        if let Some(handle) = self.pipe_thread.take() {
            join_thread(handle, Duration::from_secs(5));
        }
    }
}

impl Drop for EngineRuntime {
    fn drop(&mut self) {
        // Safety net for early returns: never leave the runtime thread or pipe
        // accept loop alive after the host decides to exit.
        let _ = self.engine.stop_and_wait(Duration::from_secs(2));
        security_ipc::pipe::request_pipe_shutdown();
        if let Some(handle) = self.pipe_thread.take() {
            join_thread(handle, Duration::from_secs(2));
        }
    }
}

fn read_poll_interval(db: &Database) -> Duration {
    let seconds = db
        .get_setting(SETTING_POLL_INTERVAL_SECS)
        .ok()
        .flatten()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(security_service::DEFAULT_POLL_INTERVAL_SECS);
    Duration::from_secs(seconds.clamp(1, 3600))
}

/// Build the optional AI router from stored settings and environment.
///
/// * `AI_ANTIVIRUS_AI_MOCK=1` forces the deterministic mock provider (no
///   network) and is intended for development.
/// * `OPENROUTER_API_KEY` supplies the key without writing it to the database.
/// * No key (or `mode = offline`) leaves AI disabled.
fn build_ai_router(db: &Database) -> Option<Arc<ai_decisions::ProviderRouter>> {
    if std::env::var("AI_ANTIVIRUS_AI_MOCK").ok().as_deref() == Some("1") {
        let config = ai_decisions::AiConfig {
            mode: ai_decisions::AiMode::Hybrid,
            ..load_ai_config(db).unwrap_or_default()
        };
        match ai_decisions::mock_router(config) {
            Ok(router) => {
                info!("AI router using the deterministic mock provider");
                return Some(Arc::new(router));
            }
            Err(err) => {
                warn!(error = %err, "could not build the mock AI router");
                return None;
            }
        }
    }

    let mut config = load_ai_config(db).unwrap_or_default();
    if let Ok(mode) = std::env::var("AI_ANTIVIRUS_AI_MODE") {
        config.mode = match mode.trim().to_ascii_lowercase().as_str() {
            "cloud" => ai_decisions::AiMode::Cloud,
            "hybrid" => ai_decisions::AiMode::Hybrid,
            _ => ai_decisions::AiMode::Offline,
        };
    }
    if let Ok(key) = std::env::var("OPENROUTER_API_KEY") {
        if !key.trim().is_empty() {
            config.api_key = Some(key);
        }
    }
    if config.mode == ai_decisions::AiMode::Offline {
        return None;
    }
    match ai_decisions::ProviderRouter::new(config) {
        Ok(router) => Some(Arc::new(router)),
        Err(err) => {
            warn!(error = %err, "AI router disabled after a configuration error");
            None
        }
    }
}

fn join_thread(handle: std::thread::JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            warn!("thread did not stop before the shutdown timeout; detaching");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Console mode
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_console() -> Result<(), String> {
    let runtime = EngineRuntime::start()?;
    println!(
        "AI Antivirus security engine listening on {}",
        security_ipc::IPC_PIPE_NAME
    );
    println!("Press Enter or Ctrl+C to stop.");

    let (sender, receiver) = std::sync::mpsc::channel();
    console_control::install(sender.clone());
    std::thread::Builder::new()
        .name("console-input".to_string())
        .spawn(move || {
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            let _ = sender.send(());
        })
        .map_err(|err| format!("cannot spawn the console input thread: {err}"))?;

    let _ = receiver.recv();
    println!("Stopping...");
    runtime.shutdown();
    println!("Stopped.");
    Ok(())
}

#[cfg(not(windows))]
fn run_console() -> Result<(), String> {
    Err("the security service is only supported on Windows".to_string())
}

#[cfg(windows)]
mod console_control {
    use std::sync::mpsc::Sender;
    use std::sync::OnceLock;

    static STOP: OnceLock<Sender<()>> = OnceLock::new();

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn handler(_control_type: u32) -> i32 {
        if let Some(sender) = STOP.get() {
            let _ = sender.send(());
        }
        1 // handled
    }

    /// Route Ctrl+C / Ctrl+Break / console close to the shutdown channel.
    pub fn install(sender: Sender<()>) {
        let _ = STOP.set(sender);
        // Failure is non-fatal: Enter and EOF still stop console mode.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows service mode
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_as_service() -> Result<(), String> {
    init_file_logging();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|err| {
        format!(
            "could not start the service dispatcher ({err}); run from the Service Control Manager or use --console for development"
        )
    })?;
    Ok(())
}

#[cfg(not(windows))]
fn run_as_service() -> Result<(), String> {
    Err("the security service is only supported on Windows".to_string())
}

#[cfg(windows)]
fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service_body() {
        error!(error = %err, "security service failed");
    }
}

#[cfg(windows)]
fn run_service_body() -> Result<(), String> {
    let (stop_sender, stop_receiver) = std::sync::mpsc::channel();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop => {
                let _ = stop_sender.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|err| format!("cannot register the service control handler: {err}"))?;

    status_handle
        .set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            1,
            Duration::from_secs(15),
        ))
        .map_err(|err| format!("cannot report the start-pending state: {err}"))?;

    let runtime = match EngineRuntime::start() {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(error = %err, "security service startup failed");
            let _ = status_handle.set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
                0,
                Duration::default(),
            ));
            return Err(err);
        }
    };

    status_handle
        .set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP,
            ServiceExitCode::NO_ERROR,
            0,
            Duration::default(),
        ))
        .map_err(|err| format!("cannot report the running state: {err}"))?;
    info!("security service is running");

    // Block until the SCM asks us to stop. If the control handler is somehow
    // never called (for example during process shutdown), the process exits
    // and SCM recovery handles it.
    let _ = stop_receiver.recv();

    status_handle
        .set_service_status(service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            1,
            Duration::from_secs(15),
        ))
        .map_err(|err| format!("cannot report the stop-pending state: {err}"))?;

    runtime.shutdown();

    status_handle
        .set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            0,
            Duration::default(),
        ))
        .map_err(|err| format!("cannot report the stopped state: {err}"))?;
    info!("security service stopped");
    Ok(())
}

#[cfg(windows)]
fn service_status(
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

// ---------------------------------------------------------------------------
// Install / uninstall / start / stop helpers
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn install_service() -> Result<(), String> {
    prepare_data_directories()?;

    let executable = std::env::current_exe()
        .map_err(|err| format!("cannot resolve the service executable: {err}"))?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|err| {
                format!("cannot open the Service Control Manager (run elevated): {err}")
            })?;

    if manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        return Err(format!(
            "service {SERVICE_NAME} is already installed; run --uninstall first"
        ));
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(|err| format!("cannot create service {SERVICE_NAME}: {err}"))?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|err| format!("cannot set the service description: {err}"))?;

    let restart = |seconds: u64| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(seconds),
    };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(10), restart(30)]),
        })
        .map_err(|err| format!("cannot configure service recovery: {err}"))?;

    service
        .start(&[] as &[&OsStr])
        .map_err(|err| format!("service was installed but could not be started: {err}"))?;
    wait_for_state(&service, ServiceState::Running, SCM_TIMEOUT)?;
    println!(
        "{SERVICE_DISPLAY_NAME} installed as {SERVICE_NAME} (LocalService, manual start) and started."
    );
    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("cannot open the Service Control Manager (run elevated): {err}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        )
        .map_err(|err| format!("service {SERVICE_NAME} is not installed: {err}"))?;

    let status = service
        .query_status()
        .map_err(|err| format!("cannot query the service state: {err}"))?;
    if status.current_state != ServiceState::Stopped {
        service
            .stop()
            .map_err(|err| format!("cannot stop {SERVICE_NAME}: {err}"))?;
        wait_for_state(&service, ServiceState::Stopped, SCM_TIMEOUT)?;
    }
    service
        .delete()
        .map_err(|err| format!("cannot delete {SERVICE_NAME}: {err}"))?;
    println!(
        "{SERVICE_NAME} removed. Data in {} was preserved (remove it explicitly if required).",
        default_data_dir().display()
    );
    Ok(())
}

#[cfg(windows)]
fn start_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("cannot open the Service Control Manager: {err}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| format!("service {SERVICE_NAME} is not installed: {err}"))?;
    service
        .start(&[] as &[&OsStr])
        .map_err(|err| format!("cannot start {SERVICE_NAME}: {err}"))?;
    wait_for_state(&service, ServiceState::Running, SCM_TIMEOUT)?;
    println!("{SERVICE_NAME} started.");
    Ok(())
}

#[cfg(windows)]
fn stop_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("cannot open the Service Control Manager: {err}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| format!("service {SERVICE_NAME} is not installed: {err}"))?;
    let status = service
        .query_status()
        .map_err(|err| format!("cannot query {SERVICE_NAME}: {err}"))?;
    if status.current_state == ServiceState::Stopped {
        println!("{SERVICE_NAME} is already stopped.");
        return Ok(());
    }
    service
        .stop()
        .map_err(|err| format!("cannot stop {SERVICE_NAME}: {err}"))?;
    wait_for_state(&service, ServiceState::Stopped, SCM_TIMEOUT)?;
    println!("{SERVICE_NAME} stopped.");
    Ok(())
}

#[cfg(windows)]
fn wait_for_state(
    service: &windows_service::service::Service,
    target: ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service
            .query_status()
            .map_err(|err| format!("cannot query the service state: {err}"))?;
        if status.current_state == target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "service did not reach {target:?} within {timeout:?} (state: {:?})",
                status.current_state
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Create `%ProgramData%\AiAntivirus` and the vault, and grant LocalService the
/// minimum access it needs. Requires an elevated shell.
#[cfg(windows)]
fn prepare_data_directories() -> Result<(), String> {
    let data_dir = default_data_dir();
    let vault_dir = default_vault_dir();
    let log_dir = data_dir.join("logs");
    for dir in [&data_dir, &vault_dir, &log_dir] {
        std::fs::create_dir_all(dir)
            .map_err(|err| format!("cannot create {}: {err}", dir.display()))?;
    }

    // S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators,
    // S-1-5-19 = NT AUTHORITY\LocalService.
    for dir in [&data_dir, &vault_dir, &log_dir] {
        apply_acl(dir)?;
    }
    Ok(())
}

#[cfg(windows)]
fn apply_acl(dir: &Path) -> Result<(), String> {
    let output = std::process::Command::new("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .arg("*S-1-5-19:(OI)(CI)M")
        .arg("/T")
        .output()
        .map_err(|err| format!("cannot run icacls for {}: {err}", dir.display()))?;
    if !output.status.success() {
        return Err(format!(
            "icacls failed for {}: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn install_service() -> Result<(), String> {
    Err("Windows services are only supported on Windows".to_string())
}

#[cfg(not(windows))]
fn uninstall_service() -> Result<(), String> {
    Err("Windows services are only supported on Windows".to_string())
}

#[cfg(not(windows))]
fn start_service() -> Result<(), String> {
    Err("Windows services are only supported on Windows".to_string())
}

#[cfg(not(windows))]
fn stop_service() -> Result<(), String> {
    Err("Windows services are only supported on Windows".to_string())
}

// Keep the imports used on every platform without warnings on Windows.
#[allow(dead_code)]
fn _unused(_: ServiceError) {}
