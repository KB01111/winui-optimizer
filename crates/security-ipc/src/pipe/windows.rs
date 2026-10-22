//! Windows implementation of the named-pipe transport.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use windows::core::{Error as Win32Error, BOOL, HSTRING, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::{
    decode_payload, decode_request_payload, encode_request, encode_response, ClientRequest,
    IpcError, RateLimiter, ServerResponse, FRAME_HEADER_BYTES, IPC_PROTOCOL_VERSION,
    MAX_FRAME_BYTES,
};

/// SDDL applied to every pipe instance: SYSTEM and Administrators get
/// `GENERIC_ALL`, interactive users get read/write, everyone else nothing.
pub const PIPE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// A connection that keeps being rate limited for this many consecutive
/// requests is disconnected instead of being served errors forever.
pub const MAX_CONSECUTIVE_RATE_LIMIT_REJECTS: u32 = 32;

/// Size of each pipe's input/output buffer.
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// Delay before recreating a pipe instance after a transient failure.
const RETRY_SLEEP: Duration = Duration::from_millis(50);

/// How long `call_pipe` waits for a busy pipe before retrying.
const CLIENT_WAIT_TIMEOUT_MS: u32 = 3_000;

/// Number of connect attempts made by `call_pipe` while the pipe is busy.
const CLIENT_CONNECT_ATTEMPTS: u32 = 3;

/// Process-wide shutdown flag for `serve_pipe`.
static PIPE_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Names of the pipes currently served by this process, used by
/// [`request_pipe_shutdown`] to wake blocked accept loops.
static SERVED_PIPES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Named-pipe server facade.
///
/// A zero-sized type that groups the transport entry points; use the free
/// functions if you prefer.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeServer;

impl PipeServer {
    /// The SDDL applied to every pipe instance created by this process.
    pub const DACL_SDDL: &'static str = PIPE_DACL_SDDL;

    /// See [`serve_pipe`].
    pub fn serve(
        name: &str,
        handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
    ) -> Result<(), IpcError> {
        serve_pipe(name, handler)
    }

    /// See [`request_pipe_shutdown`].
    pub fn request_shutdown() {
        request_pipe_shutdown();
    }

    /// See [`pipe_available`].
    pub fn available(name: &str) -> bool {
        pipe_available(name)
    }
}

/// Serve requests on the named pipe until [`request_pipe_shutdown`] is called.
///
/// `name` may be the full pipe path (`\\.\pipe\...`) or a bare pipe name.
/// Blocks the calling thread; each connected client is handled on its own
/// detached thread.
pub fn serve_pipe(
    name: &str,
    handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
) -> Result<(), IpcError> {
    let pipe_name = normalize_pipe_name(name);
    let hname = HSTRING::from(pipe_name.as_str());
    let descriptor = SecurityDescriptor::from_sddl(PIPE_DACL_SDDL)?;

    PIPE_SHUTDOWN.store(false, Ordering::SeqCst);
    register_served_pipe(&pipe_name);
    info!(pipe = %pipe_name, dacl = PIPE_DACL_SDDL, "named-pipe server listening");

    let result = serve_loop(&pipe_name, &hname, &descriptor, &handler);

    unregister_served_pipe(&pipe_name);
    result
}

fn serve_loop(
    pipe_name: &str,
    hname: &HSTRING,
    descriptor: &SecurityDescriptor,
    handler: &Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
) -> Result<(), IpcError> {
    let mut first_instance = true;
    loop {
        if PIPE_SHUTDOWN.load(Ordering::SeqCst) {
            info!(pipe = pipe_name, "named-pipe server shutting down");
            return Ok(());
        }

        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first_instance {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }

        let handle = unsafe {
            CreateNamedPipeW(
                hname,
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                Some(&descriptor.attributes),
            )
        };

        if handle.is_invalid() {
            let code = last_error();
            if code == ERROR_PIPE_BUSY.0 {
                thread::sleep(RETRY_SLEEP);
                continue;
            }
            if first_instance && code == ERROR_ACCESS_DENIED.0 {
                return Err(IpcError::Pipe(format!(
                    "pipe {pipe_name} already exists and was not created by this process (possible squatting); refusing to serve"
                )));
            }
            return Err(IpcError::Pipe(format!(
                "CreateNamedPipeW failed for {pipe_name} (win32 error {code})"
            )));
        }
        first_instance = false;

        let instance = ServerPipe(handle);
        match unsafe { ConnectNamedPipe(instance.0, None) } {
            Ok(()) => {}
            Err(err) => {
                let code = win32_code(&err);
                if code != ERROR_PIPE_CONNECTED.0 {
                    if PIPE_SHUTDOWN.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    warn!(
                        pipe = pipe_name,
                        code, "ConnectNamedPipe failed; recreating instance"
                    );
                    thread::sleep(RETRY_SLEEP);
                    continue;
                }
                // ERROR_PIPE_CONNECTED: the client connected before we called
                // ConnectNamedPipe; this is success.
            }
        }

        let client_handler = Arc::clone(handler);
        let client_pipe_name = pipe_name.to_string();
        let raw = instance.into_send();
        let raw_handle = raw.0;
        let spawn_result = thread::Builder::new()
            .name(format!("ipc-client-{}", raw_handle.0 as usize))
            .spawn(move || run_client_thread(raw, client_pipe_name, client_handler));
        if let Err(err) = spawn_result {
            warn!(pipe = pipe_name, error = %err, "failed to spawn pipe client thread; closing connection");
            unsafe {
                let _ = DisconnectNamedPipe(raw_handle);
                let _ = CloseHandle(raw_handle);
            }
        }
    }
}

/// Connect to the pipe, send one request and wait for one response.
///
/// Blocks the calling thread until the response arrives or the connection
/// fails; there is no client-side read timeout (see the module docs).
pub fn call_pipe(name: &str, request: &ClientRequest) -> Result<ServerResponse, IpcError> {
    let pipe_name = normalize_pipe_name(name);
    let handle = connect_client(&pipe_name)?;
    let _pipe = ClientPipe(handle);

    let frame = encode_request(request)?;
    write_frame(handle, &frame)?;

    let payload = match read_frame(handle)? {
        Some(payload) => payload,
        None => {
            return Err(IpcError::Pipe(
                "security service closed the pipe before responding".to_string(),
            ))
        }
    };
    let response: ServerResponse = decode_payload(&payload)?;
    validate_response(&response)?;
    Ok(response)
}

/// Ask a `serve_pipe` loop in this process to stop.
///
/// Best effort: also connects to every served pipe name to wake an accept loop
/// blocked in `ConnectNamedPipe`.
pub fn request_pipe_shutdown() {
    PIPE_SHUTDOWN.store(true, Ordering::SeqCst);
    let names = served_pipe_names();
    for name in names {
        wake_pipe(&name);
    }
}

/// True when at least one instance of the pipe is free (server listening).
pub fn pipe_available(name: &str) -> bool {
    let pipe_name = normalize_pipe_name(name);
    let hname = HSTRING::from(pipe_name.as_str());
    unsafe { WaitNamedPipeW(&hname, 0).as_bool() }
}

/// Diagnostic helper: create a short-lived pipe instance with the production
/// DACL and return the DACL of the created kernel object as SDDL.
///
/// Used by tests to verify on this machine that the DACL is applied. Does not
/// accept clients and does not require elevation.
pub fn probe_pipe_acl(name: &str) -> Result<String, IpcError> {
    let pipe_name = normalize_pipe_name(name);
    let hname = HSTRING::from(pipe_name.as_str());
    let descriptor = SecurityDescriptor::from_sddl(PIPE_DACL_SDDL)?;
    let handle = unsafe {
        CreateNamedPipeW(
            &hname,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(&descriptor.attributes),
        )
    };
    if handle.is_invalid() {
        return Err(IpcError::Pipe(format!(
            "CreateNamedPipeW failed for ACL probe (win32 error {})",
            last_error()
        )));
    }
    let instance = ServerPipe(handle);

    let mut psd = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            instance.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        )
    };
    if status.0 != 0 {
        return Err(IpcError::Pipe(format!(
            "GetSecurityInfo failed (win32 error {})",
            status.0
        )));
    }
    let _descriptor_guard = LocalMemory(psd.0);

    let mut sddl = PWSTR::null();
    let mut sddl_len: u32 = 0;
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            Some(&mut sddl_len),
        )
    }
    .map_err(|err| {
        IpcError::Pipe(format!(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {err}"
        ))
    })?;
    let _string_guard = LocalMemory(sddl.0.cast());

    unsafe { sddl.to_string() }
        .map_err(|err| IpcError::Pipe(format!("invalid SDDL string returned by Windows: {err}")))
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

fn handle_client(
    handle: HANDLE,
    pipe_name: &str,
    handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
) {
    let mut limiter = RateLimiter::default();
    let mut consecutive_rejects: u32 = 0;

    loop {
        let payload = match read_frame(handle) {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                debug!(pipe = pipe_name, "pipe client disconnected");
                return;
            }
            Err(IpcError::EmptyFrame) => {
                warn!(pipe = pipe_name, "rejected empty frame from pipe client");
                if write_error(handle, "invalid_request", "empty frame").is_err() {
                    return;
                }
                continue;
            }
            Err(err) => {
                warn!(pipe = pipe_name, error = %err, "rejected malformed frame from pipe client");
                let _ = write_error(handle, "invalid_request", &err.to_string());
                // The byte stream can no longer be resynchronised safely.
                return;
            }
        };

        if !limiter.try_acquire() {
            consecutive_rejects = consecutive_rejects.saturating_add(1);
            warn!(
                pipe = pipe_name,
                consecutive_rejects, "per-client rate limit exceeded; rejecting request"
            );
            if write_error(handle, "rate_limited", "per-client rate limit exceeded").is_err() {
                return;
            }
            if consecutive_rejects >= MAX_CONSECUTIVE_RATE_LIMIT_REJECTS {
                warn!(
                    pipe = pipe_name,
                    "disconnecting pipe client after repeated rate limit violations"
                );
                return;
            }
            continue;
        }
        consecutive_rejects = 0;

        let request = match decode_request_payload(&payload) {
            Ok(request) => request,
            Err(err) => {
                warn!(pipe = pipe_name, error = %err, "rejected invalid request");
                if write_error(handle, "invalid_request", &err.to_string()).is_err() {
                    return;
                }
                continue;
            }
        };

        debug!(
            pipe = pipe_name,
            request = request_name(&request),
            "handling pipe request"
        );
        let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request)))
            .unwrap_or_else(|_| {
                error!(pipe = pipe_name, "pipe request handler panicked");
                ServerResponse::error("internal_error", "request handler panicked")
            });

        if let Err(err) = write_response(handle, &response) {
            warn!(pipe = pipe_name, error = %err, "failed to write response; closing connection");
            return;
        }
    }
}

fn request_name(request: &ClientRequest) -> &'static str {
    match request {
        ClientRequest::Ping => "ping",
        ClientRequest::GetStatus => "get_status",
        ClientRequest::ScanPath { .. } => "scan_path",
        ClientRequest::CancelScan { .. } => "cancel_scan",
        ClientRequest::ListEvents { .. } => "list_events",
        ClientRequest::GetEvent { .. } => "get_event",
        ClientRequest::ListQuarantine => "list_quarantine",
        ClientRequest::QuarantineFile { .. } => "quarantine_file",
        ClientRequest::RestoreQuarantine { .. } => "restore_quarantine",
        ClientRequest::Subscribe => "subscribe",
    }
}

/// Per-client thread entry point: owns the connection handle until the client
/// disconnects.
fn run_client_thread(
    raw: SendHandle,
    pipe_name: String,
    handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
) {
    let handle = raw.0;
    let _instance = ServerPipe(handle);
    handle_client(handle, &pipe_name, handler);
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<bool, IpcError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut read: u32 = 0;
        match unsafe { ReadFile(handle, Some(&mut buf[filled..]), Some(&mut read), None) } {
            Ok(()) => {
                if read == 0 {
                    return Ok(false);
                }
                filled += read as usize;
            }
            Err(err) => {
                let code = win32_code(&err);
                if filled == 0 && is_disconnect_code(code) {
                    return Ok(false);
                }
                return Err(IpcError::Pipe(format!(
                    "ReadFile failed while reading a frame (win32 error {code})"
                )));
            }
        }
    }
    Ok(true)
}

fn read_frame(handle: HANDLE) -> Result<Option<Vec<u8>>, IpcError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    if !read_exact(handle, &mut header)? {
        return Ok(None);
    }
    let declared = u32::from_le_bytes(header) as usize;
    if declared == 0 {
        return Err(IpcError::EmptyFrame);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            size: declared,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0u8; declared];
    if !read_exact(handle, &mut payload)? {
        return Err(IpcError::TruncatedFrame {
            declared,
            actual: 0,
        });
    }
    Ok(Some(payload))
}

fn write_frame(handle: HANDLE, frame: &[u8]) -> Result<(), IpcError> {
    let mut written = 0usize;
    while written < frame.len() {
        let mut count: u32 = 0;
        match unsafe { WriteFile(handle, Some(&frame[written..]), Some(&mut count), None) } {
            Ok(()) => {
                if count == 0 {
                    return Err(IpcError::Pipe(
                        "WriteFile reported zero bytes written".to_string(),
                    ));
                }
                written += count as usize;
            }
            Err(err) => {
                let code = win32_code(&err);
                return Err(IpcError::Pipe(format!(
                    "WriteFile failed while writing a frame (win32 error {code})"
                )));
            }
        }
    }
    Ok(())
}

fn write_response(handle: HANDLE, response: &ServerResponse) -> Result<(), IpcError> {
    let frame = encode_response(response)?;
    write_frame(handle, &frame)
}

fn write_error(handle: HANDLE, code: &str, message: &str) -> Result<(), IpcError> {
    write_response(handle, &ServerResponse::error(code, message))
}

fn connect_client(pipe_name: &str) -> Result<HANDLE, IpcError> {
    let hname = HSTRING::from(pipe_name);
    let mut last_code = 0u32;
    for _attempt in 1..=CLIENT_CONNECT_ATTEMPTS {
        let attempt = unsafe {
            CreateFileW(
                &hname,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };
        match attempt {
            Ok(handle) => return Ok(handle),
            Err(err) => {
                let code = win32_code(&err);
                last_code = code;
                if code == ERROR_PIPE_BUSY.0 {
                    unsafe {
                        let _ = WaitNamedPipeW(&hname, CLIENT_WAIT_TIMEOUT_MS);
                    }
                    continue;
                }
                if code == ERROR_FILE_NOT_FOUND.0 {
                    return Err(IpcError::Pipe(format!(
                        "{pipe_name} does not exist; is the AI Antivirus security service installed and running?"
                    )));
                }
                if code == ERROR_ACCESS_DENIED.0 {
                    return Err(IpcError::Pipe(format!(
                        "access denied connecting to {pipe_name}; only interactive users, Administrators and SYSTEM may connect"
                    )));
                }
                return Err(IpcError::Pipe(format!(
                    "CreateFileW failed for {pipe_name} (win32 error {code})"
                )));
            }
        }
    }
    Err(IpcError::Pipe(format!(
        "{pipe_name} is still busy after {CLIENT_CONNECT_ATTEMPTS} attempts (last win32 error {last_code})"
    )))
}

fn validate_response(response: &ServerResponse) -> Result<(), IpcError> {
    if let ServerResponse::Pong { version, .. } = response {
        let got = version.parse::<u32>().unwrap_or(0);
        if got != IPC_PROTOCOL_VERSION {
            return Err(IpcError::VersionMismatch {
                expected: IPC_PROTOCOL_VERSION,
                got,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers and guards
// ---------------------------------------------------------------------------

fn win32_code(err: &Win32Error) -> u32 {
    (err.code().0 as u32) & 0xFFFF
}

fn last_error() -> u32 {
    unsafe { GetLastError().0 }
}

fn is_disconnect_code(code: u32) -> bool {
    code == ERROR_BROKEN_PIPE.0 || code == ERROR_PIPE_NOT_CONNECTED.0 || code == ERROR_NO_DATA.0
}

fn normalize_pipe_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.starts_with("\\\\") || trimmed.starts_with("//") {
        return trimmed.replace('/', "\\");
    }
    format!(r"\\.\pipe\{trimmed}")
}

fn register_served_pipe(name: &str) {
    let mut names = SERVED_PIPES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !names.iter().any(|existing| existing == name) {
        names.push(name.to_string());
    }
}

fn unregister_served_pipe(name: &str) {
    let mut names = SERVED_PIPES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    names.retain(|existing| existing != name);
}

fn served_pipe_names() -> Vec<String> {
    SERVED_PIPES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn wake_pipe(pipe_name: &str) {
    let hname = HSTRING::from(pipe_name);
    unsafe {
        let _ = WaitNamedPipeW(&hname, 200);
        if let Ok(handle) = CreateFileW(
            &hname,
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            let _ = CloseHandle(handle);
        }
    }
}

/// Owns a server-side pipe handle: disconnects any client and closes on drop.
struct ServerPipe(HANDLE);

impl ServerPipe {
    /// Relinquish ownership so the handle can be moved to a client thread.
    fn into_send(self) -> SendHandle {
        let handle = self.0;
        std::mem::forget(self);
        SendHandle(handle)
    }
}

/// `HANDLE` wraps a raw pointer and is therefore `!Send`. Moving a handle to
/// the single thread that owns it is sound; nothing else touches it afterwards.
struct SendHandle(HANDLE);

unsafe impl Send for SendHandle {}

impl Drop for ServerPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

/// Owns a client-side pipe handle.
struct ClientPipe(HANDLE);

impl Drop for ClientPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Owns a security descriptor allocated by `ConvertString...`.
struct SecurityDescriptor {
    pointer: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, IpcError> {
        let mut pointer = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut pointer,
                None,
            )
        }
        .map_err(|err| {
            IpcError::Pipe(format!(
                "failed to build pipe security descriptor from SDDL: {err}"
            ))
        })?;
        if pointer.is_invalid() {
            return Err(IpcError::Pipe(
                "failed to build pipe security descriptor from SDDL: null descriptor".to_string(),
            ));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: pointer.0,
            bInheritHandle: BOOL(0),
        };
        Ok(Self {
            pointer,
            attributes,
        })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.pointer.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.pointer.0)));
            }
            self.pointer = PSECURITY_DESCRIPTOR::default();
        }
    }
}

/// Frees memory allocated by the Windows security APIs via `LocalFree`.
struct LocalMemory(*mut core::ffi::c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    fn test_pipe_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\ai-antivirus-security-test-{tag}-{}",
            std::process::id()
        )
    }

    #[test]
    fn pipe_name_normalization() {
        assert_eq!(normalize_pipe_name("abc"), r"\\.\pipe\abc");
        assert_eq!(normalize_pipe_name(r"\\.\pipe\abc"), r"\\.\pipe\abc");
        assert_eq!(normalize_pipe_name("//./pipe/abc"), r"\\.\pipe\abc");
        assert_eq!(normalize_pipe_name("  abc  "), r"\\.\pipe\abc");
    }

    #[test]
    fn acl_probe_reports_expected_principals() {
        let name = test_pipe_name("acl");
        match probe_pipe_acl(&name) {
            Ok(sddl) => {
                assert!(
                    sddl.starts_with("D:P"),
                    "expected a protected DACL, got {sddl}"
                );
                assert!(sddl.contains("SY)"), "SYSTEM missing from {sddl}");
                assert!(sddl.contains("BA)"), "Administrators missing from {sddl}");
                assert!(
                    sddl.contains("IU)"),
                    "Interactive Users missing from {sddl}"
                );
                assert!(
                    !sddl.contains(";;;WD)") && !sddl.contains(";;;AN)"),
                    "unexpected Everyone/Anonymous ACE in {sddl}"
                );
            }
            Err(err) => {
                // Restricted environments may forbid named pipes entirely.
                eprintln!("SKIPPING ACL probe: {err}");
            }
        }
    }

    #[test]
    fn pipe_roundtrip_with_local_handler() {
        let name = test_pipe_name("roundtrip");
        let handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync> =
            Arc::new(|request| match request {
                ClientRequest::Ping => ServerResponse::Pong {
                    version: IPC_PROTOCOL_VERSION.to_string(),
                    uptime_secs: 1,
                },
                ClientRequest::GetStatus => ServerResponse::Status(serde_json::json!({"ok": true})),
                other => ServerResponse::error("unexpected", format!("{other:?}")),
            });

        let (started_tx, started_rx) = mpsc::channel();
        let server_name = name.clone();
        let server_thread = thread::spawn(move || {
            // Signal readiness just before entering the blocking loop; the
            // test additionally polls pipe_available before calling.
            let _ = started_tx.send(());
            serve_pipe(&server_name, handler)
        });

        // Wait until at least one instance is listening (or skip).
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut listening = false;
        while Instant::now() < deadline {
            if pipe_available(&name) {
                listening = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        if !listening {
            let _ = started_rx.recv_timeout(Duration::from_millis(100));
            request_pipe_shutdown();
            let _ = server_thread.join();
            eprintln!("SKIPPING pipe round-trip: no pipe instance became available (environment restriction)");
            return;
        }

        let response = call_pipe(&name, &ClientRequest::Ping).expect("ping should succeed");
        assert_eq!(
            response,
            ServerResponse::Pong {
                version: IPC_PROTOCOL_VERSION.to_string(),
                uptime_secs: 1
            }
        );

        let status = call_pipe(&name, &ClientRequest::GetStatus).expect("status should succeed");
        assert_eq!(
            status,
            ServerResponse::Status(serde_json::json!({"ok": true}))
        );

        request_pipe_shutdown();
        let joined = server_thread.join().expect("server thread must not panic");
        assert!(joined.is_ok(), "serve_pipe returned {joined:?}");
    }
}
