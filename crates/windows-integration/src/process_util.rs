//! Bounded child-process execution (Windows only).
//!
//! Helper processes (PowerShell for the Defender probe, `reg.exe` for version
//! metadata) must never be able to hang the engine. This module spawns them
//! without a console window, enforces a deadline and kills the child when the
//! deadline passes.

use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Do not flash a console window for helper processes.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Helper output is a few KiB; reading the pipes after the child exits cannot
/// deadlock on the 64 KiB pipe buffer. Keep a hard memory bound anyway.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Captured result of a finished helper process.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Why a helper process could not be completed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ProcessRunError {
    /// The executable could not be started.
    Spawn(String),
    /// The process could not be monitored or its output not read.
    Io(String),
    /// The process exceeded the caller's deadline and was killed.
    Timeout,
}

impl ProcessRunError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Spawn(message) | Self::Io(message) => message,
            Self::Timeout => "process timed out",
        }
    }
}

/// Run `program` with `args` and capture stdout/stderr, killing it when it does
/// not finish within `timeout`.
pub(crate) fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, ProcessRunError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| ProcessRunError::Spawn(format!("failed to start {program}: {error}")))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProcessRunError::Timeout);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessRunError::Io(format!(
                    "failed to monitor {program}: {error}"
                )));
            }
        }
    }

    let output = child.wait_with_output().map_err(|error| {
        ProcessRunError::Io(format!("failed to read {program} output: {error}"))
    })?;

    // `MAX_CAPTURE_BYTES` documents the pipe-buffer assumption above; keep a
    // hard bound anyway so a rogue helper cannot exhaust memory.
    let stdout = truncate_bytes(&output.stdout);
    let stderr = truncate_bytes(&output.stderr);

    Ok(ProcessOutput {
        stdout,
        stderr,
        exit_code: output.status.code().unwrap_or(-1),
    })
}

fn truncate_bytes(bytes: &[u8]) -> String {
    let slice = if bytes.len() > MAX_CAPTURE_BYTES {
        &bytes[..MAX_CAPTURE_BYTES]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout_and_exit_code() {
        let output = run_with_timeout(
            "cmd.exe",
            &["/C", "echo hello-from-test"],
            Duration::from_secs(10),
        )
        .expect("cmd.exe should start");
        assert_eq!(output.exit_code, 0);
        assert!(
            output.stdout.contains("hello-from-test"),
            "stdout was {:?}",
            output.stdout
        );
    }

    #[test]
    fn reports_nonzero_exit_codes() {
        let output = run_with_timeout("cmd.exe", &["/C", "exit 7"], Duration::from_secs(10))
            .expect("cmd.exe should start");
        assert_eq!(output.exit_code, 7);
    }

    #[test]
    fn kills_processes_that_exceed_the_deadline() {
        let result = run_with_timeout(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ],
            Duration::from_millis(500),
        );
        match result {
            Err(ProcessRunError::Timeout) => {}
            // A machine without PowerShell cannot run this scenario; do not
            // fail the suite for that.
            Err(ProcessRunError::Spawn(_)) => {}
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    #[test]
    fn missing_executables_report_spawn_errors() {
        let result = run_with_timeout(
            "definitely-not-a-real-program-xyz.exe",
            &[],
            Duration::from_millis(500),
        );
        assert!(matches!(result, Err(ProcessRunError::Spawn(_))));
    }
}
