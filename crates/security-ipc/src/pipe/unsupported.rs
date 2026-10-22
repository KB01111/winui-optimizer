//! Non-Windows stub of the named-pipe transport.
//!
//! The API mirrors the Windows module but every operation fails with
//! [`IpcError::Unsupported`] so the workspace builds on non-Windows hosts.

use std::sync::Arc;

use crate::{ClientRequest, IpcError, ServerResponse};

/// The SDDL that would be applied to pipe instances on Windows.
pub const PIPE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Rate-limit disconnection threshold used by the Windows implementation.
pub const MAX_CONSECUTIVE_RATE_LIMIT_REJECTS: u32 = 32;

/// Named-pipe server facade (unsupported on this platform).
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeServer;

impl PipeServer {
    /// See [`PIPE_DACL_SDDL`].
    pub const DACL_SDDL: &'static str = PIPE_DACL_SDDL;

    /// Always returns [`IpcError::Unsupported`] on this platform.
    pub fn serve(
        _name: &str,
        _handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
    ) -> Result<(), IpcError> {
        Err(IpcError::Unsupported)
    }

    /// No-op on this platform.
    pub fn request_shutdown() {}

    /// Always `false` on this platform.
    pub fn available(_name: &str) -> bool {
        false
    }
}

/// Always returns [`IpcError::Unsupported`] on this platform.
pub fn serve_pipe(
    _name: &str,
    _handler: Arc<dyn Fn(ClientRequest) -> ServerResponse + Send + Sync>,
) -> Result<(), IpcError> {
    Err(IpcError::Unsupported)
}

/// Always returns [`IpcError::Unsupported`] on this platform.
pub fn call_pipe(_name: &str, _request: &ClientRequest) -> Result<ServerResponse, IpcError> {
    Err(IpcError::Unsupported)
}

/// No-op on this platform.
pub fn request_pipe_shutdown() {}

/// Always `false` on this platform.
pub fn pipe_available(_name: &str) -> bool {
    false
}

/// Always returns [`IpcError::Unsupported`] on this platform.
pub fn probe_pipe_acl(_name: &str) -> Result<String, IpcError> {
    Err(IpcError::Unsupported)
}
