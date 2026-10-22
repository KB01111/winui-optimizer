//! Blocking Windows named-pipe transport for the security service.
//!
//! The public API is identical on every platform so the workspace always
//! builds:
//!
//! * [`serve_pipe`] creates instances of a named pipe and serves requests with
//!   a caller-supplied handler. One `std::thread` is spawned per connection.
//! * [`call_pipe`] connects to the pipe, sends one [`ClientRequest`] and reads
//!   one [`ServerResponse`].
//! * [`request_pipe_shutdown`] asks a `serve_pipe` loop in this process to
//!   stop and wakes it if it is blocked waiting for a client.
//!
//! # Security
//!
//! Every instance is created with
//! `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` (see [`PIPE_DACL_SDDL`]): full
//! control for SYSTEM and Administrators, generic read/write for interactive
//! users, nothing for anyone else. `PIPE_REJECT_REMOTE_CLIENTS` is always set,
//! so the pipe cannot be reached over SMB/remote transports. The first
//! instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a pre-existing
//! squatter pipe fails the server instead of being silently shared.
//!
//! Every accepted connection gets its own [`RateLimiter`] (see
//! [`DEFAULT_RATE_LIMIT_BURST`](crate::DEFAULT_RATE_LIMIT_BURST)); rejected
//! frames, unknown protocol versions, oversize frames and rate-limit hits are
//! logged with `tracing::warn`.
//!
//! # Limitations (documented, deliberate)
//!
//! * Reads and writes are blocking. There is no read timeout, so a client that
//!   connects and then goes silent holds one thread until it disconnects or the
//!   process exits. Threads are detached and reclaimed at process exit.
//! * Event streaming ([`ClientRequest::Subscribe`]) is not implemented; the
//!   request is acknowledged and clients poll instead.
//! * The shutdown flag is process-wide: run a single `serve_pipe` loop per
//!   process.

#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use unsupported::{
    call_pipe, pipe_available, probe_pipe_acl, request_pipe_shutdown, serve_pipe, PipeServer,
    MAX_CONSECUTIVE_RATE_LIMIT_REJECTS, PIPE_DACL_SDDL,
};
#[cfg(windows)]
pub use windows::{
    call_pipe, pipe_available, probe_pipe_acl, request_pipe_shutdown, serve_pipe, PipeServer,
    MAX_CONSECUTIVE_RATE_LIMIT_REJECTS, PIPE_DACL_SDDL,
};
