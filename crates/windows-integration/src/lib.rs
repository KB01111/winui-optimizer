//! Windows platform integration for the AI Antivirus engine.
//!
//! This crate is the only place in the workspace that talks to Windows
//! platform APIs. It implements the `windows-integration` contract from
//! `docs/CONTRACTS.md`:
//!
//! - [`package_identity`] / [`PackageIdentityInfo`]: MSIX package identity via
//!   the WinRT `Windows.ApplicationModel.Package` API, preserving the upstream
//!   winappCli sample behaviour (`Package::Current()` -> `Package.Id()`).
//! - [`windows_version`] / [`WindowsVersion`]: OS version, edition and
//!   architecture from `GetVersionExW`, the live registry key
//!   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` and
//!   `GetNativeSystemInfo`. `is_windows_11` is `build >= 22000`.
//! - [`execution_context`] / [`ExecutionContext`]: packaged/elevated state,
//!   user SID, **redacted** username, process id and session id.
//! - [`defender_status`] / [`DefenderStatus`]: read-only Microsoft Defender
//!   status via `Get-MpComputerStatus` (never modifies Defender, Tamper
//!   Protection or any other setting).
//! - [`show_notification`] / [`NotificationOutcome`]: toast notifications,
//!   gated on package identity (returns [`NotificationOutcome::NoPackageIdentity`]
//!   instead of throwing).
//! - [`protect_secret`] / [`unprotect_secret`]: DPAPI with
//!   `CRYPTPROTECT_UI_FORBIDDEN`.
//!
//! # Safety and privacy invariants
//!
//! - No function in this crate changes Windows security configuration. The
//!   Defender probe uses only `Get-*` cmdlets, `-NoProfile -NonInteractive`,
//!   and is bounded by a 10 second timeout.
//! - Usernames are never returned verbatim: [`execution_context`] returns a
//!   redacted form such as `k***n`.
//! - Production paths never `unwrap()`/`expect()` on untrusted input.
//! - Non-Windows builds compile and return `Unsupported`/fallback values so
//!   the workspace stays portable for tooling.

#![deny(unsafe_op_in_unsafe_fn)]

mod context;
mod defender;
mod dpapi;
mod error;
mod notifications;
mod package;
#[cfg(windows)]
mod process_util;
mod util;
mod version;

pub use context::{execution_context, ExecutionContext};
pub use defender::{defender_status, DefenderStatus};
pub use dpapi::{protect_secret, unprotect_secret};
pub use error::WindowsIntegrationError;
pub use notifications::{notifications_supported, show_notification, NotificationOutcome};
pub use package::{package_identity, PackageIdentityInfo};
pub use version::{windows_version, WindowsVersion};
