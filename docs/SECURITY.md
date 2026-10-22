# Security model and limitations

> **Scope:** This document describes what the v1.0 implementation protects, how
> those guarantees are enforced, and what it deliberately does not do. The
> independent audit and P0–P3 findings live in
> [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).

## 1. Protection model: observational, not preventive

The engine watches and analyzes; it does not interpose itself in the operating
system.

| Capability | v1.0 status |
|---|---|
| On-demand file scanning | Implemented |
| Process creation visibility | **After the fact** (Toolhelp32 diff, ~3 s) |
| PowerShell/Defender Event Log visibility | Read-only polling, if channels enabled |
| Process creation/termination **blocking** | Not implemented |
| File-system minifilter / real-time file blocking | Not implemented |
| Network filtering / DNS blocking | Not implemented |
| ELAM / boot-start / early-launch | Not implemented |
| Kernel driver | None |
| Disabling or reconfiguring Defender | Never |
| Replacing Defender as registered AV | No |

**Consequence:** this application is a security dashboard and AI-assisted
triage tool. Microsoft Defender remains the primary antivirus and the only
component that can preventively block threats on the machine. The UI says so
explicitly (`monitoringIsPreventive: false`) and never claims otherwise.

## 2. Assets and trust boundaries

**Assets**

- The user's files and process integrity.
- The OpenRouter API key.
- Local telemetry/history (paths, process names, command lines).
- Integrity of policy decisions and the audit trail.

**Trust boundaries**

1. **WebView/React → Tauri.** React is treated as a presentation layer. It can
   only call the frozen command surface; the CSP forbids remote script, and
   capabilities grant only `core:default` and `opener:default`. The AI key is
   never returned to React.
2. **Tauri → OS.** The desktop runs unprivileged. It never elevates itself,
   never installs drivers, and only uses documented user-mode APIs/commands.
3. **Engine → cloud AI.** Provider responses are untrusted input parsed with
   defaults. They cannot execute actions and cannot lower deterministic risk.
4. **Scanned files → parser.** Every file is hostile input: size caps, bounded
   reads, checked arithmetic, panic-free parsing, YARA timeouts, symlink/reparse
   rejection.
5. **Service (LocalService) → desktop (user).** The pipe uses an ACL that grants
   SYSTEM, Administrators and interactive users, with protocol versioning, frame
   size caps, rate limiting and strict request validation. The service does not
   expose arbitrary file operations beyond scan/quarantine/restore. The ACL
   grants every interactive user access to the service's machine-wide data
   directory — see the open P1 in
   [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (SEC-001).
6. **App → Defender.** Read-only query; the codebase contains no `Set-Mp*`,
   `Add-Mp*`, `Remove-Mp*`, `Disable*`, `TamperProtection` mutation or registry
   writes to Defender keys.

## 3. Enforced invariants

Each invariant has a test in the workspace.

| Invariant | Enforcement | Test |
|---|---|---|
| AI output can never produce `quarantine` | `PolicyEngine::evaluate_ai_only` caps at `Alert`; scan evaluation requires `deterministic` | `security-policy` gating matrix; `engine_pipeline::ai_output_can_never_quarantine` |
| Behavior-only events never quarantine | `evaluate_event` cap | policy tests |
| Quarantine requires auto-quarantine opt-in | `auto_quarantine_enabled` (default **false**) | policy tests |
| Quarantine requires deterministic hash/YARA basis | gating matrix; optional known-hash requirement | policy + scanner tests |
| AI cannot invoke destructive actions | `ai-decisions`/`ai-local` have no filesystem/process APIs; only the Tauri command layer performs user-requested file operations | cross-layer integration test |
| Cloud requests contain no usernames, absolute user paths or full hashes | `redact_state` before serialization; router only accepts redacted state | `ai-decisions` redaction tests; `engine_pipeline::cloud_state_redaction...` |
| API key never serialized/logged/returned to UI | `#[serde(skip_serializing)]`, redacted `Debug`, separate DPAPI blob, `configured: bool` only | ai-decisions tests; code review |
| Quarantine is reversible and collision-safe | copy + SHA-256 verification, hash-prefixed vault names, JSON sidecar, restore refuses overwrite | scanner quarantine tests; integration round-trip |
| Reparse points/symlinks are not followed into the vault or scanned as files | `symlink_metadata` + reparse attribute check | scanner tests |
| AI failure cannot stop scanning | router fails closed; caller falls back | ai-decisions provider failure tests |
| Defender is never modified | read-only `Get-MpComputerStatus`; no mutation cmdlets | code review/audit |

## 4. Quarantine design

`QuarantineVault` stores a **verified copy**:

1. Reject symlink/reparse source (`FILE_ATTRIBUTE_REPARSE_POINT`).
2. Require a regular file; hash with a capped reader.
3. Copy to `vault/<sha256-prefix>-<utc-timestamp>-<sanitized-name>.quarantine`
   (collision-safe, no path traversal).
4. Re-hash the copy and compare to the source hash.
5. Write a JSON sidecar with original path, hash, size, timestamps, reason,
   detection id, identity-verified flag.
6. Best-effort ACL hardening with `icacls`.

Restore writes to the recorded original path only if it does not already exist;
the vault copy remains until an explicit delete. Delete removes **only** the
vault copy and sidecar.

**Known limitation (P2):** v1.0 quarantine is *copy-only*. The original remains
executable at its original location. This is a deliberate trade-off: automatic
renaming/deletion of user files is a destructive action, and the product
invariant explicitly forbids AI-initiated destructive actions. Auto-quarantine
is off by default. Making quarantine an atomic, journaled *move* with rollback
is a v1.1 item; until then, treat quarantine as evidence preservation plus a
manual user workflow, not as isolation.

## 5. AI privacy and network behavior

- Cloud AI is disabled by default (`AiMode::Offline`). Enabling it requires an
  explicit toggle, an API key, and (separately) permission to include event
  state.
- Redaction before any provider call:
  - absolute user paths → file name only,
  - usernames → `<user>`,
  - full SHA-256 → 8-character prefix (for correlation only),
  - command lines → sanitized, credential-looking tokens removed,
  - environment/home directory fragments scrubbed.
- The request contains structured questions and redacted state; no file bytes
  and no raw paths.
- Bounded egress: 15 s timeout, retries with jitter, token bucket, daily USD
  ceiling, 10-minute cache. A provider failure returns a deterministic-only
  result.
- Provider health/usage is stored locally. No telemetry is uploaded by the app
  itself; there is no analytics endpoint.
- Cost/usage is recorded per model; the UI displays it. Limits are per-process
  and reset on restart (documented limitation).

## 6. Secret storage

- Windows DPAPI (`CryptProtectData`, user scope, `CRYPTPROTECT_UI_FORBIDDEN`).
- The protected blob is stored in SQLite under `ai.apiKeyProtected`; the config
  JSON deliberately omits the key.
- Decryption happens only in the Tauri process, only when a provider request is
  built. The plaintext key lives in process memory for the request lifetime and
  is never written to logs or errors (error scrubbing).
- Unpackaged builds have the same DPAPI protection (user-bound); there is no
  machine-wide key.

## 7. Least privilege and Windows hardening

- Desktop runs at medium integrity (not elevated). The MSIX uses
  `runFullTrust` (required by Tauri) but no broadFileSystemAccess or other
  restricted capabilities.
- Service runs as `NT AUTHORITY\LocalService`, manual start, separate installer.
  Its data directory is under `%ProgramData%`; the pipe ACL grants SYSTEM,
  Administrators and interactive users (see SEC-001 in
  [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md)).
- No driver, no service injection, no DLL search-path manipulation, no
  `CREATE_SUSPENDED` process manipulation.
- Child processes (PowerShell for Authenticode/Defender, `reg.exe` for version)
  are launched with `CREATE_NO_WINDOW`, bounded output (1 MiB), hard timeouts and
  kill-on-expiry. Commands are fixed strings; no user data is interpolated into
  a shell.
- Tauri CSP: `default-src 'self'`, no remote script, no `unsafe-eval`, IPC and
  asset protocols only; `object-src 'none'`, `frame-ancestors 'none'`.
- Tauri capabilities: `core:default`, `opener:default` only.

## 8. Supply chain

- Versions pinned in the workspace (`Cargo.toml`, `Cargo.lock`,
  `package-lock.json`): YARA-X 1.21.0, Tauri 2, windows 0.62.2, React 19, Fluent
  UI 9, Vite 7.
- No git dependencies; all crates are crates.io releases.
- MSIX signing uses a development certificate; production requires a trusted
  code-signing certificate and matching `Identity/Publisher` (see
  [PACKAGING.md](PACKAGING.md)).
- The AI API key is not stored in the repository; no `.env` is read.

## 9. Logging and local data

- `%LOCALAPPDATA%\AiAntivirus\` (desktop) or `%ProgramData%\AiAntivirus\`
  (service) contains SQLite, quarantine copies and sidecars.
- Logs are local (`tracing` to stderr in v1.0). They do not include API keys;
  event records may include file paths, which is why telemetry stays local by
  default.
- Retention is configurable; pruning deletes old events and scan results.
- No analytics, crash upload or remote logging exists.

## 10. Residual risks and limitations

| ID | Severity | Limitation |
|---|---|---|
| L1 | High | No preventive blocking; threats can execute before detection. |
| L2 | Medium | Process polling can miss short-lived processes between snapshots. |
| L3 | Medium | Event Log coverage depends on channels being enabled; PowerShell script-block logging is not enabled automatically. |
| L4 | Medium | Quarantine is copy-only and does not remove the original (P2 above). |
| L5 | Medium | Authenticode/Defender checks depend on PowerShell; failures degrade to `unavailable`. |
| L6 | Low | AI probabilities are uncalibrated; thresholds are defaults, not measured accuracy. |
| L7 | Low | NPU is detected but not used; local model is a deterministic mock. |
| L8 | Low | Rate/cost limits and cache are per-process, not machine-wide. |
| L9 | Low | The service's stream subscription is acknowledged but push streaming is not part of the v1.0 pipe contract; clients poll `ListEvents`. |
| L10 | Low | MSIX cannot register the service; 24/7 monitoring requires a separate installer and admin rights. |
| L11 | High | **Open P1:** the optional background service's named pipe grants every interactive user access to the machine-wide `%ProgramData%` store, so any local account can read shared telemetry and drive the service's file-copy primitive. Not present in the default embedded-engine deployment. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) SEC-001. |

## 11. Reporting a vulnerability

Do not open a public issue for an unfixed vulnerability. Provide a minimal
reproduction, affected version/commit, and impact to the maintainers. Do not
include live malware, API keys or personal data.
