# Architecture

This document describes the v1.0 system design: process model, crate
responsibilities, data flow, persistence, IPC, concurrency limits and
performance decisions. The frozen public API surface is in
[`CONTRACTS.md`](CONTRACTS.md).

## 1. Goals and non-goals

**Goals**

- Deterministic, auditable security decisions that work with no network and no
  AI provider.
- AI as a bounded *decision layer*: structured questions, redacted state,
  advisory output, deterministic policy override.
- A native Windows 11 experience: Fluent UI, MSIX identity, toasts, Defender
  awareness, DPAPI-protected secrets.
- Safe by construction: no destructive AI actions, no kernel components, no
  Defender modification, least privilege, reversible quarantine.
- Low idle cost: event-driven UI, conservative polling, bounded queues.

**Non-goals (v1.0)**

- Replacing Defender or registering as an AV provider.
- Preventive blocking (`PsSetCreateProcessNotifyRoutine`, minifilters, ELAM,
  network filtering).
- Malware execution/detonation or cloud file upload.
- Kernel drivers, boot-time protection, tamper protection.
- A production on-device neural model (the seam and routing exist; the runtime
  does not ship).

## 2. Process model

### 2.1 Desktop process (default)

`src-tauri` is an unprivileged Tauri 2 process. It owns:

- the embedded engine (`src-tauri/src/engine.rs`),
- the Tauri command surface and event emitter,
- the dashboard (WebView2),
- SQLite at `%LOCALAPPDATA%\AiAntivirus\security.db`,
- quarantine at `%LOCALAPPDATA%\AiAntivirus\quarantine`.

The embedded engine is deliberately not elevated. It can scan user-readable
files, read the user's process list, query Defender read-only and poll Event Log
channels the user can read. It cannot scan protected system files.

### 2.2 Background service (optional, 24/7)

`services/security-service` is a standalone Windows service binary
(`AiAntivirusSecurityService`). It runs as `NT AUTHORITY\LocalService` with a
**manual** start type by default and owns the same engine crates. Data moves to
`%ProgramData%\AiAntivirus` (override with `AI_ANTIVIRUS_DATA_DIR` for tests).

Because MSIX packages cannot register services, the service is distributed by a
separate installer component (`packaging/service-installer`) and is *not* part
of the MSIX. The desktop app detects it through the named pipe and shows
service state; it never starts, stops or reconfigures the service silently.

### 2.3 IPC

`security-ipc` implements a length-prefixed JSON protocol over
`\\.\pipe\ai-antivirus-security`:

- 4-byte little-endian length header, 1 MiB frame cap,
- `VersionedRequest { version, request }` with protocol version 1,
- request variants: `Ping`, `GetStatus`, `ScanPath`, `CancelScan`, `ListEvents`,
  `GetEvent`, `ListQuarantine`, `QuarantineFile`, `RestoreQuarantine`,
  `Subscribe`,
- response variants: `Pong`, `Status`, `ScanAccepted`, `Cancelled`, `Events`,
  `Event`, `Quarantine`, `QuarantineRecord`, `Restore`, `Subscribed`, `Error`,
- server-side rate limiter (burst 64, 32 req/s), bounded request size, sanitized
  error codes, owner-only pipe ACL.

The desktop UI currently uses the embedded engine for its live data. The service
status command performs a bounded `Ping` (800 ms) and reports version/uptime; a
full UI switchover to the service is a v1.1 item.

## 3. Crate map

| Crate | Responsibility | Platform code |
|---|---|---|
| `security-core` | Domain types, IDs, severity/risk scoring, policy/decision/quarantine contracts | None |
| `security-scanner` | SHA-256, entropy, PE parsing, YARA-X rules, Authenticode, recursive scan, quarantine vault | Best-effort PowerShell for Authenticode |
| `security-policy` | Deterministic gating matrix, stable rules, reasons | None |
| `security-telemetry` | Process snapshots, Event Log queries, correlation engine | Toolhelp32, EvtQuery/EvtRender |
| `security-storage` | SQLite schema, migrations, queries, health rows | SQLite only |
| `ai-decisions` | Provider trait, OpenRouter Decisions API, router, redaction, limits | HTTP |
| `ai-local` | Hardware detection, battery/AC routing, local model registry/seam | Win32/DXGI/registry |
| `windows-integration` | Package identity, OS version, execution context, Defender read-only, notifications, DPAPI | WinRT/Win32 |
| `security-ipc` | Named-pipe framing and protocol | Win32 pipes |
| `tauri-app` | Commands, state, embedded engine, UI bridge | Tauri |
| `security-service` | Service engine, schedules, pipe server | Windows service |

`security-core` has no I/O and is used by every layer.

## 4. Data flow

### 4.1 On-demand scan

```
UI invoke scan_path({path, recursive})
  → validate path (exists, UTF-8 display)
  → storage.insert_scan_job(Queued)
  → worker task:
      scanner.scan_path(root, recursive, cancel, progress)
        per file: symlink/reparse reject → metadata → size caps
                  → SHA-256 + entropy → YARA-X → PE parse
                  → best-effort Authenticode
                  → RiskSignals → RiskAssessment (0–100)
      storage.insert_scan_result(report)
      deterministic policy evaluate_scan(report, ai?)
      optional AI classify on top 3 reports (only cloud enabled)
      policy raise-to-alert only; quarantine gated + opt-in
      persist detection/policy/scan-completed events
      emit engine://scan-progress / engine://event
      toast if detections and notifications enabled
```

Progress is throttled to one update per 250 ms per job; the final state is
always persisted. Cancellation is an `AtomicBool` checked between files.

### 4.2 Continuous monitoring (embedded)

```
every 3 s (configurable 1–15 s):
  if monitoring disabled → skip
  ProcessMonitor.poll()
    Toolhelp32 snapshot → diff vs previous PIDs
      new process → SecurityEvent(ProcessCreated)
      exited      → SecurityEvent(ProcessExited)
  EventLogReader.poll(last_timestamp, 32)
    PowerShell/Operational (4104)
    Windows Defender/Operational
  for each event:
    CorrelationEngine.ingest(event) → chain events on score-band changes
    PolicyEngine.evaluate_event → capped at Alert
    storage.insert_event
    emit engine://event
```

This is **observational**: the app learns about processes after creation. It
cannot block them.

### 4.3 Correlation

`CorrelationEngine` groups events by process identity and correlation id within
a 15-minute window. It tracks signal categories (persistence, credential access,
ransomware behavior, network, obfuscation, startup write, temp execution,
LOLBin). When the accumulated band changes, it emits one `Correlation` event per
band to avoid storms. Correlation events are persisted and evaluated by policy.
Behavior-only findings can reach *Alert*; only scan evidence with a deterministic
hash/YARA basis can reach *Quarantine*.

### 4.4 AI decision routing

```
eligible event/file (score ≥ investigate threshold)
  → build_decision_state(event, assessment)
  → redact_state: paths→names, user→<user>, hash→8-char prefix,
                  command line sanitized
  → cache (10 min, keyed by FNV-1a of redacted state)
  → ProviderRouter.classify
       primary: Mercury Decide (choice/noul/score questions)
       if uncertain/high-impact: Jev 1.14 escalation
       failures: retry/backoff → cost/rate limits → deterministic fallback
  → DecisionResult (advisory, labelled uncalibrated)
  → PolicyEngine.evaluate_scan(report, Some(decision))
       AI can raise to Alert; never Quarantine
  → persist decision + AI event; UI can request classification on demand
```

Provider output is parsed field-by-field with sane fallbacks; malformed or
missing answers become `Unknown`/low confidence, never an implicit malicious
verdict. No AI path has a file operation.

## 5. Persistence

SQLite in WAL mode, foreign keys on, synchronous normal. Schema migrations are
versioned (`schema_migrations`) and applied in order:

- **v1**: `security_events`, `processes`, `process_relationships`, `files`,
  `scan_results`, `detections`, `decision_results`, `quarantine_records`,
  `scan_jobs`, `application_settings`, `provider_health`.
- **v2**: `security_events.description`.

Key indexes: event time/kind/severity/correlation/SHA, process pid/SHA,
result job/SHA, detection event/rule, decision event, quarantine status, job
started.

Retention is user-configurable (`storage.retentionDays`); pruning runs on
startup/scan completion, bounded batches. All queries used by the UI are
parameterized; event pages are capped (default 100, max 500).

## 6. Concurrency and backpressure

- Monitoring runs on one async loop; ticks never overlap.
- Scans run on Tauri's async runtime; each job has its own cancellation flag.
  Results are written as the scan proceeds, not accumulated in memory.
- Progress events are throttled per job (250 ms).
- The service uses a bounded queue (`EVENT_QUEUE_CAPACITY = 4096`) and drops
  oldest events with a counter when storage cannot keep up; persistence is
  batched (256 events) with a 250 ms fallback wakeup.
- AI requests are rate-limited and cost-limited; stale providers are skipped and
  health is exposed in the UI.
- Storage calls are short; no network or scanner work happens while holding
  engine locks. `parking_lot` mutexes are used for engine state, Tokio
  `RwLock` for the async AI service.

## 7. Performance design

- Event-driven UI (Tauri events + React state); polling is limited to the status
  snapshot and deliberately slow.
- Process polling default 3 s, clamps 1–15 s; process snapshots are cheap
  (Toolhelp32) and comparisons are incremental.
- No GPU work during routine monitoring. Hardware detection is cached 30 s and
  is diagnostic only; the discrete GPU is not initialized just to show a badge.
- Scanner streams files with capped buffers; YARA timeout 5 s; per-file size
  limit 128 MiB; scan batch size 32.
- AI is invoked only above threshold and limited to the top 3 files per scan,
  with cache and daily cost ceiling.
- Service event queue is bounded and lossy by design, with a dropped counter.

Measured figures (release, this machine) are recorded in
[`VERIFICATION.md`](VERIFICATION.md). Windows-specific runtime measurements that
could not be executed are explicitly marked unverified.

## 8. Windows integration and identity

- `appxmanifest.xml` is the upstream winappCli manifest. `Identity`
  (`tauri-app`, `CN=nikolame`) is intentionally unchanged so the extracted
  sample and its notification integration keep working. Display names are
  re-branded.
- Toast notifications use the upstream `ToastText02` XML approach and return
  `NoPackageIdentity` when unpackaged — never an exception or a fake success.
- Defender status is read-only `Get-MpComputerStatus` via a bounded
  `powershell.exe` process; no `Set-*` cmdlet exists anywhere in the codebase.
- Secrets: DPAPI `CryptProtectData`/`CryptUnprotectData` with
  `CRYPTPROTECT_UI_FORBIDDEN`. The AI key is stored separately from the
  serializable config.

## 9. Error handling

- Domain errors are typed (`StorageError`, `ScanError`, `TelemetryError`,
  `DecisionError`, `LocalAiError`, `IpcError`, `WindowsIntegrationError`).
- Every cross-boundary failure is surfaced as `unavailable` with a bounded
  reason, never silently swallowed or fabricated as healthy.
- AI failure fails closed to deterministic analysis.
- Scanner errors on individual files increment the job error count and never
  abort the whole scan.
- Poisoned locks are avoided by using `parking_lot`/Tokio primitives; engine
  startup propagates errors to Tauri setup.

## 10. Testing strategy

- **Unit**: scoring boundaries, policy matrix, PE parser (all truncations),
  YARA fixtures, quarantine collision/restore, storage migrations/queries,
  correlation window/bands, redaction, wire parsing, rate/cost/cache, routing.
- **Integration** (`src-tauri/tests/engine_pipeline.rs`): scanner→policy→
  storage, AI-never-quarantine, correlation timeline, quarantine round-trip,
  redaction of paths/users/full hashes.
- **Live Windows** (`crates/windows-integration/tests/live_windows.rs`,
  `#[ignore]`): version, token, Defender, DPAPI.
- **Frontend**: Vitest + Testing Library with explicit Tauri-unavailable state.
- **Manual**: packaged toast, MSIX install, service install/start/stop.

No test executes malware; fixtures are inert text/bytes.
