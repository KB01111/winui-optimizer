# AI Antivirus

An AI-native security dashboard for **Windows 11 x64**. A deterministic Rust
scanner, process-correlation engine and policy layer do all security work; an
optional AI decision layer (`Jev 1.14`, `Mercury Decide`, `Mercury Decide
Free`) adds structured triage on top. The UI is React 19 + Fluent UI v9 inside a
Tauri 2 shell with MSIX package identity.

> **What this is / is not**
>
> This is a working v1.0 product, but it is **not a kernel antivirus and not a
> replacement for Microsoft Defender**. Process monitoring is *observational*
> (snapshot diffing and documented Event Log channels), not preventive process
> interception. Defender is queried **read-only**. There is no filter driver, no
> ELAM, no Tamper Protection bypass and no automated deletion of user files.
> See [Security model and limitations](docs/SECURITY.md).

---

## Feature summary

| Area | Implemented in v1.0 |
|---|---|
| On-demand scanning | Recursive/bounded file scan, SHA-256, Shannon entropy, panic-free PE parsing, import/section analysis, best-effort Authenticode, bundled YARA-X rules, extra-rule support, cancellation, progress events |
| Known-bad / detection | YARA-X 1.21 rules (EICAR, PowerShell download cradle, writable+executable PE), known-hash matching, deterministic risk score (0–100) |
| Process telemetry | Toolhelp32 snapshots every 3 s, parent/child correlation, unsigned/temp/LOLBin signals |
| Windows Event Log | Read-only polling of `Microsoft-Windows-PowerShell/Operational` (script block logging) and `Microsoft-Windows-Windows Defender/Operational` |
| Correlation | 15-minute correlation chains; behavior-only escalations are capped at *Alert* (never quarantine) |
| Policy | Deterministic gating matrix, stable rule ids, explicit reasons, human-approval flag |
| Quarantine | Copy-into-vault with SHA-256 verification, collision-safe names, symlink/reparse rejection, JSON sidecars, restore (refuses overwrite), explicit delete |
| AI decision layer | OpenRouter **Decisions API** (`POST /api/alpha/decisions`), Mercury Decide → Jev 1.14 escalation, redaction, rate limit, daily cost ceiling, 10-min cache, deterministic offline path |
| Local AI | Hardware detection (CPU/iGPU/dGPU/NPU/battery), routing plan, pluggable `LocalDecisionModel` seam; only the deterministic mock ships |
| Storage | SQLite (WAL), schema migrations v1→v2, events, correlations, scans, results, detections, decisions, quarantine, settings, provider health |
| Dashboard | Overview, Live activity, Threat intelligence, Scan center, AI intelligence, Quarantine, Settings (Fluent 2 dark theme) |
| Windows integration | MSIX package identity, toast notifications (identity-gated), OS version, execution context, DPAPI key storage, read-only Defender status |
| Background service | Standalone `AiAntivirusSecurityService` (LocalService, named pipe, scheduled scans) for monitoring while the UI is closed |
| Packaging | Tauri NSIS installer + upstream winappCli MSIX flow |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  React 19 + Fluent UI v9 dashboard (src/)                            │
│  Tauri IPC only — no API keys, no direct filesystem access           │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ invoke / events
┌───────────────────────────────▼──────────────────────────────────────┐
│  Tauri shell + embedded engine (src-tauri/)                          │
│  AppState · commands · notifications · DPAPI-protected AI config     │
└───────┬───────────────────────┬───────────────────────┬──────────────┘
        │                       │                       │
┌───────▼────────┐   ┌──────────▼─────────┐   ┌─────────▼────────────┐
│ security-core  │   │ security-scanner   │   │ ai-decisions         │
│ contracts,     │   │ SHA-256, PE, YARA, │   │ OpenRouter Decisions │
│ scoring        │   │ Authenticode,vault │   │ Mercury/Jev, router  │
└───────┬────────┘   └──────────┬─────────┘   └─────────┬────────────┘
        │                       │                       │
┌───────▼────────┐   ┌──────────▼─────────┐   ┌─────────▼────────────┐
│ security-      │   │ security-policy    │   │ ai-local             │
│ storage        │   │ deterministic      │   │ hardware + routing   │
│ SQLite         │   │ gating matrix      │   │ + model seam         │
└────────────────┘   └────────────────────┘   └──────────────────────┘
        ▲                       ▲
┌───────┴───────────────────────┴──────────────────────────────────────┐
│ security-telemetry: Toolhelp32 snapshots, Event Log, correlation      │
│ windows-integration: identity, Defender (read-only), DPAPI, toasts    │
└──────────────────────────────────────────────────────────────────────┘

Optional 24/7 path:
services/security-service  ← named pipe →  security-ipc  →  desktop app
```

Detailed component and data-flow documentation: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Frozen API contracts: [docs/CONTRACTS.md](docs/CONTRACTS.md).

### Decision flow

1. **Deterministic evidence** — hash, YARA, PE features, signal weights, process
   correlation. This always runs and is the only source of quarantine authority.
2. **AI eligibility gate** — only files/events above the investigation threshold
   and only when the user enabled cloud AI.
3. **Mercury Decide** — structured questions over a **redacted** state.
4. **Deterministic policy** — AI result may raise the outcome to *Alert*, never
   to *Quarantine*.
5. **Jev 1.14 escalation** — only when the primary answer is uncertain or
   high-impact. Failure fails closed to deterministic-only.
6. **Final policy** — stable rules and reasons. Automatic quarantine is
   opt-in, off by default, and requires a deterministic hash/YARA basis.

The full pipeline stays functional with AI disabled or no network.

## Repository layout

```
src/                     React/Fluent UI dashboard
src-tauri/               Tauri shell, commands, embedded engine, integration tests
crates/
  security-core/         Domain contracts, scoring, invariants
  security-scanner/      Hashing, PE, YARA-X, Authenticode, quarantine vault
  security-policy/       Deterministic policy engine
  security-storage/      SQLite storage + migrations
  security-telemetry/    Process snapshots, Event Log, correlation
  ai-decisions/          Provider traits, OpenRouter Decisions API, router
  ai-local/              Hardware detection and local-model routing seam
  windows-integration/   Package identity, Defender, DPAPI, notifications
  security-ipc/          Framed named-pipe protocol
services/security-service/  Standalone Windows service binary
packaging/               Service installer scripts
tests/                   Additional cross-cutting tests and smoke scripts
docs/                    Architecture, security, packaging, attribution, contracts
.claude/agents/          Project subagent definitions used during development
```

This repository was extracted from
[`microsoft/winappCli` `samples/tauri-app/`](https://github.com/microsoft/winappCli)
rather than forked. The sample stays at the repository root **on purpose**, so
the winappCli `appxmanifest.xml`, `Assets/`, and package identity paths keep
working. Attribution is in [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).

## Requirements

- Windows 11 x64 (Windows 10 1809+ is the manifest minimum, untested)
- Microsoft Defender enabled (the app does not disable or reconfigure it)
- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/):
  WebView2, Rust stable (1.85+; verified with 1.95.0), MSVC build tools
- Node.js 20+ (verified with 24.11.1) and npm 10+
- Optional MSIX tooling: `winget install Microsoft.winappcli --source winget`

## Quick start (development)

```powershell
npm install
npm run tauri dev
```

This starts Vite on `http://localhost:1420` and the Tauri window. The app runs
**unpackaged** in dev: identity-dependent features (toasts, package family name)
report that identity is unavailable instead of failing. Defender status is a
read-only PowerShell query.

Faster UI-only iteration:

```powershell
# terminal 1
cargo run -p tauri-app

# terminal 2
npm run dev
```

`npm run dev` alone renders the explicit **“Tauri runtime unavailable”** state;
the dashboard never fabricates backend data.

### With MSIX identity (notifications)

```powershell
npm run tauri:dev:withidentity
```

Requires `winapp` on `PATH` and a dev certificate (`winapp cert generate
--if-exists skip`). The upstream sample package identity is preserved:
`Name="tauri-app"` / `Publisher="CN=nikolame"`. Only the display name is
re-branded. This is deliberate — changing `Identity`/`Publisher` requires a
matching re-signed certificate and would break the extracted sample's identity
and notification integration.

## The security engine

- **Scanner** (`security-scanner`): bounded reads (default 128 MiB per file,
  512 MiB total, 5 s YARA timeout), SHA-256 with capped hashing, Shannon
  entropy, PE parsing with checked reads (MZ/PE/COFF/optional headers, sections,
  imports, .NET flag), best-effort Authenticode via a bounded read-only
  PowerShell query, YARA-X rules compiled from `rules/default.yar` at startup.
  Reparse points/symlinks are rejected; scan jobs are cancellable.
- **Scoring** (`security-core`): every signal has an explicit weight; scores are
  clamped to `[0, 100]` and NaN/∞ are sanitized. Risk levels: low, medium, high,
  critical.
- **Policy** (`security-policy`): produces `allow`, `observe`, `investigate`,
  `alert`, or `quarantine` with `matched_rules`, `requires_human_approval`,
  `quarantine_allowed`, and `deterministic`. Invariants:
  - AI output alone can never produce `quarantine`.
  - Event/behavior evaluation is capped at `alert`.
  - Quarantine requires auto-quarantine enabled **and** a deterministic
    hash/YARA basis; known-hash requirement can be enforced.
  - The algorithm matrix is unit-tested (boundaries 89.9/90.0 included).
- **Telemetry** (`security-telemetry`): process snapshots via Toolhelp32,
  signed/unsigned and path heuristics, parent correlation, Event Log reads.
  Monitoring is observational; it does not block process creation.
- **Quarantine** (`security-scanner::QuarantineVault`): copy-only isolation into
  `%LOCALAPPDATA%\AiAntivirus\quarantine` (desktop) or
  `%ProgramData%\AiAntivirus\quarantine` (service), SHA-256 verified,
  collision-safe file names, JSON sidecars, `icacls` hardening best effort.
  Restore is explicit and refuses to overwrite an existing destination. **v1.0
  never deletes the original file**; automatic quarantine remains off by
  default and copy-only by design.

### Monitoring mode

- **Embedded** (default): runs inside the Tauri process while the UI is open,
  unprivileged.
- **Service** (optional): `AiAntivirusSecurityService` runs as
  `NT AUTHORITY\LocalService`, owns the same engine, supports scheduled scans,
  and exposes a framed named-pipe protocol. Start type is **manual** by default.
  MSIX cannot register services, so the service ships as a separate installer
  component. See [docs/PACKAGING.md](docs/PACKAGING.md).

## AI decision layer

OpenRouter's **Decisions API**, not chat completions:

```
POST https://openrouter.ai/api/alpha/decisions
{ "model": "...", "state": {...}, "questions": { "verdict": { "type": "choice", ... }, ... } }
```

Supported models:

| Role | Model |
|---|---|
| Primary triage | `inception/mercury-decide` |
| Free tier | `inception/mercury-decide:free` |
| Escalation | `typesafe/jev-1.14` |

- **Opt-in**: cloud AI is off by default (`AiMode::Offline`). Enable it in
  **Settings → AI intelligence** and enter an OpenRouter API key.
- **Key handling**: the key is protected with Windows DPAPI
  (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`) and stored in SQLite. It is
  never serialized into the AI config, never emitted in events/logs, and never
  reaches the React layer. The backend reports only `configured: true/false`.
- **Privacy**: every request passes `redact_state` first. Usernames, absolute
  user paths (reduced to file names), command lines and full SHA-256 hashes
  (reduced to an 8-character prefix) never leave the machine. Cloud state sharing
  has an explicit separate opt-in; the router does not send raw paths.
- **Resilience**: 15 s timeout, bounded retries with backoff/jitter, token-bucket
  rate limit, daily USD ceiling, in-memory 10-minute cache, `FailedClosed →
  deterministic_only`. Tests use fixture/loopback servers only; no live API key
  is required or bundled.
- **Calibration**: model probabilities are raw provider output, explicitly
  labelled *uncalibrated*. Confidence thresholds (0.7 escalation, 15.0
  investigation) are policy defaults, not measured accuracy.

### Local AI and hardware

`ai-local` detects CPU, integrated GPU, discrete GPU presence/state, memory,
battery/AC and NPU hints. `select_route` prefers CPU on battery and never wakes
a dGPU for routine monitoring; AVX2/AVX-512 and discrete GPU plans require an
actual runtime. The NPU is detected diagnostically but is **not** selected in
v1.0 because there is no validated runtime probe. Only the deterministic local
mock model ships; `LocalDecisionModel` is the seam for a future ONNX/DirectML
model.

## Dashboard

Seven Fluent UI pages:

- **Overview** — protection summary, engine state, Defender (read-only), service,
  identity, storage counts, quick scan targets.
- **Live activity** — streaming events, severity filters, correlation chains,
  event detail with policy decision and AI evidence.
- **Threat intelligence** — detections, risk scores, rule/hash evidence,
  stored-event search with server-side pagination.
- **Scan center** — start/cancel scans, live progress, results.
- **AI intelligence** — provider status/health, routing, cost/latency, model
  configuration, connection test.
- **Quarantine** — quarantined-file vault: manual quarantine, per-file
  restore, and explicit deletion of the vault copy.
- **Settings** — privacy, notifications, scanning limits, policy thresholds,
  AI configuration, settings persistence.

The UI invokes only the Tauri command contract in
[docs/CONTRACTS.md](docs/CONTRACTS.md). No mock data is shown when the backend is
unavailable.

## Packaging

### NSIS installer (Tauri)

```powershell
npm run tauri build
```

Output: `src-tauri/target/release/bundle/nsis/*.exe`. This is a per-user
installer without MSIX identity (toasts unavailable).

### MSIX (winappCli, identity + toasts)

```powershell
npm run pack:msix
```

Requires `winapp`. Stages `dist/tauri-app.exe` and packages/signs with
`devcert.pfx`. First install the certificate as administrator:
`winapp cert install .\devcert.pfx`. See [docs/PACKAGING.md](docs/PACKAGING.md)
for the full identity/certificate/service notes.

## Tests and verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run typecheck
npm run lint
npm test
npm run build
npm run tauri build
```

Verified results for this repository (see the final report for the exact run):

| Check | Result |
|---|---|
| `cargo test -p security-core` | 4 passed |
| `cargo test -p security-storage` | 5 passed |
| `cargo test -p security-telemetry` | 4 passed |
| `cargo test -p windows-integration` | 47 passed, 2 ignored (live checks) |
| `cargo test -p security-policy -p security-scanner` | 19 + 29 passed |
| `cargo test -p ai-decisions -p ai-local` | 76 + 23 passed |
| `cargo test -p tauri-app --test engine_pipeline` | 5 passed |
| Frontend | see `docs/VERIFICATION.md` |
| Service | see `docs/VERIFICATION.md` |

Windows-only checks that cannot run here are marked **unverified**, never
reported as passed. YARA timeout granularity is ~1 s (upstream heartbeat), so a
5 s timeout can overshoot by up to ~1 s.

## Security limitations (short form)

- No preventive protection: no process blocking, file-system minifilter, ELAM,
  network filtering, or boot-time protection. Defender remains the primary AV.
- No live malware execution/detonation; detections are static/heuristic plus
  telemetry correlation.
- Authenticode and Defender queries depend on PowerShell and the Defender
  module; failures are surfaced as unavailable, not silently trusted.
- Quarantine is copy-only in v1.0 and auto-quarantine is off by default.
- Cloud AI is advisory, redacted and opt-in; it can never quarantine or delete.
- Event Log coverage depends on channels being enabled by policy (PowerShell
  script block logging is not enabled by this app).
- Service installation is separate from the MSIX and requires administrator
  rights; the app does not self-elevate.
- NPU acceleration is detection-only, not active inference, in v1.0.
- **Open P1:** the optional background service's named pipe grants every
  interactive user access to the machine-wide `%ProgramData%` store, so any
  local account can read shared telemetry and drive the service's file-copy
  primitive. The default embedded-engine deployment is unaffected. Tracked in
  [docs/SECURITY.md](docs/SECURITY.md) (L11) and
  [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) (SEC-001).

Full threat model and audit: [docs/SECURITY.md](docs/SECURITY.md) and
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

## Attribution & license

Extracted from Microsoft's `winappCli` Tauri sample (MIT). Bundled components:
Tauri 2, Fluent UI React v9, YARA-X 1.21, SQLite, React 19, Vite. Full notices
in [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md). Project code is MIT — see
[LICENSE](LICENSE).
