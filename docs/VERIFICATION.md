# Verification results

> **Scope:** this document records what was **actually executed** in this
> repository and what it produced. Every number below comes from a real run of
> the stated command. Checks that could not be executed in this environment are
> listed as **not verified** — they are never reported as passing.
>
> Related: [ARCHITECTURE.md](ARCHITECTURE.md) · [SECURITY.md](SECURITY.md) ·
> [SECURITY_AUDIT.md](SECURITY_AUDIT.md) · [PACKAGING.md](PACKAGING.md) ·
> [../tests/README.md](../tests/README.md)

## 1. How to reproduce

```powershell
# Everything, with a pass/fail summary and real exit codes
powershell -ExecutionPolicy Bypass -File tests\smoke.ps1

# Or step by step
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run typecheck
npm run lint
npm test
npm run build
```

`tests/smoke.ps1` prints the real `$LASTEXITCODE` of every step and exits `1`
if any step failed. It does not install packages, sign an MSIX or register the
Windows service — those are explicit manual steps listed in section 6.

## 2. Environment used for this run

| Item | Value |
|---|---|
| OS | Windows 11 x64 |
| Rust toolchain | 1.95.0 (cargo 1.95.0) |
| Node.js | 24.x (npm 10+) |
| WebView2 | installed (required by the Tauri shell) |
| `winapp` CLI | **not installed** — MSIX packing and packaged-toast checks are **not verified** |
| Administrator shell | not used — service installation and live Defender queries are **not verified** |

## 3. Automated results

Executed on the environment in section 2.

### 3.1 Rust — `cargo test --workspace --no-fail-fast`

Exit code **0**. **260 tests passed, 0 failed, 2 ignored.**

| Target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `ai-decisions` (unit) | 76 | 0 | 0 |
| `ai-local` (unit) | 23 | 0 | 0 |
| `security-core` (unit) | 4 | 0 | 0 |
| `security-ipc` (unit) | 19 | 0 | 0 |
| `security-policy` (unit) | 19 | 0 | 0 |
| `security-scanner` (unit) | 29 | 0 | 0 |
| `security-service` (unit) | 12 | 0 | 0 |
| `security-service` — `service_engine` | 7 | 0 | 0 |
| `security-service` — `service_pipe` | 1 | 0 | 0 |
| `security-storage` (unit) | 5 | 0 | 0 |
| `security-telemetry` (unit) | 4 | 0 | 0 |
| `tauri-app` — `engine_pipeline` | 6 | 0 | 0 |
| `tauri-app` — `security_invariants` | 8 | 0 | 0 |
| `windows-integration` (unit) | 47 | 0 | 0 |
| `windows-integration` — `live_windows` | 0 | 0 | 2 |
| **Total** | **260** | **0** | **2** |

The two ignored tests are the live Windows checks (`live_windows.rs`). They are
`#[ignore]`d by design because they assert against the real machine state and
must be requested explicitly:

```powershell
cargo test -p windows-integration -- --ignored
```

### 3.2 Frontend

| Command | Result |
|---|---|
| `npm run typecheck` | **PASS** — `tsc --noEmit`, no errors |
| `npm run lint` | **PASS** — ESLint 9 flat config, 0 errors (advisory warnings only, see below) |
| `npm test` | **PASS** — see the test map in section 7 |
| `npm run build` | **PASS** — `tsc --noEmit && vite build` |

The lint configuration is intentionally strict about the rules that catch real
bugs (`react-hooks/rules-of-hooks`, `react-hooks/exhaustive-deps`,
`react-hooks/purity`, `react-hooks/refs`, `@typescript-eslint/no-explicit-any`)
and reports the React Compiler advisory rules
(`react-hooks/set-state-in-effect`) as **warnings**. Those warnings are the
standard "fetch on mount" and "reset derived state when a filter changes"
effects, which this dashboard uses deliberately and pairs with explicit
loading/error state.

### 3.3 Formatting and lints (Rust)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | **PASS** — exit 0, no diffs |
| `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** — exit 0, no warnings |

Both gates were **red** when this work started (rustfmt drift in ~100
locations across 15 files, and 8 clippy lints). Both were fixed; see
[`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) SEC-007 and the remediation table in
section 10.

`cargo build --release --workspace` also exits 0.


## 4. Packaging checks

`powershell -ExecutionPolicy Bypass -File tests\packaging-checks.ps1` verifies
the static package inputs and reports toolchain availability honestly:

- `appxmanifest.xml` exists and is well formed;
- the upstream identity (`Name="tauri-app"`, `Publisher="CN=nikolame"`) and
  version `1.0.0.0` are preserved;
- the package architecture is `x64`;
- the required `Assets/*.png` files and Tauri icons exist;
- `winapp` is present — otherwise the step is reported as **SKIPPED**, never
  as passed;
- `devcert.pfx` exists, its subject matches the manifest publisher and it is
  not expired;
- if an MSIX artifact exists, its name/version and Authenticode signature are
  inspected.

<!-- PACKAGING -->

## 5. Known-unverified items

These require tooling or privileges that were not available in the run
recorded above. They are listed so the gap is explicit rather than implied.

| Item | Why it is unverified | How to verify |
|---|---|---|
| MSIX packing and installation | `winapp` CLI is not installed on this machine | `winget install Microsoft.winappcli --source winget`, then `npm run pack:msix` |
| Packaged toast notifications | require MSIX package identity | `npm run tauri:dev:withidentity`, then *Settings → Send test notification* |
| Windows service install/uninstall | requires an elevated shell | `packaging\service-installer\install-service.ps1` as administrator |
| Live Defender status query | requires the Defender module and a desktop session | *Overview → Microsoft Defender* in the running app |
| Live DPAPI round-trip | requires a real user profile | `cargo test -p windows-integration -- --ignored` |
| YARA timeout precision | the upstream heartbeat granularity is ~1 s, so a 5 s timeout can overshoot by up to ~1 s | measured in a release build on a loaded machine |

## 6. Manual checks (desktop session / administrator)

1. `npm run tauri dev` — the window opens; identity-dependent features report
   "unavailable" instead of failing; Defender status resolves read-only.
2. `npm run tauri:dev:withidentity` — the package family name is shown and
   *Settings → Send test notification* produces a toast.
3. Run a manual scan of a benign folder — progress, a `scan_completed` event
   and persisted results survive a restart.
4. Scan the EICAR test file **in a disposable VM only**. Defender may quarantine
   the fixture before the app reads it; that is an environment fact, not a
   test failure.
5. Quarantine a file from *Scan center → Results* or the *Quarantine* page —
   the vault copy appears, *Restore* returns the file to its original path and
   refuses to overwrite, and *Delete* removes only the vault copy.
6. Install and uninstall the service with
   `packaging\service-installer\install-service.ps1` — do this in a VM or
   after taking a restore point.
7. On battery, the *AI intelligence* page shows a CPU route and the discrete
   GPU is not selected for routine monitoring.

## 7. Frontend test map

| File | Covers |
|---|---|
| `tests/frontend/commands.test.ts` | Tauri command wrappers: argument shapes, camelCase payloads, error normalisation, and that no command is issued outside a Tauri webview |
| `tests/frontend/app.test.tsx` | App shell: every navigation tab renders its real-data empty state |
| `tests/frontend/overview.test.tsx` | Overview: Defender and engine values come from `get_system_status`; backend errors are surfaced instead of invented data |
| `tests/frontend/settings.test.tsx` | Settings: policy defaults, persisted values, write-only API key |
| `tests/frontend/filters.test.ts` | Event filtering: severity, minimum severity, kind, free-text search, counters and sorting |
| `tests/frontend/ringBuffer.test.ts` | Bounded live-event ring buffer |
| `tests/frontend/quarantine.test.tsx` | Quarantine workflow: empty state, record rendering, restore, confirmed delete, error surfacing |
