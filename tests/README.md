# Tests and verification

## Automated suites

| Suite | Command | What it covers |
|---|---|---|
| Core contracts | `cargo test -p security-core` | scoring boundaries, serialization, quarantine contracts |
| Scanner/policy | `cargo test -p security-policy -p security-scanner` | YARA/PE/hash fixtures, gating matrix, AI-never-quarantine |
| Telemetry | `cargo test -p security-telemetry` | snapshot diffing, correlation windows/bands |
| Storage | `cargo test -p security-storage` | migrations, queries, health, quarantine |
| Windows integration | `cargo test -p windows-integration` | version parsing, DPAPI helpers, notification gating, execution context (pure) |
| Windows live checks | `cargo test -p windows-integration -- --ignored` | live version/token/Defender/DPAPI on the current machine |
| AI | `cargo test -p ai-decisions -p ai-local` | wire parsing, redaction, retries/limits/cache, routing |
| IPC/service | `cargo test -p security-ipc -p security-service` | framing, rate limits, service handler validation |
| End-to-end | `cargo test -p tauri-app --test engine_pipeline` | scan→policy→storage, correlation, quarantine, redaction |
| Frontend | `npm test` | command wrappers, settings merge, event ring buffer, quarantine workflow, pages in Tauri-unavailable state |
| Lint | `npm run lint` | ESLint flat config over `src/**` and `tests/frontend/**` (React Hooks rules are errors) |
| Typecheck/build | `npm run typecheck`, `npm run build` | TypeScript and production bundle |

`smoke.ps1` runs the full Rust + frontend sequence and prints a summary. It does
not install packages, sign MSIX or start the service — those are explicit,
documented manual steps.

## Packaging checks

`packaging-checks.ps1` verifies the static package inputs and reports runtime
toolchain availability honestly:

- `appxmanifest.xml` exists, identity is the preserved upstream identity,
  publisher and version are well-formed;
- required `Assets/*.png` and Tauri icons exist;
- `winapp` and a signing certificate are present (otherwise **SKIPPED**, never
  reported as passed);
- if an MSIX was produced, its name/version and signature are inspected.

## Manual checks (require a desktop session / administrator)

1. Launch the packaged app via `winapp run .\dist`; confirm the window opens,
   package family name is shown, and **Settings → Send test notification**
   produces a toast.
2. Unpackaged `npm run tauri dev`; confirm identity is reported unavailable and
   the notification test explains why, without crashing.
3. Run a manual scan of a benign folder; confirm progress, completion event and
   persisted results after restart.
4. Scan the EICAR test file in a disposable VM (never on a production machine);
   Defender may quarantine the fixture before the app reads it — that is an
   environment fact, not a test failure.
5. Install the service with `packaging/service-installer/install-service.ps1`
   as administrator, confirm `Get-Service AiAntivirusSecurityService`, then
   uninstall. This must be done in a VM or after a restore point.
6. On battery, confirm the AI Intelligence page shows a CPU route and the
   discrete GPU is not selected for routine monitoring.

## Environment notes

- PowerShell treats `cargo` stderr as an error stream; use `$LASTEXITCODE` for
  the real result. `smoke.ps1` does this.
- Tests never execute scanned content. The YARA test fixture is the inert
  EICAR pattern or a text download cradle.
- Windows Defender can block writing EICAR to disk; scanner unit tests treat
  that as a skip, and the cross-layer test uses a non-malware text fixture.
