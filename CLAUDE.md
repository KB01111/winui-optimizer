# CLAUDE.md

Guidance for Claude Code (and any other coding agent) working in this
repository.

## What this project is

**AI Antivirus** — a security dashboard for Windows 11 x64. A deterministic
Rust scanner, process-correlation engine and policy layer do all security work.
An *optional* AI decision layer (OpenRouter Decisions API) adds advisory
triage on top. The UI is React 19 + Fluent UI v9 inside a Tauri 2 shell with
MSIX package identity.

It is **not** a kernel antivirus and **not** a replacement for Microsoft
Defender. Process monitoring is observational; Defender is queried read-only.
See `docs/SECURITY.md` for the full threat model.

## Read these first

| Document | Why |
|---|---|
| `docs/CONTRACTS.md` | **Frozen** API contract: domain types, crate public APIs, Tauri commands and events. Do not change a type or signature here without updating the orchestrator. |
| `docs/ARCHITECTURE.md` | Crate map, data flow, persistence, concurrency, performance. |
| `docs/SECURITY.md` | Threat model, limitations, residual-risk table. |
| `docs/SECURITY_AUDIT.md` | Severity-ranked findings from the independent reviewer. |

## Ground rules

- **All data shown in the UI must be real.** Empty states are acceptable; fake
  rows are not. When the backend is unavailable, say so explicitly.
- **The engine must work with no AI provider configured.** The AI layer is
  advisory and may never quarantine, delete or otherwise act destructively.
- **AI output can never trigger quarantine.** Only `security-policy` decides
  outcomes, from deterministic signals.
- **Never weaken Defender, Tamper Protection or existing Windows security.**
- **No `.unwrap()` in production paths** for untrusted input. Tests may unwrap.
- Crate `Cargo.toml` manifests are frozen. If a dependency is missing, report
  it instead of editing the root `Cargo.toml`.
- Nobody except the orchestrator edits `crates/security-core` after the
  contract is frozen.

## Subagents

Six project subagents live in `.claude/agents/`. Each owns a disjoint set of
paths — respect the ownership boundaries and coordinate through the
orchestrator when a change crosses them.

| Subagent | Owns |
|---|---|
| `security-dashboard` | `src/**`, `package.json`, `vite.config.ts`, `tsconfig*.json`, `index.html`, `vitest.config.ts`, `eslint.config.js`, `tests/frontend/**` |
| `security-engine` | `crates/security-policy/**`, `crates/security-scanner/**`, `tests/fixtures/**` |
| `ai-decision-engine` | `crates/ai-decisions/**`, `crates/ai-local/**`, `tests/fixtures/ai/**` |
| `windows-platform` | `crates/windows-integration/**`, `appxmanifest.xml`, `Assets/**`, `packaging/msix/**` |
| `windows-service` | `crates/security-ipc/**`, `services/security-service/**`, `packaging/service-installer/**`, `tests/integration/service_*.rs` |
| `security-qa` | `docs/SECURITY_AUDIT.md`, `tests/security/**` — **read-only reviewer; writes findings, never patches implementation** |

## Layout

```
src/                     React 19 + Fluent UI v9 dashboard
src-tauri/               Tauri shell, 26 commands, embedded engine
crates/security-core/    Domain contracts, scoring, invariants
crates/security-scanner/ Hashing, PE, YARA-X, Authenticode, quarantine vault
crates/security-policy/  Deterministic policy engine
crates/security-storage/ SQLite storage + migrations
crates/security-telemetry/ Process snapshots, Event Log, correlation
crates/ai-decisions/     OpenRouter Decisions API, router, redaction, limits
crates/ai-local/         Hardware detection, local-model routing seam
crates/windows-integration/ Identity, Defender (read-only), DPAPI, toasts
crates/security-ipc/     Framed named-pipe protocol
services/security-service/ Standalone Windows service binary
packaging/               Service installer scripts
tests/                   Cross-cutting tests, frontend tests, smoke scripts
docs/                    Architecture, security, packaging, audit, contracts
```

## Commands

```powershell
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p windows-integration -- --ignored   # live Windows checks

# Frontend
npm install
npm run typecheck
npm run lint
npm test
npm run build

# Everything, with a real pass/fail summary
powershell -ExecutionPolicy Bypass -File tests\smoke.ps1
```

## Conventions

- **Frontend:** Fluent UI v9 components before custom widgets. Dark theme by
  default. Keep lists bounded and virtualized. Typed command wrappers live in
  `src/api/commands.ts` and mirror `docs/CONTRACTS.md` exactly — never invoke
  a command that is not in the contract.
- **Rust:** `#![deny(unsafe_op_in_unsafe_fn)]` in platform crates. No panics on
  untrusted input — return typed errors instead.
- **Docs:** update the doc you invalidate. A referenced-but-missing document is
  a bug.
