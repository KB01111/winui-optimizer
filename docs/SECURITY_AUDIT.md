# Security audit — AI Antivirus v1.0

> **Status:** complete for the v1.0 workspace as of 2026-10-20.
> **Auditor:** the project's own `security-qa` reviewer role.
> **Related documents:** [`SECURITY.md`](SECURITY.md) (threat model, L1–L10
> residual-risk table), [`CONTRACTS.md`](CONTRACTS.md) (frozen API contract),
> [`PACKAGING.md`](PACKAGING.md) (deployment).

---

## 1. Scope and method

### 1.1 What this document is

This is a **self-audit by the project's own reviewer**. It is **not** an
independent third-party penetration test, and it does not claim to be one. The
reviewer is the same agent team that wrote the code, which creates a known
blind spot: findings are limited to what a source-level reader notices, and no
external attacker modelling, red-team exercise, dynamic analysis, binary
analysis or on-device exploitation was performed. The findings below should be
read as "issues a careful reviewer found by reading the code", not as
"issues an adversary would find".

The reviewer deliberately **did not** modify any implementation file. The only
artefacts produced by this audit are:

- this document, and
- `src-tauri/tests/security_invariants.rs` (new Rust integration tests) plus
  `tests/security/README.md` (index of the security regression tests).

### 1.2 Date and environment

| Item | Value |
|---|---|
| Audit date | 2026-10-20 |
| Platform | Windows, `win32` |
| Toolchain | `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`, `rustc 1.95.0 (59807616e 2026-04-14)`, `rustfmt 1.9.0-stable` |
| Frontend tooling | `node v24.11.1`, `npm 11.15.0` |
| Repository HEAD | `7b75b54c5870428db7f7e912acf99fcabd92e7e6` ("Initial commit: Tauri app with winapp CLI package identity and MSIX setup") |
| Working tree | Dirty — the v1.0 workspace is largely uncommitted (`git status`: all of `crates/`, `services/`, `docs/`, `src-tauri/tests/` untracked) |

**Concurrency caveat.** Other agents were actively editing the workspace while
this audit ran. Two gates changed state during the audit window: the Rust
formatting gate and the frontend type-check/build gate were **red on the first
pass and green on the final pass** (both fixes landed from another agent's
edits, not from this audit — see §2.1, §2.4 and SEC-008). The clippy gate was
red on both passes. Every gate was therefore run **twice**; §2 records both
observations and the final pass is authoritative for the current tree. The
security findings themselves (SEC-001 … SEC-011) were re-verified against the
final tree and are unaffected by the concurrent edits, except where a line
number is quoted, which is stated as of the final pass.

### 1.3 Reviewed artefacts

Crates and key files read in full or in the relevant part:

| Area | Files reviewed |
|---|---|
| Desktop shell | `src-tauri/src/lib.rs`, `src-tauri/src/engine.rs`, `src-tauri/src/ai_service.rs`, `src-tauri/src/types.rs`, `src-tauri/src/notify.rs`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`, `src-tauri/Cargo.toml` |
| Deterministic policy | `crates/security-policy/src/lib.rs`, `crates/security-policy/src/tests.rs` |
| Scanner / vault | `crates/security-scanner/src/lib.rs`, `crates/security-scanner/src/quarantine.rs`, `crates/security-scanner/src/hashing.rs`, `crates/security-scanner/src/authenticode.rs`, `crates/security-scanner/src/tests.rs` |
| Shared types | `crates/security-core/src/lib.rs` |
| Storage | `crates/security-storage/src/lib.rs` |
| Telemetry | `crates/security-telemetry/src/lib.rs` |
| AI decision layer | `crates/ai-decisions/src/lib.rs`, `.../types.rs`, `.../error.rs`, `.../redaction.rs`, `.../router.rs`, `.../providers/openrouter.rs`, `.../transport.rs`, `.../provider_tests.rs` |
| Local AI | `crates/ai-local/src/lib.rs` (routing rules only) |
| Windows integration | `crates/windows-integration/src/lib.rs`, `.../dpapi.rs`, `.../defender.rs`, `.../process_util.rs`, `.../version.rs` |
| IPC | `crates/security-ipc/src/lib.rs`, `.../pipe.rs`, `.../pipe/windows.rs` |
| Background service | `services/security-service/src/lib.rs`, `.../engine.rs`, `.../ipc.rs`, `.../main.rs`, `services/security-service/tests/service_engine.rs`, `services/security-service/tests/service_pipe.rs` |
| Existing integration tests | `src-tauri/tests/engine_pipeline.rs`, `crates/windows-integration/tests/live_windows.rs` |
| Supply chain | `Cargo.toml`, `Cargo.lock`, `package.json`, `package-lock.json`, `docs/PACKAGING.md` |
| Threat model | `docs/SECURITY.md`, `docs/CONTRACTS.md`, `docs/PACKAGING.md`, `README.md` |

### 1.4 Not reviewed / not verified

These were **out of scope or could not be executed** in this environment. They
are stated so that no reader mistakes silence for a pass:

- **No dynamic analysis.** No malware was detonated, no file was executed, no
  reverse engineering or binary patching was attempted.
- **No penetration testing.** No attempt was made to exploit the Tauri IPC
  bridge, the WebView2 surface, the named pipe or the DPAPI key store.
- **No MSIX packaging validation.** The `winapp` CLI is not installed in this
  environment, so `npm run pack:msix` was not executed; the MSIX manifest,
  asset set and certificate were reviewed by reading only.
- **No service installation.** `packaging/service-installer/install-service.ps1`
  was not run; the service's runtime identity, pipe ACL and data-directory
  ACLs were reviewed from source and from the installer script only.
- **No toast/notification verification.** Package identity is absent in this
  environment, so `NotificationOutcome::NoPackageIdentity` is the only
  reachable path and the packaged toast path is unverified.
- **No live pipe cross-user test.** The pipe DACL was read from source and
  probed by the crate's own ACL test
  (`crates/security-ipc/src/pipe/windows.rs:765-787`); the cross-user impact
  in SEC-001 is derived from the SDDL, not from an executed multi-user
  session.
- **No Defender tampering check beyond a source grep.** The claim that
  Defender is never modified was verified by searching the whole Rust tree for
  `Set-Mp*`, `Add-Mp*`, `Remove-Mp*`, `Disable*`, `TamperProtection`,
  `MpPreference` and Defender registry writes: **no matches**. Runtime
  behaviour was not observed.
- **The React/TypeScript layer was not reviewed line by line.** Only the
  TypeScript↔Rust type surface relevant to secret handling
  (`src/api/types.ts`, `src/pages/SettingsPage.tsx`) was read.
- **Performance/idle-resource benchmarking was not performed.** The role
  definition asks for idle CPU/memory figures; the app was not launched and no
  figures were measured. This audit contains **no** performance numbers.

---

## 2. Verification evidence

All commands were run from the repository root
`C:\Users\kevin\Desktop\Programmering\Projekt\WinUI`. Outputs are quoted
verbatim; failures are reported as failures.

> **Two-pass verification.** Because other agents were editing the workspace
> concurrently (§1.2), every gate was run **twice**: once when the audit
> started and once again at the end. Where the two runs disagree, both
> results are recorded and the later one is authoritative for the current
> tree. The final pass was executed after the last observed edit.

### 2.1 `cargo fmt --all -- --check` — **FAILED on the first pass (exit 1), PASSES on the final pass (exit 0)**

First pass:

```
$ cargo fmt --all -- --check
EXIT=1
```

The check reported formatting differences in **15 files** (rustfmt 1.9.0-stable):

```
crates/security-ipc/src/lib.rs
crates/security-ipc/src/pipe.rs
crates/security-ipc/src/pipe/windows.rs
crates/security-storage/src/lib.rs
crates/security-telemetry/src/lib.rs
services/security-service/src/engine.rs
services/security-service/src/ipc.rs
services/security-service/src/lib.rs
services/security-service/src/main.rs
services/security-service/tests/service_engine.rs
services/security-service/tests/service_pipe.rs
src-tauri/src/ai_service.rs
src-tauri/src/engine.rs
src-tauri/src/lib.rs
src-tauri/tests/engine_pipeline.rs
```

First reported difference, verbatim:

```
Diff in ...\crates\security-ipc\src\lib.rs:212:
             actual: bytes.len(),
         });
     }
-    let declared =
-        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
+    let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
```

Final pass (after the concurrent formatting fix landed):

```
$ cargo fmt --all -- --check
EXIT=0
```

**No diffs.** The file added by this audit,
`src-tauri/tests/security_invariants.rs`, is rustfmt-clean (verified
independently with `rustfmt --edition 2021 --check`, exit 0).

### 2.2 `cargo clippy --workspace --all-targets -- -D warnings` — **FAILED** (exit 101)

```
$ cargo clippy --workspace --all-targets -- -D warnings
EXIT=101
```

The run stops at the first failing crate. With `--keep-going` and with the
three lints it reports relaxed, the **complete** set of default-level clippy
findings in the workspace is **8** (final pass, line numbers as of the final
tree):

```
crates/security-telemetry/src/lib.rs:153:37: warning: casting to the same type is unnecessary (`usize` -> `usize`)
crates/security-telemetry/src/lib.rs:760:13: warning: this `if` can be collapsed into the outer `match`
crates/security-telemetry/src/lib.rs:883:9:  warning: field assignment outside of initializer for an instance created with Default::default()
services/security-service/src/engine.rs:950:16: warning: manual implementation of `.is_multiple_of()`
services/security-service/src/lib.rs:392:55: warning: clamp-like pattern without using clamp function
services/security-service/src/lib.rs:744:17: warning: length comparison to zero
services/security-service/tests/service_engine.rs:208:21: warning: using `clone` on type `SecurityEventKind` which implements `Copy`
services/security-service/tests/service_engine.rs:275:27: warning: using `clone` on type `SecurityEventKind` which implements `Copy`
```

Verbatim first failure:

```
error: casting to the same type is unnecessary (`usize` -> `usize`)
   --> crates\security-telemetry\src\lib.rs:153:37
    |
153 |         let mut buffer = vec![0u16; MAX_PATH as usize * 4];
    |                                     ^^^^^^^^^^^^^^^^^ help: try: `MAX_PATH`
    |
    = note: `-D clippy::unnecessary-cast` implied by `-D warnings`
```

The new test target `src-tauri/tests/security_invariants.rs` is **clippy-clean**
(verified with `cargo clippy -p tauri-app --test security_invariants`).

### 2.3 `cargo test --workspace` — **PASSED** (exit 0)

```
$ cargo test --workspace
EXIT=0

TOTAL passed=260 failed=0 ignored=2
```

19 test binaries ran (12 unit-test binaries, 5 integration-test binaries, 11
doc-test targets). The 2 ignored tests are pre-existing
(`crates/windows-integration/tests/live_windows.rs`).

### 2.4 Frontend pipeline — **FAILED on the first pass, PASSES on the final pass**

First pass:

```
$ npm run typecheck          # tsc --noEmit
EXIT=2
src/pages/QuarantinePage.tsx(30,28): error TS6133: 'DeleteRegular' is declared but its value is never read.
src/pages/ScanCenterPage.tsx(32,3): error TS6133: 'LockClosedRegular' is declared but its value is never read.
src/pages/ScanCenterPage.tsx(109,10): error TS6133: 'quarantiningPath' is declared but its value is never read.
src/pages/ScanCenterPage.tsx(168,9): error TS6133: 'onQuarantine' is declared but its value is never read.
src/pages/ScanCenterPage.tsx(343,18): error TS2552: Cannot find name 'MessageBarTitle'. Did you mean 'MessageBar'?
src/pages/ScanCenterPage.tsx(343,62): error TS2552: Cannot find name 'MessageBarTitle'. Did you mean 'MessageBar'?
```

```
$ npm test                   # vitest run
EXIT=0
 Test Files  6 passed (6)
      Tests  28 passed (28)
```

```
$ npm run build              # tsc --noEmit && vite build
EXIT=2
src/components/EventDetailPanel.tsx(1,10): error TS6133: 'useCallback' is declared but its value is never read.
src/components/EventDetailPanel.tsx(1,23): error TS6133: 'useState' is declared but its value is never read.
src/components/EventDetailPanel.tsx(16,1): error TS6133: 'LockClosedRegular' is declared but its value is never read.
src/components/EventDetailPanel.tsx(28,1): error TS6133: 'describeError' is declared but its value is never read.
src/components/EventDetailPanel.tsx(41,1): error TS6133: 'useOptionalQuarantine' is declared but its value is never read.
src/pages/QuarantinePage.tsx(30,28): error TS6133: 'DeleteRegular' is declared but its value is never read.
src/pages/ScanCenterPage.tsx(343,18): error TS2552: Cannot find name 'MessageBarTitle'. Did you mean 'MessageBar'?
src/pages/ScanCenterPage.tsx(343,62): error TS2552: Cannot find name 'MessageBarTitle'. Did you mean 'MessageBar'?
```

The failing set **changed between the two first-pass runs** (`ScanCenterPage.tsx`
errors disappeared, `EventDetailPanel.tsx` errors appeared) because the
frontend was being edited concurrently. See SEC-008.

Final pass:

```
$ npm run typecheck          # tsc --noEmit
EXIT=0

$ npm test                   # vitest run
EXIT=0
 Test Files  7 passed (7)
      Tests  37 passed (37)
   Duration  33.77s

$ npm run build              # tsc --noEmit && vite build
EXIT=0
vite v7.3.7 building client environment for production...
✓ 2193 modules transformed.
dist/index.html                 0.40 kB │ gzip:   0.27 kB
dist/assets/index-BBKzaAsP.css  0.47 kB │ gzip:   0.28 kB
dist/assets/index-Daq6aIT5.js 858.11 kB │ gzip: 240.07 kB
✓ built in 3.67s
```

**All frontend gates are green on the final tree.**


### 2.5 `cargo build --release --workspace` — **PASSED** (exit 0)

```
$ cargo build --release --workspace
EXIT=0
    Finished `release` profile [optimized] target(s) in 2m 11s
```

### 2.6 New security regression suite — **PASSED** (exit 0)

```
$ cargo test -p tauri-app --test security_invariants
running 8 tests
test event_evaluation_is_capped_at_alert ... ok
test api_key_is_never_serialized_or_debug_printed ... ok
test auto_quarantine_requires_a_deterministic_hash_or_yara_basis ... ok
test ai_decision_can_never_trigger_quarantine_in_any_policy_configuration ... ok
test ipc_rejects_oversized_and_truncated_frames ... ok
test quarantine_delete_touches_only_the_vault_copy ... ok
test quarantine_vault_rejects_symlinks ... ok
test quarantine_restore_never_overwrites_an_existing_file ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
```

---

## 3. Architecture trust boundaries

The product has three boundaries that matter. For each: what crosses it, what
authenticates the crossing, and what a failure costs.

### 3.1 Boundary A — WebView/React → Tauri desktop process

**What crosses it.** Every `invoke` call from the React layer becomes a
`#[tauri::command]` in `src-tauri/src/lib.rs`. The frozen surface is 23
commands plus three upstream sample commands (SEC-005). Payloads include
filesystem paths (`scan_path`, `quarantine_file`), record ids
(`restore_quarantine`, `delete_quarantine`, `get_event`), an arbitrary JSON
patch (`update_settings`) and an API key (`configure_ai`).

**What authenticates it.**

- CSP (`src-tauri/tauri.conf.json:28`):
  `default-src 'self'; img-src 'self' asset: https://asset.localhost data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src ipc: http://ipc.localhost; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
  No remote script, no `unsafe-eval`, `object-src 'none'`, `frame-ancestors 'none'`.
  `style-src 'unsafe-inline'` is required by Fluent UI's runtime style
  attributes and cannot be removed; it is not a script execution sink.
- Capability (`src-tauri/capabilities/default.json:6-9`): `core:default`,
  `opener:default`, scoped to the `main` window only.
- Argument validation: **per-command and inconsistent** — the desktop commands
  mostly rely on the underlying crate's own checks; the service IPC path
  validates explicitly (SEC-002).

**Impact of a failure.** The React layer is a presentation layer, so a
compromise requires either an XSS in the bundled app or local code execution in
the WebView2 process. If it happens, the attacker inherits the desktop
process's privileges: they can ask the engine to scan and quarantine arbitrary
paths, read the whole local event history, and change policy and privacy
settings. They cannot obtain the API key (see §3.3) and they cannot bypass the
policy engine (see §6.1). The realistic worst case is *misuse of the user's
own privileges by the user's own account*, not privilege escalation — with the
exception of the settings-driven scanner memory bound (SEC-002) and the
service boundary (§3.2), where the desktop app is not the privileged party.

### 3.2 Boundary B — desktop → optional `security-service` over a named pipe

**What crosses it.** `ClientRequest` / `ServerResponse` frames
(`crates/security-ipc/src/lib.rs:101-152`): `Ping`, `GetStatus`, `ScanPath`,
`CancelScan`, `ListEvents`, `GetEvent`, `ListQuarantine`, `QuarantineFile`,
`RestoreQuarantine`, `Subscribe`. The service runs as `NT AUTHORITY\LocalService`
(`services/security-service/src/lib.rs:47`) and owns a **machine-wide**
database at `%ProgramData%\AiAntivirus\security.db`
(`services/security-service/src/lib.rs:90-107`).

**What authenticates it.**

- A DACL applied to every pipe instance:
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`
  (`crates/security-ipc/src/pipe/windows.rs:40`).
- `PIPE_REJECT_REMOTE_CLIENTS` (`crates/security-ipc/src/pipe/windows.rs:140`)
  blocks SMB/remote clients but **not** other local users.
- Length-prefixed framing with a hard 1 MiB cap
  (`crates/security-ipc/src/lib.rs:36`, `:190-239`), a protocol version
  handshake (`:282-292`) and a per-connection token bucket
  (`:309-374`, defaults 64 burst / 32 per second).
- Argument validation in `services/security-service/src/ipc.rs:17-141`:
  absolute path, ≤ 4096 characters, no NUL, ≤ 512-character reason, ≤
  128-character id, and rejection of paths inside the vault.
- **There is no client-identity check.** The service never verifies *who* is
  on the other end of the pipe (see SEC-001).

**Impact of a failure.** Because the DACL grants access to every *interactive
user* rather than to the owning user, and because the service's telemetry
database is shared machine-wide, a low-privilege local account can read the
security history of every other account on the machine and can drive the
service's file-copy and scan primitives. This is the most consequential
finding in this audit (SEC-001).

### 3.3 Boundary C — engine → cloud AI provider

**What crosses it.** A redacted `SecurityEventState` plus a fixed set of
questions to `POST https://openrouter.ai/api/alpha/decisions`, with
`Authorization: Bearer <key>`.

**What authenticates it.** Nothing authenticates the *provider* beyond TLS;
provider output is treated as untrusted input. The controls are:

- Egress is **opt-in twice**: `AiMode` must be `Cloud`/`Hybrid` *and*
  `allow_cloud_state` must be true (`src-tauri/src/ai_service.rs:85-89`);
  the default is `AiMode::Offline` with `allow_cloud_state: false`
  (`src-tauri/src/ai_service.rs:362-374`).
- Redaction is applied before every request
  (`crates/ai-decisions/src/redaction.rs:19-64`, called from
  `crates/ai-decisions/src/providers/openrouter.rs:207` and from
  `crates/ai-decisions/src/redaction.rs:141`).
- The API key never leaves the Tauri process: it is stored DPAPI-protected
  (`crates/windows-integration/src/dpapi.rs:30-111`), held in memory only for
  the request lifetime, `#[serde(skip_serializing)]`
  (`crates/ai-decisions/src/types.rs:56-57`), redacted in `Debug`
  (`crates/ai-decisions/src/types.rs:125-142`), and never included in an
  error message (`crates/ai-decisions/src/error.rs:62-100`).
- Bounded egress: 15 s default timeout, ≤ 2 retries, token bucket, daily USD
  ceiling, 10-minute cache, fail-closed routing
  (`crates/ai-decisions/src/router.rs`, `.../cost.rs`, `.../rate_limit.rs`,
  `.../cache.rs`).

**Impact of a failure.** A provider compromise, or an attacker who obtains the
API key, yields the *redacted* state of events — no file bytes, no full
hashes, no usernames, no absolute paths. The AI layer also cannot act on the
machine: neither `crates/ai-decisions` nor `crates/ai-local` references
`std::fs`, `File::` or `Command::` (the only `std::process` use in either
crate is `std::process::id()` as a jitter seed at
`crates/ai-decisions/src/providers/openrouter.rs:389`). The blast radius of a
hostile provider is therefore bounded by §6.1 — it can raise an outcome to
`Alert` and nothing else.

---

## 4. Findings

Severity scheme (matches `docs/SECURITY.md`):

| Severity | Meaning |
|---|---|
| **P0** | Critical — directly exploitable compromise of the product's core promise |
| **P1** | High — a security boundary is broken in the default configuration |
| **P2** | Medium — a control is weaker than documented, or inconsistent between layers |
| **P3** | Low — build hygiene, documentation drift, defence-in-depth gaps |
| **Informational** | No direct impact; recorded for completeness |

**Summary: 0 P0, 1 P1, 4 P2, 2 P3, 3 Informational.**

There are **no P0 findings**: no path was found by which AI output, a
compromised renderer, or a remote peer can cause a destructive action,
disable Defender, or exfiltrate the API key.

---

### SEC-001 — P1 (High) — The named-pipe DACL grants every interactive user access to the security service

**Evidence**

- `crates/security-ipc/src/pipe/windows.rs:40`
  ```rust
  pub const PIPE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
  ```
  `IU` is the well-known SID `S-1-5-4` — **Interactive Users**, i.e. every
  account with an interactive logon session on the machine, not the account
  that owns the service.
- `crates/security-ipc/src/pipe/windows.rs:765-787` — the crate's own ACL
  probe test asserts that `IU)` is *present*; it never asserts that the DACL
  is restricted to a single user.
- `crates/security-ipc/src/pipe/windows.rs:140` — `PIPE_REJECT_REMOTE_CLIENTS`
  blocks remote (SMB) clients only; it does nothing about other local users.
- `services/security-service/src/lib.rs:47` — the service account is
  `NT AUTHORITY\LocalService`.
- `services/security-service/src/lib.rs:90-107` — a single machine-wide data
  directory and database (`%ProgramData%\AiAntivirus\security.db`).
- `crates/security-telemetry/src/lib.rs:125-131` and `:249` — the process
  snapshot records each process's **image path** and stores it on the event.
- `services/security-service/src/engine.rs:616`, `:773`, `:798` — the service
  polls the whole machine's process list and persists the events to the shared
  database.
- `services/security-service/src/ipc.rs:17-141` — `handle_request` validates
  only the *arguments*; no request handler checks the caller's identity.
- `crates/security-ipc/src/lib.rs:107-119` — `ScanPath`, `ListEvents`,
  `GetEvent`, `QuarantineFile` and `RestoreQuarantine` are all reachable by
  any pipe client.
- `docs/PACKAGING.md:150` — the installer is *documented* as
  "optionally opening the named-pipe ACL only to the interactive user". The
  implementation grants it to all of them.

**Impact**

1. **Cross-user information disclosure.** `ListEvents` returns the shared
   telemetry history: the image path of every process that started on the
   machine (including other users' `C:\Users\<other>\...` paths), the paths of
   files those users scanned, and Defender/PowerShell Event Log entries
   (script-block events) produced by other sessions. Any local interactive
   account can read all of it.
2. **Service-context file primitive.** `QuarantineFile` makes the service
   (running as LocalService) copy an arbitrary path that LocalService can
   read into the service's vault; `RestoreQuarantine` writes the copy back to
   an **attacker-chosen absolute path** (`services/security-service/src/ipc.rs:120-133`
   → `engine.restore_quarantine`). Restore refuses to overwrite an existing
   file, so this is a *create*, not an *overwrite*, primitive — but it is a
   write with the service's privileges to a path the attacker chooses.
3. **Unbounded work.** `ScanPath` with `recursive: true` over an arbitrary
   root (e.g. `C:\`) is accepted, so a local account can drive the service
   into sustained heavy I/O.

**Recommendation**

- Build the pipe SDDL at runtime from the *owning* account's SID rather than
  from the static `IU` alias — e.g. resolve the service owner's token, format
  it as `S-1-5-21-…-RID`, and use
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<owner SID>)`.
- Additionally, impersonate the connected client
  (`ImpersonateNamedPipeClient` + `GetTokenInformation(TokenUser)`) and
  reject callers whose SID is not the configured owner; log every rejection.
- Replace the ACL probe test with one that asserts the DACL contains exactly
  the expected three principals and that the owner SID is machine-specific.
- Until fixed, document that the optional service must not be installed on
  shared multi-user machines.

---

### SEC-002 — P2 (Medium) — The desktop Tauri command surface applies materially weaker input validation than the service IPC surface

**Evidence**

- `src-tauri/src/lib.rs:466-478` — `scan_path` validates only
  `path.exists()`:
  ```rust
  let path = std::path::Path::new(&request.path);
  if !path.exists() {
      return Err(format!("path does not exist: {}", request.path));
  }
  ```
  No absolute-path requirement, no length bound, no NUL rejection.
- `services/security-service/src/lib.rs:495-540` — the service equivalent
  (`validate_path_string` / `validate_existing_path`) requires an **absolute**
  path (`lib.rs:512-517`), ≤ `MAX_PATH_LEN` = 4096 characters
  (`lib.rs:502-506`) and no NUL (`lib.rs:507-511`).
- `src-tauri/src/lib.rs:546-577` — `quarantine_file` validates only
  `file.exists()` and then calls `state.vault.quarantine(file, &reason, None)`.
  Unlike `services/security-service/src/ipc.rs:100-106`, it does **not**
  reject a target that lies inside the quarantine vault.
- `src-tauri/src/lib.rs:750-772` — `update_settings` accepts an arbitrary
  unvalidated `serde_json::Value` patch, deep-merged into the persisted
  settings (`src-tauri/src/lib.rs:155-174`).
- `src-tauri/src/lib.rs:252-272` — `scanner_config_from` copies
  `scanner.maxFileSizeMb` into `ScannerConfig::max_file_size` with only
  `saturating_mul`; there is **no upper clamp**, so the settings patch can
  override the documented 128 MiB default.
- `crates/security-scanner/src/lib.rs:698-707` — `read_at_most` allocates up
  to `limit` bytes via `read_to_end`, so the effective memory bound of a scan
  is the settings-controlled value.

**Impact**

- The React layer — which the threat model explicitly treats as a
  presentation layer (`docs/SECURITY.md:42-45`) — can drive the desktop
  backend into states the service path refuses: relative or NUL-bearing paths,
  unbounded path lengths, vault self-copy, and a scanner memory bound
  controlled entirely by a settings value.
- The practical worst case is a local denial of service (a multi-gigabyte
  allocation during a scan) rather than privilege escalation, because the
  desktop process already runs with the user's own privileges. The vault
  self-copy is a correctness/hygiene defect: the vault can end up containing
  copies of its own copies.

**Recommendation**

- Move `validate_path_string` / `validate_existing_path` / `validate_reason`
  out of `security-service` into a shared crate (or `security-core`) and call
  them from the Tauri commands, so both surfaces enforce the same rules.
- Add the vault-membership check to the desktop `quarantine_file` (the same
  `is_within(vault.dir(), &candidate)` guard the service uses).
- Clamp `scanner.maxFileSizeMb` to the `ScannerConfig` maximum (and clamp
  `scanner.exclusions` to a bounded count) inside `scanner_config_from`.
- Validate the `update_settings` patch against a typed settings struct rather
  than merging arbitrary JSON.

---

### SEC-003 — P2 (Medium) — Quarantine hashing is uncapped, contradicting the vault's own documented invariant

**Evidence**

- `crates/security-scanner/src/quarantine.rs:83-85`
  ```rust
  let (sha256, hashed_bytes) = hash_file_limited(path, 0)?.ok_or_else(|| {
      ScanError::Quarantine("source hashing was limited unexpectedly".to_string())
  })?;
  ```
- `crates/security-scanner/src/hashing.rs:39-58` — `hash_reader_limited`
  returns `Ok(None)` **only** when `limit > 0 && total > limit`. With
  `limit == 0` the `None` branch is unreachable, so the file is hashed in full
  and the `ok_or_else` branch is dead code.
- `crates/security-scanner/src/quarantine.rs:84` — the module doc for this
  very function says "Require a regular file; **hash with a capped reader**".
- `docs/CONTRACTS.md:117-120` — "Require a regular file; hash with a capped
  reader."
- `crates/security-scanner/src/lib.rs` — `ScannerConfig::max_hash_size`
  (512 MiB default) is applied on the *scan* path but **not** on the
  quarantine path.

**Impact**

Quarantining a very large file — or a file on a slow or network share —
blocks the scan worker for an unbounded time and copies the entire file into
the vault. Memory stays bounded (64 KiB chunks), so this is an
availability/DoS issue, not a memory-exhaustion issue. It also means the
scanner's advertised size policy is not honoured on the path that actually
retains user data.

**Recommendation**

Pass a real limit (the scanner's `max_hash_size`, or a dedicated vault cap)
into the quarantine hash, and return a clear
`ScanError::Quarantine("file exceeds the quarantine size limit")` above it.
Update the module doc to state the actual limit.

---

### SEC-004 — P2 (Medium) — The Tauri capability grants an unused plugin that exposes an unscoped filesystem-reveal command

**Evidence**

- `src-tauri/capabilities/default.json:6-9`
  ```json
  "permissions": [
    "core:default",
    "opener:default"
  ]
  ```
- `tauri-plugin-opener-2.7.2/permissions/default.toml` — `opener:default`
  expands to `allow-open-url`, `allow-reveal-item-in-dir` and
  `allow-default-urls`.
- `tauri-plugin-opener-2.7.2/permissions/autogenerated/commands/reveal_item_in_dir.toml`
  — `allow-reveal-item-in-dir` enables the command **without any
  pre-configured scope**.
- `tauri-plugin-opener-2.7.2/src/commands.rs:73-77` — the
  `reveal_item_in_dir` command performs **no scope check** (unlike
  `open_url`/`open_path`, which call `scope.is_url_allowed` /
  `scope.is_path_allowed`); it only canonicalises the path and requires it to
  exist.
- `src-tauri/src/lib.rs:827` — the plugin is registered:
  `.plugin(tauri_plugin_opener::init())`.
- A search of the whole frontend (`src/**`) for `opener`, `openUrl` and
  `openPath` returns **no matches** — the permission is never used.

**Impact**

A compromised renderer can cause Explorer windows to open at arbitrary
existing paths on the machine. This is an information-disclosure and
UI-hijack nuisance (it also does not give the attacker the file contents),
not a code-execution or file-write primitive. The real problem is
least-privilege: the app's capability set is larger than its functionality
requires, and the granted command has no path scope at all.

**Recommendation**

Remove `opener:default` from `src-tauri/capabilities/default.json` and drop
`tauri_plugin_opener::init()` from `src-tauri/src/lib.rs:827` unless a
concrete feature needs it. If it is kept, restrict it to
`allow-open-url` + `allow-default-urls` only (drop
`allow-reveal-item-in-dir`).

---

### SEC-005 — P2 (Medium) — Three upstream sample commands remain reachable and are outside the frozen command contract

**Evidence**

- `src-tauri/src/lib.rs:791-813` defines `greet`, `get_package_family_name`
  and `show_notification` as `#[tauri::command]`.
- `src-tauri/src/lib.rs:865-892` registers all three in the
  `invoke_handler`.
- `docs/CONTRACTS.md:361-385` freezes the command list; it contains **none**
  of these three.
- `src-tauri/src/lib.rs:804-813` — `show_notification` takes an arbitrary
  `title` and `body` from the webview and displays a Windows toast
  attributed to the app's AUMID.

**Impact**

A compromised renderer can display arbitrary toast text attributed to "AI
Antivirus" — notification spoofing that could be used for social engineering
(e.g. "Your computer is infected, call 1-800-…"). The toast is rendered by
Windows under the app's identity, so it carries the app's credibility. The
same three commands also widen the audited command surface beyond the
contract the rest of the product was designed against.

**Recommendation**

Remove `greet`, `get_package_family_name` and `show_notification` from the
invoke handler (keep `send_test_notification`, which is in the contract and
takes no free-text arguments), or document and explicitly approve them in
`docs/CONTRACTS.md` before shipping.

---

### SEC-006 — P3 (Low) — The Authenticode probe is not launched with `CREATE_NO_WINDOW` and does not bound captured output

**Evidence**

- `crates/security-scanner/src/authenticode.rs:45-56` spawns `powershell.exe`
  with a plain `std::process::Command` — **no `creation_flags(CREATE_NO_WINDOW)`**
  — and reads the result with `child.wait_with_output()`
  (`crates/security-scanner/src/authenticode.rs:78`), which has no output cap.
- By contrast, the Defender probe
  (`crates/windows-integration/src/defender.rs:152-158`) and the `reg.exe`
  version probe (`crates/windows-integration/src/version.rs:269`) both go
  through `windows_integration::process_util::run_with_timeout`, which sets
  `CREATE_NO_WINDOW` (`crates/windows-integration/src/process_util.rs:13`,
  `:59`), enforces a deadline and kills on expiry (`:63-83`) and truncates
  captured output at 1 MiB (`:17`, `:91-92`, `:101-108`).
- `docs/SECURITY.md:144-147` states that *all* child processes (explicitly
  naming "PowerShell for Authenticode/Defender") are launched with
  `CREATE_NO_WINDOW`, bounded output (1 MiB) and hard timeouts. For the
  Authenticode path this is **false**.

**What was verified as correct**

- The scanned path is embedded in a PowerShell script with single-quote
  doubling (`crates/security-scanner/src/authenticode.rs:96-109`), which is
  the correct defence against breaking out of a PowerShell string literal.
- The script is passed via `-EncodedCommand` (`:47-50`, `:111-117`), so it
  cannot be re-interpreted by the command line.
- The Authenticode probe *does* have a hard timeout (5 s,
  `crates/security-scanner/src/authenticode.rs:15`) and kills the child on
  expiry (`:61-70`).

**Impact**

Every scanned PE file flashes a console window, and a recursive scan of a
large tree spawns one PowerShell process per PE file with a 5 s budget each —
a visible and slow behaviour that contradicts the documented hardening. The
unbounded output capture is a minor memory concern (PowerShell's output for
this query is small and bounded by the script's own shape). No injection or
privilege issue was found on this path.

**Recommendation**

Route the Authenticode probe through `windows_integration::process_util`
(or add the same `CREATE_NO_WINDOW` flag and a 1 MiB truncation locally), and
correct the `docs/SECURITY.md` §7 bullet so it describes what the code does.

---

### SEC-007 — P3 (Low) — `cargo clippy --workspace --all-targets -- -D warnings` is red

**Evidence** — see §2.2.

- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 101**,
  8 lints on the final tree (3 in `crates/security-telemetry/src/lib.rs:153`,
  `:760`, `:883`; 2 in `services/security-service/src/lib.rs:392`, `:744`;
  1 in `services/security-service/src/engine.rs:950`; 2 in
  `services/security-service/tests/service_engine.rs:208`, `:275`).
- `cargo fmt --all -- --check` → **exit 0** on the final tree. It failed with
  15 unformatted files at the start of the audit and was fixed concurrently
  (§2.1); it is recorded here only because it was red for part of the audit
  window.

**Impact**

No runtime security impact. The significance is that the release pipeline
described in `.claude/agents/security-qa.md:18-21` cannot currently be used
as a gate: a red gate that is always red stops being a gate. The
`field_reassign_with_default` and `collapsible_match` findings also touch
`crates/security-telemetry/src/lib.rs`, which is where the event→signal
mapping lives, i.e. the code that decides deterministic risk.

**Recommendation**

Fix the eight lints and add both commands to CI.

---

### SEC-008 — Informational — The frontend quality gate was red when the audit started and was fixed during the audit

**Evidence** — see §2.4.

At the start of the audit, `npm run typecheck` and `npm run build` both
**failed** (exit 2). The blocking error was
`src/pages/ScanCenterPage.tsx:343`: `Cannot find name 'MessageBarTitle'` —
the component was used but not imported — plus several `TS6133` unused
identifier errors in `src/pages/QuarantinePage.tsx`,
`src/pages/ScanCenterPage.tsx` and `src/components/EventDetailPanel.tsx`.
The failing file set changed between two consecutive runs because the frontend
was being edited by another agent at the time.

On the final pass, all three frontend gates are **green**: `npm run typecheck`
exit 0, `npm test` exit 0 (7 files, 37 tests), `npm run build` exit 0 (2193
modules transformed).

**Impact**

None on the final tree. This entry is retained because a reader of the audit
log needs to know that the gate was red during the audit window and that the
red state was *not* a security defect — it was an in-progress edit by another
agent. It is filed as Informational rather than deleted so the audit trail
remains complete.

**Recommendation**

No action. Keep `npm run typecheck` and `npm run build` in CI so the gate
cannot silently regress again.


---

### SEC-009 — P3 (Low) — `docs/SECURITY.md` has drifted from the implementation in three places

**Evidence**

| Document statement | Reality | Code |
|---|---|---|
| §2 trust boundary 5: "The pipe uses an **owner-only** ACL" | The DACL grants SYSTEM, Administrators and **all Interactive Users** | `crates/security-ipc/src/pipe/windows.rs:40` |
| §4 step 3 and the §3 invariant row: "copy to `vault/<uuid>_<sanitized-name>`" / "UUID-prefixed vault names" | Stored names are `<sha256-prefix>-<utc-timestamp>-<sanitized-name>.quarantine` | `crates/security-scanner/src/quarantine.rs:302-326` (format string at `:316-318`) |
| §7: "Child processes (PowerShell for Authenticode/Defender, `reg.exe` for version) are launched with `CREATE_NO_WINDOW`, bounded output (1 MiB)" | True for Defender and `reg.exe`; **false** for the Authenticode probe | `crates/security-scanner/src/authenticode.rs:45-56` |

The vault-naming statement in `docs/CONTRACTS.md:117-120`
(`<sha256-prefix>-<timestamp>-<name>`) **does** match the implementation, so
`docs/SECURITY.md` is the outlier.

**Impact**

A reader who trusts `docs/SECURITY.md` would believe (a) the pipe is
owner-only, which is the single most consequential misreading in the
document (see SEC-001), and (b) the vault uses UUID-prefixed names, which
affects how an operator correlates vault files with sidecars.

**Recommendation**

Correct the three statements. The L1–L10 table itself (§10) was checked
row by row and is accurate — see §5.

---

### SEC-010 — Informational — Time-of-check/time-of-use window in the quarantine vault

**Evidence**

- `crates/security-scanner/src/quarantine.rs:73-101` — the sequence is
  `symlink_metadata` → reparse check → `fs::metadata` → hash → allocate name
  → `copy_verified`, all addressed **by path**. Between the reparse check
  (`:74-76`) and the copy (`:101`, `:330-360`) the path can be replaced.
- `crates/security-scanner/src/quarantine.rs:330-360` — `copy_verified`
  re-hashes the copy and deletes it on mismatch, so the stored copy is always
  content-identical to the recorded hash.

**Impact**

A local attacker who can replace the file between the check and the copy can
cause a different file to be read, but **not** to be stored: the copy is
hash-verified against the original's hash and removed on mismatch. The
residual effect is that the recorded `original_path` may no longer refer to
the same inode; restore writes only to that recorded path and refuses to
overwrite an existing file, so the blast radius is a confusing audit record
rather than data loss or disclosure.

**Recommendation**

Open the source with `FILE_FLAG_OPEN_REPARSE_POINT` and hash/copy from the
handle rather than re-resolving the path, which closes the window entirely.

---

### SEC-011 — Informational — Redaction has a narrow blind spot around environment-variable user names

**Evidence**

- `crates/ai-decisions/src/redaction.rs:345-368` — `environment_usernames()`
  collects `USERNAME`, `DOMAIN\USERNAME` and the last component of
  `USERPROFILE`, and replaces them case-insensitively.
- `crates/ai-decisions/src/redaction.rs:216-238` — `mask_segment_after_marker`
  masks the segment after `\users\` and `\documents and settings\`.
- `crates/ai-decisions/src/redaction.rs:318-343` — `truncate_hex_runs` shortens
  any run of ≥ 16 hex characters to 8 characters plus `…`.

**Assessment**

The redaction is materially correct and is enforced by the crate's own tests
(`crates/ai-decisions/src/redaction.rs:446-556`) and by
`src-tauri/tests/engine_pipeline.rs:300-347`. Two residual blind spots are
worth recording:

1. A user name that is *not* the current user's (for example, a path under
   `C:\Users\OtherUser\…` where `OtherUser` is not `USERNAME`/`USERPROFILE`)
   is still masked by the `\users\` marker rule, but a *file name* that
   happens to embed another account's name is not.
2. `truncate_hex_runs` shortens a ≥ 16-character hex run but leaves the
   surrounding text intact; a base64-encoded path is not detected.

Neither is exploitable against the documented threat (the current user's own
identity), and neither enables a destructive action. Recorded for
completeness.

**Recommendation**

No action required for v1.0. If the threat model ever widens to
"multi-user machines", extend `environment_usernames()` to enumerate the
profile directory listing and add a base64 detector to `truncate_hex_runs`.

---

## 5. Known limitations carried forward (L1–L10 cross-check)

Every row of the residual-risk table in `docs/SECURITY.md:175-186` was
re-checked against the code. **All ten rows remain accurate**; none needed
to be corrected or re-rated.

| ID | Severity | Limitation (as documented) | Audit verdict | Notes |
|---|---|---|---|---|
| L1 | High | No preventive blocking; threats can execute before detection. | **Accurate** | No minifilter, no ELAM, no driver, no process blocking. `src-tauri/src/engine.rs:140` sets `monitoring_is_preventive: false`. |
| L2 | Medium | Process polling can miss short-lived processes between snapshots. | **Accurate** | Toolhelp32 snapshot diffing (`crates/security-telemetry/src/lib.rs:107-140`, `:214-250`); default poll interval 3000 ms (`src-tauri/src/lib.rs:839-843`). |
| L3 | Medium | Event Log coverage depends on channels being enabled; script-block logging is not enabled automatically. | **Accurate** | The reader only polls existing channels (`crates/security-telemetry/src/lib.rs:385`); nothing in the tree enables a channel. |
| L4 | Medium | Quarantine is copy-only and does not remove the original. | **Accurate** | `crates/security-scanner/src/quarantine.rs:67-129` copies; the original is never removed by the vault. |
| L5 | Medium | Authenticode/Defender checks depend on PowerShell; failures degrade to `unavailable`. | **Accurate** | `crates/windows-integration/src/defender.rs:93-109` returns `DefenderStatus::unavailable` on failure. See also SEC-006 for the console-window and output-bound defects on the Authenticode path. |
| L6 | Low | AI probabilities are uncalibrated; thresholds are defaults, not measured accuracy. | **Accurate** | Every provider result carries the calibration note (`crates/ai-decisions/src/redaction.rs:15-16`). |
| L7 | Low | NPU is detected but not used; the local model is a deterministic mock. | **Accurate** | `MockLocalDecisionModel` is the only local implementation; the NPU appears only in `HardwareProfile`/`InferenceRoute`. |
| L8 | Low | Rate/cost limits and cache are per-process, not machine-wide. | **Accurate** | The limiter and cost tracker are in-process state (`crates/ai-decisions/src/rate_limit.rs`, `.../cost.rs`, `.../cache.rs`). |
| L9 | Low | `Subscribe` is acknowledged but push streaming is not implemented; clients poll `ListEvents`. | **Accurate** | `SUBSCRIBE_STREAMING_SUPPORTED = false` (`crates/security-ipc/src/lib.rs:383`); the handler answers `ServerResponse::Subscribed` (`services/security-service/src/ipc.rs:134`). |
| L10 | Low | MSIX cannot register the service; 24/7 monitoring requires a separate installer and admin rights. | **Accurate** | Consistent with `docs/PACKAGING.md:101-156`. |

**Statements outside the L-table that needed correcting** are listed in
SEC-009. The single most important one is the §2 claim that the pipe uses an
"owner-only ACL", which is the direct documentation counterpart of SEC-001.

---

## 6. Invariant verification matrix

The four invariants the brief asked to be verified in **both** code and test
suite, with the exact enforcing test names.

### 6.1 "AI output can never trigger quarantine or any destructive action"

**Code enforcement.**

| Location | Mechanism |
|---|---|
| `crates/security-policy/src/lib.rs:427-434` | `evaluate_ai_only` caps the outcome at `Alert` unconditionally. |
| `crates/security-policy/src/lib.rs:796-799` | `ai_escalation` caps the AI contribution at `Alert` before it is even combined with the deterministic outcome. |
| `crates/security-policy/src/lib.rs:353-358` | `evaluate_scan` caps any AI-raised outcome at `Alert`; only the deterministic qualification below can reach `Quarantine`. |
| `crates/security-policy/src/lib.rs:465-497` | `quarantine_qualification` requires `known_malware_hash \|\| yara_matches > 0` — AI contributes nothing to it. |
| `crates/security-policy/src/lib.rs:289-291` | `evaluate_event` caps at `Alert`; events are never a quarantine input. |
| `src-tauri/src/engine.rs:344-348` | The auto-quarantine site additionally requires `auto_quarantine_enabled && policy.deterministic && policy.quarantine_allowed` before it touches the vault. |
| `crates/security-policy/Cargo.toml` / `crates/ai-decisions/Cargo.toml` / `crates/ai-local/Cargo.toml` | `security-policy` depends only on `security-core` (plus `serde`/`serde_json`/`chrono`/`tracing`/`thiserror`); neither `ai-decisions` nor `ai-local` references `std::fs`, `File::` or `Command::`, so the AI layer cannot read, write or execute anything. |

**Test enforcement (exact names).**

| Test | Location |
|---|---|
| `evaluate_ai_only_never_quarantines` | `crates/security-policy/src/tests.rs:334-380` — exhaustive matrix over 3 assessments × 4 categories × 7 confidences (incl. `NaN`, `INFINITY`) × 5 flag combinations, under `auto_quarantine_enabled: true`. |
| `ai_cannot_quarantine_a_clean_scan` | `crates/security-policy/src/tests.rs:382-395` — a `LikelyMalicious`/0.99 decision attached to a clean report yields `Alert`, `quarantine_allowed == false`, `deterministic == false`. |
| `ai_cannot_lower_a_deterministic_quarantine` | `crates/security-policy/src/tests.rs:397-409` — a benign AI decision cannot downgrade a deterministic `Quarantine`. |
| `ai_cannot_lower_alert_when_quarantine_disabled` | `crates/security-policy/src/tests.rs:411-418`. |
| `auto_quarantine_gating_matrix` | `crates/security-policy/src/tests.rs:151-216` — the 9-case enabled × requires-hash × signals matrix, asserting `quarantine_allowed` tracks the outcome exactly. |
| `event_severity_floors_and_never_quarantines` | `crates/security-policy/src/tests.rs:472-495` — every severity floor, never `Quarantine`. |
| `event_qualified_quarantine_is_deferred_to_scan` | `crates/security-policy/src/tests.rs:536-548`. |
| `ai_output_can_never_quarantine` | `src-tauri/tests/engine_pipeline.rs:85-125` — cross-layer integration test. |
| `ai_decision_can_never_trigger_quarantine_in_any_policy_configuration` | `src-tauri/tests/security_invariants.rs` (**new**, this audit) — maximally aggressive AI input across 4 policy configurations × 3 assessments, including the most permissive configuration. |
| `auto_quarantine_requires_a_deterministic_hash_or_yara_basis` | `src-tauri/tests/security_invariants.rs` (**new**) — AI-only evidence cannot quarantine even with auto-quarantine on and the hash requirement waived; includes a control case proving the assertion is not vacuous. |
| `event_evaluation_is_capped_at_alert` | `src-tauri/tests/security_invariants.rs` (**new**) — a behaviour-only event with every label, a critical severity and a known-hash assessment still caps at `Alert`. |

**Verdict: enforced.** The invariant is implemented in three independent
places (the AI-only path, the scan path and the event path) and is
additionally re-checked at the single call site that writes to the vault.

### 6.2 "Quarantine vault safety"

| Documented invariant (`docs/CONTRACTS.md:117-120`) | Enforced in code | Enforced by a test |
|---|---|---|
| Reject symlinks / reparse points | `crates/security-scanner/src/quarantine.rs:73-76` (quarantine), `:148-160` (restore) | **Yes** — `quarantine_rejects_symlinks` (`crates/security-scanner/src/tests.rs:670-684`); **new** `quarantine_vault_rejects_symlinks` (`src-tauri/tests/security_invariants.rs`) |
| Verify SHA-256 before quarantine | `crates/security-scanner/src/quarantine.rs:83-92` | Partially — the happy path is asserted (`quarantine_round_trip_restores_bytes`, `crates/security-scanner/src/tests.rs:533-584`); the *failure* path (hash mismatch) is **not** covered by a test |
| Verify the vault copy after copying | `crates/security-scanner/src/quarantine.rs:346-358` | Partially — `copy_verified` runs on every quarantine, but there is **no test** that forces a mismatch and asserts the copy is deleted |
| Verify the stored copy before restore | `crates/security-scanner/src/quarantine.rs:162-173` | Partially — `restore_fails_when_stored_copy_is_missing` (`crates/security-scanner/src/tests.rs:652-668`) covers the missing case; the *tampered* case is **not** covered |
| Verify the restored file after writing | `crates/security-scanner/src/quarantine.rs:204-216` | **No test** — this path has no dedicated coverage |
| Collision-safe stored names | `crates/security-scanner/src/quarantine.rs:302-326` | **Yes** — `quarantine_names_are_collision_safe` (`crates/security-scanner/src/tests.rs:610-628`) |
| Restore never overwrites an existing file | `crates/security-scanner/src/quarantine.rs:176-181` and `:188-201` | **Yes** — `restore_refuses_to_overwrite_existing_file` (`crates/security-scanner/src/tests.rs:586-608`); **new** `quarantine_restore_never_overwrites_an_existing_file` (`src-tauri/tests/security_invariants.rs`) covers the *second* restore after a successful one, which was previously untested |
| Never touch files outside the vault on restore | `crates/security-scanner/src/quarantine.rs:141-146` (`owns_stored_path`), `:175-186` | Partially — `owns_stored_path` is exercised by the happy path; there is **no test** for a sidecar whose `stored_path` points outside the vault |
| Never delete originals automatically | `crates/security-scanner/src/quarantine.rs:281-300` (delete removes only the vault copy and sidecar) | **Yes** — `quarantine_delete_removes_only_vault_copy` (`crates/security-scanner/src/tests.rs:630-650`); **new** `quarantine_delete_touches_only_the_vault_copy` (`src-tauri/tests/security_invariants.rs`) additionally asserts the original's **bytes** are unchanged |

**Verdict: enforced in code; test coverage is good but not complete.** The
untested branches are all *fail-safe* branches (hash mismatch → delete the
copy; stored path outside the vault → refuse), and each requires filesystem
fault injection to reach. Recommend adding fault-injection tests for them;
they are the paths that would matter if an attacker could influence the vault
directory.

### 6.3 "Secret handling"

| Requirement | Evidence | Status |
|---|---|---|
| The key is stored DPAPI-protected, user-scoped | `crates/windows-integration/src/dpapi.rs:30-111` (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`, no optional entropy); stored at `src-tauri/src/ai_service.rs:460-476` as `ai.apiKeyProtected` | **Verified** |
| The key cannot reach the React layer | `AiStatus` exposes only `configured: bool` (`src-tauri/src/types.rs:73-87`); `AiConfig.api_key` is `#[serde(skip_serializing)]` (`crates/ai-decisions/src/types.rs:56-57`); the frontend treats `apiKey` as write-only (`src/api/types.ts:487-492`) | **Verified** — also asserted by the new test `api_key_is_never_serialized_or_debug_printed` |
| The key cannot reach the event log | `AiConfig::Debug` and `ProviderConfig::Debug` print `"<redacted>"` (`crates/ai-decisions/src/types.rs:125-142`; `crates/ai-decisions/src/providers/openrouter.rs:74-94`) | **Verified** |
| The key cannot reach an error message | `crates/ai-decisions/src/error.rs:62-100` scrubs `Bearer <token>` and `sk-…` tokens from every provider message before it becomes a `DecisionError` (`crates/ai-decisions/src/providers/openrouter.rs:363-369`) | **Verified in code and by the crate's own tests** (`crates/ai-decisions/src/error.rs:127-141`, `crates/ai-decisions/src/provider_tests.rs:309-327`). **Not directly re-tested by this audit**, because `sanitize_message` is `pub(crate)` and is not reachable from an external integration test — see §7 |
| The config JSON persisted to SQLite omits the key | `src-tauri/src/ai_service.rs:130-132` serialises `AiConfig` (whose `api_key` is `skip_serializing`) into the `ai.config` setting | **Verified** — asserted by the new test |
| The key is dropped from memory when cloud is disabled | `src-tauri/src/ai_service.rs:141-152` (`disable_cloud`) sets `api_key: None`; `src-tauri/src/lib.rs:760-768` calls it when `privacy.cloudAiEnabled` is set to `false` | **Verified** (the DPAPI blob itself is retained so the user does not have to re-enter it — documented behaviour) |

### 6.4 "AI redaction before egress"

| Requirement | Evidence | Status |
|---|---|---|
| Usernames removed | `crates/ai-decisions/src/redaction.rs:157-160` (environment user names) and `:216-238` (`\users\` / `\documents and settings\` segment masking) | **Verified** — `crates/ai-decisions/src/redaction.rs:446-468`, `:552-557`; `src-tauri/tests/engine_pipeline.rs:335` |
| Absolute paths reduced to file names | `crates/ai-decisions/src/redaction.rs:165-172` (`scrub_file_name`) and `:274-291` (`reduce_path_token`) | **Verified** — `src-tauri/tests/engine_pipeline.rs:336-339` |
| Command lines sanitised | `crates/ai-decisions/src/redaction.rs:25` (`command_line_redacted` → `scrub_text`), `:149-162` | **Verified** — the command line keeps the *file name* and argument shape but loses the directory and the user name |
| Full hashes removed | `crates/ai-decisions/src/redaction.rs:37-41` (8-character prefix) and `:318-343` (`truncate_hex_runs`) | **Verified** — `crates/ai-decisions/src/redaction.rs:470-481`; `src-tauri/tests/engine_pipeline.rs:340-346` |
| Redaction runs before *every* provider call | `crates/ai-decisions/src/providers/openrouter.rs:207` (`redact_state(state)`) and `crates/ai-decisions/src/redaction.rs:141` (`build_decision_state` redacts before returning) | **Verified** — defence in depth |

### 6.5 "IPC frame limits"

`crates/security-ipc/src/lib.rs:36` defines `MAX_FRAME_BYTES = 1 MiB`.
Enforcement is at `crates/security-ipc/src/lib.rs:190-203` (encode),
`:206-239` (frame_payload: empty, short header, oversized declared length,
truncated, trailing bytes) and `:252-264` (payload-level bound). Tests:
`frame_rejects_oversized_payloads` (`:505-525`),
`frame_rejects_truncated_payloads` (`:528-538`),
`frame_rejects_trailing_bytes` (`:541-548`),
`frame_rejects_empty_input` (`:489-499`),
`frame_rejects_invalid_json` (`:551-559`). **New**:
`ipc_rejects_oversized_and_truncated_frames`
(`src-tauri/tests/security_invariants.rs`), which additionally proves the limit
is *inclusive* by decoding a frame of exactly `MAX_FRAME_BYTES`.

---

## 7. Invariants that could NOT be verified

Stated explicitly rather than left implicit.

| Invariant | Why it could not be verified | What would verify it |
|---|---|---|
| "The API key can never appear in a `DecisionError`" — from an **external** test | `sanitize_message` is `pub(crate)` in `crates/ai-decisions/src/error.rs:62`; it is not exported, and `ProviderConfig::with_transport` (the injection point used by the crate's own tests) is also crate-private. An integration test in another crate cannot reach either. | Make `sanitize_message` public (or `pub(crate)` + a `#[doc(hidden)]` re-export), or add a `#[cfg(test)]` fixture that constructs a `DecisionError` from a message containing `sk-…` and asserts the scrub. The property **is** covered today by the crate's own unit tests (`crates/ai-decisions/src/error.rs:127-141`, `crates/ai-decisions/src/provider_tests.rs:309-327`), which the workspace test run executes. |
| "A cross-user caller cannot use the pipe" (SEC-001 impact) | Requires two interactive Windows accounts and a service installation; neither exists in this environment, and `winapp`/service installation was not performed. | An integration test that creates the pipe, connects from a second account, and asserts the connect fails with `ERROR_ACCESS_DENIED`. |
| "The MSIX package identity is preserved and the toast path works" | `winapp` is not installed in this environment. | `npm run pack:msix` on a machine with the `winapp` CLI and a trusted certificate. |
| "Defender is never modified at runtime" | Verified only by a source grep (`Set-Mp*`, `Add-Mp*`, `Remove-Mp*`, `Disable*`, `TamperProtection`, `MpPreference`, Defender registry writes → **no matches**). No runtime observation of Defender state was made. | A before/after `Get-MpComputerStatus` comparison around an app session, ideally with the Defender event log captured. |
| "The vault ACL is actually hardened" | `harden_vault_permissions` (`crates/security-scanner/src/quarantine.rs:522-592`) shells out to `icacls` and **logs a warning on failure without failing**; the ACL was not inspected on this machine. | An integration test that reads back the vault directory's DACL with `Get-Acl` and asserts it contains exactly the current user, SYSTEM and Administrators. |
| "Idle CPU/memory is low" (role definition) | The app was never launched and no process was profiled. | Launch the packaged app, sample the process CPU and working set over a 10-minute idle window with the monitor enabled, and report the numbers with the methodology. **This audit contains no performance figures.** |
| "The service runs as LocalService with least privilege at runtime" | The service was not installed; the account is a compile-time constant (`services/security-service/src/lib.rs:47`) and the installer script was read but not executed. | Install the service from `packaging/service-installer/install-service.ps1` and inspect the resulting service configuration and the pipe's DACL on the live machine. |

---

## 8. Residual risk summary

| Severity | Count | Findings | One-line summary |
|---|---|---|---|
| **P0 (critical)** | 0 | — | No path was found by which AI output, a compromised renderer or a remote peer can cause a destructive action, disable Defender or exfiltrate the API key. |
| **P1 (high)** | 1 | SEC-001 | The security service's named pipe is granted to **all** interactive users, exposing the shared machine-wide telemetry history and the service's file-copy primitive to any local account. |
| **P2 (medium)** | 4 | SEC-002, SEC-003, SEC-004, SEC-005 | The desktop command surface validates less than the service surface; quarantine hashing is uncapped; an unused, unscoped plugin capability is granted; three out-of-contract sample commands remain reachable. |
| **P3 (low)** | 2 | SEC-006, SEC-007 | The Authenticode probe lacks `CREATE_NO_WINDOW` and an output bound; `cargo clippy --workspace --all-targets -- -D warnings` is red (8 lints). |
| **Informational** | 3 | SEC-008, SEC-010, SEC-011 | The frontend gate was red during the audit and was fixed concurrently (no longer reproduces); a narrow TOCTOU window in the vault copy step (mitigated by hash verification); minor residual redaction blind spots. |
| **Total** | **10** | | Plus 3 documentation-drift statements corrected in §5 / SEC-009. |

**Nothing in this audit changes the product's core security posture.** The
central invariant — AI output can never trigger quarantine or any destructive
action — is implemented in three independent places, re-checked at the single
vault-writing call site, and covered by 11 named tests across three test
targets (§6.1). The highest-severity issue (SEC-001) lives in the **optional**
background service; the default, embedded-engine deployment is unaffected.

---

## 9. Recommended order of work

1. **SEC-001** — restrict the pipe DACL to the owning account's SID and add
   a client-identity check. This is the only finding that breaks a documented
   boundary in the default configuration.
2. **SEC-002** — share the service's path/reason validation with the desktop
   commands and clamp the scanner size setting.
3. **SEC-005** — remove the three sample commands.
4. **SEC-004** — drop the unused `opener:default` capability.
5. **SEC-003** — cap the quarantine hash.
6. **SEC-007** — fix the eight clippy lints so the gate can be trusted again.
7. **SEC-006 / SEC-009** — align the code and the documentation.

---

## 10. Remediation status

The findings above are recorded as found. The changes below were made in the
same pull request that produced this document, after the audit was written.

| Finding | Status | Change |
|---|---|---|
| SEC-001 (P1) | **Open — accepted for v1.0** | Not fixed. Fixing it requires a per-user pipe ACL and a client-identity check in `security-ipc`, which is a protocol change outside the frozen contract. Tracked as **L11** in [`SECURITY.md`](SECURITY.md) §10 and called out in the README limitations. The default embedded-engine deployment is unaffected; only the optional background service is exposed. |
| SEC-002 (P2) | **Open** | Not fixed. The desktop command surface still validates less than the service IPC surface. |
| SEC-003 (P2) | **Fixed** | `QuarantineVault` now carries a hashing bound (`DEFAULT_MAX_HASH_SIZE`, 512 MiB) applied to all four hash sites — source, stored copy, restored file and the verification copy. `QuarantineVault::with_max_hash_size` allows an override; `new` keeps the contract signature. |
| SEC-004 (P2) | **Fixed** | The `opener:default` capability was removed from `src-tauri/capabilities/default.json`, the plugin was unregistered from the Tauri builder, and the now-unused `tauri-plugin-opener` dependency was dropped from `src-tauri/Cargo.toml`. The dashboard never used the plugin. |
| SEC-005 (P2) | **Fixed** | The three out-of-contract sample commands (`greet`, `get_package_family_name`, `show_notification`) were deleted and removed from the invoke handler. `get_system_status` already carries the package identity and `send_test_notification` is the contracted notification path. |
| SEC-006 (P3) | **Fixed** | The Authenticode probe now sets `CREATE_NO_WINDOW` and drains stdout/stderr on dedicated threads with a hard 1 MiB bound, so the helper can neither flash a console nor exhaust memory. |
| SEC-007 (P3) | **Fixed** | All clippy lints are resolved; `cargo clippy --workspace --all-targets -- -D warnings` is green. `cargo fmt --all -- --check` is green too. |
| SEC-008 (Info) | **Closed** | The frontend gate is green. |
| SEC-009 (P3) | **Fixed** | The three drifted statements in `docs/SECURITY.md` were corrected: the pipe ACL description, the vault naming format, and the `CREATE_NO_WINDOW` claim. The pipe-ACL statement now points at SEC-001 instead of claiming "owner-only". |
| SEC-010 (Info) | Open | Documented, not fixed. The hash verification of the copy bounds the blast radius. |
| SEC-011 (Info) | Open | Documented, not fixed. |

After these changes the audit's gates read:

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo test --workspace --no-fail-fast` | exit 0 — 260 passed, 0 failed, 2 ignored |
| `npm run typecheck` | exit 0 |
| `npm run lint` | exit 0 — 0 errors |
| `npm test` | exit 0 — 37 passed |
| `npm run build` | exit 0 |

---

## 11. Artefacts produced by this audit

| File | Purpose |
|---|---|
| `docs/SECURITY_AUDIT.md` | This document. |
| `src-tauri/tests/security_invariants.rs` | New Rust integration-test target (8 tests) in the `tauri-app` package, covering the AI-cannot-quarantine invariant, the deterministic-basis requirement, the event cap, quarantine-vault safety (symlink rejection, restore overwrite refusal, delete scope), IPC frame limits and API-key serialisation. Placed here because the root `Cargo.toml` is a workspace-only manifest and the `tauri-app` package already depends on every crate the tests need (`src-tauri/Cargo.toml:22-30`, dev-dependency `tempfile` at `:43-44`); a crate-local `tests/` directory would have needed a manifest change. |
| `tests/security/README.md` | Index of the security regression tests and the invariants they protect. |

Run them with:

```powershell
cargo test -p tauri-app --test security_invariants
```
