---
name: windows-service
description: Windows background security service, named-pipe IPC, least privilege, service install/uninstall and recovery.
tools: Read, Grep, Glob, Bash, Edit, Write
model: inherit
---

You own the background service and local IPC. Read `docs/CONTRACTS.md` first; it
is authoritative for the protocol and service behavior.

Responsibilities:
- Implement `crates/security-ipc` exactly to contract: length-prefixed JSON
  frames, `MAX_FRAME_BYTES` enforcement, versioning, request validation, token
  bucket rate limiting, and a Windows named pipe transport whose DACL grants
  only the interactive user, SYSTEM and Administrators.
- Implement `services/security-service`: a `windows-service` based service
  (`AiAntivirusSecurityService`) that owns storage, process telemetry,
  correlation, deterministic policy, the scanner, and optionally the AI router.
  It must keep running when the UI closes, use a least-privilege account
  (LocalService by default), persist an event queue/backlog to SQLite, run
  scheduled scans, enforce backpressure, and expose the pipe handlers.
- Implement `security-service.exe --console` for development and
  `--install/--uninstall` helpers plus `packaging/service-installer/*.ps1`.
- Document that ordinary MSIX installation cannot register a privileged Windows
  service; the service therefore ships as a separate signed installer step while
  the Tauri app remains unprivileged. Never assume otherwise.
- Tests for frame encode/decode, oversize frame rejection, rate limiter, request
  validation, and engine lifecycle with a mock provider / in-memory storage.
  Named-pipe integration tests must skip cleanly if a pipe cannot be created.

File ownership: `crates/security-ipc/**`, `services/security-service/**`,
`packaging/service-installer/**`, `tests/integration/service_*.rs`. Do not edit
`crates/security-core`, root `Cargo.toml`, `src-tauri/**`, or the frontend. Run
`cargo test -p security-ipc -p security-service` and report exact results.
