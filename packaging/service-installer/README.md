# Windows service installer

The AI Antivirus desktop app is an unprivileged WinUI process. Kernel-adjacent
work (process telemetry, file scanning, the quarantine vault and the SQLite
database) runs in the separate `security-service` Windows service. The desktop
app talks to it over the local named pipe `\\.\pipe\ai-antivirus-security`.

This folder contains the packaging scripts for that service:

| File | Purpose |
| --- | --- |
| `install-service.ps1` | Create the service, switch it to LocalService, set recovery actions, harden ACLs and start it. |
| `uninstall-service.ps1` | Stop and delete the service; preserve data by default. |
| `README.md` | Deployment, verification and troubleshooting notes. |

Both scripts require an elevated PowerShell session and Windows 10/11. They
are the supported packaging path; `security-service.exe --install` provides the
same registration for developer machines but does not replace a signed
installer in production.

## Prerequisites

* Windows 10 1809+ or Windows 11 (x64/arm64).
* PowerShell 5.1 or PowerShell 7+.
* An elevated shell (`#Requires -RunAsAdministrator` enforces this).
* A built `security-service.exe` (`cargo build -p security-service --release`)
  and the `security-service` crate's runtime dependencies. The binary is
  self-contained apart from the Visual C++ runtime that ships with Windows.
* No existing service with the same name. Run the uninstall script first when
  upgrading.

The service runs as `NT AUTHORITY\LocalService`, not LocalSystem. It needs
read access to the paths users ask it to scan; files outside that account's
access (for example other users' private profiles) fail with a descriptive
scanner error instead of running with administrator rights.

## Install

From an elevated PowerShell prompt:

```powershell
Set-Location .\packaging\service-installer
.\install-service.ps1 -BinaryPath 'C:\Program Files\AI Antivirus\security-service.exe'
```

Without `-BinaryPath` the script looks for `security-service.exe` next to
itself, then in `target\release` and `target\debug` relative to the repository.
Useful switches:

| Switch | Effect |
| --- | --- |
| `-NoStart` | Register the service but leave it stopped (Manual startup). |
| `-SkipAcl` | Do not rewrite the data-directory ACL. Only when another installer already hardened it. |
| `-DataDirectory <path>` | Use a different data root. Defaults to `%ProgramData%\AiAntivirus`. |

The script performs these steps:

1. Creates `%ProgramData%\AiAntivirus`, `quarantine\` and `logs\`.
2. Removes inherited ACEs from the data root and grants:
   * `SYSTEM` and `Administrators` — full control (recursive).
   * `NT AUTHORITY\LocalService` — modify (recursive).
   The database contains process and file telemetry that should not be
   world-readable.
3. Creates the service with `New-Service`:
   * Name: `AiAntivirusSecurityService`
   * Display name: `AI Antivirus Security Engine`
   * Startup: **Manual** (the agent/app decides when to start it)
   * Account: `NT AUTHORITY\LocalService` (set with `sc.exe config ... obj=`)
4. Configures SCM recovery with `sc.exe failure`: restart after 5 s, then
   10 s, then 30 s, resetting the failure counter after 86 400 s.
5. Starts the service and waits for `\\.\pipe\ai-antivirus-security`.

The service executable itself has a second installation path:

```powershell
security-service.exe --install     # register, harden ACLs, start
security-service.exe --uninstall   # stop, delete, preserve data
security-service.exe --start
security-service.exe --stop
```

It uses the same service identity and recovery configuration. Packaging should
prefer the PowerShell scripts because they can be signed and versioned together
with the rest of the installer.

## Data and logs

| Item | Path |
| --- | --- |
| Data root | `%ProgramData%\AiAntivirus` |
| SQLite database | `%ProgramData%\AiAntivirus\security.db` |
| Quarantine vault | `%ProgramData%\AiAntivirus\quarantine` |
| Service log | `%ProgramData%\AiAntivirus\logs\security-service.log` |
| Pipe | `\\.\pipe\ai-antivirus-security` |

The data directory can be overridden with the `AI_ANTIVIRUS_DATA_DIR`
environment variable (development/testing only). Set it for the service
account, not just the current user, if the service must honour it.

Logging is append-only and has no built-in rotation. For long-lived
deployments add a scheduled task/agent policy that trims
`security-service.log` (for example at 10–50 MiB) or forwards it to the
endpoint management pipeline. Do not delete the file while the service is
running; truncate or rotate it with a copy-and-replace operation.

## Verify

```powershell
Get-Service AiAntivirusSecurityService
sc.exe qc AiAntivirusSecurityService
sc.exe qfailure AiAntivirusSecurityService
Get-Content "$env:ProgramData\AiAntivirus\logs\security-service.log" -Tail 50
Test-Path '\\.\pipe\ai-antivirus-security'
```

Expected values:

* `STATE` is `RUNNING` after installation.
* `START_TYPE` is `DEMAND_START` (Manual).
* `SERVICE_START_NAME` is `NT AUTHORITY\LocalService`.
* Recovery actions show three restarts and a reset period of 86 400 s.
* The pipe exists while the service is running.

A quick protocol check from a client uses `security_ipc::pipe::call_pipe` with
`ClientRequest::Ping`; the reply must be a `Pong` with version `1`. The service
rejects clients that send an unknown protocol version, oversized frames
(> 1 MiB) or malformed JSON with a structured `Error` response.

For development, run the engine in the foreground instead of installing it:

```powershell
$env:AI_ANTIVIRUS_DATA_DIR = "$env:TEMP\ai-antivirus-dev"
$env:AI_ANTIVIRUS_AI_MOCK = '1'
security-service.exe --console
```

`--console` serves the same pipe, logs to stderr and stops on Enter or Ctrl+C.

## Uninstall and upgrade

```powershell
# Preserve database, logs and quarantined files (default)
.\uninstall-service.ps1

# Also delete %ProgramData%\AiAntivirus — irreversible
.\uninstall-service.ps1 -PurgeData
```

The default uninstall stops the service, deletes the SCM entry and leaves the
quarantine vault intact. Quarantined files may still be needed for incident
review or restoration, so deletion must be an explicit decision.

To upgrade, run the uninstall script (without `-PurgeData`), replace the
binary, then run the install script again. The database schema is migrated by
the service on startup; keep a backup of `security.db` for major upgrades.

## Why not MSIX?

An MSIX package cannot install the security service:

* MSIX installs per-user app payloads and cannot create or control a Windows
  service through the Service Control Manager.
* The package cannot run as `LocalService`, set SCM recovery actions, or grant
  service-account ACLs on `%ProgramData%`.
* Store/MSIX policy expects the app to run at the user's privilege level;
  privileged background services belong to a separate, signed installer.

Ship the WinUI client as MSIX and the service as a signed MSI/EXE bootstrapper
(MSIX Bundle + optional elevated installer, or a classic installer that
installs both). The client should treat a missing service as "engine not
installed": `call_pipe` returns a descriptive `IpcError::Pipe` ("does not
exist; is the AI Antivirus security service installed and running?") and the UI
should offer to start the service or point the user at the installer. Do not
silently fall back to scanning inside the unprivileged client.

## Security properties

* The pipe DACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` — SYSTEM and
  Administrators have full access, interactive users can read/write, and
  remote clients are rejected with `PIPE_REJECT_REMOTE_CLIENTS`.
* Each connection has its own token bucket (`64` burst, `32` requests/second by
  default). Repeated violations disconnect the client.
* Frames are 4-byte little-endian length-prefixed JSON capped at 1 MiB; empty,
  truncated, oversized and unknown-version messages are rejected before
  parsing.
* Paths accepted over IPC must be absolute and exist. The service validates
  list limits, ids and free-text reasons. Quarantine operations never accept a
  path inside the vault.
* The service does not run as administrator. This limits the blast radius of a
  scanner bug at the cost of not being able to inspect every user profile.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Install fails with "service already exists" | Run `uninstall-service.ps1`, wait for deletion, retry. |
| `sc.exe config` fails with access denied | The shell is not elevated. |
| Service exits immediately / error 1069 | The logon account or profile is wrong. Re-run the install script; LocalService needs no password. |
| Pipe is missing but the service is Running | Another process may hold `\\.\pipe\ai-antivirus-security` (the server refuses to squat). Check `security-service.log`. |
| Client gets "access denied connecting to pipe" | The client is not an interactive user, Administrator or SYSTEM (for example a restrictive service or sandbox). |
| Client gets "does not exist" | The service is not installed, stopped, or was started with a different pipe name (not supported). |
| Database is locked | Only one service instance may use `%ProgramData%\AiAntivirus\security.db`. Stop stray `--console` instances. |
| Uninstall says "marked for deletion" | A handle to the service is still open. Close Services.msc/PowerShell sessions and retry in a few seconds. |
| Scanning many files fails with access denied | Expected for LocalService; scan user-owned or public paths, or run targeted scans from the app. |

## Recovery behaviour

SCM recovery restarts the service after a crash. It does not restart the
quarantine database or repair a corrupted vault. If the engine cannot open the
database, it reports the error in the log and the service stops; the SCM then
applies the crash recovery policy. Repeated restarts indicate a persistent
configuration/storage problem, so check the log rather than increasing the
restart count.
