# Packaging and deployment

The project produces two independent Windows distributions plus an optional
background service. They solve different problems and are **not**
interchangeable.

| Artifact | Identity | Notifications | 24/7 monitoring | Installer |
|---|---|---|---|---|
| MSIX (`winapp`) | MSIX package identity (upstream `tauri-app`) | Yes | No (embedded engine only while running) | `winapp` / App Installer |
| NSIS (`tauri build`) | None | No (graceful `NoPackageIdentity`) | No | per-user EXE |
| Service (`AiAntivirusSecurityService`) | Windows service, LocalService | N/A | Yes | separate elevated script |

> **Build environment note (this checkout):** `winapp` is **not installed**, so
> MSIX packing/running and packaged-toast checks are **unverified** and reported
> as skipped by `tests/packaging-checks.ps1`. The NSIS build requires a full
> Tauri build; its result is recorded in `docs/VERIFICATION.md`. Nothing in this
> document should be read as a claim that an unexecuted step passed.

## 1. MSIX (package identity + notifications)

The upstream winappCli flow is preserved.

### One-time setup

```powershell
winget install Microsoft.winappcli --source winget
winapp cert generate --if-exists skip
# Administrator:
winapp cert install .\devcert.pfx
```

### Build and run with identity

```powershell
# Frontend + debug backend + staged exe + winapp run
npm run tauri:dev:withidentity
```

or manually:

```powershell
npm run build
cargo build --manifest-path src-tauri/Cargo.toml
if (!(Test-Path dist)) { New-Item -ItemType Directory dist | Out-Null }
Copy-Item .\src-tauri\target\debug\tauri-app.exe .\dist\
winapp run .\dist
```

`winapp run` uses `appxmanifest.xml` and `Assets/`. The manifest is configured
with the preserved identity:

```xml
<Identity Name="tauri-app" Publisher="CN=nikolame" Version="1.0.0.0" />
```

- **Do not change `Name`/`Publisher`** unless you also generate a matching
  certificate and update `devcert.pfx`; changing them breaks the extracted
  sample's identity and notification integration.
- Display name/description are re-branded to “AI Antivirus”; the AUMID remains
  derived from the preserved identity.
- `Assets/StoreLogo.png`, `Square150x150Logo.png`, `Square44x44Logo.png`,
  `Wide310x150Logo.png` are required and checked by the packaging script.

### Package and sign

```powershell
npm run pack:msix
```

This builds release (`npm run tauri build`), stages
`src-tauri/target/release/tauri-app.exe` into `dist/`, and runs
`winapp pack .\dist --cert .\devcert.pfx`. The resulting `.msix` can be
double-clicked to install once the certificate is trusted.

For production:

1. Obtain a trusted code-signing certificate whose subject matches
   `Publisher` (or change both together).
2. Sign with `signtool`/`winapp` and timestamp the signature.
3. Consider `PackageIntegrity` enforcement (already enabled in the manifest) and
   an update channel (`App Installer` URI) if distributing via HTTPS.
4. Validate on a clean Windows 11 VM: install, launch, run a scan, send a toast,
   uninstall, confirm `%LOCALAPPDATA%\AiAntivirus` behavior.

## 2. NSIS installer (no identity)

```powershell
npm run tauri build
```

Output is under `src-tauri/target/release/bundle/nsis/`. This installer is
per-user and does not require a certificate. Because it has no package
identity:

- **toast notifications are unavailable** — the command returns
  `NoPackageIdentity` and the Settings page explains this;
- package family name reports `No package identity`.

Use this channel for local development or environments without MSIX.

## 3. Background service (optional)

MSIX cannot register Windows services. The service is therefore a separate
component and requires administrator rights once for installation.

Service identity:

| Property | Value |
|---|---|
| Name | `AiAntivirusSecurityService` |
| Display name | `AI Antivirus Security Engine` |
| Account | `NT AUTHORITY\LocalService` |
| Start type | Manual (default) |
| Binary | `services/security-service` release build |
| Data | `%ProgramData%\AiAntivirus` (override: `AI_ANTIVIRUS_DATA_DIR`) |
| IPC | `\\.\pipe\ai-antivirus-security` |

### Build

```powershell
cargo build --release -p security-service
```

### Install

Use the installer scripts in `packaging/service-installer/`:

```powershell
# Administrator PowerShell, from the repository root
powershell -ExecutionPolicy Bypass -File .\packaging\service-installer\install-service.ps1
powershell -ExecutionPolicy Bypass -File .\packaging\service-installer\uninstall-service.ps1
```

If the scripts are unavailable in your checkout, the equivalent manual steps
are:

```powershell
sc.exe create AiAntivirusSecurityService binPath= "C:\Path\security-service.exe" start= demand obj= "NT AUTHORITY\LocalService" DisplayName= "AI Antivirus Security Engine"
sc.exe description AiAntivirusSecurityService "Deterministic local security telemetry, scanning and quarantine engine for AI Antivirus."
sc.exe start AiAntivirusSecurityService
sc.exe query AiAntivirusSecurityService
```

The installer is responsible for:

- copying the binary to a protected location (for example
  `%ProgramFiles%\AiAntivirus\`),
- granting LocalService access to the data directory,
- creating the service with a manual start type and least-privilege account,
- optionally opening the named-pipe ACL only to the interactive user,
- clean removal (stop, delete service, leave or delete data only with explicit
  confirmation).

**Security:** the service must never run as `LocalSystem` merely for
convenience. It has no driver, no kernel component, and no Defender mutation
capability. Test installation in a VM or after a restore point.

### Desktop ↔ service

The desktop app detects the pipe, calls `Ping` with an 800 ms timeout, and shows
version/uptime in the Overview page. The embedded engine remains the source of
the live dashboard feed in v1.0; switching the entire feed to the service is a
v1.1 item. See the IPC limitation in [`SECURITY.md`](SECURITY.md).

## 4. Data locations and uninstall

| Mode | Database / vault | Logs |
|---|---|---|
| Desktop (MSIX or NSIS) | `%LOCALAPPDATA%\AiAntivirus\security.db`, `...\quarantine\` | local tracing output |
| Service | `%ProgramData%\AiAntivirus\security.db`, `...\quarantine\` | service logs (v1.0: stderr/host) |

Uninstalling the app does **not** silently delete quarantined copies or
security history. Remove the data directory manually after backing up anything
you need. Quarantined files are copies; restoring copies back to the original
path is explicit and refuses to overwrite.

## 5. Verification checklist

Automated static checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\packaging-checks.ps1
```

It verifies manifest identity, versions, architecture, assets/icons, toolchain
presence, certificate presence and any produced artifacts. Missing `winapp` or
artifacts are reported as **SKIP**, not pass.

Manual, unverified in this environment:

- [ ] MSIX pack and install on a clean Windows 11 VM
- [ ] Toast while packaged
- [ ] Toast while unpackaged shows the exact “no package identity” message
- [ ] NSIS installer install/uninstall
- [ ] Service install, start, ping from the app, stop, uninstall
- [ ] Scheduled scan while the UI is closed (service)
- [ ] Upgrade in place (MSIX version bump) preserves settings/history
