# Attribution and third-party notices

## Upstream sample

This repository was **extracted from**, not forked from, Microsoft's
[`microsoft/winappCli`](https://github.com/microsoft/winappCli) repository,
specifically `samples/tauri-app/`. The original sample demonstrated:

- a Tauri desktop application,
- retrieving MSIX package identity through `Windows.ApplicationModel.Package`,
- sending Windows toast notifications via `Windows.UI.Notifications`,
- packaging with winappCli (`appxmanifest.xml`, `Assets/`, `devcert.pfx`
  workflow).

Retained from upstream:

- `appxmanifest.xml` — **package identity is intentionally unchanged**
  (`Name="tauri-app"`, `Publisher="CN=nikolame"`) so the sample's identity and
  notification integration keep working.
- `Assets/` (package logos), `src-tauri/icons/`, the winappCli dev-certificate
  workflow, `test.Tests.ps1`, and the winappCli packaging scripts in
  `package.json` (`tauri:dev:withidentity`, `pack:msix`).
- The original `get_package_family_name` and `show_notification` integration
  behaviour, now wrapped by `windows-integration` / the Tauri command layer.
  The two sample-only Tauri commands that duplicated them (`greet` and
  `get_package_family_name`, plus the free-text `show_notification`) were
  removed: they sat outside the frozen command contract and
  `show_notification` could raise arbitrary toast text under the app's AUMID.
  The package identity and the notification test are served by the contracted
  `get_system_status` and `send_test_notification` commands instead.

Changes made for this project: the vanilla HTML/JS frontend was replaced with
React 19 + Fluent UI v9, the Rust backend was replaced with the full security
engine, and the repository was extended with `crates/`, `services/`,
`packaging/`, `tests/`, `docs/` and `.claude/agents/`. The sample remains at the
repository root deliberately (rather than `apps/desktop/`) to preserve the MSIX
manifest/paths/identity.

Upstream license: MIT. Copyright (c) Microsoft Corporation. See
<https://github.com/microsoft/winappCli/blob/main/LICENSE>.

## Runtime and build dependencies

This project depends on open-source packages resolved via Cargo and npm. Exact
versions are pinned in `Cargo.lock` and `package-lock.json`; the table lists the
direct dependencies and their licenses.

| Component | Version (pinned) | License |
|---|---|---|
| Tauri | 2.x | MIT / Apache-2.0 |
| tauri-plugin-opener | 2.x | MIT / Apache-2.0 |
| React / React DOM | 19.x | MIT |
| Fluent UI React Components | 9.x | MIT |
| Fluent UI React Icons | 2.x | MIT |
| Vite | 7.x | MIT |
| TypeScript | 5.9.x | Apache-2.0 |
| ESLint (+ typescript-eslint, react-hooks, react-refresh plugins) | 9.x | MIT |
| Vitest / Testing Library | current | MIT |
| yara-x | 1.21.0 | BSD-3-Clause |
| SQLite (via rusqlite) | 3.x | Public domain |
| rusqlite | 0.40 | MIT |
| windows-rs (`windows`) | 0.62.2 | MIT / Apache-2.0 |
| reqwest | 0.12 | MIT / Apache-2.0 |
| tokio | 1.x | MIT |
| serde / serde_json | 1.x | MIT / Apache-2.0 |
| chrono | 0.4 | MIT / Apache-2.0 |
| tracing / tracing-subscriber | 0.1 / 0.3 | MIT |
| thiserror | 2.x | MIT / Apache-2.0 |
| uuid | 1.x | Apache-2.0 / MIT |
| sha2 | 0.10 | MIT / Apache-2.0 |
| parking_lot | 0.12 | MIT / Apache-2.0 |
| base64 | 0.22 | MIT / Apache-2.0 |
| walkdir | 2.x | Unlicense / MIT |
| tempfile (tests) | 3.x | MIT / Apache-2.0 |

The full transitive dependency set, including licenses, is described by
`Cargo.lock` and `package-lock.json`. No dependency is vendored or modified.

## Rules and fixtures

- `crates/security-scanner/rules/default.yar` was written for this project. It
  contains the industry-standard EICAR test signature encoded as a hex string
  (so the rule file itself is not flagged) plus rules for PowerShell download
  cradles and writable+executable PE sections. The EICAR string is a harmless
  antivirus test pattern, not malware.
- Test fixtures are inert bytes/strings. No malware sample is included or
  downloaded. Tests never execute scanned content.

## Services and trademarks

- AI decisions use the OpenRouter **Decisions API** and the models
  `inception/mercury-decide`, `inception/mercury-decide:free` and
  `typesafe/jev-1.14`. These are third-party services/models; this project is not
  affiliated with or endorsed by OpenRouter, Inception Labs or TypeSafe.
- Microsoft, Windows, Microsoft Defender and related marks are trademarks of
  Microsoft Corporation. This project is not affiliated with or endorsed by
  Microsoft.
- YARA is a trademark of VirusTotal. YARA-X is an independent Rust
  implementation.

## Fonts and artwork

The dashboard uses Fluent UI's system font stack and Segoe UI on Windows; no
custom font files are bundled. Package logos and Tauri icons originate from the
upstream winappCli sample (MIT).
