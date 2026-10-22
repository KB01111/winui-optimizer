# Security regression tests

This directory is the index for the **security regression suite** — the tests
that protect the invariants the product promises, rather than the tests that
exercise features.

The audit that motivated this suite is
[`docs/SECURITY_AUDIT.md`](../../docs/SECURITY_AUDIT.md). The threat model
and the L1–L10 residual-risk table are in
[`docs/SECURITY.md`](../../docs/SECURITY.md).

## Where the Rust tests live

The Rust security regression tests are a Cargo integration-test target in the
`tauri-app` package:

| File | Target | Run with |
|---|---|---|
| [`src-tauri/tests/security_invariants.rs`](../../src-tauri/tests/security_invariants.rs) | `security_invariants` | `cargo test -p tauri-app --test security_invariants` |

They live there rather than in this directory because the repository root
`Cargo.toml` is a **workspace-only** manifest: a `tests/` directory at the
repository root is not a Cargo package and would never be compiled. The
`tauri-app` package already depends on every crate the tests need
(`security-core`, `security-policy`, `security-scanner`, `security-storage`,
`security-ipc`, `ai-decisions` — see `src-tauri/Cargo.toml`) and already has
the `tempfile` dev-dependency, so the target compiles without any manifest
change.

## Invariants covered by `security_invariants`

| Test | Invariant protected |
|---|---|
| `ai_decision_can_never_trigger_quarantine_in_any_policy_configuration` | **AI output can never trigger quarantine or any destructive action.** A maximally aggressive `DecisionResult` (category `likely_malicious`, confidence 1.0, every high-impact flag raised) fed to `PolicyEngine::evaluate_ai_only` must never yield `Quarantine` and must always report `quarantine_allowed == false`, across the shipped defaults and the most permissive configuration the settings UI can produce. |
| `auto_quarantine_requires_a_deterministic_hash_or_yara_basis` | **Auto-quarantine requires a deterministic basis.** A scan report whose only evidence is an AI decision (no known hash, no YARA match) must not reach `Quarantine`, even with auto-quarantine enabled and the known-hash requirement waived. Includes a control case proving the assertion is not vacuous. |
| `event_evaluation_is_capped_at_alert` | **Behaviour-only events never quarantine.** No combination of behavioural labels, a critical severity and a known-hash assessment attached to an *event* may produce a quarantine outcome. |
| `quarantine_restore_never_overwrites_an_existing_file` | **Restore refuses to overwrite.** After a successful restore, a second restore attempt must be refused and must leave the on-disk file byte-identical. |
| `quarantine_vault_rejects_symlinks` | **Symlinks and reparse points are never copied into the vault** (a copy would point at a target outside the vault). Skips gracefully when the OS does not permit symlink creation. |
| `quarantine_delete_touches_only_the_vault_copy` | **Delete removes only the vault copy and its sidecar.** The original file must survive with byte-identical content. |
| `ipc_rejects_oversized_and_truncated_frames` | **The IPC transport enforces a hard frame size limit.** A frame larger than `MAX_FRAME_BYTES` is rejected before allocation; a truncated frame or a short header is rejected instead of being partially interpreted. The test also proves the limit is inclusive by decoding a frame of exactly `MAX_FRAME_BYTES`. |
| `api_key_is_never_serialized_or_debug_printed` | **The OpenRouter API key never reaches the React layer, the event log or a persisted configuration.** `AiConfig` (the type the desktop layer serialises into the `ai.config` settings row) and `ProviderConfig` must never emit the key through `Serialize` or `Debug`. |

## Related coverage elsewhere in the workspace

These are **not** duplicated here, but they are the primary enforcement points
referenced by the audit:

| Area | Tests |
|---|---|
| Policy gating matrix and AI caps | `crates/security-policy/src/tests.rs` — `auto_quarantine_gating_matrix`, `evaluate_ai_only_never_quarantines`, `ai_cannot_quarantine_a_clean_scan`, `event_severity_floors_and_never_quarantines` |
| Quarantine vault unit tests | `crates/security-scanner/src/tests.rs` — `quarantine_round_trip_restores_bytes`, `restore_refuses_to_overwrite_existing_file`, `quarantine_names_are_collision_safe`, `quarantine_delete_removes_only_vault_copy`, `quarantine_rejects_symlinks` |
| Cross-layer integration | `src-tauri/tests/engine_pipeline.rs` — `ai_output_can_never_quarantine`, `cloud_state_redaction_removes_paths_users_and_full_hashes`, `quarantine_copy_is_verified_and_restorable` |
| IPC framing and rate limits | `crates/security-ipc/src/lib.rs` — `frame_rejects_oversized_payloads`, `frame_rejects_truncated_payloads`, `frame_rejects_trailing_bytes`, `rate_limiter_allows_burst_then_denies` |
| Pipe ACL probe | `crates/security-ipc/src/pipe/windows.rs` — `acl_probe_reports_expected_principals` (see audit finding SEC-001) |
| Secret scrubbing | `crates/ai-decisions/src/error.rs` — `sanitizer_removes_keys_and_bearer_tokens`, `sanitizer_redacts_json_embedded_keys`; `crates/ai-decisions/src/provider_tests.rs` — `api_key_never_appears_in_errors_or_debug`; `crates/ai-decisions/src/types.rs` — `ai_config_debug_and_serialize_redact_key` |
| Redaction | `crates/ai-decisions/src/redaction.rs` — `redacts_usernames_and_absolute_paths_in_command_lines`, `truncates_hashes_to_eight_characters`, `scrubs_hashes_and_paths_in_reasons_and_rule_names` |
| Subprocess hardening | `crates/windows-integration/src/process_util.rs` — `kills_processes_that_exceed_the_deadline`, `captures_stdout_and_exit_code` |

## Notes

- These tests never touch the network, never execute scanned content and do
  not require Windows package identity.
- The symlink test is `#[cfg(windows)]` and prints a skip message (rather
  than failing) on a machine where creating symlinks is not permitted.
- See §7 of [`docs/SECURITY_AUDIT.md`](../../docs/SECURITY_AUDIT.md) for the
  invariants that could **not** be verified automatically and the manual
  checks required for them.
