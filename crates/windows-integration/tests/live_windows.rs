//! Live Windows integration checks.
//!
//! These tests call real Windows APIs (registry, token, WinRT package
//! activation, the read-only Defender probe) and are therefore excluded from
//! the default test run. Execute them explicitly with:
//!
//! ```text
//! cargo test -p windows-integration --test live_windows -- --ignored --nocapture
//! ```

#![cfg(windows)]

#[test]
#[ignore = "queries live Windows APIs; run explicitly with --ignored"]
fn reports_plausible_platform_state() {
    let version = windows_integration::windows_version();
    println!("windows_version: {version:#?}");

    let identity = windows_integration::package_identity();
    println!("package_identity: {identity:#?}");

    let context = windows_integration::execution_context();
    println!("execution_context: {context:#?}");

    let defender = windows_integration::defender_status();
    println!("defender_status: {defender:#?}");

    // Every supported Windows build reports at least 10.0 through the registry
    // source, regardless of application manifest.
    assert!(version.major >= 10, "unexpected major version: {version:?}");
    assert!(version.build >= 10_240, "unexpected build: {version:?}");
    assert!(!version.architecture.is_empty());
    assert_eq!(version.is_windows_11, version.build >= 22_000);

    // The username must never be returned verbatim; the raw name is only
    // available to the test for comparison, never from the library.
    if let (Some(redacted), Ok(raw)) = (&context.username_redacted, std::env::var("USERNAME")) {
        let raw = raw.trim();
        assert!(!redacted.is_empty());
        if raw.chars().count() >= 3 {
            assert_ne!(redacted.as_str(), raw);
        }
    }
    assert!(context.process_id > 0);
    assert!(!context.user_sid.as_deref().unwrap_or("").is_empty());
}

#[test]
#[ignore = "queries live Windows APIs; run explicitly with --ignored"]
fn dpapi_round_trip_against_live_api() {
    let secret = b"live dpapi round trip";
    let protected = windows_integration::protect_secret(secret).expect("protects");
    let unprotected = windows_integration::unprotect_secret(&protected).expect("unprotects");
    assert_eq!(unprotected, secret);
}
