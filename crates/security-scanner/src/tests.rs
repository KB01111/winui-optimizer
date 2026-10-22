//! Unit tests for the scanner crate.
//!
//! Fixtures are written to temporary directories at runtime. The EICAR
//! fixture is a harmless, industry-standard test string that is only ever
//! written to disk and scanned; it is never executed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use security_core::{QuarantineStatus, ScanProgress, ScanSource};

use super::*;

/// The standard EICAR anti-malware test string. Harmless: it is never
/// executed, only written to temporary files so YARA matching can be verified
/// end to end. The backslash is escaped for Rust string syntax.
const EICAR_TEST_STRING: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temp dir")
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn scanner() -> Scanner {
    Scanner::new(ScannerConfig::default()).expect("default scanner")
}

fn scanner_with(config: ScannerConfig) -> Scanner {
    Scanner::new(config).expect("configured scanner")
}

/// EICAR fixture with a leading comment line, so the file does not start with
/// the bare signature (temporary test directories are scanned by resident
/// antivirus products) while YARA still matches the string.
fn eicar_fixture() -> String {
    format!("; harmless EICAR test fixture, used by security-scanner tests\n{EICAR_TEST_STRING}\n")
}

/// Builds a tiny but valid PE64 image with one `.text` section that is
/// writable and executable, an import of `KERNEL32.dll!CreateFileW`, and
/// optionally an export table, a .NET COM descriptor and the DLL flag.
fn tiny_pe_fixture(with_exports: bool, with_dotnet: bool, is_dll: bool) -> Vec<u8> {
    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut data = vec![0u8; 0x600];
    // Raw section content first (pattern bytes), structures overwrite parts.
    for (index, byte) in data[0x200..0x600].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    // DOS header.
    data[0] = b'M';
    data[1] = b'Z';
    put_u32(&mut data, 0x3C, 0x40);

    // PE signature + COFF header.
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    put_u16(&mut data, coff, 0x8664); // machine = amd64
    put_u16(&mut data, coff + 2, 1); // 1 section
    put_u32(&mut data, coff + 4, 0x1234_5678); // timestamp
    put_u16(&mut data, coff + 16, 0xF0); // size of optional header
    put_u16(&mut data, coff + 18, if is_dll { 0x2022 } else { 0x0022 });

    // Optional header (PE32+).
    let opt = coff + 20; // 0x58
    put_u16(&mut data, opt, 0x20B);
    put_u32(&mut data, opt + 16, 0x1000); // entry point
    put_u16(&mut data, opt + 68, 3); // windows_console
    put_u32(&mut data, opt + 108, 16); // number of data directories
    let dirs = opt + 112; // 0xC8
    if with_exports {
        put_u32(&mut data, dirs, 0x1200); // export table RVA
        put_u32(&mut data, dirs + 4, 0x28);
    }
    put_u32(&mut data, dirs + 8, 0x1000); // import descriptor table RVA (index 1)
    put_u32(&mut data, dirs + 12, 0x28);
    if with_dotnet {
        put_u32(&mut data, dirs + 14 * 8, 0x1300); // COM descriptor (index 14)
        put_u32(&mut data, dirs + 14 * 8 + 4, 0x48);
    }

    // Section table.
    let section = opt + 0xF0; // 0x148
    data[section..section + 6].copy_from_slice(b".text\0");
    put_u32(&mut data, section + 8, 0x2000); // virtual size
    put_u32(&mut data, section + 12, 0x1000); // virtual address
    put_u32(&mut data, section + 16, 0x400); // raw size
    put_u32(&mut data, section + 20, 0x200); // raw pointer
    put_u32(&mut data, section + 36, 0xE000_0020); // code | exec | read | write

    // Import directory table at raw 0x200 (RVA 0x1000).
    put_u32(&mut data, 0x200, 0x1100); // OriginalFirstThunk (RVA)
    put_u32(&mut data, 0x20C, 0x1080); // Name (RVA)
    put_u32(&mut data, 0x210, 0x1100); // FirstThunk (RVA)
    data[0x214..0x228].fill(0); // terminator descriptor
    data[0x280..0x28D].copy_from_slice(b"KERNEL32.dll\0");
    put_u64(&mut data, 0x300, 0x1180); // thunk -> import-by-name
    data[0x308..0x310].fill(0); // terminator thunk
    put_u16(&mut data, 0x380, 0); // hint
    data[0x382..0x38E].copy_from_slice(b"CreateFileW\0");

    if with_exports {
        // IMAGE_EXPORT_DIRECTORY at raw 0x400 (RVA 0x1200).
        put_u32(&mut data, 0x400 + 12, 0x1240); // Name RVA
        put_u32(&mut data, 0x400 + 16, 1); // Base
        put_u32(&mut data, 0x400 + 20, 1); // NumberOfFunctions
        put_u32(&mut data, 0x400 + 24, 1); // NumberOfNames
        put_u32(&mut data, 0x400 + 28, 0x1280); // AddressOfFunctions
        put_u32(&mut data, 0x400 + 32, 0x1290); // AddressOfNames
        put_u32(&mut data, 0x400 + 36, 0x12A0); // AddressOfNameOrdinals
        put_u32(&mut data, 0x480, 0x1000); // function RVA
        put_u32(&mut data, 0x490, 0x12B0); // export name RVA
        put_u16(&mut data, 0x4A0, 0); // ordinal
        data[0x4B0..0x4BB].copy_from_slice(b"TestExport\0");
    }

    data
}

#[test]
fn hashing_matches_known_vectors() {
    let dir = tmp();
    let hello = write_file(dir.path(), "hello.txt", b"hello world");
    assert_eq!(
        compute_sha256(&hello).expect("hash hello"),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    let empty = write_file(dir.path(), "empty.bin", b"");
    assert_eq!(
        compute_sha256(&empty).expect("hash empty"),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn entropy_bounds() {
    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-6);

    let mut uniform = Vec::new();
    for _ in 0..64 {
        uniform.extend(0u8..=255);
    }
    let entropy = shannon_entropy(&uniform);
    assert!(
        entropy > 7.99 && entropy <= 8.0,
        "uniform entropy was {entropy}"
    );
}

#[test]
fn pe_parser_reads_tiny_fixture() {
    let fixture = tiny_pe_fixture(true, false, false);
    let metadata = analyze_pe(&fixture).expect("fixture is a PE");

    assert_eq!(metadata.machine, "amd64");
    assert_eq!(metadata.subsystem, "windows_console");
    assert!(!metadata.is_dll);
    assert!(!metadata.is_dotnet);
    assert_eq!(metadata.timestamp, Some(0x1234_5678));
    assert_eq!(metadata.entry_point, Some(0x1000));

    assert_eq!(metadata.sections.len(), 1);
    let section = &metadata.sections[0];
    assert_eq!(section.name, ".text");
    assert!(section.executable);
    assert!(section.writable);
    assert!(
        section.entropy > 0.0 && section.entropy < 8.0,
        "section entropy {}",
        section.entropy
    );

    assert_eq!(metadata.imports.len(), 1);
    assert_eq!(metadata.imports[0].dll, "KERNEL32.dll");
    assert_eq!(
        metadata.imports[0].functions,
        vec!["CreateFileW".to_string()]
    );
    assert_eq!(metadata.exports, vec!["TestExport".to_string()]);
}

#[test]
fn pe_parser_reads_flags() {
    let dll = analyze_pe(&tiny_pe_fixture(false, false, true)).expect("dll parses");
    assert!(dll.is_dll);
    assert!(dll.exports.is_empty());

    let dotnet = analyze_pe(&tiny_pe_fixture(false, true, false)).expect("dotnet parses");
    assert!(dotnet.is_dotnet);
}

#[test]
fn pe_parser_does_not_panic_on_malformed_input() {
    assert_eq!(analyze_pe(&[]), None);
    assert_eq!(analyze_pe(b"MZ"), None);
    assert_eq!(analyze_pe(&[0xAB; 4096]), None);

    let mut bad_offset = vec![0u8; 64];
    bad_offset[0] = b'M';
    bad_offset[1] = b'Z';
    bad_offset[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert_eq!(analyze_pe(&bad_offset), None);

    let mut no_pe_signature = vec![0u8; 64];
    no_pe_signature[0] = b'M';
    no_pe_signature[1] = b'Z';
    no_pe_signature[2] = b'X';
    assert_eq!(analyze_pe(&no_pe_signature), None);

    // Every truncation of a valid fixture must return without panicking.
    let fixture = tiny_pe_fixture(true, true, true);
    for length in 0..fixture.len() {
        let _ = analyze_pe(&fixture[..length]);
    }

    // Header corruption: huge section count and out-of-range import RVA.
    let mut corrupt = fixture.clone();
    corrupt[0x44 + 2..0x44 + 4].copy_from_slice(&0xFFFEu16.to_le_bytes());
    let _ = analyze_pe(&corrupt);
    let mut corrupt = fixture.clone();
    corrupt[0xC8 + 8..0xC8 + 12].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
    let _ = analyze_pe(&corrupt);
}

#[test]
fn pe_parser_handles_the_test_executable() {
    let exe = std::env::current_exe().expect("current test executable");
    let data = std::fs::read(&exe).expect("read test executable");
    let metadata = analyze_pe(&data).expect("the test executable is a PE image");
    assert!(!metadata.machine.is_empty());
    assert!(
        metadata
            .sections
            .iter()
            .any(|section| !section.name.is_empty()),
        "at least one named section"
    );
}

#[test]
fn scanner_config_defaults_match_contract() {
    let config = ScannerConfig::default();
    assert_eq!(config.max_file_size, 128 * 1024 * 1024);
    assert_eq!(config.max_hash_size, 512 * 1024 * 1024);
    assert_eq!(config.yara_timeout_ms, 5000);
    assert!(!config.follow_symlinks);
    assert!(config.extra_yara_rules.is_none());
}

#[test]
fn scanner_rejects_invalid_config_and_rules() {
    assert!(matches!(
        Scanner::new(ScannerConfig {
            max_file_size: 0,
            ..Default::default()
        }),
        Err(ScanError::Invalid(_))
    ));
    assert!(matches!(
        Scanner::new(ScannerConfig {
            max_hash_size: 0,
            ..Default::default()
        }),
        Err(ScanError::Invalid(_))
    ));
    assert!(matches!(
        Scanner::new(ScannerConfig {
            extra_yara_rules: Some("rule broken { condition: ".to_string()),
            ..Default::default()
        }),
        Err(ScanError::Rules(_))
    ));
}

#[test]
fn scanner_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Scanner>();
    assert_send_sync::<ScanError>();
    assert_send_sync::<ScanSummary>();
    assert_send_sync::<QuarantineVault>();
}

#[test]
fn scan_file_matches_eicar_fixture() {
    let dir = tmp();
    let fixture = write_file(dir.path(), "eicar.txt", eicar_fixture().as_bytes());

    let report = scanner()
        .scan_file(&fixture, ScanSource::Manual)
        .expect("scan eicar fixture");

    assert!(!report.cache_hit);
    assert_eq!(report.source, ScanSource::Manual);
    assert_eq!(report.file.size, eicar_fixture().len() as u64);
    assert!(report.file.sha256.is_some());
    assert!(report.assessment.signals.yara_matches >= 1);

    let detection = report
        .detections
        .iter()
        .find(|detection| detection.rule_id == "eicar_test_string")
        .expect("eicar detection");
    assert_eq!(detection.source, security_core::DetectionSource::Yara);
    assert_eq!(detection.severity, security_core::Severity::High);
    assert!(detection.score_contribution >= 45.0);
    assert!(!detection.evidence.is_empty());
    assert!(report.assessment.score >= 45.0);
}

#[test]
fn scan_file_benign_fixture_has_no_detections() {
    let dir = tmp();
    let benign = write_file(
        dir.path(),
        "notes.txt",
        b"An ordinary text file used to verify that clean files stay clean.",
    );
    let report = scanner()
        .scan_file(&benign, ScanSource::Scheduled)
        .expect("scan benign file");
    assert!(report.detections.is_empty());
    assert_eq!(report.assessment.score, 0.0);
    assert_eq!(report.assessment.level, security_core::RiskLevel::Clean);
    assert_eq!(report.source, ScanSource::Scheduled);
}

#[test]
fn extra_yara_rules_are_compiled_and_match() {
    let dir = tmp();
    let marker = write_file(dir.path(), "marker.txt", b"prefix CUSTOM_MARKER_XYZ suffix");
    let scanner = scanner_with(ScannerConfig {
        extra_yara_rules: Some(
            "rule custom_marker { strings: $m = \"CUSTOM_MARKER_XYZ\" condition: $m }".to_string(),
        ),
        ..Default::default()
    });
    let report = scanner
        .scan_file(&marker, ScanSource::Manual)
        .expect("scan marker");
    assert!(report
        .detections
        .iter()
        .any(|detection| detection.rule_id == "custom_marker"));
}

#[test]
fn scan_file_respects_max_file_size() {
    let dir = tmp();
    let big = write_file(dir.path(), "big.bin", &vec![7u8; 4096]);
    let scanner = scanner_with(ScannerConfig {
        max_file_size: 16,
        ..Default::default()
    });
    let report = scanner
        .scan_file(&big, ScanSource::Manual)
        .expect("scan big");
    assert!(report.file.pe.is_none());
    assert_eq!(report.file.entropy, Some(0.0));
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("pe analysis skipped")));
    assert!(report.file.sha256.is_some());
}

#[test]
fn scan_file_respects_max_hash_size() {
    let dir = tmp();
    let file = write_file(dir.path(), "unhashed.bin", &vec![1u8; 4096]);
    let scanner = scanner_with(ScannerConfig {
        max_hash_size: 8,
        ..Default::default()
    });
    let report = scanner
        .scan_file(&file, ScanSource::Manual)
        .expect("scan unhashed");
    assert!(report.file.sha256.is_none());
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("sha256 skipped")));
}

#[test]
fn oversized_file_is_scanned_via_mmap_prefix() {
    let dir = tmp();
    let scanner = scanner_with(ScannerConfig {
        max_file_size: 64,
        extra_yara_rules: Some(
            "rule custom_marker { strings: $m = \"CUSTOM_MARKER_XYZ\" condition: $m }".to_string(),
        ),
        ..Default::default()
    });
    let mut content = b"CUSTOM_MARKER_XYZ".to_vec();
    content.extend(vec![0u8; 4096]);
    let file = write_file(dir.path(), "oversize.bin", &content);
    let report = scanner
        .scan_file(&file, ScanSource::Manual)
        .expect("scan oversize");
    assert!(report
        .detections
        .iter()
        .any(|detection| detection.rule_id == "custom_marker"));
    assert!(report.file.sha256.is_some());
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("pe analysis skipped")));
}

#[test]
fn default_rules_flag_writable_executable_pe() {
    let dir = tmp();
    let fixture = write_file(
        dir.path(),
        "fixture.exe",
        &tiny_pe_fixture(true, false, false),
    );
    let report = scanner()
        .scan_file(&fixture, ScanSource::Manual)
        .expect("scan PE fixture");
    assert!(report.file.is_pe);
    assert!(report.assessment.signals.writable_executable_section);
    assert!(report
        .detections
        .iter()
        .any(|detection| detection.rule_id == "pe_writable_executable_section"));
    let pe = report.file.pe.expect("pe metadata");
    assert!(pe.imports.iter().any(|import| import.dll == "KERNEL32.dll"));
}

#[test]
fn scan_path_counts_files_and_progress() {
    let dir = tmp();
    write_file(dir.path(), "benign.txt", b"benign text content");
    write_file(dir.path(), "eicar.txt", eicar_fixture().as_bytes());
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).expect("create nested dir");
    write_file(&nested, "deep.txt", b"nested benign text");

    let scanner = scanner();
    let cancel = AtomicBool::new(false);
    let progress_calls = AtomicUsize::new(0);
    let progress = |_update: ScanProgress| {
        progress_calls.fetch_add(1, Ordering::SeqCst);
    };

    let summary = scanner.scan_path(dir.path(), false, &cancel, &progress);
    assert!(!summary.cancelled);
    assert_eq!(summary.files_scanned, 2, "non-recursive scans one level");
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.detections, 1);
    assert_eq!(summary.reports.len(), 2);
    assert!(
        progress_calls.load(Ordering::SeqCst) >= 3,
        "per-file + final"
    );

    let channel = AtomicBool::new(false);
    let summary = scanner.scan_path(dir.path(), true, &channel, &progress);
    assert_eq!(summary.files_scanned, 3, "recursive includes nested");
    assert_eq!(summary.detections, 1);
}

#[test]
fn scan_path_honours_cancellation() {
    let dir = tmp();
    write_file(dir.path(), "benign.txt", b"benign text content");
    let scanner = scanner();
    let cancel = AtomicBool::new(true);
    let summary = scanner.scan_path(dir.path(), true, &cancel, &|_update| {});
    assert!(summary.cancelled);
    assert_eq!(summary.files_scanned, 0);
    assert!(summary.reports.is_empty());
}

#[cfg(windows)]
fn try_symlink(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(not(windows))]
fn try_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[test]
fn symlinks_are_rejected_unless_followed() {
    let dir = tmp();
    let target = write_file(dir.path(), "target.txt", b"data");
    let link = dir.path().join("link.txt");
    if !try_symlink(&target, &link) {
        eprintln!("skipping symlink test: cannot create symlinks on this system");
        return;
    }

    let scanner = scanner();
    let error = scanner
        .scan_file(&link, ScanSource::Manual)
        .expect_err("symlink must be rejected");
    assert!(matches!(error, ScanError::SymlinkRejected(_)));

    let follower = scanner_with(ScannerConfig {
        follow_symlinks: true,
        ..Default::default()
    });
    let report = follower
        .scan_file(&link, ScanSource::Manual)
        .expect("followed symlink scans");
    assert_eq!(report.file.size, 4);
}

#[test]
fn quarantine_round_trip_restores_bytes() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let payload = b"quarantine round trip payload".to_vec();
    let original = write_file(work.path(), "sample.exe", &payload);
    let original_hash = compute_sha256(&original).expect("hash original");

    let record = vault
        .quarantine(&original, "unit test", Some("det_test".to_string()))
        .expect("quarantine");
    assert_eq!(record.sha256, original_hash);
    assert_eq!(record.size, payload.len() as u64);
    assert_eq!(record.status, QuarantineStatus::Quarantined);
    assert!(record.identity_verified);
    assert!(record.original_path.ends_with("sample.exe"));
    assert_eq!(record.detection_id.as_deref(), Some("det_test"));

    let stored = PathBuf::from(&record.stored_path);
    assert!(stored.starts_with(vault.dir()));
    assert!(stored.exists());
    assert_eq!(std::fs::read(&stored).expect("read stored"), payload);
    // Quarantine copies: the original is never deleted automatically.
    assert!(original.exists());

    let listed = vault.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, record.id);

    // The user removes the original, then restores it explicitly.
    std::fs::remove_file(&original).expect("remove original");
    let restored = vault.restore(&record.id).expect("restore");
    assert!(restored.success, "{}", restored.message);
    let restored_path = PathBuf::from(
        restored
            .restored_path
            .clone()
            .expect("restored path present"),
    );
    assert_eq!(
        restored_path.canonicalize().expect("canonical restored"),
        original.canonicalize().expect("canonical original")
    );
    assert_eq!(std::fs::read(&original).expect("read restored"), payload);
    assert_eq!(
        compute_sha256(&original).expect("hash restored"),
        original_hash
    );

    let listed = vault.list();
    assert_eq!(listed[0].status, QuarantineStatus::Restored);
    assert!(listed[0].restored_at_ms.is_some());
}

#[test]
fn restore_refuses_to_overwrite_existing_file() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let original = write_file(work.path(), "keep.txt", b"original bytes");
    let record = vault
        .quarantine(&original, "unit test", None)
        .expect("quarantine");

    std::fs::write(&original, b"replacement content").expect("replace original");
    let result = vault.restore(&record.id).expect("restore attempt");
    assert!(!result.success);
    assert!(
        result.message.contains("refusing to overwrite"),
        "message was {}",
        result.message
    );
    assert_eq!(
        std::fs::read(&original).expect("read replacement"),
        b"replacement content"
    );
    assert_eq!(vault.list()[0].status, QuarantineStatus::Quarantined);
}

#[test]
fn quarantine_names_are_collision_safe() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let original = write_file(work.path(), "same.txt", b"same bytes");
    let first = vault.quarantine(&original, "first", None).expect("first");
    let second = vault.quarantine(&original, "second", None).expect("second");
    assert_ne!(first.stored_path, second.stored_path);
    assert_ne!(first.id, second.id);
    assert_eq!(vault.list().len(), 2);
    assert_eq!(
        compute_sha256(Path::new(&first.stored_path)).expect("first hash"),
        first.sha256
    );
    assert_eq!(
        compute_sha256(Path::new(&second.stored_path)).expect("second hash"),
        second.sha256
    );
}

#[test]
fn quarantine_delete_removes_only_vault_copy() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let original = write_file(work.path(), "victim.txt", b"victim bytes");
    let record = vault
        .quarantine(&original, "unit test", None)
        .expect("quarantine");

    vault.delete(&record.id).expect("delete");
    assert!(!Path::new(&record.stored_path).exists());
    assert!(vault.list().is_empty());
    assert!(
        original.exists(),
        "original must survive quarantine deletion"
    );
    assert!(matches!(
        vault.delete(&record.id),
        Err(ScanError::NotFound(_))
    ));
}

#[test]
fn restore_fails_when_stored_copy_is_missing() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let original = write_file(work.path(), "gone.txt", b"gone bytes");
    let record = vault
        .quarantine(&original, "unit test", None)
        .expect("quarantine");

    std::fs::remove_file(&record.stored_path).expect("remove stored copy");
    std::fs::remove_file(&original).expect("remove original");
    let error = vault.restore(&record.id).expect_err("restore must fail");
    assert!(
        matches!(error, ScanError::Quarantine(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn quarantine_rejects_symlinks() {
    let work = tmp();
    let vault = QuarantineVault::new(work.path().join("vault")).expect("vault");
    let target = write_file(work.path(), "target.bin", b"target bytes");
    let link = work.path().join("link.bin");
    if !try_symlink(&target, &link) {
        eprintln!("skipping quarantine symlink test: cannot create symlinks");
        return;
    }
    let error = vault
        .quarantine(&link, "unit test", None)
        .expect_err("symlink quarantine must fail");
    assert!(matches!(error, ScanError::SymlinkRejected(_)));
}

#[test]
fn quarantine_timestamp_format_is_utc_and_filename_safe() {
    use quarantine::format_utc_stamp;
    assert_eq!(format_utc_stamp(0), "19700101T000000.000Z");
    assert_eq!(format_utc_stamp(86_400_000), "19700102T000000.000Z");
    assert_eq!(format_utc_stamp(951_782_400_000), "20000229T000000.000Z");
    assert_eq!(format_utc_stamp(1_000_000_000_123), "20010909T014640.123Z");
}

#[test]
fn known_hash_seed_list_is_well_formed() {
    for (hash, rule_id, description) in yara_rules::KNOWN_MALWARE_SHA256 {
        assert_eq!(hash.len(), 64, "hash length for {rule_id}");
        assert!(hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
        assert!(!rule_id.is_empty());
        assert!(!description.is_empty());
    }
    let eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    assert!(yara_rules::known_hash_entry(eicar).is_some());
    assert!(yara_rules::known_hash_entry(&eicar.to_uppercase()).is_some());
    assert!(yara_rules::known_hash_entry("  00  ").is_none());
}

#[test]
fn authenticode_query_never_panics() {
    let missing = Path::new("C:\\definitely\\missing\\authenticode\\fixture.exe");
    let outcome = read_authenticode(missing);
    assert!(
        outcome.is_err() || matches!(outcome, Ok(None)),
        "unexpected authenticode outcome: {outcome:?}"
    );

    // The test executable exists; the query must return without panicking.
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(Some(info)) = read_authenticode(&exe) {
            assert!(!info.status.is_empty());
        }
    }
}

#[test]
fn default_rules_compile_and_are_embedded() {
    let rules = default_yara_rules();
    assert!(rules.contains("eicar_test_string"));
    assert!(rules.contains("powershell_download_cradle"));
    assert!(rules.contains("pe_writable_executable_section"));
}
