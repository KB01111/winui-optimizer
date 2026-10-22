//! Desktop notification helper.
//!
//! Toast notifications require MSIX package identity. When the app runs
//! unpackaged the helper returns `NoPackageIdentity` instead of throwing; the
//! caller decides whether to surface that to the user.

use security_core::ScanJobSummary;
use windows_integration::NotificationOutcome;

pub fn notify(title: &str, body: &str, tag: &str) -> NotificationOutcome {
    windows_integration::show_notification(title, body, tag)
}

/// Notify the user that a scan finished with detections. Body text is
/// intentionally minimal: no file paths are put into notification contents.
pub fn notify_scan_complete(job: &ScanJobSummary) {
    let _ = notify(
        "AI Antivirus",
        &format!(
            "Scan finished: {} detection(s) in {} file(s)",
            job.detections, job.files_scanned
        ),
        "scan-complete",
    );
}
