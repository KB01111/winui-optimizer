//! Toast notifications.
//!
//! Contract behaviour:
//! - [`notifications_supported`] is true only when the process has MSIX
//!   package identity, because `ToastNotificationManager::CreateToastNotifier`
//!   requires it.
//! - [`show_notification`] never throws: without package identity it returns
//!   [`NotificationOutcome::NoPackageIdentity`].
//!
//! The toast itself uses the upstream winappCli approach
//! (`ToastText02` template XML from `ToastNotificationManager`), extended with
//! `Tag`/`Group` so alerts from one rule replace each other in Action Center
//! instead of piling up.

use serde::{Deserialize, Serialize};

use crate::util::truncate_chars;

/// Windows limits toast tags and groups to 64 characters.
pub(crate) const MAX_TAG_CHARS: usize = 64;
/// Fixed group so all AI Antivirus toasts are grouped together.
pub(crate) const NOTIFICATION_GROUP: &str = "ai-antivirus-security";

/// Result of attempting to show a toast notification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationOutcome {
    /// The toast was handed to Windows.
    Sent,
    /// The process has no MSIX package identity; Windows cannot show toasts
    /// for it. This is a normal state for development builds.
    NoPackageIdentity,
    /// The platform cannot show toasts at all (non-Windows builds).
    Unsupported,
    /// The toast failed for any other reason; the string is a printable error.
    Failed(String),
}

/// True when toast notifications can actually be attempted: Windows with
/// package identity. Never panics.
pub fn notifications_supported() -> bool {
    cfg!(windows) && crate::package::package_identity().available
}

/// Show a toast notification.
///
/// Only attempts `ToastNotificationManager` when package identity exists,
/// preserving the upstream toast XML approach. Never throws: all failures are
/// mapped to [`NotificationOutcome`].
pub fn show_notification(title: &str, body: &str, tag: &str) -> NotificationOutcome {
    imp::show_notification(title, body, tag)
}

/// Gating rule, kept pure for tests: without package identity nothing may be
/// attempted, and the caller must receive `NoPackageIdentity`.
pub(crate) fn notification_gate(packaged: bool) -> Result<(), NotificationOutcome> {
    if packaged {
        Ok(())
    } else {
        Err(NotificationOutcome::NoPackageIdentity)
    }
}

/// Prepare a toast tag: drop control characters (invalid in XML attributes),
/// trim, and truncate to the Windows limit without splitting a code point.
pub(crate) fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    truncate_chars(cleaned.trim(), MAX_TAG_CHARS)
}

#[cfg(windows)]
mod imp {
    use super::{notification_gate, sanitize_tag, NotificationOutcome, NOTIFICATION_GROUP};

    pub fn show_notification(title: &str, body: &str, tag: &str) -> NotificationOutcome {
        if let Err(outcome) = notification_gate(crate::package::package_identity().available) {
            return outcome;
        }
        match show_toast(title, body, tag) {
            Ok(()) => NotificationOutcome::Sent,
            Err(error) => NotificationOutcome::Failed(error.to_string()),
        }
    }

    fn show_toast(title: &str, body: &str, tag: &str) -> windows::core::Result<()> {
        use windows::core::HSTRING;
        use windows::UI::Notifications::{
            ToastNotification, ToastNotificationManager, ToastTemplateType,
        };

        // Upstream winappCli approach: start from the ToastText02 template and
        // fill in the two `<text>` nodes.
        let toast_xml =
            ToastNotificationManager::GetTemplateContent(ToastTemplateType::ToastText02)?;
        let text_nodes = toast_xml.GetElementsByTagName(&HSTRING::from("text"))?;

        let title_node = toast_xml.CreateTextNode(&HSTRING::from(title))?;
        text_nodes.Item(0)?.AppendChild(&title_node)?;

        let body_node = toast_xml.CreateTextNode(&HSTRING::from(body))?;
        text_nodes.Item(1)?.AppendChild(&body_node)?;

        let notification = ToastNotification::CreateToastNotification(&toast_xml)?;

        // Tag/group so repeated alerts for the same rule collapse into one
        // entry instead of flooding Action Center.
        let tag = sanitize_tag(tag);
        if !tag.is_empty() {
            notification.SetTag(&HSTRING::from(tag.as_str()))?;
            notification.SetGroup(&HSTRING::from(NOTIFICATION_GROUP))?;
        }

        ToastNotificationManager::CreateToastNotifier()?.Show(&notification)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::NotificationOutcome;

    pub fn show_notification(_title: &str, _body: &str, _tag: &str) -> NotificationOutcome {
        NotificationOutcome::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_package_identity() {
        assert_eq!(
            notification_gate(false),
            Err(NotificationOutcome::NoPackageIdentity)
        );
        assert_eq!(notification_gate(true), Ok(()));
    }

    #[test]
    fn sanitize_tag_truncates_to_windows_limit() {
        let long = "a".repeat(100);
        let sanitized = sanitize_tag(&long);
        assert_eq!(sanitized.chars().count(), MAX_TAG_CHARS);
        assert_eq!(sanitize_tag("  rule-42  "), "rule-42");
        assert_eq!(sanitize_tag(""), "");
        assert_eq!(sanitize_tag("   "), "");
    }

    #[test]
    fn sanitize_tag_removes_control_characters_and_keeps_unicode_intact() {
        assert_eq!(sanitize_tag("ru\u{0}le\r\n\t"), "rule");
        let unicode = "åäö".repeat(30);
        let sanitized = sanitize_tag(&unicode);
        assert_eq!(sanitized.chars().count(), MAX_TAG_CHARS);
        assert!(sanitized.starts_with("åäö"));
    }

    #[test]
    fn notification_outcome_serializes_snake_case() {
        let sent = serde_json::to_value(NotificationOutcome::Sent).expect("serializes");
        assert_eq!(sent, serde_json::json!("sent"));

        let no_identity =
            serde_json::to_value(NotificationOutcome::NoPackageIdentity).expect("serializes");
        assert_eq!(no_identity, serde_json::json!("no_package_identity"));

        let failed = serde_json::to_value(NotificationOutcome::Failed("denied".to_string()))
            .expect("serializes");
        assert_eq!(failed, serde_json::json!({"failed": "denied"}));
    }

    #[test]
    fn unsupported_without_package_identity_on_this_machine() {
        // The test binary is unpackaged, so this must stay false / gated.
        assert!(!notifications_supported());
        assert_eq!(
            show_notification("title", "body", "tag"),
            if cfg!(windows) {
                NotificationOutcome::NoPackageIdentity
            } else {
                NotificationOutcome::Unsupported
            }
        );
    }
}
