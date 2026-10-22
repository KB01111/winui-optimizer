//! Error type shared by the Windows integration helpers.

/// Errors returned by Windows integration operations.
///
/// Error messages never contain secret material: only the failing operation
/// and the platform error text are exposed.
#[derive(Debug, thiserror::Error)]
pub enum WindowsIntegrationError {
    /// The feature is not available on this platform or Windows build.
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),
    /// A Windows API call failed. `operation` is a stable label for logs and
    /// `message` is the platform error text.
    #[error("windows api error in {operation}: {message}")]
    Api {
        /// Stable operation label, for example `CryptProtectData`.
        operation: &'static str,
        /// Platform error text.
        message: String,
    },
    /// Input was rejected before any Windows API was called.
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Build an [`WindowsIntegrationError::Api`] from any platform error.
#[cfg(windows)]
pub(crate) fn api_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> WindowsIntegrationError {
    WindowsIntegrationError::Api {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_are_stable_labels() {
        let unsupported = WindowsIntegrationError::Unsupported("DPAPI");
        assert_eq!(
            unsupported.to_string(),
            "unsupported on this platform: DPAPI"
        );

        let api = WindowsIntegrationError::Api {
            operation: "CryptProtectData",
            message: "access denied".to_string(),
        };
        assert_eq!(
            api.to_string(),
            "windows api error in CryptProtectData: access denied"
        );

        let invalid = WindowsIntegrationError::Invalid("empty secret".to_string());
        assert_eq!(invalid.to_string(), "invalid input: empty secret");
    }
}
