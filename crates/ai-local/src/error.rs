//! Errors for local hardware detection and local decision models.

/// Errors surfaced by local decision models.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LocalAiError {
    /// The model (or its runtime) is not available on this machine.
    #[error("local model is not available: {0}")]
    NotAvailable(String),
    /// The input state cannot be classified.
    #[error("invalid local model input: {0}")]
    InvalidInput(String),
    /// The local inference runtime failed.
    #[error("local inference failed: {0}")]
    InferenceFailed(String),
}

impl LocalAiError {
    /// True when the failure is caused by an unavailable runtime rather than
    /// bad input or an inference fault.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::NotAvailable(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_detection() {
        assert!(LocalAiError::NotAvailable("no runtime".into()).is_unavailable());
        assert!(!LocalAiError::InvalidInput("x".into()).is_unavailable());
        assert!(!LocalAiError::InferenceFailed("x".into()).is_unavailable());
    }
}
