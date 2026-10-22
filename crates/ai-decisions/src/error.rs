//! Error type for the AI decision layer.
//!
//! `DecisionError` never contains the API key: every provider/transport
//! message goes through [`sanitize_message`] and `AiConfig`/`ProviderConfig`
//! redact the key in their `Debug` implementations.

/// Maximum length of a sanitized provider message shown to the UI.
const MAX_MESSAGE_CHARS: usize = 320;

/// Errors surfaced by decision providers and the provider router.
///
/// Failures never propagate as panics: the router turns them into a
/// `DecisionRoute::FailedClosed` result so that scanning is never blocked.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DecisionError {
    /// The provider rejected the API key (HTTP 401/403).
    #[error("decision provider rejected the API key (unauthorized)")]
    Unauthorized,
    /// The provider rate limited us (HTTP 429). `retry_after_ms` is the earliest
    /// moment a retry could succeed according to the provider or local bucket.
    #[error("decision provider rate limit reached (retry after {retry_after_ms} ms)")]
    RateLimited {
        /// Earliest retry moment, in milliseconds.
        retry_after_ms: u64,
    },
    /// The request exceeded the configured timeout.
    #[error("decision request timed out")]
    Timeout,
    /// A transport or provider error. `status` is `0` for transport failures.
    #[error("decision provider error (status {0}): {1}")]
    ProviderError(u16, String),
    /// The provider answered with a body we could not parse.
    #[error("invalid decision response: {0}")]
    InvalidResponse(String),
    /// No API key is configured for the provider.
    #[error("decision provider is not configured (missing API key)")]
    NotConfigured,
    /// The accumulated daily cost reached `daily_cost_limit_usd`; no network
    /// call was made.
    #[error("daily AI cost limit exceeded")]
    CostLimitExceeded,
    /// The decision provider is offline (AI mode is `Offline`).
    #[error("decision provider is offline")]
    Offline,
}

impl DecisionError {
    /// True when retrying the same request may succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            DecisionError::RateLimited { .. } | DecisionError::Timeout => true,
            DecisionError::ProviderError(status, _) => *status == 0 || *status >= 500,
            _ => false,
        }
    }
}

/// Best-effort scrub of credentials from an arbitrary message.
///
/// Redacts `Bearer <token>` pairs and anything that looks like an OpenRouter
/// key (`sk-...`), then truncates the result.
pub(crate) fn sanitize_message(input: &str) -> String {
    let mut pieces: Vec<String> = Vec::new();
    let mut previous_was_bearer = false;
    for token in input.split_whitespace() {
        if previous_was_bearer {
            previous_was_bearer = false;
            pieces.push("[redacted-key]".to_string());
            continue;
        }
        if token.eq_ignore_ascii_case("bearer") {
            previous_was_bearer = true;
            pieces.push("Bearer".to_string());
            continue;
        }
        pieces.push(redact_key_token(token));
    }
    truncate_chars(&pieces.join(" "), MAX_MESSAGE_CHARS)
}

fn redact_key_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    let Some(start) = lower.find("sk-") else {
        return token.to_string();
    };
    let bytes = token.as_bytes();
    let mut end = token.len();
    for (index, byte) in bytes.iter().enumerate().skip(start + 3) {
        let ch = *byte as char;
        if ch == '"' || ch == '\'' || ch == ',' || ch == '}' || ch == ']' || ch.is_whitespace() {
            end = index;
            break;
        }
    }
    let mut out = String::with_capacity(token.len());
    out.push_str(&token[..start]);
    out.push_str("[redacted-key]");
    out.push_str(&token[end..]);
    out
}

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(DecisionError::RateLimited { retry_after_ms: 5 }.is_retryable());
        assert!(DecisionError::Timeout.is_retryable());
        assert!(DecisionError::ProviderError(500, "boom".into()).is_retryable());
        assert!(DecisionError::ProviderError(0, "connection reset".into()).is_retryable());
        assert!(!DecisionError::ProviderError(400, "bad request".into()).is_retryable());
        assert!(!DecisionError::Unauthorized.is_retryable());
        assert!(!DecisionError::InvalidResponse("x".into()).is_retryable());
        assert!(!DecisionError::CostLimitExceeded.is_retryable());
    }

    #[test]
    fn sanitizer_removes_keys_and_bearer_tokens() {
        let raw = "request failed for Bearer sk-or-v1-deadbeefcafebabe while posting";
        let clean = sanitize_message(raw);
        assert!(!clean.contains("sk-or-v1-deadbeefcafebabe"), "{clean}");
        assert!(!clean.contains("deadbeef"), "{clean}");
        assert!(clean.contains("[redacted-key]"), "{clean}");
    }

    #[test]
    fn sanitizer_redacts_json_embedded_keys() {
        let clean = sanitize_message(r#"{"error":"bad key","key":"sk-abc123"}"#);
        assert!(!clean.contains("sk-abc123"), "{clean}");
    }

    #[test]
    fn sanitizer_truncates_long_messages() {
        let clean = sanitize_message(&"x".repeat(1000));
        assert!(clean.chars().count() <= MAX_MESSAGE_CHARS + 1);
    }
}
