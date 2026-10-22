//! HTTP transport abstraction for the OpenRouter Decisions API.
//!
//! The production path uses `reqwest` with rustls. The `Transport` trait is an
//! internal seam so unit tests can script responses, retries and failures
//! without touching the network. The API key is only ever placed in the
//! `Authorization` header of the outgoing request; it is never logged.

use async_trait::async_trait;
use std::time::Duration;

use crate::error::{sanitize_message, DecisionError};

/// Maximum accepted response body size (1 MiB).
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const USER_AGENT: &str = "ai-antivirus-engine/1.0";

/// One POST request prepared by a provider.
#[derive(Debug, Clone)]
pub(crate) struct TransportRequest {
    pub url: String,
    pub api_key: String,
    pub body: serde_json::Value,
}

/// A raw HTTP response.
#[derive(Debug, Clone)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub retry_after_ms: Option<u64>,
    pub body: String,
}

/// Transport seam used by providers (injectable for tests).
#[async_trait]
pub(crate) trait Transport: Send + Sync {
    async fn post_json(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse, DecisionError>;
}

/// `reqwest`-based transport.
pub(crate) struct ReqwestTransport {
    client: Option<reqwest::Client>,
}

impl ReqwestTransport {
    /// Build a client with the given per-request timeout (0 => 30 s default).
    pub(crate) fn new(timeout_ms: u64) -> Self {
        let timeout = Duration::from_millis(if timeout_ms == 0 { 30_000 } else { timeout_ms });
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(USER_AGENT)
            .build();
        match client {
            Ok(client) => Self {
                client: Some(client),
            },
            Err(error) => {
                tracing::warn!(
                    error = %sanitize_message(&error.to_string()),
                    "failed to build the HTTP client; decision providers will fail closed"
                );
                Self { client: None }
            }
        }
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn post_json(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse, DecisionError> {
        let client = self.client.as_ref().ok_or_else(|| {
            DecisionError::ProviderError(0, "HTTP client is unavailable".to_string())
        })?;
        let response = client
            .post(&request.url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", request.api_key),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&request.body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let retry_after_ms = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        let body = response.text().await.map_err(map_reqwest_error)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DecisionError::InvalidResponse(
                "decision response body exceeded the 1 MiB limit".to_string(),
            ));
        }
        Ok(TransportResponse {
            status,
            retry_after_ms,
            body,
        })
    }
}

/// Map a `reqwest` failure onto the contract error type. The request (and thus
/// the API key) is never part of the message.
pub(crate) fn map_reqwest_error(error: reqwest::Error) -> DecisionError {
    if error.is_timeout() {
        DecisionError::Timeout
    } else {
        DecisionError::ProviderError(0, sanitize_message(&error.to_string()))
    }
}

/// Parse a `Retry-After` header value (delta-seconds form only; HTTP-date
/// values fall back to exponential backoff).
pub(crate) fn parse_retry_after(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_retry_after_seconds() {
        assert_eq!(parse_retry_after("3"), Some(3_000));
        assert_eq!(parse_retry_after(" 12 "), Some(12_000));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("nonsense"), None);
    }

    #[test]
    fn transport_response_fields_are_plain() {
        let response = TransportResponse {
            status: 200,
            retry_after_ms: None,
            body: "{}".into(),
        };
        assert_eq!(response.status, 200);
    }
}
