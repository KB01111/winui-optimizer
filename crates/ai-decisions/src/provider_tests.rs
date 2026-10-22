//! HTTP provider behavior tests: request shape, retries, cache, cost and rate
//! limiting, error mapping, and API-key hygiene. No live network.

use std::sync::Arc;

use security_core::DecisionCategory;

use crate::error::DecisionError;
use crate::providers::openrouter::{
    JevProvider, MercuryDecideFreeProvider, MercuryDecideProvider, ProviderConfig,
};
use crate::providers::DecisionProvider;
use crate::test_support::{
    assessment_with_score, sample_state, ScriptedStep, ScriptedTransport,
    RESPONSE_CHOICE_SUSPICIOUS, RESPONSE_MIXED_SCORE_AND_CHOICE, RESPONSE_NOUL_BOOLEAN,
};

fn test_config(model: &str) -> ProviderConfig {
    ProviderConfig {
        model: model.to_string(),
        api_key: Some("sk-or-v1-testkey123456".to_string()),
        base_url: "http://127.0.0.1:1/decisions".to_string(),
        timeout_ms: 1_000,
        max_retries: 2,
        requests_per_minute: 0,
        daily_cost_limit_usd: 0.0,
        allow_cloud_state: true,
        cache_ttl_ms: 600_000,
        max_rate_wait_ms: 0,
        retry_base_delay_ms: 1,
        retry_max_delay_ms: 2,
    }
}

fn jev_with(
    steps: Vec<ScriptedStep>,
    config: ProviderConfig,
) -> (JevProvider, Arc<ScriptedTransport>) {
    let script = ScriptedTransport::new(steps).into_arc();
    let provider = JevProvider::with_transport(
        config,
        script.clone() as Arc<dyn crate::transport::Transport>,
    );
    (provider, script)
}

#[tokio::test]
async fn default_models_match_the_contract() {
    assert_eq!(JevProvider::DEFAULT_MODEL, "typesafe/jev-1.14");
    assert_eq!(
        MercuryDecideProvider::DEFAULT_MODEL,
        "inception/mercury-decide"
    );
    assert_eq!(
        MercuryDecideFreeProvider::DEFAULT_MODEL,
        "inception/mercury-decide:free"
    );
    let provider = MercuryDecideFreeProvider::new("sk-test");
    assert_eq!(provider.provider_name(), "openrouter");
    assert_eq!(provider.model(), "inception/mercury-decide:free");
    assert!(provider.is_configured());
    assert_eq!(provider.config().base_url, crate::wire::DEFAULT_BASE_URL);
}

#[tokio::test]
async fn builds_the_contract_request_with_redacted_state() {
    let (provider, script) = jev_with(
        vec![ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS)],
        test_config("typesafe/jev-1.14"),
    );
    let result = provider.classify(&sample_state(80.0)).await.unwrap();
    assert_eq!(script.calls(), 1);

    let request = script.last_request().unwrap();
    assert_eq!(request.api_key, "sk-or-v1-testkey123456");
    assert_eq!(request.body["model"], "typesafe/jev-1.14");
    assert_eq!(
        request.body["questions"]["classification"]["type"],
        "choice"
    );
    assert_eq!(
        request.body["questions"]["requires_investigation"]["type"],
        "noul"
    );
    assert_eq!(
        request.body["questions"]["classification"]["criteria"]["benign"],
        "No meaningful security concern; behavior, provenance and detections are consistent with normal software."
    );

    let serialized = serde_json::to_string(&request.body).unwrap();
    assert!(!serialized.contains("someuser"), "{serialized}");
    assert!(!serialized.contains("AppData"), "{serialized}");
    assert!(serialized.contains("evil.exe"), "{serialized}");
    assert_eq!(result.category, DecisionCategory::Suspicious);
}

#[tokio::test]
async fn withholds_state_when_cloud_state_is_disallowed() {
    let mut config = test_config("inception/mercury-decide");
    config.allow_cloud_state = false;
    let (provider, script) = jev_with(
        vec![ScriptedStep::json(RESPONSE_MIXED_SCORE_AND_CHOICE)],
        config,
    );
    provider.classify(&sample_state(80.0)).await.unwrap();
    let request = script.last_request().unwrap();
    assert_eq!(request.body["state"]["stateWithheld"], true);
    let serialized = serde_json::to_string(&request.body).unwrap();
    assert!(!serialized.contains("someuser"), "{serialized}");
    assert!(!serialized.contains("evil.exe"), "{serialized}");
    assert!(serialized.contains("deterministicScore"), "{serialized}");
}

#[tokio::test]
async fn parses_noul_and_fallback_model() {
    let (provider, _) = jev_with(
        vec![ScriptedStep::json(RESPONSE_NOUL_BOOLEAN)],
        test_config("typesafe/jev-1.14"),
    );
    let result = provider.classify(&sample_state(80.0)).await.unwrap();
    assert_eq!(result.model, "inception/mercury-decide");
    assert!(result.suspicious_persistence);
    assert!(!result.ransomware);
    assert_eq!(result.cost_usd, Some(0.00051));
}

#[tokio::test]
async fn unauthorized_is_not_retried() {
    let (provider, script) = jev_with(
        vec![ScriptedStep::status(401, r#"{"error":"invalid key"}"#)],
        test_config("typesafe/jev-1.14"),
    );
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    assert_eq!(error, DecisionError::Unauthorized);
    assert_eq!(script.calls(), 1);
}

#[tokio::test]
async fn server_errors_are_retried_then_fail() {
    let (provider, script) = jev_with(
        vec![
            ScriptedStep::status(500, "boom one"),
            ScriptedStep::status(503, "boom two"),
            ScriptedStep::status(500, "boom three"),
        ],
        test_config("typesafe/jev-1.14"),
    );
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    assert!(
        matches!(error, DecisionError::ProviderError(500, _)),
        "{error:?}"
    );
    assert_eq!(script.calls(), 3);
    let health = provider.health().await;
    assert_eq!(health.requests, 3);
    assert_eq!(health.failures, 1);
    assert_eq!(health.status, crate::types::ProviderStatus::Unavailable);
}

#[tokio::test]
async fn retries_then_succeeds() {
    let (provider, script) = jev_with(
        vec![
            ScriptedStep::status(500, "transient"),
            ScriptedStep::rate_limited(1),
            ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS),
        ],
        test_config("typesafe/jev-1.14"),
    );
    let result = provider.classify(&sample_state(80.0)).await.unwrap();
    assert_eq!(result.category, DecisionCategory::Suspicious);
    assert_eq!(script.calls(), 3);
    let health = provider.health().await;
    assert_eq!(health.successes, 1);
    assert_eq!(health.requests, 3);
    assert_eq!(health.status, crate::types::ProviderStatus::Healthy);
}

#[tokio::test]
async fn timeouts_map_to_timeout_and_retry() {
    let mut config = test_config("typesafe/jev-1.14");
    config.max_retries = 2;
    let (provider, script) = jev_with(
        vec![
            ScriptedStep::Fail(DecisionError::Timeout),
            ScriptedStep::Fail(DecisionError::Timeout),
            ScriptedStep::Fail(DecisionError::Timeout),
        ],
        config,
    );
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    assert_eq!(error, DecisionError::Timeout);
    assert_eq!(script.calls(), 3);
}

#[tokio::test]
async fn invalid_json_is_invalid_response() {
    let (provider, script) = jev_with(
        vec![ScriptedStep::json("{not valid json")],
        test_config("typesafe/jev-1.14"),
    );
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    assert!(
        matches!(error, DecisionError::InvalidResponse(_)),
        "{error:?}"
    );
    assert_eq!(script.calls(), 1);
}

#[tokio::test]
async fn rate_limiter_blocks_without_starting_a_request() {
    let mut config = test_config("typesafe/jev-1.14");
    config.requests_per_minute = 1;
    config.max_rate_wait_ms = 0;
    let (provider, script) = jev_with(vec![ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS)], config);

    provider.classify(&sample_state(80.0)).await.unwrap();
    assert_eq!(script.calls(), 1);

    let error = provider.classify(&sample_state(50.0)).await.unwrap_err();
    assert!(
        matches!(error, DecisionError::RateLimited { .. }),
        "{error:?}"
    );
    assert_eq!(script.calls(), 1);
}

#[tokio::test]
async fn daily_cost_limit_blocks_without_network_call() {
    const PRICEY: &str = r#"{
      "id": "gen-pricey",
      "answers": {
        "classification": { "type": "choice", "choice": "suspicious", "confidence": 0.75 },
        "requires_investigation": { "type": "noul", "noul": 0.9 },
        "persistence": { "type": "noul", "noul": 0.1 },
        "credential_theft": { "type": "noul", "noul": 0.1 },
        "ransomware": { "type": "noul", "noul": 0.1 }
      },
      "usage": { "input_tokens": 10, "output_tokens": 10, "cost": 0.0006 }
    }"#;
    let mut config = test_config("typesafe/jev-1.14");
    config.daily_cost_limit_usd = 0.001;
    let (provider, script) = jev_with(
        vec![
            ScriptedStep::json(PRICEY),
            ScriptedStep::json(PRICEY),
            ScriptedStep::json(PRICEY),
        ],
        config,
    );

    provider.classify(&sample_state(80.0)).await.unwrap();
    provider.classify(&sample_state(50.0)).await.unwrap();
    let error = provider.classify(&sample_state(30.0)).await.unwrap_err();
    assert_eq!(error, DecisionError::CostLimitExceeded);
    assert_eq!(script.calls(), 2);
}

#[tokio::test]
async fn cache_dedupes_identical_redacted_states() {
    let (provider, script) = jev_with(
        vec![ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS)],
        test_config("typesafe/jev-1.14"),
    );
    let first = sample_state(80.0);
    let mut second = first.clone();
    second.event_id = "evt_other".to_string();
    second.timestamp_ms = first.timestamp_ms + 123_456;

    let first_result = provider.classify(&first).await.unwrap();
    let second_result = provider.classify(&second).await.unwrap();
    assert_eq!(script.calls(), 1);
    assert_eq!(first_result.id, second_result.id);
    assert!(second_result
        .evidence
        .iter()
        .any(|line| line.contains("local decision cache")));

    // A semantically different state must bypass the cache.
    let (provider, script2) = jev_with(
        vec![
            ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS),
            ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS),
        ],
        test_config("typesafe/jev-1.14"),
    );
    provider.classify(&sample_state(80.0)).await.unwrap();
    provider.classify(&sample_state(81.0)).await.unwrap();
    assert_eq!(script2.calls(), 2);
}

#[tokio::test]
async fn unconfigured_provider_fails_without_network() {
    let script =
        ScriptedTransport::new(vec![ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS)]).into_arc();
    let provider = JevProvider::with_transport(
        ProviderConfig::new(JevProvider::DEFAULT_MODEL, None),
        script.clone() as Arc<dyn crate::transport::Transport>,
    );
    assert!(!provider.is_configured());
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    assert_eq!(error, DecisionError::NotConfigured);
    assert_eq!(script.calls(), 0);
    let health = provider.health().await;
    assert_eq!(health.requests, 0);
    assert_eq!(health.status, crate::types::ProviderStatus::Unknown);
}

#[tokio::test]
async fn api_key_never_appears_in_errors_or_debug() {
    let body = r#"{"error":{"message":"bad key sk-or-v1-leakme123"}}"#;
    let (provider, _) = jev_with(
        vec![
            ScriptedStep::status(500, body),
            ScriptedStep::status(500, body),
            ScriptedStep::status(500, body),
        ],
        test_config("typesafe/jev-1.14"),
    );
    let error = provider.classify(&sample_state(80.0)).await.unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("leakme123"), "{rendered}");
    assert!(!rendered.contains("testkey123456"), "{rendered}");
    let debug = format!("{:?}", provider.config());
    assert!(!debug.contains("testkey123456"), "{debug}");
    assert!(debug.contains("<redacted>"));
}

#[tokio::test]
async fn health_reports_degraded_after_success_then_failure() {
    let (provider, _) = jev_with(
        vec![
            ScriptedStep::json(RESPONSE_CHOICE_SUSPICIOUS),
            ScriptedStep::status(500, "boom"),
            ScriptedStep::status(500, "boom"),
            ScriptedStep::status(500, "boom"),
        ],
        test_config("typesafe/jev-1.14"),
    );
    provider.classify(&sample_state(80.0)).await.unwrap();
    let _ = provider.classify(&sample_state(50.0)).await;
    let health = provider.health().await;
    assert_eq!(health.successes, 1);
    assert_eq!(health.failures, 1);
    assert_eq!(health.status, crate::types::ProviderStatus::Degraded);
    assert!(health.last_error.is_some());
    assert!(health.last_latency_ms.is_some());
    assert!(health.total_cost_usd > 0.0);
    assert!(health.checked_at_ms > 0);
}

#[tokio::test]
async fn state_hash_ignores_map_ordering_of_state_fields() {
    // Two identical states constructed independently must hit the cache.
    let a = sample_state(80.0);
    let b = sample_state(80.0);
    assert_eq!(
        crate::cache::state_cache_key(&crate::redaction::redact_state(&a)),
        crate::cache::state_cache_key(&crate::redaction::redact_state(&b))
    );
    let _ = assessment_with_score(80.0);
}

/// Exercises the real `reqwest` transport against a loopback TCP server (never
/// the internet): header, JSON body and response parsing.
#[tokio::test]
async fn reqwest_transport_posts_over_loopback() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&request);
            if let Some(header_end) = text.find("\r\n\r\n") {
                let headers = &text[..header_end];
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let text = String::from_utf8_lossy(&request).to_string();
        let body = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            RESPONSE_CHOICE_SUSPICIOUS.len(),
            RESPONSE_CHOICE_SUSPICIOUS
        );
        stream.write_all(body.as_bytes()).unwrap();
        stream.flush().unwrap();
        text
    });

    let mut config = test_config("typesafe/jev-1.14");
    config.api_key = Some("sk-loopback-key".to_string());
    config.base_url = format!("http://{address}/api/alpha/decisions");
    config.max_retries = 0;
    let provider = JevProvider::with_config(config);
    let result = provider.classify(&sample_state(80.0)).await.unwrap();
    assert_eq!(result.category, DecisionCategory::Suspicious);

    let request = server.join().unwrap();
    let lower = request.to_ascii_lowercase();
    assert!(lower.contains("bearer sk-loopback-key"), "{request}");
    assert!(lower.contains("post /api/alpha/decisions"), "{request}");
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["model"], "typesafe/jev-1.14");
    assert_eq!(parsed["questions"]["classification"]["type"], "choice");
    assert!(body.contains("evil.exe"), "{body}");
    assert!(!body.contains("someuser"), "{body}");
}
