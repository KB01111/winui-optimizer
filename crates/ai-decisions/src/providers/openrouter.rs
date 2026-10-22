//! OpenRouter Decisions API providers (Jev, Mercury Decide, Mercury Decide Free).
//!
//! All three share one core: contract request building, redaction, TTL cache,
//! token-bucket rate limiting, daily cost tracking, bounded retry with
//! exponential backoff and jitter, and health counters. Only the model id and
//! default endpoint tuning differ.

use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use security_core::{DecisionResult, SecurityEventState};
use tokio::sync::Mutex as AsyncMutex;

use crate::cache::{fnv1a64, state_cache_key, DecisionCache, DEFAULT_CACHE_TTL_MS};
use crate::cost::CostTracker;
use crate::error::{sanitize_message, DecisionError};
use crate::providers::DecisionProvider;
use crate::rate_limit::AsyncRateLimiter;
use crate::redaction::redact_state;
use crate::transport::{ReqwestTransport, Transport, TransportRequest};
use crate::types::{now_ms, AiConfig, ProviderHealth, ProviderStatus};
use crate::wire::{self, DEFAULT_BASE_URL};

/// Provider tuning. `Debug` redacts the API key.
#[derive(Clone)]
pub struct ProviderConfig {
    /// Model id sent in the request body.
    pub model: String,
    /// OpenRouter API key (never logged).
    pub api_key: Option<String>,
    /// Endpoint override; defaults to the verified Decisions API endpoint.
    pub base_url: String,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Retries after the initial attempt.
    pub max_retries: u32,
    /// Local token-bucket capacity per minute (0 disables).
    pub requests_per_minute: u32,
    /// Daily cost ceiling in USD (0 disables).
    pub daily_cost_limit_usd: f64,
    /// When false the structured state is withheld from the provider.
    pub allow_cloud_state: bool,
    /// Decision cache TTL in milliseconds (default 10 minutes).
    pub cache_ttl_ms: i64,
    /// Maximum time to wait for a rate-limit token before failing (0 = never wait).
    pub max_rate_wait_ms: u64,
    /// Base delay for exponential backoff.
    pub retry_base_delay_ms: u64,
    /// Cap for exponential backoff and `Retry-After` delays.
    pub retry_max_delay_ms: u64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            model: crate::types::models::MERCURY_DECIDE.to_string(),
            api_key: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout_ms: 30_000,
            max_retries: 2,
            requests_per_minute: 20,
            daily_cost_limit_usd: 1.0,
            allow_cloud_state: true,
            cache_ttl_ms: DEFAULT_CACHE_TTL_MS,
            max_rate_wait_ms: 15_000,
            retry_base_delay_ms: 500,
            retry_max_delay_ms: 8_000,
        }
    }
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("model", &self.model)
            .field(
                "api_key",
                &self.api_key.as_ref().map(|_| "<redacted>".to_string()),
            )
            .field("base_url", &self.base_url)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("daily_cost_limit_usd", &self.daily_cost_limit_usd)
            .field("allow_cloud_state", &self.allow_cloud_state)
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .field("max_rate_wait_ms", &self.max_rate_wait_ms)
            .field("retry_base_delay_ms", &self.retry_base_delay_ms)
            .field("retry_max_delay_ms", &self.retry_max_delay_ms)
            .finish()
    }
}

impl ProviderConfig {
    /// Create a config for a model with an optional key and default tuning.
    pub fn new(model: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.map(|key| key.trim().to_string()),
            ..Self::default()
        }
    }

    /// Override the endpoint (tests and compatible deployments).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Build a provider config from the router-level AI configuration.
    pub fn from_ai_config(ai: &AiConfig, model: &str) -> Self {
        Self {
            model: model.trim().to_string(),
            api_key: ai.api_key.clone(),
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout_ms: ai.timeout_ms,
            max_retries: ai.max_retries,
            requests_per_minute: ai.requests_per_minute,
            daily_cost_limit_usd: ai.daily_cost_limit_usd,
            allow_cloud_state: ai.allow_cloud_state,
            ..Self::default()
        }
    }

    fn normalized_model(mut self, default_model: &str) -> Self {
        if self.model.trim().is_empty() {
            self.model = default_model.to_string();
        }
        self
    }
}

#[derive(Debug, Clone, Default)]
struct HealthState {
    requests: u64,
    successes: u64,
    failures: u64,
    consecutive_failures: u32,
    last_latency_ms: Option<u64>,
    last_error: Option<String>,
    last_ok: Option<bool>,
    total_cost_usd: f64,
}

pub(crate) struct OpenRouterCore {
    config: ProviderConfig,
    transport: Arc<dyn Transport>,
    rate: AsyncRateLimiter,
    cost: AsyncMutex<CostTracker>,
    cache: Mutex<DecisionCache>,
    health: Mutex<HealthState>,
}

impl OpenRouterCore {
    pub(crate) fn new(config: ProviderConfig) -> Self {
        let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::new(config.timeout_ms));
        Self::with_transport(config, transport)
    }

    pub(crate) fn with_transport(config: ProviderConfig, transport: Arc<dyn Transport>) -> Self {
        let cache = DecisionCache::new(config.cache_ttl_ms);
        let cost = CostTracker::new(config.daily_cost_limit_usd);
        let rate = AsyncRateLimiter::new(config.requests_per_minute, config.max_rate_wait_ms);
        Self {
            config,
            transport,
            rate,
            cost: AsyncMutex::new(cost),
            cache: Mutex::new(cache),
            health: Mutex::new(HealthState::default()),
        }
    }

    pub(crate) fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.config
            .api_key
            .as_deref()
            .map(|key| !key.trim().is_empty())
            .unwrap_or(false)
    }

    fn lock_health(&self) -> std::sync::MutexGuard<'_, HealthState> {
        self.health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) async fn classify(
        &self,
        state: &SecurityEventState,
    ) -> Result<DecisionResult, DecisionError> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .ok_or(DecisionError::NotConfigured)?
            .to_string();

        let redacted = redact_state(state);
        let cache_key = state_cache_key(&redacted);
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(mut cached) = cache.get(cache_key, now_ms()) {
                cached.evidence.push(
                    "served from local decision cache (identical redacted state within TTL)".into(),
                );
                tracing::debug!(model = %self.config.model, "decision cache hit");
                return Ok(cached);
            }
        }

        // Cost limit check happens before any network activity.
        self.cost.lock().await.check(now_ms())?;

        let body =
            wire::build_request_body(&self.config.model, &redacted, self.config.allow_cloud_state);

        let mut last_error: Option<DecisionError> = None;
        for attempt in 0..=self.config.max_retries {
            self.rate.acquire().await?;
            {
                let mut health = self.lock_health();
                health.requests += 1;
            }

            let attempt_started = Instant::now();
            let outcome = self
                .transport
                .post_json(TransportRequest {
                    url: self.config.base_url.clone(),
                    api_key: api_key.clone(),
                    body: body.clone(),
                })
                .await;
            let latency_ms = attempt_started.elapsed().as_millis().min(u64::MAX as u128) as u64;

            match outcome {
                Ok(response) if (200..300).contains(&response.status) => {
                    match wire::decision_from_response(
                        &response.body,
                        "openrouter",
                        &self.config.model,
                        latency_ms,
                    ) {
                        Ok(decision) => {
                            self.cost.lock().await.record(now_ms(), decision.cost_usd);
                            {
                                let mut health = self.lock_health();
                                health.successes += 1;
                                health.consecutive_failures = 0;
                                health.last_latency_ms = Some(latency_ms);
                                health.last_ok = Some(true);
                                health.last_error = None;
                                health.total_cost_usd += decision.cost_usd.unwrap_or(0.0).max(0.0);
                            }
                            if let Ok(mut cache) = self.cache.lock() {
                                cache.insert(cache_key, decision.clone(), now_ms());
                            }
                            return Ok(decision);
                        }
                        Err(error) => {
                            self.note_failure(&error, Some(latency_ms));
                            return Err(error);
                        }
                    }
                }
                Ok(response) => {
                    let error =
                        map_status_error(response.status, response.retry_after_ms, &response.body);
                    if error.is_retryable() && attempt < self.config.max_retries {
                        last_error = Some(error);
                        let delay = self.retry_delay_ms(attempt, response.retry_after_ms);
                        tracing::debug!(
                            attempt,
                            delay,
                            status = response.status,
                            "retrying decision request after retryable provider response"
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    self.note_failure(&error, Some(latency_ms));
                    return Err(error);
                }
                Err(error) => {
                    if error.is_retryable() && attempt < self.config.max_retries {
                        last_error = Some(error);
                        let delay = self.retry_delay_ms(attempt, None);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    self.note_failure(&error, Some(latency_ms));
                    return Err(error);
                }
            }
        }

        let error = last_error.unwrap_or_else(|| {
            DecisionError::InvalidResponse("retry loop exhausted without a response".to_string())
        });
        self.note_failure(&error, None);
        Err(error)
    }

    fn note_failure(&self, error: &DecisionError, latency_ms: Option<u64>) {
        let mut health = self.lock_health();
        health.failures += 1;
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_ok = Some(false);
        health.last_error = Some(error.to_string());
        if latency_ms.is_some() {
            health.last_latency_ms = latency_ms;
        }
    }

    fn retry_delay_ms(&self, attempt: u32, retry_after_ms: Option<u64>) -> u64 {
        let cap = self.config.retry_max_delay_ms.max(1);
        if let Some(retry_after) = retry_after_ms {
            return retry_after.clamp(1, cap);
        }
        let exponent = attempt.min(6);
        let base = self
            .config
            .retry_base_delay_ms
            .saturating_mul(1u64 << exponent)
            .min(cap);
        base + jitter_ms(attempt, base)
    }

    pub(crate) fn health_snapshot(&self) -> ProviderHealth {
        let health = self.lock_health().clone();
        let status = if health.requests == 0 {
            ProviderStatus::Unknown
        } else if health.last_ok == Some(true) {
            ProviderStatus::Healthy
        } else if health.successes > 0 {
            ProviderStatus::Degraded
        } else {
            ProviderStatus::Unavailable
        };
        ProviderHealth {
            provider: "openrouter".to_string(),
            model: self.config.model.clone(),
            status,
            successes: health.successes,
            failures: health.failures,
            last_latency_ms: health.last_latency_ms,
            last_error: health.last_error,
            total_cost_usd: health.total_cost_usd,
            requests: health.requests,
            checked_at_ms: now_ms(),
        }
    }
}

fn map_status_error(status: u16, retry_after_ms: Option<u64>, body: &str) -> DecisionError {
    match status {
        401 | 403 => DecisionError::Unauthorized,
        429 => DecisionError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(1_000),
        },
        _ => DecisionError::ProviderError(status, sanitize_message(&truncate(body, 300))),
    }
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// Half-backoff jitter derived from the attempt number and a per-process seed.
fn jitter_ms(attempt: u32, cap: u64) -> u64 {
    let half = cap / 2;
    if half == 0 {
        return 0;
    }
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ ((std::process::id() as u64) << 32)
    });
    let mut buffer = [0u8; 12];
    buffer[..4].copy_from_slice(&attempt.to_le_bytes());
    buffer[4..].copy_from_slice(&seed.to_le_bytes());
    fnv1a64(&buffer) % (half + 1)
}

macro_rules! openrouter_provider {
    ($provider:ident, $default_model:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $provider {
            core: OpenRouterCore,
        }

        impl $provider {
            /// Default model id for this provider.
            pub const DEFAULT_MODEL: &'static str = $default_model;

            /// Create a provider with the official endpoint and default tuning.
            pub fn new(api_key: impl Into<String>) -> Self {
                Self::with_config(ProviderConfig::new($default_model, Some(api_key.into())))
            }

            /// Create a provider without an API key (`is_configured() == false`).
            pub fn anonymous() -> Self {
                Self::with_config(ProviderConfig::new($default_model, None))
            }

            /// Create a provider from an explicit configuration.
            pub fn with_config(config: ProviderConfig) -> Self {
                let config = config.normalized_model($default_model);
                Self {
                    core: OpenRouterCore::new(config),
                }
            }

            /// Effective configuration; `Debug` redacts the API key.
            pub fn config(&self) -> &ProviderConfig {
                self.core.config()
            }

            #[cfg(test)]
            #[allow(dead_code)] // test-only transport hook; not every provider has a mock-transport test
            pub(crate) fn with_transport(
                config: ProviderConfig,
                transport: std::sync::Arc<dyn crate::transport::Transport>,
            ) -> Self {
                let config = config.normalized_model($default_model);
                Self {
                    core: OpenRouterCore::with_transport(config, transport),
                }
            }
        }

        #[async_trait]
        impl DecisionProvider for $provider {
            fn provider_name(&self) -> &'static str {
                "openrouter"
            }

            fn model(&self) -> &str {
                &self.core.config().model
            }

            fn is_configured(&self) -> bool {
                self.core.is_configured()
            }

            async fn classify(
                &self,
                state: &SecurityEventState,
            ) -> Result<DecisionResult, DecisionError> {
                self.core.classify(state).await
            }

            async fn health(&self) -> ProviderHealth {
                self.core.health_snapshot()
            }
        }
    };
}

openrouter_provider!(
    JevProvider,
    crate::types::models::JEV,
    "Escalation provider backed by the `typesafe/jev-1.14` decision model."
);

openrouter_provider!(
    MercuryDecideProvider,
    crate::types::models::MERCURY_DECIDE,
    "Primary triage provider backed by the `inception/mercury-decide` decision model."
);

openrouter_provider!(
    MercuryDecideFreeProvider,
    crate::types::models::MERCURY_DECIDE_FREE,
    "Primary triage provider backed by the free `inception/mercury-decide:free` tier."
);
