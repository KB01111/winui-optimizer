//! Structured AI decision layer: provider traits, OpenRouter Decisions API
//! adapters (Jev, Mercury Decide), a deterministic mock provider, and a router
//! that fails closed without blocking scanning.
//!
//! # Guarantees
//! - The engine works with **no AI provider configured**: `AiMode::Offline`
//!   never touches the network and the router reports `SkippedOffline`.
//! - AI output is advisory only; nothing here can quarantine or delete files.
//! - Redaction always runs (`redact_state`) before a state is serialized for a
//!   provider: user names, absolute paths (reduced to file names) and full
//!   SHA-256 hashes (reduced to 8 characters) never leave the machine.
//! - The API key is never logged, never serialized and never part of an error.
//! - Failures are bounded (retries with exponential backoff + jitter), rate
//!   limited (token bucket per minute), cost limited (daily USD ceiling) and
//!   cached (10 minute TTL keyed by a stable hash of the redacted state).
//!
//! # Calibration
//! Model probabilities are raw provider output. Every result carries an
//! explicit evidence line: *"uncalibrated model probabilities"*. Treat them as
//! relative signals, never as measured error rates.

mod cache;
mod cost;
mod error;
mod providers;
mod rate_limit;
mod redaction;
mod router;
mod transport;
mod types;
mod wire;

#[cfg(test)]
mod provider_tests;
#[cfg(test)]
mod test_support;

pub use error::DecisionError;
pub use providers::mock::{MockDecisionProvider, MockFlags};
pub use providers::openrouter::{
    JevProvider, MercuryDecideFreeProvider, MercuryDecideProvider, ProviderConfig,
};
pub use providers::DecisionProvider;
pub use redaction::{build_decision_state, redact_state};
pub use router::{mock_router, ProviderRouter, DEFAULT_INVESTIGATE_MIN_SCORE};
pub use types::{
    models, AiConfig, AiMode, DecisionRoute, ProviderHealth, ProviderStatus, RoutedDecision,
};
