//! Decision provider implementations.

pub(crate) mod mock;
pub(crate) mod openrouter;

use async_trait::async_trait;

use security_core::{DecisionResult, SecurityEventState};

use crate::error::DecisionError;
use crate::types::ProviderHealth;

/// A structured decision provider (Jev, Mercury Decide, mock).
///
/// Implementations must never panic on provider output: every failure is a
/// [`DecisionError`]; the router converts failures into `FailedClosed`.
#[async_trait]
pub trait DecisionProvider: Send + Sync {
    /// Stable provider implementation name, e.g. `openrouter` or `mock`.
    fn provider_name(&self) -> &'static str;

    /// Effective model id.
    fn model(&self) -> &str;

    /// True when the provider has everything it needs (a non-empty API key).
    fn is_configured(&self) -> bool;

    /// Classify a redacted security event state.
    async fn classify(&self, state: &SecurityEventState) -> Result<DecisionResult, DecisionError>;

    /// Current health counters for the UI.
    async fn health(&self) -> ProviderHealth;
}
