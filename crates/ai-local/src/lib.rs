//! Runtime hardware detection and local inference routing interfaces.
//!
//! # Scope
//! - `detect_hardware()` reports what Windows reports (native arch/cores, RAM,
//!   DXGI adapters, power status) plus a best-effort NPU *hint* from the
//!   registry. It never claims validated NPU inference: `NpuInfo::available`
//!   is only set by a future validated runtime probe.
//! - `select_route()` maps `(HardwareProfile, PowerMode, AiMode)` onto a local
//!   runtime. On battery the discrete GPU is never selected for routine
//!   background analysis.
//! - `LocalDecisionModel` is the extensibility seam for real local models
//!   (ONNX/NPU). Only the deterministic [`MockLocalDecisionModel`] ships; no
//!   ONNX runtime dependency is added.
//!
//! The frozen manifest does not include `async-trait`, so the trait uses the
//! equivalent manual boxed-future form and remains object-safe.

mod error;
mod hardware;
mod model;
mod registry;
mod route;

#[cfg(windows)]
mod reg;
#[cfg(test)]
mod test_util;

pub use error::LocalAiError;
pub use hardware::{
    detect_hardware, vendor_name, BatteryState, GpuAdapter, HardwareProfile, NpuInfo,
};
pub use model::{LocalDecisionModel, MockLocalDecisionModel};
pub use registry::{LocalModelEntry, LocalModelKind, LocalModelRegistry};
pub use route::{select_route, AiMode, InferenceRoute, PowerMode, RuntimeKind};
