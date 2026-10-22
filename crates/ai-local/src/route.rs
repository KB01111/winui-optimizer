//! Local inference routing: pick a runtime for background analysis.
//!
//! Rules (contract + prompt):
//! - **Battery**: primary is a `Cpu`, or `Npu` when a *validated* NPU runtime is
//!   present; fallback is always `Cpu`; `allow_discrete_gpu` is `false`.
//! - **AC**: prefer a validated NPU, otherwise `Cpu` (no validated GPU runtime
//!   exists in this build, so iGPU/dGPU are never selected); the discrete GPU
//!   is only *allowed* for explicit user-initiated heavy analysis.
//! - **Cloud** is only ever the primary route in `AiMode::Cloud`, and it is a
//!   separate route from local runtimes.

use serde::{Deserialize, Serialize};

use crate::hardware::HardwareProfile;

/// AI operating mode. Mirrors `ai_decisions::AiMode` (serialized identically,
/// `offline`/`cloud`/`hybrid`) so `ai-local` stays a dependency leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiMode {
    /// Local analysis only; no cloud decisions.
    Offline,
    /// Cloud decision provider only.
    Cloud,
    /// Local analysis preferred; the decision router may use the cloud.
    Hybrid,
}

/// Where a piece of local analysis should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Cpu,
    Npu,
    IntegratedGpu,
    DiscreteGpu,
    Cloud,
}

impl RuntimeKind {
    /// Stable string form for logs and UI.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Npu => "npu",
            Self::IntegratedGpu => "integrated_gpu",
            Self::DiscreteGpu => "discrete_gpu",
            Self::Cloud => "cloud",
        }
    }
}

/// Power source for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerMode {
    Battery,
    Ac,
}

impl PowerMode {
    /// Derive from a detected battery state: AC is assumed only when the power
    /// API explicitly reports the AC line online.
    pub fn from_battery(battery: &crate::hardware::BatteryState) -> Self {
        if battery.ac_online {
            Self::Ac
        } else {
            Self::Battery
        }
    }
}

/// Result of local runtime selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceRoute {
    /// Preferred runtime.
    pub primary: RuntimeKind,
    /// Fallback runtime when the primary is unavailable.
    pub fallback: RuntimeKind,
    /// Human readable explanation of the decision.
    pub reason: String,
    /// True when an explicit user-initiated heavy analysis may use the dGPU.
    pub allow_discrete_gpu: bool,
}

/// Select the local inference route for the given hardware, power and AI mode.
pub fn select_route(profile: &HardwareProfile, mode: PowerMode, ai: AiMode) -> InferenceRoute {
    let validated_npu = profile
        .npu
        .as_ref()
        .map(|npu| npu.available)
        .unwrap_or(false);
    let npu_name = profile.npu.as_ref().map(|npu| npu.name.as_str());
    let npu_hint = profile
        .npu
        .as_ref()
        .and_then(|npu| npu.driver_hint.as_deref());
    let has_discrete_gpu = profile
        .gpus
        .iter()
        .any(|gpu| gpu.is_discrete && !gpu.is_software);
    let has_hardware_gpu = profile.gpus.iter().any(|gpu| !gpu.is_software);

    if ai == AiMode::Cloud {
        return InferenceRoute {
            primary: RuntimeKind::Cloud,
            fallback: RuntimeKind::Cpu,
            reason: "cloud AI mode: classification runs in the configured cloud decision provider; local CPU analysis remains the deterministic fallback and no local GPU or NPU is reserved".to_string(),
            allow_discrete_gpu: false,
        };
    }

    let mut reason = String::new();
    let primary = if validated_npu {
        reason.push_str(&format!(
            "validated NPU runtime present ({})",
            npu_name.unwrap_or("NPU")
        ));
        RuntimeKind::Npu
    } else {
        reason.push_str("no validated local accelerator runtime is available");
        RuntimeKind::Cpu
    };

    match mode {
        PowerMode::Battery => {
            reason.push_str(&format!(
                "; running on battery, primary {} keeps background analysis low-power",
                primary.as_str()
            ));
            if !validated_npu {
                if let Some(hint) = npu_hint {
                    reason.push_str(&format!(
                        "; NPU driver hint only ({hint}), never selected without a validated runtime"
                    ));
                }
            }
            reason
                .push_str("; discrete GPU is not used for routine background analysis on battery");
        }
        PowerMode::Ac => {
            reason.push_str("; running on AC power");
            if !validated_npu {
                if has_hardware_gpu {
                    reason.push_str(
                        "; GPU hardware is present but no validated GPU inference runtime exists in this build, so CPU is used",
                    );
                } else {
                    reason.push_str("; no GPU or NPU inference runtime available, so CPU is used");
                }
                if let Some(hint) = npu_hint {
                    reason.push_str(&format!(
                        "; NPU driver hint only ({hint}), never selected without a validated runtime"
                    ));
                }
            }
        }
    }

    let allow_discrete_gpu = mode == PowerMode::Ac && has_discrete_gpu;
    if allow_discrete_gpu {
        reason
            .push_str("; an explicit user-initiated heavy analysis may opt into the discrete GPU");
        // Mention that background analysis still avoids it.
        if primary != RuntimeKind::DiscreteGpu {
            reason.push_str(" (background analysis never does)");
        }
    }

    match ai {
        AiMode::Offline => {
            reason.push_str("; offline mode: no cloud decisions are requested");
        }
        AiMode::Hybrid => {
            reason.push_str(
                "; hybrid mode: the decision router may use the configured cloud provider when policy allows",
            );
        }
        AiMode::Cloud => {}
    }

    InferenceRoute {
        primary,
        fallback: RuntimeKind::Cpu,
        reason,
        allow_discrete_gpu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{BatteryState, GpuAdapter, HardwareProfile, NpuInfo};

    fn gpu(name: &str, vendor: &str, vram_mb: u64, discrete: bool) -> GpuAdapter {
        GpuAdapter {
            name: name.to_string(),
            vendor: vendor.to_string(),
            dedicated_vram_mb: vram_mb,
            is_discrete: discrete,
            is_software: false,
        }
    }

    fn profile_with(
        gpus: Vec<GpuAdapter>,
        npu: Option<NpuInfo>,
        battery: BatteryState,
    ) -> HardwareProfile {
        HardwareProfile {
            gpus,
            npu,
            battery,
            ..HardwareProfile::default()
        }
    }

    fn npu(available: bool, hint: Option<&str>) -> NpuInfo {
        NpuInfo {
            name: "AMD XDNA NPU".to_string(),
            available,
            driver_hint: hint.map(|hint| hint.to_string()),
        }
    }

    fn battery_state(ac: bool) -> BatteryState {
        BatteryState {
            present: !ac,
            percent: Some(90),
            ac_online: ac,
            charging: false,
        }
    }

    #[test]
    fn battery_never_selects_discrete_gpu_even_when_present() {
        let profile = profile_with(
            vec![gpu("GeForce RTX 4090", "NVIDIA", 24_576, true)],
            None,
            battery_state(false),
        );
        let route = select_route(&profile, PowerMode::Battery, AiMode::Offline);
        assert_eq!(route.primary, RuntimeKind::Cpu);
        assert_eq!(route.fallback, RuntimeKind::Cpu);
        assert!(!route.allow_discrete_gpu);
        assert_ne!(route.primary, RuntimeKind::DiscreteGpu);
        assert!(route.reason.contains("battery"), "{}", route.reason);
        assert!(route.reason.contains("discrete GPU"), "{}", route.reason);

        // Same for hybrid mode.
        let route = select_route(&profile, PowerMode::Battery, AiMode::Hybrid);
        assert_ne!(route.primary, RuntimeKind::DiscreteGpu);
        assert!(!route.allow_discrete_gpu);
        assert!(route.reason.contains("hybrid"), "{}", route.reason);
    }

    #[test]
    fn battery_prefers_validated_npu() {
        let profile = profile_with(
            vec![gpu("GeForce RTX 4090", "NVIDIA", 24_576, true)],
            Some(npu(true, None)),
            battery_state(false),
        );
        let route = select_route(&profile, PowerMode::Battery, AiMode::Offline);
        assert_eq!(route.primary, RuntimeKind::Npu);
        assert_eq!(route.fallback, RuntimeKind::Cpu);
        assert!(!route.allow_discrete_gpu);
        assert!(route.reason.contains("validated NPU"), "{}", route.reason);
    }

    #[test]
    fn battery_with_registry_hint_only_stays_on_cpu_and_says_so() {
        let profile = profile_with(
            vec![],
            Some(npu(false, Some("driver service 'Amdxdna' present"))),
            battery_state(false),
        );
        let route = select_route(&profile, PowerMode::Battery, AiMode::Offline);
        assert_eq!(route.primary, RuntimeKind::Cpu);
        assert!(
            route.reason.contains("driver hint only"),
            "{}",
            route.reason
        );
        assert!(
            route
                .reason
                .contains("never selected without a validated runtime"),
            "{}",
            route.reason
        );
    }

    #[test]
    fn ac_with_validated_npu_selects_npu() {
        let profile = profile_with(
            vec![gpu("Intel Iris Xe", "Intel", 128, false)],
            Some(npu(true, None)),
            battery_state(true),
        );
        let route = select_route(&profile, PowerMode::Ac, AiMode::Hybrid);
        assert_eq!(route.primary, RuntimeKind::Npu);
        assert_eq!(route.fallback, RuntimeKind::Cpu);
        assert!(route.reason.contains("AC power"), "{}", route.reason);
    }

    #[test]
    fn ac_without_validated_runtime_uses_cpu_and_allows_explicit_dgpu() {
        let profile = profile_with(
            vec![gpu("GeForce RTX 4060", "NVIDIA", 8_192, true)],
            None,
            battery_state(true),
        );
        let route = select_route(&profile, PowerMode::Ac, AiMode::Offline);
        assert_eq!(route.primary, RuntimeKind::Cpu);
        assert!(route.allow_discrete_gpu);
        assert!(
            route.reason.contains("no validated GPU inference runtime"),
            "{}",
            route.reason
        );
        assert!(
            route.reason.contains("explicit user-initiated"),
            "{}",
            route.reason
        );
    }

    #[test]
    fn no_gpu_routes_to_cpu() {
        let profile = profile_with(vec![], None, battery_state(true));
        for ai in [AiMode::Offline, AiMode::Hybrid] {
            let route = select_route(&profile, PowerMode::Ac, ai);
            assert_eq!(route.primary, RuntimeKind::Cpu);
            assert_eq!(route.fallback, RuntimeKind::Cpu);
            assert!(!route.allow_discrete_gpu);
            assert!(!route.reason.is_empty());
        }
    }

    #[test]
    fn integrated_gpu_alone_never_allows_discrete() {
        let profile = profile_with(
            vec![gpu("Intel UHD Graphics", "Intel", 128, false)],
            None,
            battery_state(true),
        );
        let route = select_route(&profile, PowerMode::Ac, AiMode::Offline);
        assert_eq!(route.primary, RuntimeKind::Cpu);
        assert!(!route.allow_discrete_gpu);
        assert_ne!(route.primary, RuntimeKind::IntegratedGpu);
    }

    #[test]
    fn cloud_mode_is_cloud_with_cpu_fallback() {
        let profile = profile_with(
            vec![gpu("GeForce RTX 4090", "NVIDIA", 24_576, true)],
            Some(npu(true, None)),
            battery_state(true),
        );
        let route = select_route(&profile, PowerMode::Ac, AiMode::Cloud);
        assert_eq!(route.primary, RuntimeKind::Cloud);
        assert_eq!(route.fallback, RuntimeKind::Cpu);
        assert!(!route.allow_discrete_gpu);
        assert!(route.reason.contains("cloud"), "{}", route.reason);
    }

    #[test]
    fn power_mode_from_battery_state() {
        assert_eq!(PowerMode::from_battery(&battery_state(true)), PowerMode::Ac);
        assert_eq!(
            PowerMode::from_battery(&battery_state(false)),
            PowerMode::Battery
        );
    }

    #[test]
    fn route_serializes_camel_case() {
        let route = select_route(
            &profile_with(vec![], None, battery_state(true)),
            PowerMode::Ac,
            AiMode::Offline,
        );
        let value = serde_json::to_value(&route).unwrap();
        assert!(value.get("allowDiscreteGpu").is_some());
        assert_eq!(value["primary"], "cpu");
        assert_eq!(value["fallback"], "cpu");
    }
}
