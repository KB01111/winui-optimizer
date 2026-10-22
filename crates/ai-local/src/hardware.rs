//! Best-effort hardware detection (Windows) and the hardware profile types.
//!
//! Detection never panics and never fails: every unknown field is `None` or a
//! zero value. NPU support is reported as **unvalidated**: this crate never
//! claims working NPU inference from a registry hint alone.

use serde::{Deserialize, Serialize};

/// Full hardware picture used for local inference routing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareProfile {
    /// Target architecture, e.g. `x86_64`, `arm64`.
    pub cpu_arch: String,
    /// Marketing CPU name when readable, otherwise a fallback identifier.
    pub cpu_name: Option<String>,
    /// Logical processor count.
    pub logical_cores: u32,
    /// Physical core count when cheaply available.
    pub physical_cores: Option<u32>,
    /// Total physical RAM in MiB.
    pub total_ram_mb: u64,
    /// Currently available physical RAM in MiB.
    pub available_ram_mb: u64,
    /// Hardware GPU adapters (software adapters are skipped).
    pub gpus: Vec<GpuAdapter>,
    /// NPU information; `available` is only ever true when a validated runtime
    /// has been probed (never on this build from registry hints alone).
    pub npu: Option<NpuInfo>,
    /// Battery / power status.
    pub battery: BatteryState,
}

impl Default for HardwareProfile {
    fn default() -> Self {
        Self {
            cpu_arch: std::env::consts::ARCH.to_string(),
            cpu_name: None,
            logical_cores: std::thread::available_parallelism()
                .map(|count| count.get() as u32)
                .unwrap_or(1),
            physical_cores: None,
            total_ram_mb: 0,
            available_ram_mb: 0,
            gpus: Vec::new(),
            npu: None,
            battery: BatteryState {
                present: false,
                percent: None,
                ac_online: true,
                charging: false,
            },
        }
    }
}

/// One GPU adapter (from DXGI on Windows).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuAdapter {
    /// Adapter description as reported by the driver.
    pub name: String,
    /// Vendor name derived from the PCI vendor id.
    pub vendor: String,
    /// Dedicated video memory in MiB (`DedicatedVideoMemory`).
    pub dedicated_vram_mb: u64,
    /// Heuristic discrete-GPU flag (DXGI has no explicit DISCRETE flag).
    pub is_discrete: bool,
    /// True for software adapters (WARP); detect_hardware skips these.
    pub is_software: bool,
}

/// NPU detection result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpuInfo {
    /// Human readable NPU name.
    pub name: String,
    /// True only when a validated local runtime was probed successfully.
    pub available: bool,
    /// Registry-only hint (driver service present); informational.
    pub driver_hint: Option<String>,
}

/// Battery / AC state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatteryState {
    /// A battery is present.
    pub present: bool,
    /// Charge percentage when known.
    pub percent: Option<u8>,
    /// AC power is connected.
    pub ac_online: bool,
    /// Battery is charging.
    pub charging: bool,
}

/// Detect the local hardware. Never panics. Unknown fields are empty.
pub fn detect_hardware() -> HardwareProfile {
    #[cfg(windows)]
    {
        detect_windows()
    }
    #[cfg(not(windows))]
    {
        HardwareProfile::default()
    }
}

/// Map a PCI vendor id onto a human-readable vendor name.
pub fn vendor_name(vendor_id: u32) -> String {
    match vendor_id {
        0x10DE => "NVIDIA".to_string(),
        0x1002 => "AMD".to_string(),
        0x8086 => "Intel".to_string(),
        0x13B5 => "ARM".to_string(),
        0x5143 => "Qualcomm".to_string(),
        0x1AE0 => "Google".to_string(),
        0x15AD => "VMware".to_string(),
        0x1234 => "Bochs".to_string(),
        0x1AF4 => "Red Hat".to_string(),
        other => format!("Unknown (0x{other:04X})"),
    }
}

/// Vendor ids considered discrete-only (NVIDIA never ships integrated GPUs that
/// DXGI enumerates as a display adapter).
const VENDOR_NVIDIA: u32 = 0x10DE;

/// DXGI reports `DedicatedVideoMemory`; adapters with >= 1 GiB dedicated memory
/// are treated as discrete. Integrated GPUs typically report a small carve-out.
const DISCRETE_VRAM_THRESHOLD_MB: u64 = 1024;

/// `DXGI_ADAPTER_FLAG_SOFTWARE` (the `windows` feature set used here does not
/// enable the enum type, so the raw bit is checked).
const DXGI_ADAPTER_FLAG_SOFTWARE: u32 = 0x2;

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn detect_windows() -> HardwareProfile {
    let (cpu_arch, logical_cores) = system_info();
    let cpu_name = crate::reg::read_string_hklm(
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    )
    .or_else(|| {
        std::env::var("PROCESSOR_IDENTIFIER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    let (total_ram_mb, available_ram_mb) = memory_status();
    HardwareProfile {
        cpu_arch,
        cpu_name,
        logical_cores,
        physical_cores: physical_core_count(),
        total_ram_mb,
        available_ram_mb,
        gpus: detect_gpus(),
        npu: detect_npu(),
        battery: battery_state(),
    }
}

#[cfg(windows)]
fn system_info() -> (String, u32) {
    use windows::Win32::System::SystemInformation::{
        GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM,
        PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_IA64, PROCESSOR_ARCHITECTURE_INTEL,
        SYSTEM_INFO,
    };

    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    let architecture = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture.0 };
    let arch = if architecture == PROCESSOR_ARCHITECTURE_AMD64.0 {
        "x86_64"
    } else if architecture == PROCESSOR_ARCHITECTURE_ARM64.0 {
        "arm64"
    } else if architecture == PROCESSOR_ARCHITECTURE_INTEL.0 {
        "x86"
    } else if architecture == PROCESSOR_ARCHITECTURE_ARM.0 {
        "arm"
    } else if architecture == PROCESSOR_ARCHITECTURE_IA64.0 {
        "ia64"
    } else {
        std::env::consts::ARCH
    };
    (arch.to_string(), info.dwNumberOfProcessors)
}

/// Physical core count via `GetLogicalProcessorInformationEx`. Returns `None`
/// when the API fails (cheap enough to always attempt).
#[cfg(windows)]
fn physical_core_count() -> Option<u32> {
    use windows::Win32::System::SystemInformation::{
        GetLogicalProcessorInformationEx, LOGICAL_PROCESSOR_RELATIONSHIP,
    };

    const RELATION_PROCESSOR_CORE: i32 = 0;
    let relationship = LOGICAL_PROCESSOR_RELATIONSHIP(RELATION_PROCESSOR_CORE);

    let mut length: u32 = 0;
    let _ = unsafe { GetLogicalProcessorInformationEx(relationship, None, &mut length) };
    if length == 0 {
        return None;
    }
    let mut buffer: Vec<u64> = vec![0; (length as usize).div_ceil(8)];
    let result = unsafe {
        GetLogicalProcessorInformationEx(
            relationship,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut length,
        )
    };
    if result.is_err() {
        return None;
    }

    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, length as usize) };
    let mut count = 0u32;
    let mut offset = 0usize;
    while offset + 8 <= bytes.len() {
        let record_relationship = i32::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let record_size = u32::from_ne_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;
        if record_size < 8 || offset + record_size > bytes.len() {
            break;
        }
        if record_relationship == RELATION_PROCESSOR_CORE {
            count += 1;
        }
        offset += record_size;
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

#[cfg(windows)]
fn memory_status() -> (u64, u64) {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    const MB: u64 = 1024 * 1024;
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut status) }.is_ok() {
        (status.ullTotalPhys / MB, status.ullAvailPhys / MB)
    } else {
        (0, 0)
    }
}

#[cfg(windows)]
fn battery_state() -> BatteryState {
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

    const BATTERY_FLAG_CHARGING: u8 = 8;
    const BATTERY_FLAG_NO_BATTERY: u8 = 128;
    const BATTERY_FLAG_UNKNOWN: u8 = 255;
    const AC_LINE_STATUS_ONLINE: u8 = 1;

    let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { GetSystemPowerStatus(&mut status) }.is_ok() {
        let flag = status.BatteryFlag;
        BatteryState {
            present: flag != BATTERY_FLAG_UNKNOWN && (flag & BATTERY_FLAG_NO_BATTERY) == 0,
            percent: (status.BatteryLifePercent <= 100).then_some(status.BatteryLifePercent),
            ac_online: status.ACLineStatus == AC_LINE_STATUS_ONLINE,
            charging: (flag & BATTERY_FLAG_CHARGING) != 0,
        }
    } else {
        BatteryState {
            present: false,
            percent: None,
            ac_online: true,
            charging: false,
        }
    }
}

#[cfg(windows)]
fn detect_gpus() -> Vec<GpuAdapter> {
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};

    let mut adapters = Vec::new();
    let factory: IDXGIFactory1 = match unsafe { CreateDXGIFactory1::<IDXGIFactory1>() } {
        Ok(factory) => factory,
        Err(error) => {
            tracing::debug!(error = %error, "DXGI factory creation failed; GPU list unavailable");
            return adapters;
        }
    };

    let mut index = 0u32;
    loop {
        let adapter = match unsafe { factory.EnumAdapters1(index) } {
            Ok(adapter) => adapter,
            Err(_) => break, // DXGI_ERROR_NOT_FOUND when the index is past the end
        };
        index += 1;
        let description = match unsafe { adapter.GetDesc1() } {
            Ok(description) => description,
            Err(_) => continue,
        };

        let is_software = (description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0;
        if is_software {
            tracing::debug!("skipping software GPU adapter");
            continue;
        }

        let name = String::from_utf16_lossy(&description.Description)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        let vendor_id = description.VendorId;
        let dedicated_vram_mb = (description.DedicatedVideoMemory as u64) / (1024 * 1024);
        let is_discrete =
            vendor_id == VENDOR_NVIDIA || dedicated_vram_mb >= DISCRETE_VRAM_THRESHOLD_MB;

        adapters.push(GpuAdapter {
            name,
            vendor: vendor_name(vendor_id),
            dedicated_vram_mb,
            is_discrete,
            is_software: false,
        });
    }
    adapters
}

/// Registry service names that *hint* at NPU driver packages. Finding one is
/// not proof of a usable runtime; `available` stays false.
#[cfg(windows)]
const NPU_SERVICE_HINTS: &[(&str, &str)] = &[
    ("Amdxdna", "AMD XDNA"),
    ("amdipu", "AMD IPU"),
    ("IntelNpu", "Intel"),
    ("intel_npu", "Intel"),
    ("QcNpu", "Qualcomm"),
    ("QcNpuDriver", "Qualcomm"),
];

#[cfg(windows)]
fn detect_npu() -> Option<NpuInfo> {
    for (service, vendor) in NPU_SERVICE_HINTS {
        let subkey = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
        if crate::reg::key_exists_hklm(&subkey) {
            tracing::debug!(service, "NPU driver service hint found in the registry");
            return Some(NpuInfo {
                name: format!("{vendor} NPU (unvalidated)"),
                available: false,
                driver_hint: Some(format!(
                    "driver service '{service}' is present in the registry, but no validated local NPU inference runtime is available; NPU inference is not claimed"
                )),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_hardware_never_panics_and_reports_cores() {
        let profile = detect_hardware();
        assert!(!profile.cpu_arch.is_empty());
        assert!(profile.logical_cores >= 1);
        if let Some(physical) = profile.physical_cores {
            assert!(physical >= 1);
            assert!(physical <= profile.logical_cores);
        }
        // Software adapters must never be reported.
        assert!(profile.gpus.iter().all(|gpu| !gpu.is_software));
        // We never claim a validated NPU runtime from detection alone.
        if let Some(npu) = &profile.npu {
            assert!(!npu.available);
            assert!(npu.driver_hint.is_some());
        }
    }

    #[test]
    fn vendor_names_are_stable() {
        assert_eq!(vendor_name(0x10DE), "NVIDIA");
        assert_eq!(vendor_name(0x1002), "AMD");
        assert_eq!(vendor_name(0x8086), "Intel");
        assert!(vendor_name(0xFFFF).contains("0xFFFF"));
    }

    #[test]
    fn default_profile_is_sane() {
        let profile = HardwareProfile::default();
        assert!(profile.logical_cores >= 1);
        assert!(profile.gpus.is_empty());
        assert!(!profile.battery.present);
    }

    #[test]
    fn profile_serializes_camel_case() {
        let value = serde_json::to_value(HardwareProfile::default()).unwrap();
        assert!(value.get("cpuArch").is_some());
        assert!(value.get("logicalCores").is_some());
        assert!(value.get("totalRamMb").is_some());
    }
}
