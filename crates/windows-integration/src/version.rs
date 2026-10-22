//! Windows version, edition and architecture detection.
//!
//! The engine reports what Windows actually reports, combining three sources:
//!
//! 1. `GetVersionExW` (windows-rs `Win32::System::SystemInformation`). This
//!    call returns fictional values for un-manifested processes, so its
//!    results are only used as a fallback.
//! 2. The live registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
//!    (`CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`,
//!    `CurrentBuildNumber`/`CurrentBuild`, `UBR`, `DisplayVersion`,
//!    `ReleaseId`, `ProductName`, `EditionID`). These values are correct
//!    regardless of application manifest.
//! 3. `GetNativeSystemInfo` for the processor architecture.
//!
//! `is_windows_11` is true when the build number is `>= 22000`.
//!
//! `RtlGetVersion` would be the ideal source but requires the
//! `Wdk_System_SystemServices` feature of the `windows` crate, which is frozen
//! out of this crate's manifest; see the workstream report.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::clean_string;

/// Build number of the first Windows 11 release (21H2).
pub(crate) const WINDOWS_11_MIN_BUILD: u32 = 22_000;
/// Registry key that holds the real OS version metadata on all NT releases.
pub(crate) const REGISTRY_CURRENT_VERSION_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const REGISTRY_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Windows version information reported to the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsVersion {
    /// Major version, for example `10`.
    pub major: u32,
    /// Minor version, for example `0`.
    pub minor: u32,
    /// Build number, for example `22631`.
    pub build: u32,
    /// Update build revision (`UBR`), for example `4317`.
    pub revision: u32,
    /// Marketing/feature update name, for example `23H2`.
    pub display_version: String,
    /// Product name, for example `Windows 11 Pro`. `Windows 10` product names
    /// are corrected to `Windows 11` when the build is `>= 22000`, because
    /// Windows never updated that registry value.
    pub edition: String,
    /// Processor architecture as reported by `GetNativeSystemInfo`
    /// (`x86_64`, `aarch64`, `x86`, `arm`, `ia64`).
    pub architecture: String,
    /// True when `build >= 22000`.
    pub is_windows_11: bool,
}

/// Read the Windows version, edition and architecture.
///
/// Never fails: when a source is unavailable a documented fallback is used
/// (and on non-Windows platforms a zeroed fallback is returned).
pub fn windows_version() -> WindowsVersion {
    imp::windows_version()
}

/// Raw values read from the registry key `...\CurrentVersion`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RegistryOsInfo {
    pub product_name: Option<String>,
    pub edition_id: Option<String>,
    pub display_version: Option<String>,
    pub release_id: Option<String>,
    pub current_build: Option<u32>,
    pub current_build_number: Option<u32>,
    pub ubr: Option<u32>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
}

impl RegistryOsInfo {
    pub(crate) fn build(&self) -> Option<u32> {
        self.current_build_number.or(self.current_build)
    }
}

/// Parse the output of `reg.exe query <key>`. Unknown values are ignored;
/// expected values are matched case-insensitively.
pub(crate) fn parse_registry_output(output: &str) -> RegistryOsInfo {
    let mut info = RegistryOsInfo::default();
    for line in output.lines() {
        let Some((name, kind, data)) = split_registry_line(line) else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "productname" => info.product_name = clean_string(data),
            "editionid" => info.edition_id = clean_string(data),
            "displayversion" => info.display_version = clean_string(data),
            "releaseid" => info.release_id = clean_string(data),
            "currentbuild" => info.current_build = parse_registry_u32(kind, data),
            "currentbuildnumber" => info.current_build_number = parse_registry_u32(kind, data),
            "ubr" => info.ubr = parse_registry_u32(kind, data),
            "currentmajorversionnumber" => info.major = parse_registry_u32(kind, data),
            "currentminorversionnumber" => info.minor = parse_registry_u32(kind, data),
            _ => {}
        }
    }
    info
}

fn split_registry_line(line: &str) -> Option<(&str, &str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("HKEY") {
        return None;
    }
    let name_end = line.find(char::is_whitespace)?;
    let name = &line[..name_end];
    let rest = line[name_end..].trim_start();
    let kind_end = rest.find(char::is_whitespace)?;
    let kind = &rest[..kind_end];
    if !kind.starts_with("REG_") {
        return None;
    }
    let data = rest[kind_end..].trim_start();
    Some((name, kind, data))
}

fn parse_registry_u32(kind: &str, data: &str) -> Option<u32> {
    let data = data.trim();
    if data.is_empty() {
        return None;
    }
    if kind.eq_ignore_ascii_case("REG_DWORD") {
        if let Some(hex) = data.strip_prefix("0x").or_else(|| data.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok();
        }
        // Some tools print REG_DWORD values in decimal.
        return data.parse().ok();
    }
    // REG_SZ values such as `CurrentBuildNumber` are decimal strings.
    data.parse().ok()
}

/// Merge the sources into the reported [`WindowsVersion`].
///
/// Registry values win over `GetVersionExW` because they stay correct for
/// processes without an OS-compatibility manifest.
pub(crate) fn assemble_windows_version(
    version_ex: Option<(u32, u32, u32)>,
    registry: &RegistryOsInfo,
    architecture: &str,
) -> WindowsVersion {
    let major = registry
        .major
        .or_else(|| version_ex.map(|(major, _, _)| major))
        .unwrap_or(0);
    let minor = registry
        .minor
        .or_else(|| version_ex.map(|(_, minor, _)| minor))
        .unwrap_or(0);
    let build = registry
        .build()
        .or_else(|| version_ex.map(|(_, _, build)| build))
        .unwrap_or(0);
    let revision = registry.ubr.unwrap_or(0);

    let display_version = registry
        .display_version
        .clone()
        .or_else(|| registry.release_id.clone())
        .unwrap_or_else(|| format!("{major}.{minor}.{build}"));

    let edition = registry
        .product_name
        .as_deref()
        .map(|name| normalize_edition(name, build))
        .or_else(|| registry.edition_id.clone())
        .unwrap_or_else(|| "Windows".to_string());

    WindowsVersion {
        major,
        minor,
        build,
        revision,
        display_version,
        edition,
        architecture: architecture.to_string(),
        is_windows_11: is_windows_11_build(build),
    }
}

/// True when the build number belongs to Windows 11 or later.
pub(crate) fn is_windows_11_build(build: u32) -> bool {
    build >= WINDOWS_11_MIN_BUILD
}

/// Windows keeps reporting `Windows 10 <edition>` in `ProductName` on
/// Windows 11; correct the prefix when the build proves it is Windows 11.
pub(crate) fn normalize_edition(product_name: &str, build: u32) -> String {
    if is_windows_11_build(build) {
        if let Some(rest) = product_name.strip_prefix("Windows 10 ") {
            return format!("Windows 11 {rest}");
        }
    }
    product_name.to_string()
}

/// Map a raw `PROCESSOR_ARCHITECTURE` value (as returned by
/// `GetNativeSystemInfo`) to a stable name.
pub(crate) fn architecture_name(raw: u16) -> String {
    match raw {
        0 => "x86".to_string(),
        5 => "arm".to_string(),
        6 => "ia64".to_string(),
        9 => "x86_64".to_string(),
        12 => "aarch64".to_string(),
        13 => "arm32_on_win64".to_string(),
        0xFFFF => "unknown".to_string(),
        other => format!("unknown({other})"),
    }
}

#[cfg(windows)]
mod imp {
    use std::mem::size_of;

    use super::{
        architecture_name, assemble_windows_version, RegistryOsInfo, REGISTRY_CURRENT_VERSION_KEY,
        REGISTRY_QUERY_TIMEOUT,
    };
    use crate::WindowsVersion;

    pub fn windows_version() -> WindowsVersion {
        let version_ex = unsafe { version_ex() };
        let registry = read_registry_os_info().unwrap_or_default();
        let architecture = detect_architecture();
        assemble_windows_version(version_ex, &registry, &architecture)
    }

    /// `GetVersionExW` fallback. Values are only used when the registry does
    /// not provide them; without an OS-compatibility manifest this call
    /// returns `6.2` for modern Windows.
    unsafe fn version_ex() -> Option<(u32, u32, u32)> {
        use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        unsafe { GetVersionExW(&mut info) }.ok()?;
        Some((info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber))
    }

    fn detect_architecture() -> String {
        use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};

        let mut info = SYSTEM_INFO::default();
        // SAFETY: `info` is a live, correctly sized `SYSTEM_INFO`.
        let raw = unsafe {
            GetNativeSystemInfo(&mut info);
            info.Anonymous.Anonymous.wProcessorArchitecture
        };
        architecture_name(raw.0)
    }

    fn read_registry_os_info() -> Option<RegistryOsInfo> {
        // `reg.exe` is present on every supported Windows build and needs no
        // extra windows-rs feature (the registry API feature is frozen out).
        let output = crate::process_util::run_with_timeout(
            "reg.exe",
            &["query", REGISTRY_CURRENT_VERSION_KEY],
            REGISTRY_QUERY_TIMEOUT,
        )
        .ok()?;
        if output.exit_code != 0 {
            return None;
        }
        Some(super::parse_registry_output(&output.stdout))
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::WindowsVersion;

    pub fn windows_version() -> WindowsVersion {
        WindowsVersion {
            major: 0,
            minor: 0,
            build: 0,
            revision: 0,
            display_version: "Unknown".to_string(),
            edition: "Unsupported on this platform".to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            is_windows_11: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic `reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"`
    /// output (CRLF line endings, four-space indents).
    const REGISTRY_FIXTURE: &str = "\r
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r
    BuildLab    REG_SZ    22631.1.amd64fre.ni_release.220506-1250\r
    CurrentBuild    REG_SZ    22631\r
    CurrentBuildNumber    REG_SZ    22631\r
    CurrentMajorVersionNumber    REG_DWORD    0xa\r
    CurrentMinorVersionNumber    REG_DWORD    0x0\r
    DisplayVersion    REG_SZ    23H2\r
    EditionID    REG_SZ    Professional\r
    ProductName    REG_SZ    Windows 10 Pro\r
    UBR    REG_DWORD    0x109d\r
    InstallDate    REG_DWORD    0x5f2a1b2c\r
";

    #[test]
    fn parses_registry_fixture() {
        let info = parse_registry_output(REGISTRY_FIXTURE);
        assert_eq!(info.product_name.as_deref(), Some("Windows 10 Pro"));
        assert_eq!(info.edition_id.as_deref(), Some("Professional"));
        assert_eq!(info.display_version.as_deref(), Some("23H2"));
        assert_eq!(info.current_build_number, Some(22631));
        assert_eq!(info.current_build, Some(22631));
        assert_eq!(info.ubr, Some(0x109d));
        assert_eq!(info.major, Some(10));
        assert_eq!(info.minor, Some(0));
        assert_eq!(info.release_id, None);
    }

    #[test]
    fn registry_parsing_tolerates_missing_and_odd_lines() {
        let info = parse_registry_output(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\n\
             \x20   ReleaseId    REG_SZ    2009\n\
             garbage line without columns\n\
             \x20   EmptyValue   REG_SZ    \n\
             \x20   Weird    REG_MULTI_SZ    a\\0b\n",
        );
        assert_eq!(info.release_id.as_deref(), Some("2009"));
        assert_eq!(info.display_version, None);
        assert_eq!(info.current_build, None);
    }

    #[test]
    fn parses_decimal_dword_values() {
        let info = parse_registry_output("    UBR    REG_DWORD    4317\n");
        assert_eq!(info.ubr, Some(4317));
    }

    #[test]
    fn windows_11_boundary_is_22000() {
        assert!(!is_windows_11_build(21_999));
        assert!(is_windows_11_build(22_000));
        assert!(is_windows_11_build(26_100));
    }

    #[test]
    fn normalize_edition_corrects_windows_11_product_name() {
        assert_eq!(
            normalize_edition("Windows 10 Pro", 22_631),
            "Windows 11 Pro"
        );
        assert_eq!(
            normalize_edition("Windows 10 Home Single Language", 22_631),
            "Windows 11 Home Single Language"
        );
        assert_eq!(
            normalize_edition("Windows 10 Pro", 19_045),
            "Windows 10 Pro"
        );
        assert_eq!(
            normalize_edition("Windows Server 2022 Datacenter", 20_348),
            "Windows Server 2022 Datacenter"
        );
    }

    #[test]
    fn registry_values_win_over_get_version_ex() {
        let registry = parse_registry_output(REGISTRY_FIXTURE);
        // An un-manifested process reports 6.2.9200; the registry must win.
        let version = assemble_windows_version(Some((6, 2, 9200)), &registry, "x86_64");
        assert_eq!(version.major, 10);
        assert_eq!(version.minor, 0);
        assert_eq!(version.build, 22_631);
        assert_eq!(version.revision, 0x109d);
        assert_eq!(version.display_version, "23H2");
        assert_eq!(version.edition, "Windows 11 Pro");
        assert_eq!(version.architecture, "x86_64");
        assert!(version.is_windows_11);
    }

    #[test]
    fn falls_back_to_get_version_ex_without_registry() {
        let version =
            assemble_windows_version(Some((10, 0, 19_045)), &RegistryOsInfo::default(), "x86_64");
        assert_eq!(version.major, 10);
        assert_eq!(version.minor, 0);
        assert_eq!(version.build, 19_045);
        assert_eq!(version.revision, 0);
        assert_eq!(version.display_version, "10.0.19045");
        assert_eq!(version.edition, "Windows");
        assert!(!version.is_windows_11);
    }

    #[test]
    fn falls_back_to_zeroes_without_any_source() {
        let version = assemble_windows_version(None, &RegistryOsInfo::default(), "aarch64");
        assert_eq!(version.major, 0);
        assert_eq!(version.build, 0);
        assert_eq!(version.display_version, "0.0.0");
        assert!(!version.is_windows_11);
    }

    #[test]
    fn release_id_is_used_when_display_version_is_missing() {
        let registry = RegistryOsInfo {
            release_id: Some("2009".to_string()),
            current_build_number: Some(19_045),
            ..RegistryOsInfo::default()
        };
        let version = assemble_windows_version(None, &registry, "x86_64");
        assert_eq!(version.display_version, "2009");
    }

    #[test]
    fn edition_id_is_used_when_product_name_is_missing() {
        let registry = RegistryOsInfo {
            edition_id: Some("Enterprise".to_string()),
            current_build_number: Some(22_631),
            ..RegistryOsInfo::default()
        };
        let version = assemble_windows_version(None, &registry, "x86_64");
        assert_eq!(version.edition, "Enterprise");
    }

    #[test]
    fn architecture_names_are_stable() {
        assert_eq!(architecture_name(9), "x86_64");
        assert_eq!(architecture_name(12), "aarch64");
        assert_eq!(architecture_name(0), "x86");
        assert_eq!(architecture_name(0xFFFF), "unknown");
        assert_eq!(architecture_name(77), "unknown(77)");
    }

    #[test]
    fn serializes_with_camel_case_field_names() {
        let version = assemble_windows_version(None, &RegistryOsInfo::default(), "x86_64");
        let value = serde_json::to_value(&version).expect("serializes");
        assert!(value.get("displayVersion").is_some());
        assert!(value.get("isWindows11").is_some());
        assert!(value.get("display_version").is_none());
    }
}
