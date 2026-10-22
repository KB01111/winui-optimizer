//! MSIX/AppX package identity.
//!
//! Preserves the upstream winappCli sample behaviour from
//! `src-tauri/src/lib.rs`: `Package::Current()` succeeds only when the process
//! runs with package identity, and every field is read from `Package.Id()`.

use serde::{Deserialize, Serialize};

/// Identity of the MSIX package the process runs under.
///
/// When the process is not packaged (`Package::Current()` fails) only
/// `available` is set and every optional field is `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageIdentityInfo {
    /// True when the process has MSIX package identity.
    pub available: bool,
    /// Package family name, for example `Contoso.App_1234567890abc`.
    pub family_name: Option<String>,
    /// Full package identity, for example `Contoso.App_1.0.0.0_x64__1234567890abc`.
    pub full_name: Option<String>,
    /// `CN=...` publisher distinguished name.
    pub publisher: Option<String>,
    /// Package version formatted as `Major.Minor.Build.Revision`.
    pub version: Option<String>,
    /// Install location reported by Windows (`Package.InstalledPath`).
    pub install_location: Option<String>,
    /// Application user model id of the first app entry, for example
    /// `Contoso.App_1234567890abc!App`.
    pub app_user_model_id: Option<String>,
}

impl PackageIdentityInfo {
    /// Value used when the process has no package identity.
    pub(crate) fn unavailable() -> Self {
        Self {
            available: false,
            family_name: None,
            full_name: None,
            publisher: None,
            version: None,
            install_location: None,
            app_user_model_id: None,
        }
    }
}

/// Read the current process package identity.
///
/// Never fails: unpackaged processes and non-Windows platforms yield
/// `available: false` with no optional fields set.
pub fn package_identity() -> PackageIdentityInfo {
    imp::package_identity()
}

#[cfg(windows)]
mod imp {
    use super::PackageIdentityInfo;
    use windows::core::HSTRING;
    use windows::ApplicationModel::{AppInfo, Package};

    pub fn package_identity() -> PackageIdentityInfo {
        // `Package::Current()` fails when the app runs without identity, which
        // is the expected state for an un-packaged development build.
        match Package::Current() {
            Ok(package) => package_identity_from(&package),
            Err(_) => PackageIdentityInfo::unavailable(),
        }
    }

    fn package_identity_from(package: &Package) -> PackageIdentityInfo {
        let id = package.Id().ok();

        let family_name = id
            .as_ref()
            .and_then(|id| id.FamilyName().ok())
            .and_then(clean_hstring);

        let full_name = id
            .as_ref()
            .and_then(|id| id.FullName().ok())
            .and_then(clean_hstring);

        let publisher = id
            .as_ref()
            .and_then(|id| id.Publisher().ok())
            .and_then(clean_hstring);

        let version = id.as_ref().and_then(|id| id.Version().ok()).map(|version| {
            format!(
                "{}.{}.{}.{}",
                version.Major, version.Minor, version.Build, version.Revision
            )
        });

        let install_location = package.InstalledPath().ok().and_then(clean_hstring);

        let app_user_model_id = app_user_model_id(package);

        PackageIdentityInfo {
            available: true,
            family_name,
            full_name,
            publisher,
            version,
            install_location,
            app_user_model_id,
        }
    }

    fn app_user_model_id(_package: &Package) -> Option<String> {
        // `AppInfo::Current()` resolves the AUMID of the packaged app. It is a
        // Windows 11 API; on older builds the call fails and the field stays
        // `None`. (`Package::GetAppListEntries` would also work but needs the
        // frozen-out `ApplicationModel_Core` feature.)
        AppInfo::Current()
            .ok()
            .and_then(|info| info.AppUserModelId().ok())
            .and_then(clean_hstring)
    }

    fn clean_hstring(value: HSTRING) -> Option<String> {
        crate::util::clean_string(&value.to_string())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::PackageIdentityInfo;

    pub fn package_identity() -> PackageIdentityInfo {
        PackageIdentityInfo::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_has_no_identity_fields() {
        let info = PackageIdentityInfo::unavailable();
        assert!(!info.available);
        assert!(info.family_name.is_none());
        assert!(info.full_name.is_none());
        assert!(info.publisher.is_none());
        assert!(info.version.is_none());
        assert!(info.install_location.is_none());
        assert!(info.app_user_model_id.is_none());
    }

    #[test]
    fn serializes_with_camel_case_field_names() {
        let info = PackageIdentityInfo {
            available: true,
            family_name: Some("Contoso.App_abc".to_string()),
            full_name: Some("Contoso.App_1.0.0.0_x64__abc".to_string()),
            publisher: Some("CN=Contoso".to_string()),
            version: Some("1.0.0.0".to_string()),
            install_location: Some(r"C:\Program Files\WindowsApps\Contoso.App".to_string()),
            app_user_model_id: Some("Contoso.App_abc!App".to_string()),
        };

        let value = serde_json::to_value(&info).expect("serializes");
        assert_eq!(value["available"], serde_json::json!(true));
        assert!(value.get("familyName").is_some());
        assert!(value.get("fullName").is_some());
        assert!(value.get("installLocation").is_some());
        assert!(value.get("appUserModelId").is_some());
        assert!(value.get("family_name").is_none());
    }
}
