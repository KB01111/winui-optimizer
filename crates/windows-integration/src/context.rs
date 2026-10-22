//! Process execution context: packaged state, elevation, identity.
//!
//! Privacy invariant: the username is **never** returned verbatim. The
//! dashboard receives a redacted form such as `k***n`.

use serde::{Deserialize, Serialize};

/// How the process is running: package identity, elevation, identity of the
/// signed-in user and session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionContext {
    /// True when the process has MSIX package identity.
    pub packaged: bool,
    /// True when the process token is elevated.
    pub elevated: bool,
    /// Security identifier of the process user, for example
    /// `S-1-5-21-...`. Not a secret, but never combined with the username.
    pub user_sid: Option<String>,
    /// Username in redacted display form, for example `k***n`.
    pub username_redacted: Option<String>,
    /// Current process id.
    pub process_id: u32,
    /// Terminal services session id when the query succeeds.
    pub session_id: Option<u32>,
}

/// Read the current process execution context.
///
/// Never fails; individual fields are `None` when the corresponding Windows
/// query is unavailable.
pub fn execution_context() -> ExecutionContext {
    imp::execution_context()
}

/// Redact a username for display, keeping only the first and last character:
/// `kevin` becomes `k***n`.
///
/// Names shorter than three characters do not contain enough information to
/// keep any character meaningfully, so they become `*` (one character) or
/// `***` (two characters). Empty or whitespace-only input yields `None`.
pub(crate) fn redact_username(name: &str) -> Option<String> {
    let name = name.trim();
    let mut chars = name.chars();
    let first = chars.next()?;
    let rest: Vec<char> = chars.collect();
    match rest.len() {
        0 => Some("*".to_string()),
        1 => Some("***".to_string()),
        _ => {
            let last = *rest.last().unwrap_or(&first);
            Some(format!("{first}***{last}"))
        }
    }
}

/// Format SID parts as the canonical `S-1-5-...` string. Pure helper kept
/// separate from the raw-pointer reading so it can be unit-tested.
pub(crate) fn format_sid_parts(
    revision: u8,
    authority: [u8; 6],
    sub_authorities: &[u32],
) -> String {
    let authority_value = authority
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut value = format!("S-{revision}-{authority_value}");
    for sub_authority in sub_authorities {
        value.push('-');
        value.push_str(&sub_authority.to_string());
    }
    value
}

#[cfg(windows)]
mod imp {
    use super::{format_sid_parts, redact_username, ExecutionContext};

    /// Hard cap on the number of sub-authorities a SID can have.
    const MAX_SID_SUB_AUTHORITIES: usize = 15;
    /// Buffer that comfortably holds `TOKEN_USER` plus the longest SID.
    const TOKEN_BUFFER_WORDS: usize = 128; // 1 KiB, 8-byte aligned

    /// Values read from the process token.
    #[derive(Debug, Default)]
    struct TokenInfo {
        elevated: bool,
        session_id: Option<u32>,
        user_sid: Option<String>,
        account_name: Option<String>,
    }

    pub fn execution_context() -> ExecutionContext {
        // SAFETY: token handles are closed inside `query_token`.
        let token = unsafe { query_token() };

        let username = token
            .account_name
            .or_else(|| std::env::var("USERNAME").ok());

        ExecutionContext {
            packaged: crate::package::package_identity().available,
            elevated: token.elevated,
            user_sid: token.user_sid,
            username_redacted: username.as_deref().and_then(redact_username),
            process_id: std::process::id(),
            session_id: token.session_id,
        }
    }

    unsafe fn query_token() -> TokenInfo {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut handle = HANDLE::default();
        // SAFETY: `handle` is a valid out-pointer; `GetCurrentProcess` is a
        // pseudo handle that must not be closed.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) };
        if opened.is_err() {
            return TokenInfo::default();
        }
        // SAFETY: `handle` was returned by `OpenProcessToken`.
        let info = unsafe { read_token_info(handle) };
        // SAFETY: `handle` is owned by this function and closed exactly once.
        let _ = unsafe { CloseHandle(handle) };
        info
    }

    unsafe fn read_token_info(token: windows::Win32::Foundation::HANDLE) -> TokenInfo {
        use windows::Win32::Security::{
            TokenElevation, TokenSessionId, TokenUser, TOKEN_ELEVATION, TOKEN_USER,
        };

        let mut info = TokenInfo::default();

        let mut elevation = TOKEN_ELEVATION::default();
        // SAFETY: `elevation` matches the `TokenElevation` information class.
        if unsafe { query_token_value(token, TokenElevation, &mut elevation) } {
            info.elevated = elevation.TokenIsElevated != 0;
        }

        let mut session_id = 0u32;
        // SAFETY: `session_id` matches the `TokenSessionId` information class.
        if unsafe { query_token_value(token, TokenSessionId, &mut session_id) } {
            info.session_id = Some(session_id);
        }

        // `u64` words keep the buffer 8-byte aligned for `TOKEN_USER`.
        let mut buffer = [0u64; TOKEN_BUFFER_WORDS];
        // SAFETY: the buffer is 1 KiB, which always fits `TOKEN_USER` and its
        // embedded SID.
        let user_ok = unsafe { query_token_value(token, TokenUser, &mut buffer) };
        if user_ok {
            // SAFETY: the OS wrote a `TOKEN_USER` at the start of `buffer`.
            let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
            info.user_sid = unsafe { sid_to_string(sid) };
            info.account_name = unsafe { lookup_account_name(sid) };
        }

        info
    }

    /// Query a fixed-size token information class.
    ///
    /// # Safety
    ///
    /// `value` must be the correct type for `class`.
    unsafe fn query_token_value<T>(
        token: windows::Win32::Foundation::HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
        value: &mut T,
    ) -> bool {
        use std::ffi::c_void;
        use std::mem::size_of;

        use windows::Win32::Security::GetTokenInformation;

        let mut returned = 0u32;
        // SAFETY: caller guarantees `value` matches `class`; the length is the
        // size of `T`.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some((value as *mut T).cast::<c_void>()),
                size_of::<T>() as u32,
                &mut returned,
            )
        }
        .is_ok()
    }

    /// Read a SID from its raw memory representation.
    ///
    /// # Safety
    ///
    /// `sid` must point to a valid SID inside a live token buffer.
    unsafe fn sid_to_string(sid: windows::Win32::Security::PSID) -> Option<String> {
        use std::ptr::read_unaligned;

        if sid.is_invalid() {
            return None;
        }
        // SAFETY: SID layout: revision (u8), sub-authority count (u8),
        // identifier authority (6 bytes, big endian), sub-authorities (u32
        // each). The pointer is inside the token buffer, which outlives this
        // call.
        let base = sid.0.cast::<u8>();
        let revision = unsafe { *base };
        let count = unsafe { *base.add(1) } as usize;
        if count > MAX_SID_SUB_AUTHORITIES {
            return None;
        }
        let mut authority = [0u8; 6];
        for (index, byte) in authority.iter_mut().enumerate() {
            *byte = unsafe { *base.add(2 + index) };
        }
        let mut sub_authorities = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: the token buffer is at least `8 + 4 * count` bytes for a
            // valid SID; `read_unaligned` tolerates any alignment.
            let value = unsafe { read_unaligned(base.add(8 + 4 * index).cast::<u32>()) };
            sub_authorities.push(value);
        }
        Some(format_sid_parts(revision, authority, &sub_authorities))
    }

    /// Resolve the account name for a SID. Returns `None` for orphaned SIDs
    /// and when the lookup is denied.
    ///
    /// # Safety
    ///
    /// `sid` must point to a valid SID.
    unsafe fn lookup_account_name(sid: windows::Win32::Security::PSID) -> Option<String> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut kind = SID_NAME_USE::default();

        // SAFETY: buffers are live and their lengths are passed correctly.
        let result = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        };
        if result.is_err() {
            return None;
        }
        let len = (name_len as usize).min(name.len());
        crate::util::clean_string(&String::from_utf16_lossy(&name[..len]))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::ExecutionContext;

    pub fn execution_context() -> ExecutionContext {
        ExecutionContext {
            packaged: false,
            elevated: false,
            user_sid: None,
            username_redacted: None,
            process_id: std::process::id(),
            session_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_username_keeping_first_and_last_character() {
        assert_eq!(redact_username("kevin").as_deref(), Some("k***n"));
        assert_eq!(redact_username("u").as_deref(), Some("*"));
        assert_eq!(redact_username("ab").as_deref(), Some("***"));
        assert_eq!(redact_username("  kevin  ").as_deref(), Some("k***n"));
        assert_eq!(redact_username("").as_deref(), None);
        assert_eq!(redact_username("   ").as_deref(), None);
    }

    #[test]
    fn redaction_never_leaks_full_username() {
        for name in ["kevin", "Administrator", "service-account"] {
            let redacted = redact_username(name).expect("redaction produces a value");
            assert_ne!(redacted, name);
            assert!(!redacted.contains(&name[1..name.len() - 1]));
        }
    }

    #[test]
    fn redaction_handles_unicode_usernames() {
        assert_eq!(redact_username("åsa").as_deref(), Some("å***a"));
        assert_eq!(redact_username("josé").as_deref(), Some("j***é"));
        assert_eq!(redact_username("用户").as_deref(), Some("***"));
    }

    #[test]
    fn formats_well_known_sids() {
        // S-1-5-18 (LocalSystem)
        assert_eq!(format_sid_parts(1, [0, 0, 0, 0, 0, 5], &[18]), "S-1-5-18");
        // S-1-5-21-1111111111-2222222222-3333333333 (domain user)
        assert_eq!(
            format_sid_parts(
                1,
                [0, 0, 0, 0, 0, 5],
                &[21, 1_111_111_111, 2_222_222_222, 3_333_333_333]
            ),
            "S-1-5-21-1111111111-2222222222-3333333333"
        );
        // Default S-1-0-0 (Nobody)
        assert_eq!(format_sid_parts(1, [0, 0, 0, 0, 0, 0], &[0]), "S-1-0-0");
    }

    #[test]
    fn sid_authority_is_big_endian_48_bit() {
        // 0x0000_0100_0000 == 65536.
        assert_eq!(format_sid_parts(2, [0, 0, 0, 1, 0, 0], &[1]), "S-2-65536-1");
    }

    #[test]
    fn serializes_with_camel_case_field_names() {
        let context = ExecutionContext {
            packaged: false,
            elevated: true,
            user_sid: Some("S-1-5-21-1".to_string()),
            username_redacted: Some("k***n".to_string()),
            process_id: 42,
            session_id: Some(1),
        };
        let value = serde_json::to_value(&context).expect("serializes");
        assert!(value.get("userSid").is_some());
        assert!(value.get("usernameRedacted").is_some());
        assert!(value.get("processId").is_some());
        assert!(value.get("sessionId").is_some());
        assert!(value.get("session_id").is_none());
    }
}
