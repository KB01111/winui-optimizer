//! Minimal read-only registry access.
//!
//! The frozen `windows` crate feature set for this crate does not include
//! `Win32_System_Registry`, so `advapi32` is called directly. Only read-only
//! operations are declared here; this module can never modify the registry.
//! Every call is best-effort and returns `None`/`false` on any failure.

use std::os::windows::ffi::OsStrExt;

type Hkey = *mut core::ffi::c_void;

/// `HKEY_LOCAL_MACHINE` (`(HKEY)(LONG)0x80000002`, sign-extended on x64).
const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002u32 as i32 as isize as usize as *mut core::ffi::c_void;
const ERROR_SUCCESS: i32 = 0;
const ERROR_MORE_DATA: i32 = 234;
/// `RRF_RT_REG_SZ`
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
/// `KEY_READ`
const KEY_READ: u32 = 0x0002_0019;

#[link(name = "advapi32")]
extern "system" {
    fn RegGetValueW(
        hkey: Hkey,
        lpsubkey: *const u16,
        lpvalue: *const u16,
        dwflags: u32,
        pdwtype: *mut u32,
        pvdata: *mut core::ffi::c_void,
        pcbdata: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        hkey: Hkey,
        lpsubkey: *const u16,
        uloptions: u32,
        samdesired: u32,
        phkresult: *mut Hkey,
    ) -> i32;
    fn RegCloseKey(hkey: Hkey) -> i32;
}

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Read a `REG_SZ` value under `HKLM\<subkey>`.
pub(crate) fn read_string_hklm(subkey: &str, value_name: &str) -> Option<String> {
    let subkey_w = wide(subkey);
    let value_w = wide(value_name);

    let mut size: u32 = 0;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            value_w.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) || size == 0 {
        return None;
    }

    let mut buffer = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut buffer_size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            value_w.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            &mut buffer_size,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    let length = ((buffer_size as usize).div_ceil(2)).min(buffer.len());
    let end = buffer[..length]
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(length);
    if end == 0 {
        return None;
    }
    let value = String::from_utf16_lossy(&buffer[..end]).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// True when `HKLM\<subkey>` exists and is readable.
pub(crate) fn key_exists_hklm(subkey: &str) -> bool {
    let subkey_w = wide(subkey);
    let mut handle: Hkey = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            KEY_READ,
            &mut handle,
        )
    };
    if status == ERROR_SUCCESS && !handle.is_null() {
        unsafe { RegCloseKey(handle) };
        true
    } else {
        false
    }
}
