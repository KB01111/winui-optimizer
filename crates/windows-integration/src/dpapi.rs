//! Data Protection API (DPAPI) helpers.
//!
//! Secrets are encrypted with the current user's DPAPI key and
//! `CRYPTPROTECT_UI_FORBIDDEN`, so no UI prompt can ever appear and no
//! additional entropy is required. Non-Windows builds return
//! [`crate::WindowsIntegrationError::Unsupported`].

use crate::error::WindowsIntegrationError;

/// Encrypt `plaintext` with DPAPI (current user scope).
pub fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
    imp::protect_secret(plaintext)
}

/// Decrypt a blob produced by [`protect_secret`].
pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
    imp::unprotect_secret(ciphertext)
}

#[cfg(windows)]
mod imp {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use crate::error::{api_error, WindowsIntegrationError};

    pub fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
        crypt(true, plaintext)
    }

    pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
        crypt(false, ciphertext)
    }

    fn crypt(protect: bool, data: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
        let operation = if protect {
            "CryptProtectData"
        } else {
            "CryptUnprotectData"
        };
        if data.is_empty() {
            return Err(WindowsIntegrationError::Invalid(
                "secret data must not be empty".to_string(),
            ));
        }
        let length = u32::try_from(data.len()).map_err(|_| {
            WindowsIntegrationError::Invalid("secret is too large for DPAPI".to_string())
        })?;

        let input = CRYPT_INTEGER_BLOB {
            cbData: length,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: both blobs are live for the duration of the call; the OS
        // allocates `output.pbData` with LocalAlloc and it is freed below.
        let result = unsafe {
            if protect {
                CryptProtectData(
                    &input,
                    PCWSTR::null(),
                    None,
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    None,
                    None,
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            }
        };
        result.map_err(|error| api_error(operation, error))?;

        let bytes = if output.pbData.is_null() || output.cbData == 0 {
            Vec::new()
        } else {
            // SAFETY: the OS returned a buffer of `cbData` bytes.
            unsafe {
                std::slice::from_raw_parts(output.pbData as *const u8, output.cbData as usize)
                    .to_vec()
            }
        };

        if !output.pbData.is_null() {
            // SAFETY: the buffer was allocated by the crypt API with
            // LocalAlloc and is freed exactly once here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
            }
        }

        // An encrypted empty payload is indistinguishable from a failure.
        if protect && bytes.is_empty() {
            return Err(WindowsIntegrationError::Invalid(
                "DPAPI returned no ciphertext".to_string(),
            ));
        }
        Ok(bytes)
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::error::WindowsIntegrationError;

    pub fn protect_secret(_plaintext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
        Err(WindowsIntegrationError::Unsupported(
            "DPAPI secret protection",
        ))
    }

    pub fn unprotect_secret(_ciphertext: &[u8]) -> Result<Vec<u8>, WindowsIntegrationError> {
        Err(WindowsIntegrationError::Unsupported(
            "DPAPI secret protection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn protect_unprotect_round_trip() {
        let secret = b"sk-test-secret-value";
        let protected = protect_secret(secret).expect("protects");
        assert_ne!(protected.as_slice(), secret.as_slice());
        assert!(protected.len() > secret.len());

        let unprotected = unprotect_secret(&protected).expect("unprotects");
        assert_eq!(unprotected, secret);
    }

    #[cfg(windows)]
    #[test]
    fn protection_is_randomized() {
        let secret = b"same input";
        let first = protect_secret(secret).expect("protects");
        let second = protect_secret(secret).expect("protects");
        assert_ne!(first, second, "DPAPI output must be randomized");
    }

    #[cfg(windows)]
    #[test]
    fn unprotect_rejects_garbage() {
        assert!(unprotect_secret(b"definitely not a dpapi blob").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn empty_input_is_rejected_without_calling_dpapi() {
        assert!(matches!(
            protect_secret(&[]),
            Err(WindowsIntegrationError::Invalid(_))
        ));
        assert!(matches!(
            unprotect_secret(&[]),
            Err(WindowsIntegrationError::Invalid(_))
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_returns_unsupported() {
        assert!(matches!(
            protect_secret(b"x"),
            Err(WindowsIntegrationError::Unsupported(_))
        ));
        assert!(matches!(
            unprotect_secret(b"x"),
            Err(WindowsIntegrationError::Unsupported(_))
        ));
    }
}
