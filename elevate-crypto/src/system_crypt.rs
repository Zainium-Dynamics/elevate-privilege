//! Optional `crypt(3)` via libcrypt (feature `system_crypt`).
//!
//! Covers formats pure-Rust may not implement yet (e.g. `$y$` yescrypt).

use std::ffi::{CStr, CString};
use std::sync::Mutex;

use crate::common::ct_eq;
use crate::error::{CryptoError, CryptoResult};

// crypt(3) is not thread-safe; serialize calls.
static CRYPT_LOCK: Mutex<()> = Mutex::new(());

extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify password with system crypt(3).
pub fn verify(password: &str, hash: &str) -> CryptoResult<bool> {
    let c_pass = CString::new(password).map_err(|_| CryptoError::InvalidInput("password NUL"))?;
    let c_hash = CString::new(hash).map_err(|_| CryptoError::InvalidInput("hash NUL"))?;

    let _guard = CRYPT_LOCK
        .lock()
        .map_err(|_| CryptoError::Internal("crypt lock poisoned"))?;

    // SAFETY: crypt returns pointer into static/thread buffer; copy immediately.
    let result = unsafe { crypt(c_pass.as_ptr(), c_hash.as_ptr()) };
    if result.is_null() {
        return Ok(false);
    }
    let out = unsafe { CStr::from_ptr(result) }
        .to_string_lossy()
        .into_owned();
    if out.starts_with('*') || out.is_empty() {
        return Ok(false);
    }
    Ok(ct_eq(out.as_bytes(), hash.as_bytes()))
}
