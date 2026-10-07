//! Secure memory helpers for authentication tokens.

use alloc::string::String;
use alloc::vec::Vec;

/// A password / auth token that is wiped on drop when `secure_mem` is enabled.
#[derive(Clone, Default)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Create from an owned string.
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Create from a string slice.
    pub fn from_str_slice(s: &str) -> Self {
        Self {
            inner: String::from(s),
        }
    }

    /// Borrow the secret as `&str`.
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Take ownership of the inner string without wiping (caller responsible).
    pub fn into_inner(mut self) -> String {
        core::mem::take(&mut self.inner)
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        #[cfg(feature = "secure_mem")]
        {
            use zeroize::Zeroize;
            self.inner.zeroize();
        }
        #[cfg(not(feature = "secure_mem"))]
        {
            self.inner.clear();
        }
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// Secure byte buffer wiped on drop.
#[derive(Clone, Default)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// From vector.
    pub fn new(v: Vec<u8>) -> Self {
        Self { inner: v }
    }

    /// Expose bytes.
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Mutable expose.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        #[cfg(feature = "secure_mem")]
        {
            use zeroize::Zeroize;
            self.inner.zeroize();
        }
        #[cfg(not(feature = "secure_mem"))]
        {
            self.inner.fill(0);
        }
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Best-effort wipe of a mutable byte slice.
pub fn wipe_bytes(buf: &mut [u8]) {
    #[cfg(feature = "secure_mem")]
    {
        use zeroize::Zeroize;
        buf.zeroize();
    }
    #[cfg(not(feature = "secure_mem"))]
    {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
}
