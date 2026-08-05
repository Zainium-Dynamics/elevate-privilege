//! Shared helpers (constant-time compare, encoding, wipe).

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Constant-time equality for equal-length slices.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Wipe a mutable byte buffer.
#[inline]
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Secure buffer wiped on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(pub alloc::vec::Vec<u8>);

impl SecretBytes {
    /// From vector.
    pub fn new(v: alloc::vec::Vec<u8>) -> Self {
        Self(v)
    }

    /// Expose.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Crypt output max (libxcrypt `CRYPT_OUTPUT_SIZE`).
pub const CRYPT_OUTPUT_SIZE: usize = 384;
/// Max passphrase (libxcrypt).
pub const CRYPT_MAX_PASSPHRASE_SIZE: usize = 512;
/// Gensalt output max.
pub const CRYPT_GENSALT_OUTPUT_SIZE: usize = 192;

/// Encode bytes as lowercase hex into `out` (must be 2× len).
pub fn hex_encode(bytes: &[u8], out: &mut [u8]) -> Result<(), ()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if out.len() < bytes.len() * 2 {
        return Err(());
    }
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xf) as usize];
    }
    Ok(())
}

/// Hex string (alloc).
#[cfg(feature = "alloc")]
pub fn hex_encode_string(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
