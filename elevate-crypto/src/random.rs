//! Pure-Rust CSPRNG via the OS (`getrandom`) — no OpenSSL.

use crate::error::{CryptoError, CryptoResult};

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> CryptoResult<()> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_all_zero() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        // extremely unlikely equal
        assert_ne!(a, b);
    }
}
