//! Errors for elevate-crypto.

use core::fmt;

/// Crypto operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid input (length, encoding, empty key, …).
    InvalidInput(&'static str),
    /// Algorithm / format not supported.
    Unsupported(&'static str),
    /// Verification failed (password or signature).
    VerificationFailed,
    /// Randomness unavailable.
    Random,
    /// Backend (OpenSSL / system crypt) error.
    Backend(alloc::string::String),
    /// Internal invariant broken.
    Internal(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::Random => write!(f, "random number generation failed"),
            Self::Backend(m) => write!(f, "backend: {m}"),
            Self::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Result alias.
pub type CryptoResult<T> = core::result::Result<T, CryptoError>;
