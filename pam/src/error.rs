//! Error and result types for Elevate PAM.

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::constants::{pam_strerror_static, PAM_SUCCESS};

/// PAM status code wrapper (compatible with Linux-PAM return values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PamStatus(pub i32);

impl PamStatus {
    /// Success.
    pub const SUCCESS: Self = Self(PAM_SUCCESS);

    /// Construct from a raw `i32`.
    #[inline]
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// Raw status code.
    #[inline]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Whether this is [`PAM_SUCCESS`](crate::constants::PAM_SUCCESS).
    #[inline]
    pub const fn is_success(self) -> bool {
        self.0 == PAM_SUCCESS
    }

    /// Static description string.
    pub fn description(self) -> &'static str {
        pam_strerror_static(self.0)
    }
}

impl From<i32> for PamStatus {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl From<PamStatus> for i32 {
    fn from(s: PamStatus) -> Self {
        s.0
    }
}

impl core::fmt::Display for PamStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.description(), self.0)
    }
}

/// Rich error for Rust API callers (not the C ABI path).
#[derive(Debug, Clone)]
pub enum PamError {
    /// PAM status failure.
    Status(PamStatus),
    /// Configuration / TOML error.
    Config(alloc::string::String),
    /// I/O error message (no_std-friendly string form).
    Io(alloc::string::String),
    /// Invalid argument.
    InvalidArgument(alloc::string::String),
    /// Module load / symbol error.
    Module(alloc::string::String),
    /// Internal invariant broken.
    Internal(alloc::string::String),
}

impl PamError {
    /// Map to a PAM status code for C ABI returns.
    pub fn to_status(&self) -> PamStatus {
        match self {
            PamError::Status(s) => *s,
            PamError::Config(_) => PamStatus::new(crate::constants::PAM_SERVICE_ERR),
            PamError::Io(_) => PamStatus::new(crate::constants::PAM_SYSTEM_ERR),
            PamError::InvalidArgument(_) => PamStatus::new(crate::constants::PAM_SYSTEM_ERR),
            PamError::Module(_) => PamStatus::new(crate::constants::PAM_OPEN_ERR),
            PamError::Internal(_) => PamStatus::new(crate::constants::PAM_SYSTEM_ERR),
        }
    }
}

impl core::fmt::Display for PamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PamError::Status(s) => write!(f, "PAM: {s}"),
            PamError::Config(m) => write!(f, "config: {m}"),
            PamError::Io(m) => write!(f, "io: {m}"),
            PamError::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            PamError::Module(m) => write!(f, "module: {m}"),
            PamError::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PamError {}

impl From<PamStatus> for PamError {
    fn from(s: PamStatus) -> Self {
        PamError::Status(s)
    }
}

impl From<i32> for PamError {
    fn from(code: i32) -> Self {
        PamError::Status(PamStatus::new(code))
    }
}

/// Result alias for elevate-pam operations.
pub type PamResult<T> = core::result::Result<T, PamError>;

/// Convert a [`PamResult`] into a C-style status code.
pub fn result_to_c<T>(r: PamResult<T>) -> i32 {
    match r {
        Ok(_) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}
