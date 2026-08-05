//! Shared module `pam_cap.so` for elevate-pam — Linux capabilities capability manager.

use elevate_pam::constants::*;
use std::os::raw::{c_char, c_int, c_void};

/// # Safety
/// `_pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// # Safety
/// `_pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// # Safety
/// `_pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// # Safety
/// `_pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
