//! Shared module `pam_xauth.so` for elevate-pam — X11 authorization cookie forwarder.

use std::os::raw::{c_char, c_int, c_void};
use elevate_pam::constants::*;

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
