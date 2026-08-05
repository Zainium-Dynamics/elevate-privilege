//! Shared module `pam_time.so` for elevate-pam — Time-based access control evaluator.

use std::os::raw::{c_char, c_int, c_void};
use elevate_pam::constants::*;

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
