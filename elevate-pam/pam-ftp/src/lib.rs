//! Shared module `pam_ftp.so` for elevate-pam — Anonymous FTP authentication validator.

use std::os::raw::{c_char, c_int, c_void};
use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::types::ItemType;

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() { return PAM_SYSTEM_ERR; }
    let h = &mut *(pamh as *mut PamHandle);

    let user: String = match h.get_item_str(ItemType::User) {
        Some(u) => u.to_string(),
        None => return PAM_AUTH_ERR,
    };

    if user == "ftp" || user == "anonymous" {
        PAM_SUCCESS
    } else {
        PAM_AUTH_ERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
