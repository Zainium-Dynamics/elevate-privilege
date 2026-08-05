//! Shared module `pam_loginuid.so` for elevate-pam.

use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::types::ItemType;
use std::fs;
use std::os::raw::{c_char, c_int, c_void};

/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let h = &mut *(pamh as *mut PamHandle);

    let username: String = match h.get_item_str(ItemType::User) {
        Some(u) => u.to_string(),
        None => return PAM_USER_UNKNOWN,
    };

    let c_user = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return PAM_USER_UNKNOWN,
    };

    let pwd = libc::getpwnam(c_user.as_ptr());
    if pwd.is_null() {
        return PAM_USER_UNKNOWN;
    }

    let uid = (*pwd).pw_uid;
    let _ = fs::write("/proc/self/loginuid", uid.to_string());

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
