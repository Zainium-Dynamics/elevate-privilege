//! Shared module `pam_canonicalize_user.so` for elevate-pam — User name canonicalizer.

use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::types::ItemType;
use std::os::raw::{c_char, c_int, c_void};

/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let h = &mut *(pamh as *mut PamHandle);

    if let Some(u) = h.get_item_str(ItemType::User) {
        let normalized = u.trim().to_lowercase();
        let _ = h.set_item_str(ItemType::User, Some(&normalized));
    }

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
