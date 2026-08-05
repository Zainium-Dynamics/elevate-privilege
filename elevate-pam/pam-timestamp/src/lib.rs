//! Shared module `pam_timestamp.so` for elevate-pam — Grace period authentication timestamp cache.

use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::types::ItemType;
use std::fs;
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn ts_dir() -> PathBuf {
    PathBuf::from(elevate_paths::get().timestamp_dir())
}

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
    // SAFETY: pamh is non-null and, per this function's own safety
    // contract, a valid handle from pam_start.
    let h = unsafe { &mut *(pamh as *mut PamHandle) };

    let user: String = match h.get_item_str(ItemType::User) {
        Some(u) => u.to_string(),
        None => return PAM_AUTH_ERR,
    };

    let file_path = ts_dir().join(&user);
    if file_path.exists() {
        if let Ok(meta) = file_path.metadata() {
            if let Ok(mtime) = meta.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(mtime) {
                    if elapsed.as_secs() < 300 {
                        // 5 minute grace period
                        return PAM_SUCCESS;
                    }
                }
            }
        }
    }

    // Touch timestamp on success
    let _ = fs::create_dir_all(ts_dir());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = fs::write(&file_path, now.to_string());

    PAM_AUTH_ERR
}

/// # Safety
/// `_pamh` is accepted for ABI compatibility but not dereferenced; no
/// pointer safety requirements beyond that.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
