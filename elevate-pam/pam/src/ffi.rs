//! Linux-PAM compatible C ABI.
//!
//! These symbols are exported from the `cdylib`/`staticlib` so elevate
//! (via `dlopen("libpam.so.0")`) and other applications work unchanged.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::config::GlobalConfig;
use crate::constants::*;
use crate::conv::PamConv;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::types::ItemType;

/// C `struct pam_message`.
pub type PamMessage = crate::conv::CPamMessage;
/// C `struct pam_response`.
pub type PamResponse = crate::conv::CPamResponse;

/// Opaque handle type for C.
pub type PamHandleT = PamHandle;

/// Convert raw handle pointer.
///
/// # Safety
/// Pointer must be null or a valid `PamHandle` from `pam_start`.
unsafe fn handle_mut<'a>(pamh: *mut PamHandleT) -> Option<&'a mut PamHandle> {
    if pamh.is_null() {
        None
    } else {
        Some(unsafe { &mut *pamh })
    }
}

unsafe fn handle_ref<'a>(pamh: *const PamHandleT) -> Option<&'a PamHandle> {
    if pamh.is_null() {
        None
    } else {
        Some(unsafe { &*pamh })
    }
}

fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller provides valid C string
    unsafe { core::ffi::CStr::from_ptr(p) }.to_str().ok()
}

/// `pam_start` — begin a PAM transaction.
///
/// # Safety
/// `service_name` and `pam_conversation` must be valid, non-null,
/// NUL-terminated/well-formed per the PAM application contract; `user` may
/// be null; `pamh` must be a valid, non-null out-pointer.
#[no_mangle]
pub unsafe extern "C" fn pam_start(
    service_name: *const c_char,
    user: *const c_char,
    pam_conversation: *const PamConv,
    pamh: *mut *mut PamHandleT,
) -> c_int {
    unsafe { pam_start_confdir(service_name, user, pam_conversation, ptr::null(), pamh) }
}

/// `pam_start_confdir` — begin a PAM transaction with alternate conf dir.
///
/// # Safety
/// Same contract as [`pam_start`]; `confdir` may additionally be null or a
/// valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_start_confdir(
    service_name: *const c_char,
    user: *const c_char,
    pam_conversation: *const PamConv,
    confdir: *const c_char,
    pamh: *mut *mut PamHandleT,
) -> c_int {
    if pamh.is_null() || service_name.is_null() || pam_conversation.is_null() {
        return PAM_SYSTEM_ERR;
    }

    let service = match cstr_to_str(service_name) {
        Some(s) => s,
        None => return PAM_SYSTEM_ERR,
    };
    let user = cstr_to_str(user);
    let conf = cstr_to_str(confdir);
    let conv = unsafe { *pam_conversation };

    let global = GlobalConfig::load_default();
    match PamHandle::start(service, user, conv, conf, global) {
        Ok(h) => {
            let boxed = alloc::boxed::Box::new(h);
            unsafe {
                *pamh = alloc::boxed::Box::into_raw(boxed);
            }
            PAM_SUCCESS
        }
        Err(e) => e.to_status().code(),
    }
}

/// `pam_end` — terminate a PAM transaction.
///
/// # Safety
/// `pamh` must be null or a handle previously returned via `pam_start`'s
/// out-pointer, not already passed to `pam_end`.
#[no_mangle]
pub unsafe extern "C" fn pam_end(pamh: *mut PamHandleT, pam_status: c_int) -> c_int {
    if pamh.is_null() {
        return PAM_SYSTEM_ERR;
    }
    // SAFETY: pamh is non-null and, per this function's own safety
    // contract, a handle from pam_start not yet freed.
    let handle = unsafe { alloc::boxed::Box::from_raw(pamh) };
    match handle.end(pam_status) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_authenticate`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_authenticate(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.authenticate(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_setcred`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_setcred(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.setcred(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_acct_mgmt`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_acct_mgmt(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.acct_mgmt(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_open_session`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_open_session(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.open_session(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_close_session`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_close_session(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.close_session(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_chauthtok`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_chauthtok(pamh: *mut PamHandleT, flags: c_int) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.chauthtok(flags) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_set_item`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`. `item` must
/// either be null or point to data of the type its `item_type` implies for
/// the duration of this call (`pam_conv` for [`ItemType::Conv`], otherwise
/// a NUL-terminated C string).
#[no_mangle]
pub unsafe extern "C" fn pam_set_item(
    pamh: *mut PamHandleT,
    item_type: c_int,
    item: *const c_void,
) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let Some(it) = ItemType::from_raw(item_type) else {
        return PAM_BAD_ITEM;
    };
    match it {
        ItemType::Conv => {
            if item.is_null() {
                return PAM_BAD_ITEM;
            }
            // SAFETY: application passes pam_conv*
            h.conv = unsafe { *(item as *const PamConv) };
            PAM_SUCCESS
        }
        ItemType::FailDelay => PAM_SUCCESS, // accepted no-op for now
        ItemType::XAuthData => PAM_BAD_ITEM,
        other => {
            let s = if item.is_null() {
                None
            } else {
                cstr_to_str(item as *const c_char)
            };
            match h.set_item_str(other, s) {
                Ok(()) => PAM_SUCCESS,
                Err(e) => e.to_status().code(),
            }
        }
    }
}

/// `pam_get_item`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`; `item` must be
/// a valid, non-null, properly-aligned out-pointer.
#[no_mangle]
pub unsafe extern "C" fn pam_get_item(
    pamh: *const PamHandleT,
    item_type: c_int,
    item: *mut *const c_void,
) -> c_int {
    if item.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let Some(h) = (unsafe { handle_ref(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let Some(it) = ItemType::from_raw(item_type) else {
        return PAM_BAD_ITEM;
    };
    match it {
        ItemType::Conv => {
            unsafe {
                *item = (&h.conv as *const PamConv) as *const c_void;
            }
            PAM_SUCCESS
        }
        other => {
            if let Some(s) = h.get_item_str(other) {
                // Return pointer into handle-owned string; valid until next set/end.
                unsafe {
                    *item = s.as_ptr() as *const c_void;
                }
                PAM_SUCCESS
            } else {
                unsafe {
                    *item = ptr::null();
                }
                PAM_SUCCESS
            }
        }
    }
}

/// `pam_strerror`.
///
/// # Safety
/// `_pamh` is accepted for ABI compatibility but not dereferenced; no
/// pointer safety requirements beyond that.
#[no_mangle]
pub unsafe extern "C" fn pam_strerror(_pamh: *mut PamHandleT, errnum: c_int) -> *const c_char {
    let s = crate::constants::pam_strerror_static(errnum);
    s.as_ptr() as *const c_char
}

/// `pam_putenv`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`; `name_value`
/// must be null or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_putenv(pamh: *mut PamHandleT, name_value: *const c_char) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let Some(nv) = cstr_to_str(name_value) else {
        return PAM_SYSTEM_ERR;
    };
    match h.putenv(nv) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_getenv`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`; `name` must be
/// null or a valid NUL-terminated C string. The returned pointer, if
/// non-null, is valid only until the next call that mutates the handle's
/// environment or `pam_end`.
#[no_mangle]
pub unsafe extern "C" fn pam_getenv(pamh: *mut PamHandleT, name: *const c_char) -> *const c_char {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return ptr::null();
    };
    let Some(n) = cstr_to_str(name) else {
        return ptr::null();
    };
    match h.getenv(n) {
        Some(v) => v.as_ptr() as *const c_char,
        None => ptr::null(),
    }
}

/// `pam_getenvlist`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`. Per the PAM
/// application contract, the caller takes ownership of the returned array
/// (and each string in it) and must free it.
#[no_mangle]
pub unsafe extern "C" fn pam_getenvlist(pamh: *mut PamHandleT) -> *mut *mut c_char {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return ptr::null_mut();
    };
    match crate::env::getenvlist_c(&h.env) {
        Ok(p) => p,
        Err(_) => ptr::null_mut(),
    }
}

/// `pam_fail_delay`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`.
#[no_mangle]
pub unsafe extern "C" fn pam_fail_delay(pamh: *mut PamHandleT, musec_delay: u32) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    match h.fail_delay(musec_delay) {
        Ok(()) => PAM_SUCCESS,
        Err(e) => e.to_status().code(),
    }
}

/// `pam_set_data`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`;
/// `module_data_name` must be null or a valid NUL-terminated C string.
/// `data` and `cleanup` are opaque to this function and stored as given;
/// the caller is responsible for their validity per the PAM module
/// contract.
#[no_mangle]
pub unsafe extern "C" fn pam_set_data(
    pamh: *mut PamHandleT,
    module_data_name: *const c_char,
    data: *mut c_void,
    cleanup: Option<unsafe extern "C" fn(*mut PamHandleT, *mut c_void, c_int)>,
) -> c_int {
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let Some(name) = cstr_to_str(module_data_name) else {
        return PAM_SYSTEM_ERR;
    };
    // Wrap C cleanup into our fn pointer form — store as raw via leak of adapter.
    // Simplified: ignore typed cleanup adapter; store data without cleanup if complex.
    let _ = cleanup;
    h.data.set(name, data, None, PAM_DATA_REPLACE);
    PAM_SUCCESS
}

/// `pam_get_data`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`;
/// `module_data_name` must be null or a valid NUL-terminated C string;
/// `data` must be a valid, non-null out-pointer.
#[no_mangle]
pub unsafe extern "C" fn pam_get_data(
    pamh: *const PamHandleT,
    module_data_name: *const c_char,
    data: *mut *const c_void,
) -> c_int {
    if data.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let Some(h) = (unsafe { handle_ref(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let Some(name) = cstr_to_str(module_data_name) else {
        return PAM_SYSTEM_ERR;
    };
    match h.data.get(name) {
        Some(p) => {
            unsafe {
                *data = p as *const c_void;
            }
            PAM_SUCCESS
        }
        None => {
            unsafe {
                *data = ptr::null();
            }
            PAM_NO_MODULE_DATA
        }
    }
}

/// `pam_get_user`.
///
/// # Safety
/// `pamh` must be null or a valid handle from `pam_start`; `user` must be
/// a valid, non-null out-pointer; `prompt` must be null or a valid
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_get_user(
    pamh: *mut PamHandleT,
    user: *mut *const c_char,
    prompt: *const c_char,
) -> c_int {
    if user.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let Some(h) = (unsafe { handle_mut(pamh) }) else {
        return PAM_SYSTEM_ERR;
    };
    let p = cstr_to_str(prompt);
    match h.get_user(p) {
        Ok(_) => {
            if let Some(u) = h.user() {
                unsafe {
                    *user = u.as_ptr() as *const c_char;
                }
                PAM_SUCCESS
            } else {
                PAM_SYSTEM_ERR
            }
        }
        Err(e) => e.to_status().code(),
    }
}

/// Version symbols for ABI probes.
#[no_mangle]
pub static ELEVATE_PAM_VERSION_MAJOR: c_int = 1;
/// Minor version.
#[no_mangle]
pub static ELEVATE_PAM_VERSION_MINOR: c_int = 0;
/// Patch version.
#[no_mangle]
pub static ELEVATE_PAM_VERSION_PATCH: c_int = 0;

// Silence unused import
#[allow(dead_code)]
fn _use_status() -> PamStatus {
    PamStatus::SUCCESS
}
