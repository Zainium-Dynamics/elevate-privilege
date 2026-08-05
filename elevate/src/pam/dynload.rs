//! Runtime loader for **elevate-pam** (`libelevate_pam`).
//!
//! This module does NOT link PAM at link-time. elevate is often built
//! musl-static (`crt-static`); a link-time `-lpam` would break that.
//!
//! At runtime we `dlopen` **elevate-pam first** (Zainium / elevate product),
//! then optional absolute paths under `/lib` (no `/usr` on Zainium).
//! Classic `libpam.so*` is only a last-resort fallback when
//! `ELEVATE_ALLOW_LIBPAM=1` is set (migration / foreign hosts).

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::OnceLock;

use super::sys::{pam_conv, pam_handle_t};

/// Libraries / paths tried in order for Zainium + elevate-pam.
///
/// Prefer the elevate product name; never require `/usr`.
fn elevate_pam_sonames() -> Vec<String> {
    let libdir = &elevate_paths::get().libdir;
    vec![
        // Primary: elevate-pam (this project's cdylib)
        "libelevate_pam.so.0".into(),
        "libelevate_pam.so".into(),
        "libelevate_pam.so.1".into(),
        // Absolute paths (Zainium: configured libdir only, no /usr)
        format!("{libdir}/libelevate_pam.so.0"),
        format!("{libdir}/libelevate_pam.so"),
        format!("{libdir}/libelevate_pam.so.1"),
    ]
}

/// Classic Linux-PAM sonames — only if ELEVATE_ALLOW_LIBPAM=1.
fn legacy_libpam_sonames() -> Vec<String> {
    let libdir = &elevate_paths::get().libdir;
    vec![
        "libpam.so.0".into(),
        "libpam.so".into(),
        "libpam.so.1".into(),
        format!("{libdir}/libpam.so.0"),
        format!("{libdir}/libpam.so"),
    ]
}

type PamSetItemFn = unsafe extern "C" fn(*mut pam_handle_t, c_int, *const c_void) -> c_int;
type PamGetItemFn = unsafe extern "C" fn(*const pam_handle_t, c_int, *mut *const c_void) -> c_int;
type PamStrerrorFn = unsafe extern "C" fn(*mut pam_handle_t, c_int) -> *const c_char;
type PamGetenvlistFn = unsafe extern "C" fn(*mut pam_handle_t) -> *mut *mut c_char;
type PamStartFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const pam_conv,
    *mut *mut pam_handle_t,
) -> c_int;
type PamEndFn = unsafe extern "C" fn(*mut pam_handle_t, c_int) -> c_int;
type PamSimpleFlagsFn = unsafe extern "C" fn(*mut pam_handle_t, c_int) -> c_int;

/// Resolved elevate-pam / PAM function pointers.
pub struct PamLib {
    pub pam_set_item: PamSetItemFn,
    pub pam_get_item: PamGetItemFn,
    pub pam_strerror: PamStrerrorFn,
    pub pam_getenvlist: PamGetenvlistFn,
    pub pam_start: PamStartFn,
    pub pam_end: PamEndFn,
    pub pam_authenticate: PamSimpleFlagsFn,
    pub pam_setcred: PamSimpleFlagsFn,
    pub pam_acct_mgmt: PamSimpleFlagsFn,
    pub pam_open_session: PamSimpleFlagsFn,
    pub pam_close_session: PamSimpleFlagsFn,
    pub pam_chauthtok: PamSimpleFlagsFn,
}

// Never dlclose — same lifetime contract as classic PAM modules.
static PAM_LIB: OnceLock<PamLib> = OnceLock::new();

fn allow_legacy_libpam() -> bool {
    std::env::var_os("ELEVATE_ALLOW_LIBPAM").is_some_and(|v| v != "0")
}

fn dlopen_one(soname: &str) -> *mut c_void {
    let Ok(cname) = CString::new(soname) else {
        return std::ptr::null_mut();
    };
    // SAFETY: soname is a valid C string; RTLD_NOW fails fast on missing symbols.
    unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW) }
}

fn dlopen_elevate_pam() -> *mut c_void {
    for soname in &elevate_pam_sonames() {
        let handle = dlopen_one(soname);
        if !handle.is_null() {
            return handle;
        }
    }
    if allow_legacy_libpam() {
        for soname in &legacy_libpam_sonames() {
            let handle = dlopen_one(soname);
            if !handle.is_null() {
                return handle;
            }
        }
    }
    std::ptr::null_mut()
}

/// # Safety
/// `handle` must be a valid handle returned by a live `dlopen` call (not
/// yet `dlclose`d).
unsafe fn must_dlsym(handle: *mut c_void, name: &str) -> *mut c_void {
    let cname = CString::new(name).expect("symbol name has no NUL bytes");
    // SAFETY: handle is valid per this function's own safety contract;
    // cname is a NUL-terminated CString kept alive for this call.
    let sym = unsafe { libc::dlsym(handle, cname.as_ptr()) };
    if sym.is_null() {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "elevate: fatal: required elevate-pam symbol '{name}' was not found in \
             libelevate_pam. Reinstall elevate-pam or check /lib/libelevate_pam.so*."
        );
        std::process::exit(1);
    }
    sym
}

/// Loads elevate-pam (if not already loaded) and returns its function table.
pub fn pam_lib() -> &'static PamLib {
    PAM_LIB.get_or_init(|| {
        let handle = dlopen_elevate_pam();
        if handle.is_null() {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "elevate: fatal: failed to load elevate-pam (libelevate_pam.so).\n\
                 Install elevate-pam to /lib (e.g. /lib/libelevate_pam.so.0) and\n\
                 service stacks under /etc/elevate-pam/services/.\n\
                 Zainium has no /usr — use /lib and /etc only.\n\
                 For temporary classic libpam.so fallback set ELEVATE_ALLOW_LIBPAM=1."
            );
            std::process::exit(1);
        }

        // SAFETY: symbols match elevate-pam / pam_appl C ABI.
        unsafe {
            PamLib {
                pam_set_item: std::mem::transmute::<*mut c_void, PamSetItemFn>(must_dlsym(
                    handle,
                    "pam_set_item",
                )),
                pam_get_item: std::mem::transmute::<*mut c_void, PamGetItemFn>(must_dlsym(
                    handle,
                    "pam_get_item",
                )),
                pam_strerror: std::mem::transmute::<*mut c_void, PamStrerrorFn>(must_dlsym(
                    handle,
                    "pam_strerror",
                )),
                pam_getenvlist: std::mem::transmute::<*mut c_void, PamGetenvlistFn>(must_dlsym(
                    handle,
                    "pam_getenvlist",
                )),
                pam_start: std::mem::transmute::<*mut c_void, PamStartFn>(must_dlsym(
                    handle,
                    "pam_start",
                )),
                pam_end: std::mem::transmute::<*mut c_void, PamEndFn>(must_dlsym(
                    handle, "pam_end",
                )),
                pam_authenticate: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(must_dlsym(
                    handle,
                    "pam_authenticate",
                )),
                pam_setcred: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(must_dlsym(
                    handle,
                    "pam_setcred",
                )),
                pam_acct_mgmt: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(must_dlsym(
                    handle,
                    "pam_acct_mgmt",
                )),
                pam_open_session: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(must_dlsym(
                    handle,
                    "pam_open_session",
                )),
                pam_close_session: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(
                    must_dlsym(handle, "pam_close_session"),
                ),
                pam_chauthtok: std::mem::transmute::<*mut c_void, PamSimpleFlagsFn>(must_dlsym(
                    handle,
                    "pam_chauthtok",
                )),
            }
        }
    })
}
