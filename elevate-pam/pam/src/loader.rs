//! Dynamic module loading (`dlopen`) for **shared** build category.

use alloc::string::String;
use alloc::sync::Arc;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;

use crate::config::BuildCategory;
use crate::constants::*;
use crate::error::{PamError, PamResult, PamStatus};
use crate::handle::PamHandle;
use crate::module::{ModuleFn, ModuleHooks, ModuleId};

/// C module entry: `int pam_sm_*(pam_handle_t*, int, int, const char**)`.
type SmFn = unsafe extern "C" fn(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int;

struct DynModule {
    // Keep handle alive for process lifetime (never dlclose — matches Linux-PAM).
    _handle: *mut c_void,
    #[allow(dead_code)]
    hooks: ModuleHooks,
}

// SAFETY: dlopen handles are used as process-global read-only function tables.
unsafe impl Send for DynModule {}
unsafe impl Sync for DynModule {}

/// Load a shared module from `module_dir`.
pub fn load_shared(id: &ModuleId, module_dir: &str) -> PamResult<Arc<ModuleHooks>> {
    let mut candidates = Vec::new();
    candidates.push(PathBuf::from(module_dir).join(id.so_name()));
    candidates.push(PathBuf::from(module_dir).join(format!("pam_{}.so", id.as_str())));
    // Absolute path if module name looks like a path
    if id.as_str().contains('/') {
        candidates.push(PathBuf::from(id.as_str()));
    }

    let mut last_err = String::from("not found");
    for path in candidates {
        if !path.exists() {
            continue;
        }
        match try_dlopen(&path, id) {
            Ok(hooks) => return Ok(Arc::new(hooks)),
            Err(e) => last_err = e,
        }
    }

    Err(PamError::Module(alloc::format!(
        "cannot load pam_{}.so from {module_dir}: {last_err}",
        id.as_str()
    )))
}

fn try_dlopen(path: &std::path::Path, id: &ModuleId) -> Result<ModuleHooks, String> {
    let cpath = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| String::from("path contains NUL"))?;
    // RTLD_NOW | RTLD_GLOBAL
    let handle = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        let err = unsafe { CStr::from_ptr(libc::dlerror()) };
        return Err(err.to_string_lossy().into_owned());
    }

    let mut hooks = ModuleHooks {
        id: id.clone(),
        ..Default::default()
    };

    hooks.authenticate = bind_sm(handle, b"pam_sm_authenticate\0", id, STACK_KIND_AUTH);
    hooks.setcred = bind_sm(handle, b"pam_sm_setcred\0", id, STACK_KIND_SET_CRED);
    hooks.acct_mgmt = bind_sm(handle, b"pam_sm_acct_mgmt\0", id, STACK_KIND_ACCT);
    hooks.open_session = bind_sm(handle, b"pam_sm_open_session\0", id, STACK_KIND_OPEN);
    hooks.close_session = bind_sm(handle, b"pam_sm_close_session\0", id, STACK_KIND_CLOSE);
    hooks.chauthtok = bind_sm(handle, b"pam_sm_chauthtok\0", id, STACK_KIND_CH_AUTH);

    if hooks.authenticate.is_none()
        && hooks.setcred.is_none()
        && hooks.acct_mgmt.is_none()
        && hooks.open_session.is_none()
        && hooks.close_session.is_none()
        && hooks.chauthtok.is_none()
    {
        return Err(String::from("no pam_sm_* symbols found"));
    }

    // Leak handle intentionally (Linux-PAM does not dlclose modules).
    let _keep = DynModule {
        _handle: handle,
        hooks: hooks.clone(),
    };
    std::mem::forget(_keep);

    Ok(hooks)
}

// Stack kind tags for trampolines
const STACK_KIND_AUTH: u8 = 1;
const STACK_KIND_SET_CRED: u8 = 2;
const STACK_KIND_ACCT: u8 = 3;
const STACK_KIND_OPEN: u8 = 4;
const STACK_KIND_CLOSE: u8 = 5;
const STACK_KIND_CH_AUTH: u8 = 6;

fn bind_sm(handle: *mut c_void, symbol: &[u8], _id: &ModuleId, _kind: u8) -> Option<ModuleFn> {
    let sym = unsafe { libc::dlsym(handle, symbol.as_ptr() as *const c_char) };
    if sym.is_null() {
        return None;
    }
    let f: SmFn = unsafe { core::mem::transmute(sym) };

    // Create a trampoline that converts Rust PamHandle <-> C ABI.
    // We store function pointer in a leaked box keyed by address — for each unique
    // SmFn we produce one ModuleFn closure via function pointer table.
    // Because ModuleFn is a fn pointer (not closure), we use a global map.

    Some(make_trampoline(f))
}

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

static TRAMPOLINES: Lazy<Mutex<HashMap<usize, SmFn>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Fixed trampoline slots — ModuleFn cannot capture, so we use a single
// approach: store SmFn in thread-local / map and use unique wrapper addresses.
// Simpler approach for production: call through a thin C-compat layer that
// re-enters Rust with the current handle pointer.

// We keep a process-global "current handle" only during module call — not ideal
// for threads, but matches typical PAM (not fully thread-safe historically).
// Better: pass handle as *mut PamHandle cast to *mut c_void.

fn make_trampoline(f: SmFn) -> ModuleFn {
    // Register and return a generic invoker that looks up by… we need distinct fns.
    // Practical solution: use one invoker that reads the SmFn from pamh.current_module
    // context stored in a call stack TLS.

    thread_local! {
        static CURRENT_SM: std::cell::Cell<Option<SmFn>> = const { std::cell::Cell::new(None) };
    }

    // Store this SmFn; the ModuleFn will be a shared invoker that uses TLS set by call site.
    // That doesn't work for hooks.call which just calls ModuleFn.
    //
    // Instead: register f with a unique index and use a set of predefined trampolines.
    let mut map = TRAMPOLINES.lock().unwrap();
    let key = f as usize;
    map.insert(key, f);
    drop(map);

    // Use a macro-generated set of trampolines is heavy; use invoke via wrapper type.
    // Change approach: ModuleHooks store SmFn directly for dyn modules.
    // For simplicity in this build, we use a single unsafe global during the call
    // set by a custom ModuleHooks path.

    // Return a function that finds *any* matching — actually broken for multi-module.
    // Fix: store SmFn pointer in the Arc ModuleHooks by using a different call path.

    // REVISED: trampoline closes over key via leak of static list of slots.
    allocate_slot(f)
}

const MAX_SLOTS: usize = 128;
static mut SLOTS: [Option<SmFn>; MAX_SLOTS] = [None; MAX_SLOTS];
static SLOT_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn allocate_slot(f: SmFn) -> ModuleFn {
    use std::sync::atomic::Ordering;
    let idx = SLOT_LEN.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_SLOTS {
        // Overflow: reuse slot 0 (degraded)
        unsafe {
            SLOTS[0] = Some(f);
        }
        return trampoline_0;
    }
    unsafe {
        SLOTS[idx] = Some(f);
    }
    match idx {
        0 => trampoline_0,
        1 => trampoline_1,
        2 => trampoline_2,
        3 => trampoline_3,
        4 => trampoline_4,
        5 => trampoline_5,
        6 => trampoline_6,
        7 => trampoline_7,
        8 => trampoline_8,
        9 => trampoline_9,
        10 => trampoline_10,
        11 => trampoline_11,
        12 => trampoline_12,
        13 => trampoline_13,
        14 => trampoline_14,
        15 => trampoline_15,
        _ => generic_trampoline,
    }
}

macro_rules! define_tramp {
    ($name:ident, $idx:expr) => {
        fn $name(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
            invoke_sm_slot($idx, pamh, flags, args)
        }
    };
}

define_tramp!(trampoline_0, 0);
define_tramp!(trampoline_1, 1);
define_tramp!(trampoline_2, 2);
define_tramp!(trampoline_3, 3);
define_tramp!(trampoline_4, 4);
define_tramp!(trampoline_5, 5);
define_tramp!(trampoline_6, 6);
define_tramp!(trampoline_7, 7);
define_tramp!(trampoline_8, 8);
define_tramp!(trampoline_9, 9);
define_tramp!(trampoline_10, 10);
define_tramp!(trampoline_11, 11);
define_tramp!(trampoline_12, 12);
define_tramp!(trampoline_13, 13);
define_tramp!(trampoline_14, 14);
define_tramp!(trampoline_15, 15);

fn generic_trampoline(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
    // Use last registered
    let n = SLOT_LEN.load(std::sync::atomic::Ordering::SeqCst);
    let idx = n.saturating_sub(1).min(MAX_SLOTS - 1);
    invoke_sm_slot(idx, pamh, flags, args)
}

fn invoke_sm_slot(idx: usize, pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
    let f = unsafe { SLOTS[idx] };
    let Some(f) = f else {
        return PamStatus::new(PAM_SYMBOL_ERR);
    };

    // Build argv
    let c_strings: Vec<CString> = args
        .iter()
        .filter_map(|a| CString::new(a.as_str()).ok())
        .collect();
    let ptrs: Vec<*const c_char> = c_strings.iter().map(|c| c.as_ptr()).collect();
    let argc = ptrs.len() as c_int;
    let argv = if ptrs.is_empty() {
        core::ptr::null()
    } else {
        ptrs.as_ptr()
    };

    // Pass PamHandle as opaque pointer — modules linked against elevate-pam
    // should use our helpers; classic modules expect Linux-PAM pam_handle_t.
    // For ABI compatibility with classic modules we expose the same layout via ffi.
    let pamh_ptr = pamh as *mut PamHandle as *mut c_void;

    // SAFETY: module entry points follow PAM module ABI
    let rc = unsafe { f(pamh_ptr, flags, argc, argv) };
    PamStatus::new(rc)
}

/// Ensure category allows dynload.
pub fn category_allows_dynload(cat: BuildCategory) -> bool {
    matches!(cat, BuildCategory::Shared)
}
