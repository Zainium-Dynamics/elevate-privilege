//! Shared module `pam_nologin.so` for elevate-pam.

use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::module::ModuleId;
use std::os::raw::{c_char, c_int, c_void};

fn args_from_c(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let mut out = Vec::new();
    if argv.is_null() || argc <= 0 {
        return out;
    }
    for i in 0..argc as isize {
        unsafe {
            let p = *argv.offset(i);
            if p.is_null() {
                continue;
            }
            if let Ok(s) = std::ffi::CStr::from_ptr(p).to_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

unsafe fn pamh_mut<'a>(pamh: *mut c_void) -> Option<&'a mut PamHandle> {
    if pamh.is_null() {
        None
    } else {
        Some(&mut *(pamh as *mut PamHandle))
    }
}

macro_rules! sm {
    ($name:ident, $method:ident) => {
        /// # Safety
        /// `pamh` must be null or a valid handle from `pam_start`; `argv` must
        /// point to `argc` valid, non-null, NUL-terminated C strings.

        #[no_mangle]
        pub unsafe extern "C" fn $name(
            pamh: *mut c_void,
            flags: c_int,
            argc: c_int,
            argv: *const *const c_char,
        ) -> c_int {
            elevate_pam::module::global::ensure_builtins();
            let Some(h) = pamh_mut(pamh) else {
                return PAM_SYSTEM_ERR;
            };
            let args = args_from_c(argc, argv);
            let id = ModuleId::normalize("nologin");
            let Some(hooks) = elevate_pam::module::global::get(&id) else {
                return PAM_MODULE_UNKNOWN;
            };
            hooks
                .$method
                .map(|f| f(h, flags, &args).code())
                .unwrap_or(PAM_MODULE_UNKNOWN)
        }
    };
}

sm!(pam_sm_authenticate, authenticate);
sm!(pam_sm_setcred, setcred);
sm!(pam_sm_acct_mgmt, acct_mgmt);
sm!(pam_sm_open_session, open_session);
sm!(pam_sm_close_session, close_session);
sm!(pam_sm_chauthtok, chauthtok);
