//! Shared module `pam_listfile.so` for elevate-pam — File-based allow/deny list evaluator.

use std::os::raw::{c_char, c_int, c_void};
use std::fs::File;
use std::io::{BufRead, BufReader};
use elevate_pam::constants::*;
use elevate_pam::handle::PamHandle;
use elevate_pam::types::ItemType;

fn parse_args(argc: c_int, argv: *const *const c_char) -> (String, String, String, String) {
    let mut item = "user".to_string();
    let mut sense = "deny".to_string();
    let mut file = "".to_string();
    let mut onerr = "fail".to_string();

    if argv.is_null() || argc <= 0 { return (item, sense, file, onerr); }
    for i in 0..argc as isize {
        unsafe {
            let p = *argv.offset(i);
            if p.is_null() { continue; }
            if let Ok(s) = std::ffi::CStr::from_ptr(p).to_str() {
                if let Some(v) = s.strip_prefix("item=") { item = v.to_string(); }
                else if let Some(v) = s.strip_prefix("sense=") { sense = v.to_string(); }
                else if let Some(v) = s.strip_prefix("file=") { file = v.to_string(); }
                else if let Some(v) = s.strip_prefix("onerr=") { onerr = v.to_string(); }
            }
        }
    }
    (item, sense, file, onerr)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void, _flags: c_int, argc: c_int, argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() { return PAM_SYSTEM_ERR; }
    let h = &mut *(pamh as *mut PamHandle);
    let (_item, sense, file, onerr) = parse_args(argc, argv);

    let username: String = match h.get_item_str(ItemType::User) {
        Some(u) => u.to_string(),
        None => return if onerr == "succeed" { PAM_SUCCESS } else { PAM_AUTH_ERR },
    };

    if file.is_empty() {
        return if onerr == "succeed" { PAM_SUCCESS } else { PAM_AUTH_ERR };
    }

    let mut found = false;
    if let Ok(f) = File::open(&file) {
        for line in BufReader::new(f).lines().flatten() {
            let l = line.trim();
            if !l.starts_with('#') && l == username {
                found = true;
                break;
            }
        }
    }

    let ok = match sense.as_str() {
        "allow" => found,
        "deny" => !found,
        _ => !found,
    };

    if ok { PAM_SUCCESS } else { PAM_AUTH_ERR }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
