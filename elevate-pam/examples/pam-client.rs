//! Example: Rust application API (not the C FFI).
//!
//! Run from workspace root after building services configs:
//!   cargo run --example pam-client -p elevate-pam -- elevate

use elevate_pam::appl::PamBuilder;
use elevate_pam::config::GlobalConfig;
use elevate_pam::constants::*;
use elevate_pam::conv::{CPamMessage, CPamResponse, PamConv};
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_void};

extern "C" fn fixed_conv(
    num_msg: c_int,
    msg: *mut *const CPamMessage,
    resp: *mut *mut CPamResponse,
    appdata: *mut c_void,
) -> c_int {
    let password = unsafe {
        if appdata.is_null() {
            ""
        } else {
            CStr::from_ptr(appdata as *const _).to_str().unwrap_or("")
        }
    };
    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    let table =
        unsafe { libc::calloc(n, core::mem::size_of::<CPamResponse>()) as *mut CPamResponse };
    if table.is_null() {
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        let m = unsafe { &**msg.add(i) };
        let answer = match m.msg_style {
            PAM_PROMPT_ECHO_OFF => password.to_string(),
            PAM_PROMPT_ECHO_ON => "nobody".to_string(),
            _ => String::new(),
        };
        let c = CString::new(answer).unwrap_or_default();
        unsafe {
            (*table.add(i)).resp = c.into_raw();
            (*table.add(i)).resp_retcode = 0;
        }
    }
    unsafe {
        *resp = table;
    }
    PAM_SUCCESS
}

fn main() {
    let service = std::env::args().nth(1).unwrap_or_else(|| "other".into());
    let mut global = GlobalConfig::load_default();
    if std::path::Path::new("config/services").is_dir() {
        global.paths.services_dir = "config/services".into();
    }
    let pw = CString::new("wrong-password").unwrap();
    let conv = PamConv {
        conv: Some(fixed_conv),
        appdata_ptr: pw.as_ptr() as *mut c_void,
    };
    let mut pamh = PamBuilder::new(service)
        .user("nobody")
        .global(global)
        .start(conv)
        .expect("pam start");
    match pamh.authenticate(0) {
        Ok(()) => println!("authenticated"),
        Err(e) => println!("auth failed (expected for wrong password): {e}"),
    }
}
