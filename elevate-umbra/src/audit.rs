//! Syslog audit logging for elevate-umbra operations.
//! Port of shadow-4.17.2 `lib/shadowlog.c` — logs to LOG_AUTHPRIV.

use std::ffi::CString;

/// Syslog facility for authentication (LOG_AUTHPRIV).
const LOG_AUTHPRIV: libc::c_int = 10 << 3; // 80

/// Syslog priorities.
pub const LOG_INFO: libc::c_int = 6;
pub const LOG_WARNING: libc::c_int = 4;
pub const LOG_ERR: libc::c_int = 3;
pub const LOG_CRIT: libc::c_int = 2;

/// Syslog options.
const LOG_PID: libc::c_int = 0x01;

/// Open syslog with the given program name.
pub fn openlog(progname: &str) {
    // We use a leaked CString because openlog stores the pointer
    let c_name = CString::new(progname).unwrap_or_else(|_| CString::new("elevate-umbra").unwrap());
    let ptr = c_name.into_raw();
    unsafe {
        libc::openlog(ptr, LOG_PID, LOG_AUTHPRIV);
    }
}

/// Close syslog.
pub fn closelog() {
    unsafe {
        libc::closelog();
    }
}

/// Log a message to syslog at the given priority.
pub fn syslog(priority: libc::c_int, message: &str) {
    let c_fmt = CString::new("%s").unwrap();
    let c_msg =
        CString::new(message).unwrap_or_else(|_| CString::new("(invalid message)").unwrap());
    unsafe {
        libc::syslog(priority, c_fmt.as_ptr(), c_msg.as_ptr());
    }
}

/// Log an informational message.
pub fn audit_info(prog: &str, msg: &str) {
    syslog(LOG_INFO, &format!("{}: {}", prog, msg));
}

/// Log a warning message.
pub fn audit_warn(prog: &str, msg: &str) {
    syslog(LOG_WARNING, &format!("{}: {}", prog, msg));
}

/// Log an error message.
pub fn audit_error(prog: &str, msg: &str) {
    syslog(LOG_ERR, &format!("{}: {}", prog, msg));
}

/// Log a critical audit event (e.g. user added, user deleted).
pub fn audit_crit(prog: &str, msg: &str) {
    syslog(LOG_CRIT, &format!("{}: {}", prog, msg));
}

/// Log a user/group operation with structured fields.
pub fn audit_user_op(prog: &str, op: &str, name: &str, uid: Option<u32>, result: bool) {
    let status = if result { "OK" } else { "FAILED" };
    let uid_str = uid.map(|u| format!(" uid={}", u)).unwrap_or_default();
    let msg = format!(
        "{}: op={} name={}{} result={}",
        prog, op, name, uid_str, status
    );
    let priority = if result { LOG_INFO } else { LOG_CRIT };
    syslog(priority, &msg);
}
