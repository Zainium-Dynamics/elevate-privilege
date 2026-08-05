//! Logging (syslog when available, stderr fallback).

use crate::handle::PamHandle;

/// Log an error.
pub fn error(pamh: &PamHandle, msg: &str) {
    write(pamh, "error", msg);
}

/// Log a warning.
pub fn warn(pamh: &PamHandle, msg: &str) {
    write(pamh, "warn", msg);
}

/// Log info.
pub fn info(pamh: &PamHandle, msg: &str) {
    write(pamh, "info", msg);
}

/// Log debug.
pub fn debug(pamh: &PamHandle, msg: &str) {
    write(pamh, "debug", msg);
}

fn write(pamh: &PamHandle, level: &str, msg: &str) {
    let mod_name = pamh
        .current_module
        .as_deref()
        .unwrap_or("elevate-pam");
    let line = format!(
        "elevate-pam({}:{})[{}]: {}",
        pamh.service(),
        mod_name,
        level,
        msg
    );

    #[cfg(feature = "syslog")]
    {
        // Best-effort libc syslog
        use std::ffi::CString;
        if let Ok(c) = CString::new(line.as_str()) {
            // LOG_AUTHPRIV | LOG_ERR style priorities
            let pri = match level {
                "error" => 3, // LOG_ERR
                "warn" => 4,  // LOG_WARNING
                "info" => 6,  // LOG_INFO
                _ => 7,       // LOG_DEBUG
            };
            // LOG_AUTHPRIV = (10<<3) = 80
            let priority = 80 | pri;
            unsafe {
                libc::syslog(priority, c"%s".as_ptr() as *const libc::c_char, c.as_ptr());
            }
            return;
        }
    }

    // Fallback
    eprintln!("{line}");
    let _ = log::log!(
        match level {
            "error" => log::Level::Error,
            "warn" => log::Level::Warn,
            "info" => log::Level::Info,
            _ => log::Level::Debug,
        },
        "{line}"
    );
}
