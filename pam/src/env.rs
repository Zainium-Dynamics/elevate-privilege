//! PAM environment list (`pam_putenv` / `pam_getenv` / `pam_getenvlist`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::constants::{PAM_BAD_ITEM, PAM_BUF_ERR, PAM_SUCCESS};
use crate::error::{PamError, PamResult};

/// Environment store as `NAME=value` strings (Linux-PAM layout).
#[derive(Debug, Clone, Default)]
pub struct PamEnv {
    entries: Vec<String>,
}

impl PamEnv {
    /// Empty environment.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Put `NAME=value` or `NAME` (delete if no `=`).
    pub fn putenv(&mut self, name_value: &str) -> PamResult<()> {
        if name_value.is_empty() {
            return Err(PamError::Status(crate::error::PamStatus::new(PAM_BAD_ITEM)));
        }
        if let Some(eq) = name_value.find('=') {
            let name = &name_value[..eq];
            if name.is_empty() {
                return Err(PamError::Status(crate::error::PamStatus::new(PAM_BAD_ITEM)));
            }
            self.remove_name(name);
            self.entries.push(String::from(name_value));
        } else {
            // delete
            self.remove_name(name_value);
        }
        Ok(())
    }

    /// Get value for `name` (without `=`).
    pub fn getenv(&self, name: &str) -> Option<&str> {
        let prefix = alloc::format!("{name}=");
        for e in &self.entries {
            if let Some(rest) = e.strip_prefix(&prefix) {
                return Some(rest);
            }
        }
        None
    }

    /// Snapshot of all entries.
    pub fn list(&self) -> &[String] {
        &self.entries
    }

    /// Into owned list.
    pub fn into_list(self) -> Vec<String> {
        self.entries
    }

    fn remove_name(&mut self, name: &str) {
        let prefix = alloc::format!("{name}=");
        self.entries
            .retain(|e| !(e == name || e.starts_with(&prefix)));
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty check.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// C-compatible getenvlist: returns malloc'd array of malloc'd strings, NULL terminated.
///
/// Caller must free each string and the array with `libc::free` (Linux-PAM contract).
#[cfg(feature = "std")]
pub fn getenvlist_c(env: &PamEnv) -> Result<*mut *mut libc::c_char, i32> {
    use std::ffi::CString;

    let n = env.entries.len();
    // SAFETY: calloc for pointer table
    let table = unsafe {
        libc::calloc(n + 1, core::mem::size_of::<*mut libc::c_char>()) as *mut *mut libc::c_char
    };
    if table.is_null() {
        return Err(PAM_BUF_ERR);
    }
    for (i, e) in env.entries.iter().enumerate() {
        let c = match CString::new(e.as_str()) {
            Ok(c) => c,
            Err(_) => {
                // free partial
                for j in 0..i {
                    unsafe {
                        libc::free(*table.add(j) as *mut libc::c_void);
                    }
                }
                unsafe {
                    libc::free(table as *mut libc::c_void);
                }
                return Err(PAM_BUF_ERR);
            }
        };
        let raw = c.into_raw();
        unsafe {
            *table.add(i) = raw;
        }
    }
    // last is already NULL from calloc
    let _ = PAM_SUCCESS;
    Ok(table)
}
