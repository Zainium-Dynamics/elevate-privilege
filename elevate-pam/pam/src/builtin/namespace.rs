//! pam_namespace — per-user directory polyinstantiation via bind mounts in
//! a private mount namespace. See `pam_namespace(8)`/`namespace.conf(5)`.
//!
//! Config (`namespace.conf`-style, one rule per line, `#` comments):
//! ```text
//! polydir instance_prefix method
//! ```
//! e.g. `/tmp /overlayer/syshub/var/namespaces/tmp user` polyinstantiates
//! `/tmp` per-user, each user getting `instance_prefix/<uid>` bind-mounted
//! onto `polydir` inside a private mount namespace for the session.
//!
//! Scope (documented, not silent): only the `user` method is implemented
//! (one instance directory per uid). Upstream's `context` method
//! (SELinux-level polyinstantiation) and MLS/tmpfs-only variants aren't --
//! this project has no SELinux integration elsewhere either.

use alloc::string::String;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::constants::{PAM_SESSION_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("namespace"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(open_session),
        close_session: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        chauthtok: None,
    }
}

struct Rule {
    polydir: String,
    instance_prefix: String,
}

fn parse_conf(text: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if parts[2] != "user" {
            // Only the `user` method is supported -- see module doc.
            continue;
        }
        rules.push(Rule {
            polydir: parts[0].to_string(),
            instance_prefix: parts[1].to_string(),
        });
    }
    rules
}

fn open_session(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };
    let Some(uid) = lookup_uid(&user) else {
        return PamStatus::new(PAM_SUCCESS);
    };

    let conf_path = arg_value(args, "conf")
        .map(String::from)
        .unwrap_or_else(|| elevate_paths::get().namespace_conf());
    let text = match fs::read_to_string(&conf_path) {
        Ok(t) => t,
        Err(_) => return PamStatus::new(PAM_SUCCESS), // no config == nothing to polyinstantiate
    };
    let rules = parse_conf(&text);
    if rules.is_empty() {
        return PamStatus::new(PAM_SUCCESS);
    }

    // SAFETY: no arguments, no pointers; unshare(CLONE_NEWNS) only affects
    // this process's own mount namespace (torn down automatically when the
    // process exits), which is exactly the intended per-session scope.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        crate::log::warn(
            pamh,
            &format!(
                "namespace: unshare(CLONE_NEWNS): {}",
                std::io::Error::last_os_error()
            ),
        );
        return PamStatus::new(PAM_SESSION_ERR);
    }

    for rule in &rules {
        if let Err(e) = polyinstantiate(&rule.polydir, &rule.instance_prefix, uid) {
            crate::log::warn(
                pamh,
                &format!(
                    "namespace: {} -> {}: {e}",
                    rule.polydir, rule.instance_prefix
                ),
            );
        }
    }
    PamStatus::new(PAM_SUCCESS)
}

fn polyinstantiate(polydir: &str, instance_prefix: &str, uid: u32) -> Result<(), String> {
    let instance_dir = PathBuf::from(instance_prefix).join(uid.to_string());
    fs::create_dir_all(&instance_dir)
        .map_err(|e| format!("mkdir {}: {e}", instance_dir.display()))?;
    fs::set_permissions(&instance_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {}: {e}", instance_dir.display()))?;
    chown(&instance_dir, uid)?;

    let c_src = CString::new(instance_dir.to_string_lossy().as_bytes())
        .map_err(|_| "invalid instance path".to_string())?;
    let c_dst = CString::new(polydir).map_err(|_| "invalid polydir path".to_string())?;
    // SAFETY: c_src/c_dst are valid NUL-terminated strings for this call;
    // MS_BIND ignores the fstype/data arguments, both null here.
    let ret = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind mount {} -> {polydir}: {}",
            instance_dir.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn lookup_uid(user: &str) -> Option<u32> {
    let c_user = CString::new(user).ok()?;
    // SAFETY: c_user is a valid NUL-terminated string for this call; the
    // returned pointer is only read (uid field copied out) before any
    // other libc call in this function.
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}

fn chown(path: &std::path::Path, uid: u32) -> Result<(), String> {
    let c_path =
        CString::new(path.to_string_lossy().as_bytes()).map_err(|_| "invalid path".to_string())?;
    // SAFETY: c_path is a valid NUL-terminated string for the duration of this call.
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, u32::MAX) };
    if ret != 0 {
        Err(format!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_conf_skips_comments_and_non_user_methods() {
        let text = "\
# a comment
/tmp /var/namespaces/tmp user
/home /var/namespaces/home context
malformed line
/var/tmp /var/namespaces/vartmp user
";
        let rules = parse_conf(text);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].polydir, "/tmp");
        assert_eq!(rules[0].instance_prefix, "/var/namespaces/tmp");
        assert_eq!(rules[1].polydir, "/var/tmp");
    }

    #[test]
    fn parse_conf_empty_for_blank_text() {
        assert!(parse_conf("").is_empty());
        assert!(parse_conf("   \n  \n").is_empty());
    }
}
