//! pam_env — set environment variables from config files (TOML or classic).

use alloc::string::String;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::constants::{PAM_IGNORE, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("env"),
        authenticate: Some(set_env),
        setcred: Some(set_env),
        acct_mgmt: None,
        open_session: Some(set_env),
        close_session: None,
        chauthtok: None,
    }
}

fn set_env(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    if !arg_has(args, "readenv=1") && !arg_has(args, "readenv") {
        // still allow conffile=
        if arg_value(args, "conffile").is_none() && arg_value(args, "envfile").is_none() {
            return PamStatus::new(PAM_SUCCESS);
        }
    }

    let conffile = arg_value(args, "conffile")
        .map(String::from)
        .unwrap_or_else(|| elevate_paths::get().pam_env_conf());
    let envfile = arg_value(args, "envfile")
        .map(String::from)
        .unwrap_or_else(|| elevate_paths::get().environment_file());
    let user_env = arg_has(args, "user_readenv=1") || arg_has(args, "user_readenv");

    let _ = load_env_file(pamh, &envfile);
    let _ = load_pam_env_conf(pamh, &conffile);

    if user_env {
        if let Some(user) = pamh.user() {
            let home = home_dir(user);
            if let Some(h) = home {
                let p = format!("{h}/.pam_environment");
                let _ = load_env_file(pamh, &p);
            }
        }
    }

    PamStatus::new(PAM_SUCCESS)
}

fn load_env_file(pamh: &mut PamHandle, path: &str) -> Result<(), ()> {
    let f = fs::File::open(path).map_err(|_| ())?;
    for line in BufReader::new(f).lines().flatten() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // KEY=value or KEY="value"
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            let entry = format!("{}={}", k.trim(), v);
            let _ = pamh.putenv(&entry);
        }
    }
    Ok(())
}

fn load_pam_env_conf(pamh: &mut PamHandle, path: &str) -> Result<(), ()> {
    if !Path::new(path).is_file() {
        return Ok(());
    }
    let f = fs::File::open(path).map_err(|_| ())?;
    for line in BufReader::new(f).lines().flatten() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // VAR DEFAULT=... OVERRIDE=...
        let mut parts = line.split_whitespace();
        let Some(var) = parts.next() else { continue };
        let mut default = None;
        let mut override_v = None;
        for p in parts {
            if let Some(v) = p.strip_prefix("DEFAULT=") {
                default = Some(v.trim_matches('"'));
            } else if let Some(v) = p.strip_prefix("OVERRIDE=") {
                override_v = Some(v.trim_matches('"'));
            }
        }
        let value = override_v.or(default);
        if let Some(v) = value {
            let entry = format!("{var}={v}");
            let _ = pamh.putenv(&entry);
        }
    }
    Ok(())
}

fn home_dir(user: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c = CString::new(user).ok()?;
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned())
    }
}

#[allow(dead_code)]
fn _ignore() -> PamStatus {
    PamStatus::new(PAM_IGNORE)
}
