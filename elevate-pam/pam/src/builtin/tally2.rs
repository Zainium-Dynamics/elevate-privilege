//! pam_tally2 — legacy failed-login counter. See `pam_tally2(8)`.
//!
//! Deprecated upstream in favor of `pam_faillock` (also implemented, see
//! `builtin/faillock.rs`), but still used by some existing configs. Unlike
//! faillock's explicit preauth/authfail/authsucc call-site convention,
//! classic tally2 uses a single-call convention: `authenticate()`
//! optimistically increments the tally on every call (checking the limit
//! first), and `acct_mgmt()` -- reached only once the whole auth stack has
//! actually succeeded -- resets it. Storage is a tally file per user under
//! `elevate_paths::tallylog_dir()`, kept separate from faillock's own.

use alloc::string::String;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("tally2"),
        authenticate: Some(check_and_increment),
        setcred: None,
        acct_mgmt: Some(reset_on_success),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

struct Opts {
    deny: u32,
    unlock_time: u64,
    root_unlock_time: Option<u64>,
    even_deny_root: bool,
    dir: String,
}

fn parse_opts(args: &[String]) -> Opts {
    Opts {
        deny: arg_value(args, "deny")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3),
        unlock_time: arg_value(args, "unlock_time")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        root_unlock_time: arg_value(args, "root_unlock_time").and_then(|s| s.parse().ok()),
        even_deny_root: arg_has(args, "even_deny_root") || arg_has(args, "no_magic_root"),
        dir: arg_value(args, "dir")
            .map(String::from)
            .unwrap_or_else(|| elevate_paths::get().tallylog_dir()),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn tally_path(dir: &str, user: &str) -> PathBuf {
    Path::new(dir).join(user)
}

fn read_tally(path: &Path) -> Vec<u64> {
    fs::read_to_string(path)
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

fn write_tally(dir: &str, path: &Path, entries: &[u64]) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).ok();
    let mut f = fs::File::create(path)?;
    for ts in entries {
        writeln!(f, "{ts}")?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn check_and_increment(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    if arg_has(args, "reset") {
        let user = pamh.user().unwrap_or_default().to_string();
        let opts = parse_opts(args);
        let _ = fs::remove_file(tally_path(&opts.dir, &user));
        return PamStatus::new(PAM_SUCCESS);
    }

    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };
    let opts = parse_opts(args);
    let is_root = user == "root";
    let unlock_time = if is_root {
        opts.root_unlock_time.unwrap_or(opts.unlock_time)
    } else {
        opts.unlock_time
    };
    let path = tally_path(&opts.dir, &user);

    if !is_root || opts.even_deny_root {
        let now = now_secs();
        let mut entries = read_tally(&path);
        if unlock_time > 0 {
            entries.retain(|&ts| now.saturating_sub(ts) <= unlock_time);
        }
        if opts.deny > 0 && entries.len() as u32 >= opts.deny {
            crate::log::warn(
                pamh,
                &alloc::format!(
                    "tally2: user '{user}' locked out ({} failed attempts)",
                    entries.len()
                ),
            );
            return PamStatus::new(PAM_AUTH_ERR);
        }
        entries.push(now);
        if let Err(e) = write_tally(&opts.dir, &path, &entries) {
            crate::log::warn(
                pamh,
                &alloc::format!("tally2: write tally for '{user}': {e}"),
            );
        }
    }
    PamStatus::new(PAM_SUCCESS)
}

fn reset_on_success(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };
    let opts = parse_opts(args);
    let _ = fs::remove_file(tally_path(&opts.dir, &user));
    PamStatus::new(PAM_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_roundtrip() {
        let dir = std::env::temp_dir().join(alloc::format!(
            "elevate-pam-tally2-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let path = tally_path(dir.to_str().unwrap(), "alice");
        write_tally(dir.to_str().unwrap(), &path, &[1, 2, 3]).unwrap();
        assert_eq!(read_tally(&path), vec![1, 2, 3]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
