//! pam_faillock — track failed login attempts per-user and lock the account
//! after too many within a rolling window. See `pam_faillock(8)`.
//!
//! Stacked (upstream convention) as e.g.:
//! ```text
//! auth required pam_faillock.so preauth
//! auth [success=1 default=ignore] pam_unix.so
//! auth [default=die] pam_faillock.so authfail
//! auth sufficient pam_faillock.so authsucc
//! ```
//!
//! Storage: one file per user under the tally directory, each line a unix
//! timestamp (seconds) of a failed attempt -- functionally equivalent to
//! upstream's binary tally format, simpler to implement correctly.

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
        id: ModuleId::normalize("faillock"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: None,
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

struct Opts {
    deny: u32,
    fail_interval: u64,
    unlock_time: u64,
    root_unlock_time: Option<u64>,
    even_deny_root: bool,
    local_users_only: bool,
    silent: bool,
    dir: String,
}

fn parse_opts(args: &[String]) -> Opts {
    Opts {
        deny: arg_value(args, "deny")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3),
        fail_interval: arg_value(args, "fail_interval")
            .and_then(|s| s.parse().ok())
            .unwrap_or(900),
        unlock_time: arg_value(args, "unlock_time")
            .and_then(|s| s.parse().ok())
            .unwrap_or(600),
        root_unlock_time: arg_value(args, "root_unlock_time").and_then(|s| s.parse().ok()),
        even_deny_root: arg_has(args, "even_deny_root"),
        local_users_only: arg_has(args, "local_users_only"),
        silent: arg_has(args, "silent"),
        dir: arg_value(args, "dir")
            .map(String::from)
            .unwrap_or_else(|| elevate_paths::get().faillock_dir()),
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

fn check(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };
    let opts = parse_opts(args);

    if opts.local_users_only && pamh.get_item_str(crate::types::ItemType::RHost).is_some() {
        return PamStatus::new(PAM_SUCCESS);
    }
    let is_root = user == "root";
    let unlock_time = if is_root {
        opts.root_unlock_time.unwrap_or(opts.unlock_time)
    } else {
        opts.unlock_time
    };

    let path = tally_path(&opts.dir, &user);

    if arg_has(args, "authsucc") {
        let _ = fs::remove_file(&path);
        return PamStatus::new(PAM_SUCCESS);
    }

    if arg_has(args, "authfail") {
        let now = now_secs();
        let mut entries = read_tally(&path);
        entries.retain(|&ts| now.saturating_sub(ts) <= opts.fail_interval);
        entries.push(now);
        if let Err(e) = write_tally(&opts.dir, &path, &entries) {
            crate::log::warn(pamh, &format!("faillock: write tally for '{user}': {e}"));
        }
        return PamStatus::new(PAM_SUCCESS);
    }

    // preauth (default when no phase arg given)
    if !is_root || opts.even_deny_root {
        let now = now_secs();
        let mut entries = read_tally(&path);
        entries.retain(|&ts| now.saturating_sub(ts) <= opts.fail_interval);
        if entries.len() as u32 >= opts.deny {
            let last = *entries.iter().max().unwrap_or(&0);
            if unlock_time == 0 || now.saturating_sub(last) < unlock_time {
                if !opts.silent {
                    crate::log::warn(
                        pamh,
                        &format!(
                            "faillock: user '{user}' locked out ({} failed attempts)",
                            entries.len()
                        ),
                    );
                }
                return PamStatus::new(PAM_AUTH_ERR);
            }
            // unlock_time elapsed: reset the tally, allow through.
            let _ = fs::remove_file(&path);
        }
    }
    PamStatus::new(PAM_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_roundtrip_and_pruning() {
        let dir = std::env::temp_dir().join(format!(
            "elevate-pam-faillock-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let path = tally_path(dir.to_str().unwrap(), "alice");

        let now = now_secs();
        write_tally(dir.to_str().unwrap(), &path, &[now - 5000, now - 100, now]).unwrap();

        let entries = read_tally(&path);
        assert_eq!(entries, vec![now - 5000, now - 100, now]);

        // Pruning: only entries within fail_interval=900s should remain.
        let pruned: Vec<u64> = entries
            .into_iter()
            .filter(|&ts| now.saturating_sub(ts) <= 900)
            .collect();
        assert_eq!(pruned, vec![now - 100, now]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tally_file_permissions_are_owner_only() {
        let dir = std::env::temp_dir().join(format!(
            "elevate-pam-faillock-test-perm-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let path = tally_path(dir.to_str().unwrap(), "bob");
        write_tally(dir.to_str().unwrap(), &path, &[now_secs()]).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }
}
