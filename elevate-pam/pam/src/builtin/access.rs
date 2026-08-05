//! pam_access — login.access(5)-style access control, evaluating
//! `access.conf(5)`. See `pam_access(8)`.
//!
//! Each non-comment, non-blank line is `permission : users : origins`
//! (fields separated by `:`, list items within a field by `,`). The first
//! matching line wins; if no line matches, access is granted (matches
//! upstream's default-allow behavior).
//!
//! Simplifications vs upstream (documented, not silent): no netgroup
//! (`NIS`/`@@netgroup`) support, no DNS/domain-suffix matching for origins
//! (exact hostname or `LOCAL`/`ALL` only) — matches the same pragmatic
//! scope already accepted in `pam-limits`'s `@group` handling.

use alloc::string::String;
use std::ffi::CStr;
use std::fs;

use crate::constants::{PAM_PERM_DENIED, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("access"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: Some(check),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

fn check(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };
    let debug = arg_has(args, "debug");
    let accessfile = arg_value(args, "accessfile")
        .map(String::from)
        .unwrap_or_else(|| elevate_paths::get().access_conf());
    let origin = pamh
        .get_item_str(crate::types::ItemType::Tty)
        .map(String::from);
    let rhost = pamh
        .get_item_str(crate::types::ItemType::RHost)
        .map(String::from);
    let origin = rhost.or(origin).unwrap_or_else(|| "LOCAL".into());

    let text = match fs::read_to_string(&accessfile) {
        Ok(t) => t,
        Err(_) => return PamStatus::new(PAM_SUCCESS), // no config == no restriction
    };

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(3, ':').map(str::trim);
        let (Some(perm), Some(users), Some(origins)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !user_matches(users, &user) {
            continue;
        }
        if !origin_matches(origins, &origin) {
            continue;
        }
        let allow = perm == "+";
        if debug {
            crate::log::debug(
                pamh,
                &format!(
                    "access: line {}: user='{user}' origin='{origin}' -> {}",
                    lineno + 1,
                    if allow { "allow" } else { "deny" }
                ),
            );
        }
        if allow {
            return PamStatus::new(PAM_SUCCESS);
        }
        if !arg_has(args, "noaudit") {
            crate::log::warn(
                pamh,
                &format!(
                    "access: denied for user '{user}' from '{origin}' (access.conf:{})",
                    lineno + 1
                ),
            );
        }
        return PamStatus::new(PAM_PERM_DENIED);
    }

    // No matching line: default allow (matches login.access(5)).
    PamStatus::new(PAM_SUCCESS)
}

fn user_matches(field: &str, user: &str) -> bool {
    field
        .split(',')
        .map(str::trim)
        .any(|item| match_one_user(item, user))
}

fn match_one_user(item: &str, user: &str) -> bool {
    if item == "ALL" {
        return true;
    }
    if let Some(except) = item.strip_prefix("EXCEPT ") {
        return !match_one_user(except.trim(), user);
    }
    if let Some(group) = item.strip_prefix('@') {
        return is_group_member(user, group);
    }
    item == user
}

fn origin_matches(field: &str, origin: &str) -> bool {
    field
        .split(',')
        .map(str::trim)
        .any(|item| match_one_origin(item, origin))
}

fn match_one_origin(item: &str, origin: &str) -> bool {
    if item == "ALL" {
        return true;
    }
    if item == "LOCAL" {
        return origin == "LOCAL" || !origin.contains('.');
    }
    if let Some(except) = item.strip_prefix("EXCEPT ") {
        return !match_one_origin(except.trim(), origin);
    }
    item.eq_ignore_ascii_case(origin)
}

fn is_group_member(user: &str, group: &str) -> bool {
    let (Ok(c_user), Ok(c_group)) = (std::ffi::CString::new(user), std::ffi::CString::new(group))
    else {
        return false;
    };
    // SAFETY: c_user/c_group are valid NUL-terminated strings for the
    // duration of these libc calls; the returned pointers are only read
    // (via CStr, never retained) before the next libc call in this scope.
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            return false;
        }
        let primary_gid = (*pw).pw_gid;

        let gr = libc::getgrnam(c_group.as_ptr());
        if gr.is_null() {
            return false;
        }
        if (*gr).gr_gid == primary_gid {
            return true;
        }
        let mut mem = (*gr).gr_mem;
        if !mem.is_null() {
            while !(*mem).is_null() {
                if CStr::from_ptr(*mem).to_string_lossy() == user {
                    return true;
                }
                mem = mem.add(1);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_matches_all_and_exact() {
        assert!(user_matches("ALL", "alice"));
        assert!(user_matches("alice", "alice"));
        assert!(!user_matches("bob", "alice"));
        assert!(user_matches("bob, alice", "alice"));
    }

    #[test]
    fn user_matches_except() {
        assert!(!user_matches("EXCEPT alice", "alice"));
        assert!(user_matches("EXCEPT alice", "bob"));
    }

    #[test]
    fn origin_matches_all_local_and_except() {
        assert!(origin_matches("ALL", "some.host"));
        assert!(origin_matches("LOCAL", "LOCAL"));
        assert!(origin_matches("LOCAL", "tty1"));
        assert!(!origin_matches("LOCAL", "remote.example.com"));
        assert!(origin_matches("remote.example.com", "remote.example.com"));
        assert!(!origin_matches("EXCEPT ALL", "anything"));
    }

    #[test]
    fn origin_matches_case_insensitive() {
        assert!(origin_matches("Some.Host", "some.host"));
    }
}
