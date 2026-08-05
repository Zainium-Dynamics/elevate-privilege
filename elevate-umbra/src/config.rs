//! System path constants and limits for elevate-umbra on ZainiumOS syshub.

use std::path::PathBuf;

/// Maximum line length for passwd/shadow/group entries (shadow-4.17.2 PASSWD_ENTRY_MAX_LENGTH = 32768).
pub const PASSWD_ENTRY_MAX_LENGTH: usize = 32768;

/// Maximum password length (shadow-4.17.2 PASS_MAX = 8191).
pub const PASS_MAX: usize = 8191;

/// Maximum login name length (shadow-4.17.2 LOGIN_NAME_MAX = 256).
pub const LOGIN_NAME_MAX: usize = 256;

/// Seconds in a day.
pub const DAY: i64 = 86400;

/// Seconds in a week.
pub const WEEK: i64 = 604800;

pub fn syshub_etc() -> PathBuf {
    PathBuf::from(elevate_paths::get().etc_dir())
}

pub fn passwd_path() -> PathBuf {
    syshub_etc().join("passwd")
}

pub fn shadow_path() -> PathBuf {
    syshub_etc().join("shadow")
}

pub fn group_path() -> PathBuf {
    syshub_etc().join("group")
}

pub fn gshadow_path() -> PathBuf {
    syshub_etc().join("gshadow")
}

pub fn subuid_path() -> PathBuf {
    syshub_etc().join("subuid")
}

pub fn subgid_path() -> PathBuf {
    syshub_etc().join("subgid")
}

pub fn useradd_defaults_path() -> PathBuf {
    syshub_etc().join("default/useradd")
}

pub fn skel_dir() -> PathBuf {
    syshub_etc().join("skel")
}
