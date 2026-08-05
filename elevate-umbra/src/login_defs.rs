//! Parser for `/etc/login.defs` (shadow-4.17.2 `lib/getdef.c` equivalent).
//! Reads system-wide defaults: UID_MIN, UID_MAX, GID_MIN, GID_MAX, UMASK, etc.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::config::syshub_etc;

/// Parsed login.defs configuration.
#[derive(Debug, Clone)]
pub struct LoginDefs {
    defs: HashMap<String, String>,
}

impl LoginDefs {
    /// Load login.defs from the default syshub path or fallback.
    pub fn load_default() -> Self {
        let primary = syshub_etc().join("login.defs");
        if primary.exists() {
            return Self::load(&primary);
        }
        let fallback = Path::new("/etc/login.defs");
        if fallback.exists() {
            return Self::load(fallback);
        }
        Self::empty()
    }

    /// Load from a specific path.
    pub fn load(path: &Path) -> Self {
        let mut defs = HashMap::new();
        if let Ok(file) = File::open(path) {
            for line in BufReader::new(file).lines().flatten() {
                let line = line.trim().to_string();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Format: KEY VALUE  or  KEY\tVALUE
                let mut parts = line.splitn(2, |c: char| c == ' ' || c == '\t');
                if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                    defs.insert(key.trim().to_uppercase(), val.trim().to_string());
                }
            }
        }
        Self { defs }
    }

    /// Create empty defaults (no file loaded).
    pub fn empty() -> Self {
        Self {
            defs: HashMap::new(),
        }
    }

    /// Get a string value.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.defs.get(key).map(|s| s.as_str())
    }

    /// Get an integer value with a default fallback.
    pub fn get_num(&self, key: &str, default: i64) -> i64 {
        self.defs
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get an unsigned integer value with a default fallback.
    pub fn get_unum(&self, key: &str, default: u64) -> u64 {
        self.defs
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get a boolean value.
    pub fn get_bool(&self, key: &str) -> bool {
        self.defs
            .get(key)
            .map(|v| matches!(v.to_lowercase().as_str(), "yes" | "true" | "1"))
            .unwrap_or(false)
    }

    // ---- Convenience accessors matching shadow getdef.c usage ----

    pub fn uid_min(&self) -> u32 {
        self.get_num("UID_MIN", 1000) as u32
    }
    pub fn uid_max(&self) -> u32 {
        self.get_num("UID_MAX", 60000) as u32
    }
    pub fn sys_uid_min(&self) -> u32 {
        self.get_num("SYS_UID_MIN", 100) as u32
    }
    pub fn sys_uid_max(&self) -> u32 {
        self.get_num("SYS_UID_MAX", 999) as u32
    }
    pub fn gid_min(&self) -> u32 {
        self.get_num("GID_MIN", 1000) as u32
    }
    pub fn gid_max(&self) -> u32 {
        self.get_num("GID_MAX", 60000) as u32
    }
    pub fn sys_gid_min(&self) -> u32 {
        self.get_num("SYS_GID_MIN", 100) as u32
    }
    pub fn sys_gid_max(&self) -> u32 {
        self.get_num("SYS_GID_MAX", 999) as u32
    }
    pub fn umask(&self) -> u32 {
        // Parse octal umask
        self.defs
            .get("UMASK")
            .and_then(|v| u32::from_str_radix(v, 8).ok())
            .unwrap_or(0o022)
    }
    pub fn pass_max_days(&self) -> i64 {
        self.get_num("PASS_MAX_DAYS", 99999)
    }
    pub fn pass_min_days(&self) -> i64 {
        self.get_num("PASS_MIN_DAYS", 0)
    }
    pub fn pass_warn_age(&self) -> i64 {
        self.get_num("PASS_WARN_AGE", 7)
    }
    pub fn pass_min_len(&self) -> usize {
        self.get_num("PASS_MIN_LEN", 5) as usize
    }
    pub fn encrypt_method(&self) -> &str {
        self.get_str("ENCRYPT_METHOD").unwrap_or("YESCRYPT")
    }
    pub fn create_home(&self) -> bool {
        self.get_bool("CREATE_HOME")
    }
    pub fn usergroups_enab(&self) -> bool {
        // Default true on most distros
        self.defs
            .get("USERGROUPS_ENAB")
            .map(|v| !matches!(v.to_lowercase().as_str(), "no" | "false" | "0"))
            .unwrap_or(true)
    }
    pub fn default_home(&self) -> &str {
        self.get_str("DEFAULT_HOME").unwrap_or("/home")
    }
    pub fn mail_dir(&self) -> Option<&str> {
        self.get_str("MAIL_DIR")
    }
    pub fn env_path(&self) -> String {
        self.get_str("ENV_PATH")
            .map(String::from)
            .unwrap_or_else(|| {
                let paths = elevate_paths::get();
                format!("{}:/bin:/sbin", paths.bindir)
            })
    }
    pub fn login_retries(&self) -> u32 {
        self.get_num("LOGIN_RETRIES", 5) as u32
    }
    pub fn login_timeout(&self) -> u32 {
        self.get_num("LOGIN_TIMEOUT", 60) as u32
    }
    pub fn max_members_per_group(&self) -> i64 {
        self.get_num("MAX_MEMBERS_PER_GROUP", 0)
    }
}
