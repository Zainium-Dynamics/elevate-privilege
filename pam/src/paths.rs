//! Filesystem locations used by elevate-pam and its builtin modules.
//!
//! Paths come from the `[paths]` table of `elevate-pam.toml`; anything not
//! set there is derived from `prefix` (default: empty, i.e. the real `/`),
//! so setting only `prefix` moves every path together. With no config file
//! the conventional Linux layout is used (`/etc`, `/lib/security`, ...).
//!
//! The config file is the first that exists of:
//! 1. `$ELEVATE_PAM_CONFIG` (explicit path)
//! 2. `/etc/elevate-pam/elevate-pam.toml`
//! 3. `/etc/elevate-pam.toml`
//! 4. `./elevate-pam.toml` (dev checkout)
//!
//! ```toml
//! [paths]
//! prefix = "/opt/pam"      # optional; everything below derives from it
//! etc_dir = "/opt/pam/etc" # optional, default <prefix>/etc
//! conf_dir = "..."         # default <etc_dir>/elevate-pam
//! module_dir = "..."       # default <prefix>/lib/security
//! vendor_dir = "..."       # default <prefix>/lib/elevate-pam/services
//! var_dir = "..."          # default <prefix>/var/run/elevate
//! ```

use std::sync::OnceLock;

use serde::Deserialize;

/// Resolved elevate-pam filesystem locations.
#[derive(Debug, Clone)]
pub struct PathsConfig {
    /// Install root; empty means the real `/`.
    pub prefix: String,
    /// elevate-pam config directory (`elevate-pam.toml`, `services/`).
    pub conf_dir: String,
    /// Directory of loadable `pam_*.so` modules.
    pub module_dir: String,
    /// Vendor-shipped service stacks.
    pub vendor_dir: String,
    /// Runtime state (faillock, tallylog, timestamps).
    pub var_dir: String,
    etc_dir: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawPaths {
    prefix: Option<String>,
    etc_dir: Option<String>,
    conf_dir: Option<String>,
    module_dir: Option<String>,
    vendor_dir: Option<String>,
    var_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TopLevel {
    #[serde(default)]
    paths: Option<RawPaths>,
}

fn clean(s: String) -> String {
    s.trim_end_matches('/').to_string()
}

impl From<RawPaths> for PathsConfig {
    fn from(raw: RawPaths) -> Self {
        let prefix = clean(raw.prefix.unwrap_or_default());
        let etc_dir = clean(raw.etc_dir.unwrap_or_else(|| format!("{prefix}/etc")));
        Self {
            conf_dir: clean(
                raw.conf_dir
                    .unwrap_or_else(|| format!("{etc_dir}/elevate-pam")),
            ),
            module_dir: clean(
                raw.module_dir
                    .unwrap_or_else(|| format!("{prefix}/lib/security")),
            ),
            vendor_dir: clean(
                raw.vendor_dir
                    .unwrap_or_else(|| format!("{prefix}/lib/elevate-pam/services")),
            ),
            var_dir: clean(
                raw.var_dir
                    .unwrap_or_else(|| format!("{prefix}/var/run/elevate")),
            ),
            etc_dir,
            prefix,
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        RawPaths::default().into()
    }
}

impl PathsConfig {
    fn candidates() -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(explicit) = std::env::var("ELEVATE_PAM_CONFIG") {
            out.push(explicit.into());
        }
        out.push("/etc/elevate-pam/elevate-pam.toml".into());
        out.push("/etc/elevate-pam.toml".into());
        out.push("elevate-pam.toml".into());
        out
    }

    fn from_toml(text: &str) -> Option<Self> {
        let top: TopLevel = toml::from_str(text).ok()?;
        Some(top.paths.unwrap_or_default().into())
    }

    fn load() -> Self {
        Self::candidates()
            .into_iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .find_map(|t| Self::from_toml(&t))
            .unwrap_or_default()
    }

    /// Process-wide cached config (resolved once on first access).
    pub fn get() -> &'static Self {
        static CACHE: OnceLock<PathsConfig> = OnceLock::new();
        CACHE.get_or_init(Self::load)
    }

    /// Base `/etc`-equivalent directory.
    pub fn etc_dir(&self) -> &str {
        &self.etc_dir
    }
    /// `passwd(5)`.
    pub fn passwd_file(&self) -> String {
        format!("{}/passwd", self.etc_dir)
    }
    /// `group(5)`.
    pub fn group_file(&self) -> String {
        format!("{}/group", self.etc_dir)
    }
    /// `shadow(5)`.
    pub fn shadow_file(&self) -> String {
        format!("{}/shadow", self.etc_dir)
    }
    /// `shells(5)`.
    pub fn shells_file(&self) -> String {
        format!("{}/shells", self.etc_dir)
    }
    /// `pam_unix`'s `remember=` password-history file (`opasswd(5)`).
    pub fn opasswd_file(&self) -> String {
        format!("{}/security/opasswd", self.etc_dir)
    }
    /// `securetty(5)` list.
    pub fn securetty_file(&self) -> String {
        format!("{}/securetty", self.etc_dir)
    }
    /// `nologin` flag file.
    pub fn nologin_file(&self) -> String {
        format!("{}/nologin", self.etc_dir)
    }
    /// Message of the day.
    pub fn motd_file(&self) -> String {
        format!("{}/motd", self.etc_dir)
    }
    /// Pre-login banner.
    pub fn issue_file(&self) -> String {
        format!("{}/issue", self.etc_dir)
    }
    /// Global `environment` file.
    pub fn environment_file(&self) -> String {
        format!("{}/environment", self.etc_dir)
    }
    /// Skeleton home directory.
    pub fn skel_dir(&self) -> String {
        format!("{}/skel", self.etc_dir)
    }
    /// `pam_env.conf`.
    pub fn pam_env_conf(&self) -> String {
        format!("{}/security/pam_env.conf", self.etc_dir)
    }
    /// `limits.conf`.
    pub fn limits_conf(&self) -> String {
        format!("{}/security/limits.conf", self.etc_dir)
    }
    /// `access.conf`.
    pub fn access_conf(&self) -> String {
        format!("{}/security/access.conf", self.etc_dir)
    }
    /// `namespace.conf`.
    pub fn namespace_conf(&self) -> String {
        format!("{}/security/namespace.conf", self.etc_dir)
    }
    /// `pam-faillock` per-user tally directory.
    pub fn faillock_dir(&self) -> String {
        format!("{}/faillock", self.var_dir)
    }
    /// `pam-tally2` tally directory (kept separate from faillock's).
    pub fn tallylog_dir(&self) -> String {
        format!("{}/tallylog", self.var_dir)
    }
    /// Grace-period auth timestamp cache directory (`pam-timestamp`).
    pub fn timestamp_dir(&self) -> String {
        format!("{}/ts", self.var_dir)
    }
}

/// Shortcut for `PathsConfig::get()`.
pub fn get() -> &'static PathsConfig {
    PathsConfig::get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conventional_linux_paths() {
        let c = PathsConfig::default();
        assert_eq!(c.conf_dir, "/etc/elevate-pam");
        assert_eq!(c.module_dir, "/lib/security");
        assert_eq!(c.shadow_file(), "/etc/shadow");
        assert_eq!(c.timestamp_dir(), "/var/run/elevate/ts");
    }

    #[test]
    fn prefix_cascades_to_derived_paths() {
        let c = PathsConfig::from_toml("[paths]\nprefix = \"/opt/pam/\"\n").unwrap();
        assert_eq!(c.prefix, "/opt/pam");
        assert_eq!(c.conf_dir, "/opt/pam/etc/elevate-pam");
        assert_eq!(c.module_dir, "/opt/pam/lib/security");
        assert_eq!(c.shadow_file(), "/opt/pam/etc/shadow");
        assert_eq!(c.faillock_dir(), "/opt/pam/var/run/elevate/faillock");
    }

    #[test]
    fn explicit_keys_override_prefix() {
        let c = PathsConfig::from_toml(
            "[paths]\nprefix = \"/opt/pam\"\netc_dir = \"/etc\"\nmodule_dir = \"/lib64/security\"\n",
        )
        .unwrap();
        assert_eq!(c.passwd_file(), "/etc/passwd");
        assert_eq!(c.conf_dir, "/etc/elevate-pam");
        assert_eq!(c.module_dir, "/lib64/security");
    }
}
