//! Single source of truth for install/runtime paths across the elevate
//! monorepo, driven by `elevate_privilege.toml`'s `[paths]` table.
//!
//! Resolution order (first match wins):
//! 1. `ELEVATE_PRIVILEGE_TOML` env var — explicit path to a config file.
//! 2. `SYSHUB_PREFIX` / `SYSHUB_ETC` env vars — override just the prefix /
//!    conf dir (kept for backward compatibility with the pre-existing
//!    per-crate convention).
//! 3. `elevate_privilege.toml` found on disk at one of a few well-known
//!    locations.
//! 4. Compiled-in defaults matching the historical hardcoded values, so
//!    behavior is unchanged when no config file is present.
//!
//! Every field not explicitly set in the toml is derived from the
//! *resolved* `prefix` (not a fixed literal), so overriding just `prefix`
//! correctly cascades to `bindir`, `libdir`, etc.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct PathsConfig {
    pub prefix: String,
    pub bindir: String,
    pub sbindir: String,
    pub libdir: String,
    pub var_dir: String,
    pub includedir: String,
    pub conf_dir: String,
    pub services_dir: String,
    pub services_dropin_dir: String,
    pub module_dir: String,
    pub vendor_dir: String,
    pub elevators_dir: String,
    pub elevators_file: String,
}

fn syshub_prefix_env() -> Option<String> {
    std::env::var("SYSHUB_PREFIX").ok()
}
fn syshub_etc_env() -> Option<String> {
    std::env::var("SYSHUB_ETC").ok()
}

fn default_prefix() -> String {
    syshub_prefix_env().unwrap_or_else(|| "/overlayer/syshub".into())
}

#[derive(Debug, Default, Deserialize)]
struct RawPathsConfig {
    prefix: Option<String>,
    bindir: Option<String>,
    sbindir: Option<String>,
    libdir: Option<String>,
    var_dir: Option<String>,
    includedir: Option<String>,
    conf_dir: Option<String>,
    services_dir: Option<String>,
    services_dropin_dir: Option<String>,
    module_dir: Option<String>,
    vendor_dir: Option<String>,
    elevators_dir: Option<String>,
    elevators_file: Option<String>,
}

impl From<RawPathsConfig> for PathsConfig {
    /// Resolves every omitted field from the already-resolved `prefix` /
    /// `conf_dir` / `elevators_dir`, so a lone `prefix` override cascades
    /// correctly instead of leaving siblings pointed at the old default.
    fn from(raw: RawPathsConfig) -> Self {
        let prefix = raw.prefix.unwrap_or_else(default_prefix);
        let conf_dir = raw
            .conf_dir
            .or_else(syshub_etc_env)
            .unwrap_or_else(|| format!("{prefix}/etc/elevate-pam"));
        let elevators_dir = raw
            .elevators_dir
            .unwrap_or_else(|| format!("{prefix}/etc/elevators"));

        Self {
            bindir: raw.bindir.unwrap_or_else(|| format!("{prefix}/bin")),
            sbindir: raw.sbindir.unwrap_or_else(|| format!("{prefix}/bin")),
            libdir: raw.libdir.unwrap_or_else(|| format!("{prefix}/lib")),
            var_dir: raw
                .var_dir
                .unwrap_or_else(|| format!("{prefix}/var/run/elevate")),
            includedir: raw
                .includedir
                .unwrap_or_else(|| format!("{prefix}/include")),
            services_dir: raw
                .services_dir
                .unwrap_or_else(|| format!("{conf_dir}/services")),
            services_dropin_dir: raw
                .services_dropin_dir
                .unwrap_or_else(|| format!("{conf_dir}/services.d")),
            module_dir: raw
                .module_dir
                .unwrap_or_else(|| format!("{prefix}/lib/security")),
            vendor_dir: raw
                .vendor_dir
                .unwrap_or_else(|| format!("{prefix}/lib/elevate-pam/services")),
            elevators_file: raw
                .elevators_file
                .unwrap_or_else(|| format!("{elevators_dir}/elevate.toml")),
            elevators_dir,
            conf_dir,
            prefix,
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        RawPathsConfig::default().into()
    }
}

impl PathsConfig {
    /// Well-known locations to search for `elevate_privilege.toml`, in order.
    fn candidates() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(explicit) = std::env::var("ELEVATE_PRIVILEGE_TOML") {
            out.push(PathBuf::from(explicit));
        }
        out.push(PathBuf::from("/etc/elevate_privilege.toml"));
        out.push(PathBuf::from(format!(
            "{}/etc/elevate_privilege.toml",
            default_prefix()
        )));
        // Dev tree fallback (running from a repo checkout).
        out.push(PathBuf::from("elevate_privilege.toml"));
        out
    }

    fn load_path(path: impl AsRef<Path>) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        let top: TopLevel = toml::from_str(&text).ok()?;
        Some(top.paths.unwrap_or_default().into())
    }

    /// Load from the first matching well-known location, or compiled-in
    /// defaults if none are found.
    pub fn load() -> Self {
        for candidate in Self::candidates() {
            if let Some(cfg) = Self::load_path(&candidate) {
                return cfg;
            }
        }
        Self::default()
    }

    /// Process-wide cached config (loaded once on first access).
    pub fn get() -> &'static Self {
        static CACHE: OnceLock<PathsConfig> = OnceLock::new();
        CACHE.get_or_init(Self::load)
    }

    // --- derived paths (not separate toml keys — relative to `etc_dir()`,
    // so the `SYSHUB_ETC` env-var override cascades to all of them, matching
    // the historical per-crate convention) ---

    /// Base `/etc`-equivalent directory. Honors `SYSHUB_ETC` directly (kept
    /// for backward compatibility), else `<prefix>/etc`.
    pub fn etc_dir(&self) -> String {
        syshub_etc_env().unwrap_or_else(|| format!("{}/etc", self.prefix))
    }
    pub fn shadow_file(&self) -> String {
        format!("{}/shadow", self.etc_dir())
    }
    pub fn passwd_file(&self) -> String {
        format!("{}/passwd", self.etc_dir())
    }
    pub fn shells_file(&self) -> String {
        format!("{}/shells", self.etc_dir())
    }
    pub fn login_defs_file(&self) -> String {
        format!("{}/login.defs", self.etc_dir())
    }
    pub fn securetty_file(&self) -> String {
        format!("{}/securetty", self.etc_dir())
    }
    pub fn nologin_file(&self) -> String {
        format!("{}/nologin", self.etc_dir())
    }
    pub fn motd_file(&self) -> String {
        format!("{}/motd", self.etc_dir())
    }
    pub fn issue_file(&self) -> String {
        format!("{}/issue", self.etc_dir())
    }
    pub fn pam_env_conf(&self) -> String {
        format!("{}/security/pam_env.conf", self.etc_dir())
    }
    pub fn limits_conf(&self) -> String {
        format!("{}/security/limits.conf", self.etc_dir())
    }
    /// `pam-access` config (`access.conf(5)`).
    pub fn access_conf(&self) -> String {
        format!("{}/security/access.conf", self.etc_dir())
    }
    /// `pam-faillock` per-user tally directory.
    pub fn faillock_dir(&self) -> String {
        format!("{}/faillock", self.var_dir.trim_end_matches('/'))
    }
    pub fn skel_dir(&self) -> String {
        format!("{}/skel", self.etc_dir())
    }
    pub fn environment_file(&self) -> String {
        format!("{}/environment", self.etc_dir())
    }
    /// Zoneinfo search directories, in priority order.
    pub fn zoneinfo_dirs(&self) -> [String; 2] {
        [
            format!("{}/zoneinfo", self.etc_dir()),
            format!("{}/lib/zoneinfo", self.prefix),
        ]
    }
    /// Grace-period auth timestamp cache directory (`pam-timestamp`).
    pub fn timestamp_dir(&self) -> String {
        format!("{}/ts", self.var_dir.trim_end_matches('/'))
    }

    /// Immutable OS core layers the Zero-Trust Core Protector refuses to let
    /// destructive commands touch: the overlay root (`prefix`'s parent),
    /// `prefix` itself, and the sibling `zaisys` layer under that same root.
    pub fn protected_layers(&self) -> Vec<String> {
        let prefix = self.prefix.trim_end_matches('/');
        let overlay_root = match prefix.rfind('/') {
            Some(0) | None => prefix.to_string(),
            Some(pos) => prefix[..pos].to_string(),
        };
        vec![
            overlay_root.clone(),
            prefix.to_string(),
            format!("{overlay_root}/zaisys"),
        ]
    }
}

#[derive(Debug, Default, Deserialize)]
struct TopLevel {
    #[serde(default)]
    paths: Option<RawPathsConfig>,
}

/// Shortcut for `PathsConfig::get()`.
pub fn get() -> &'static PathsConfig {
    PathsConfig::get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_historical_hardcoded_values() {
        // SAFETY: single-threaded test, no concurrent env mutation.
        unsafe {
            std::env::remove_var("SYSHUB_PREFIX");
            std::env::remove_var("SYSHUB_ETC");
        }
        let cfg = PathsConfig::default();
        assert_eq!(cfg.prefix, "/overlayer/syshub");
        assert_eq!(cfg.bindir, "/overlayer/syshub/bin");
        assert_eq!(cfg.module_dir, "/overlayer/syshub/lib/security");
        assert_eq!(
            cfg.elevators_file,
            "/overlayer/syshub/etc/elevators/elevate.toml"
        );
        assert_eq!(cfg.shadow_file(), "/overlayer/syshub/etc/shadow");
        assert_eq!(cfg.timestamp_dir(), "/overlayer/syshub/var/run/elevate/ts");
    }

    #[test]
    fn prefix_override_cascades_to_derived_fields() {
        let dir = std::env::temp_dir().join(format!(
            "elevate-paths-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("elevate_privilege.toml");
        std::fs::write(&toml_path, "[paths]\nprefix = \"/tmp/fake-prefix\"\n").unwrap();

        let cfg = PathsConfig::load_path(&toml_path).expect("config should parse");
        assert_eq!(cfg.prefix, "/tmp/fake-prefix");
        assert_eq!(cfg.bindir, "/tmp/fake-prefix/bin");
        assert_eq!(cfg.module_dir, "/tmp/fake-prefix/lib/security");
        assert_eq!(cfg.shadow_file(), "/tmp/fake-prefix/etc/shadow");

        std::fs::remove_dir_all(&dir).ok();
    }
}
