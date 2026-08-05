//! TOML-only configuration for elevate-pam.
//!
//! JSON is **not** supported. Service stacks, build categories, and global
//! options are all declared in `.toml` files.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::{PamError, PamResult};
use crate::types::{Action, StackKind};
use crate::constants::{
    PAM_ABORT, PAM_ACCT_EXPIRED, PAM_AUTHINFO_UNAVAIL, PAM_AUTHTOK_DISABLE_AGING,
    PAM_AUTHTOK_ERR, PAM_AUTHTOK_EXPIRED, PAM_AUTHTOK_LOCK_BUSY, PAM_AUTHTOK_RECOVERY_ERR,
    PAM_AUTH_ERR, PAM_BAD_ITEM, PAM_BUF_ERR, PAM_CONV_AGAIN, PAM_CONV_ERR, PAM_CRED_ERR,
    PAM_CRED_EXPIRED, PAM_CRED_INSUFFICIENT, PAM_CRED_UNAVAIL, PAM_IGNORE, PAM_INCOMPLETE,
    PAM_MAXTRIES, PAM_MODULE_UNKNOWN, PAM_NEW_AUTHTOK_REQD, PAM_NO_MODULE_DATA, PAM_OPEN_ERR,
    PAM_PERM_DENIED, PAM_SERVICE_ERR, PAM_SESSION_ERR, PAM_SUCCESS, PAM_SYMBOL_ERR,
    PAM_SYSTEM_ERR, PAM_TRY_AGAIN, PAM_USER_UNKNOWN, PAM_RETURN_VALUES,
};

/// Build / linkage category for elevate-pam artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BuildCategory {
    /// Dynamic shared library + dlopen modules.
    #[default]
    Shared,
    /// Static archive with modules linked in.
    Static,
    /// Standalone binary / fully embedded registry.
    Standalone,
}

/// Build section from `elevate-pam.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    /// Produce / use shared library mode.
    #[serde(default = "default_true")]
    pub shared: bool,
    /// Produce / use static library mode.
    #[serde(default, rename = "static")]
    pub static_: bool,
    /// Produce / use standalone mode.
    #[serde(default)]
    pub standalone: bool,
}

fn default_true() -> bool {
    true
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            shared: true,
            static_: false,
            standalone: false,
        }
    }
}

impl BuildConfig {
    /// Resolve the primary build category from booleans.
    ///
    /// Priority: `standalone` > `static` > `shared` (if multiple true).
    pub fn primary_category(&self) -> BuildCategory {
        if self.standalone {
            BuildCategory::Standalone
        } else if self.static_ {
            BuildCategory::Static
        } else {
            BuildCategory::Shared
        }
    }
}

// Serde field rename for `static` reserved keyword
mod build_config_serde {
    // handled via #[serde(rename = "static")] on a wrapper if needed
}

impl BuildConfig {
    /// Parse from TOML string, accepting field name `static`.
    pub fn from_toml_value(v: &toml::Value) -> Self {
        let table = v.as_table();
        let get_bool = |k: &str| {
            table
                .and_then(|t| t.get(k))
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
        };
        let shared = table
            .and_then(|t| t.get("shared"))
            .and_then(|x| x.as_bool())
            .unwrap_or(true);
        Self {
            shared,
            static_: get_bool("static"),
            standalone: get_bool("standalone"),
        }
    }
}

/// Path configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    /// Base conf directory.
    #[serde(default = "default_conf_dir")]
    pub conf_dir: String,
    /// Service stack directory.
    #[serde(default = "default_services_dir")]
    pub services_dir: String,
    /// Drop-in service directory.
    #[serde(default = "default_services_dropin")]
    pub services_dropin_dir: String,
    /// Shared module directory.
    #[serde(default = "default_module_dir")]
    pub module_dir: String,
    /// Vendor services directory.
    #[serde(default = "default_vendor_dir")]
    pub vendor_dir: String,
    /// Default / fallback service name.
    #[serde(default = "default_service_name")]
    pub default_service: String,
}

#[cfg(feature = "std")]
fn default_conf_dir() -> String {
    elevate_paths::get().conf_dir.clone()
}
#[cfg(not(feature = "std"))]
fn default_conf_dir() -> String {
    "/overlayer/syshub/etc/elevate-pam".into()
}
fn default_services_dir() -> String {
    format!("{}/services", default_conf_dir())
}
fn default_services_dropin() -> String {
    format!("{}/services.d", default_conf_dir())
}
#[cfg(feature = "std")]
fn default_module_dir() -> String {
    elevate_paths::get().module_dir.clone()
}
#[cfg(not(feature = "std"))]
fn default_module_dir() -> String {
    "/overlayer/syshub/lib/security".into()
}
#[cfg(feature = "std")]
fn default_vendor_dir() -> String {
    elevate_paths::get().vendor_dir.clone()
}
#[cfg(not(feature = "std"))]
fn default_vendor_dir() -> String {
    "/overlayer/syshub/lib/elevate-pam/services".into()
}
fn default_service_name() -> String {
    "other".into()
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            conf_dir: default_conf_dir(),
            services_dir: default_services_dir(),
            services_dropin_dir: default_services_dropin(),
            module_dir: default_module_dir(),
            vendor_dir: default_vendor_dir(),
            default_service: default_service_name(),
        }
    }
}

/// Security-related knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Fail delay in microseconds.
    #[serde(default = "default_fail_delay")]
    pub fail_delay_usec: u32,
    /// Zeroize auth tokens on end.
    #[serde(default = "default_true")]
    pub zeroize_authtok: bool,
    /// Reject service names with path separators.
    #[serde(default = "default_true")]
    pub reject_service_paths: bool,
    /// Max include depth.
    #[serde(default = "default_max_include")]
    pub max_include_depth: u32,
    /// Max substack level.
    #[serde(default = "default_max_substack")]
    pub max_substack_level: u32,
    /// Max modules per stack.
    #[serde(default = "default_max_stack")]
    pub max_stack_modules: u32,
}

fn default_fail_delay() -> u32 {
    2_000_000
}
fn default_max_include() -> u32 {
    32
}
fn default_max_substack() -> u32 {
    16
}
fn default_max_stack() -> u32 {
    64
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            fail_delay_usec: default_fail_delay(),
            zeroize_authtok: true,
            reject_service_paths: true,
            max_include_depth: default_max_include(),
            max_substack_level: default_max_substack(),
            max_stack_modules: default_max_stack(),
        }
    }
}

/// Feature toggles from TOML (runtime view of Cargo features).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    /// OS integration (`std`).
    #[serde(default = "default_true")]
    pub std: bool,
    /// Heap allocation support.
    #[serde(default = "default_true")]
    pub alloc: bool,
    /// Dynamic module loading.
    #[serde(default = "default_true")]
    pub dynload: bool,
    /// Syslog logging.
    #[serde(default = "default_true")]
    pub syslog: bool,
    /// Legacy `/etc/pam.d` bridge.
    #[serde(default = "default_true")]
    pub legacy_pamd: bool,
    /// Secure memory wiping.
    #[serde(default = "default_true")]
    pub secure_mem: bool,
    /// Fail-delay on auth failure.
    #[serde(default = "default_true")]
    pub fail_delay: bool,
    /// Built-in modules always available.
    #[serde(default = "default_true")]
    pub builtin_modules: bool,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            std: true,
            alloc: true,
            dynload: true,
            syslog: true,
            legacy_pamd: true,
            secure_mem: true,
            fail_delay: true,
            builtin_modules: true,
        }
    }
}

/// Top-level global configuration (`elevate-pam.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    /// Build categories.
    #[serde(default)]
    pub build: BuildConfig,
    /// Feature toggles.
    #[serde(default)]
    pub features: FeaturesConfig,
    /// Paths.
    #[serde(default)]
    pub paths: PathsConfig,
    /// Security.
    #[serde(default)]
    pub security: SecurityConfig,
}

impl GlobalConfig {
    /// Parse from TOML text.
    pub fn parse(text: &str) -> PamResult<Self> {
        // Custom parse for `static` keyword in [build]
        let value: toml::Value = toml::from_str(text).map_err(|e| {
            PamError::Config(alloc::format!("elevate-pam.toml parse error: {e}"))
        })?;
        let mut cfg: GlobalConfig = value.clone().try_into().map_err(|e| {
            PamError::Config(alloc::format!("elevate-pam.toml schema error: {e}"))
        })?;
        if let Some(build) = value.get("build") {
            cfg.build = BuildConfig::from_toml_value(build);
        }
        Ok(cfg)
    }

    /// Default embedded config (used when no file is found).
    pub fn embedded_default() -> Self {
        Self::default()
    }
}

/// Control flag for a module in a stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlFlag {
    /// Failure is fatal at end of stack; continue on fail.
    Required,
    /// Failure is immediate.
    Requisite,
    /// Success short-circuits stack if no prior required failure.
    Sufficient,
    /// Result only matters if no other module decided.
    Optional,
    /// Include another service file (inline).
    Include,
    /// Substack of another service.
    Substack,
}

impl ControlFlag {
    /// Parse from string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "required" => Some(Self::Required),
            "requisite" => Some(Self::Requisite),
            "sufficient" => Some(Self::Sufficient),
            "optional" => Some(Self::Optional),
            "include" => Some(Self::Include),
            "substack" => Some(Self::Substack),
            _ => None,
        }
    }

    /// Build the action table for this control flag (Linux-PAM semantics).
    pub fn actions(self) -> [Action; PAM_RETURN_VALUES] {
        let mut actions = [Action::Bad; PAM_RETURN_VALUES];
        match self {
            Self::Required => {
                actions[PAM_SUCCESS as usize] = Action::Ok;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Ok;
                actions[PAM_IGNORE as usize] = Action::Ignore;
            }
            Self::Requisite => {
                actions[PAM_SUCCESS as usize] = Action::Ok;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Ok;
                actions[PAM_IGNORE as usize] = Action::Ignore;
                // default remains Bad -> DIE mapped in dispatch for requisite
                for a in actions.iter_mut() {
                    if *a == Action::Bad {
                        *a = Action::Die;
                    }
                }
                actions[PAM_SUCCESS as usize] = Action::Ok;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Ok;
                actions[PAM_IGNORE as usize] = Action::Ignore;
            }
            Self::Optional => {
                actions[PAM_SUCCESS as usize] = Action::Ok;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Ok;
                for a in actions.iter_mut() {
                    if *a == Action::Bad {
                        *a = Action::Ignore;
                    }
                }
                actions[PAM_SUCCESS as usize] = Action::Ok;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Ok;
            }
            Self::Sufficient => {
                actions[PAM_SUCCESS as usize] = Action::Done;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Done;
                for a in actions.iter_mut() {
                    if *a == Action::Bad {
                        *a = Action::Ignore;
                    }
                }
                actions[PAM_SUCCESS as usize] = Action::Done;
                actions[PAM_NEW_AUTHTOK_REQD as usize] = Action::Done;
            }
            Self::Include | Self::Substack => {
                // not dispatched as a normal module
            }
        }
        actions
    }
}

/// One module entry in a service stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Control flag.
    pub control: ControlFlag,
    /// Module name (`unix`, `env`, `limits`) or path (`pam_unix.so`).
    pub module: String,
    /// Module arguments (key=value or flags).
    #[serde(default)]
    pub args: Vec<String>,
    /// If true, suppress module load errors (leading `-` in classic pam.d).
    #[serde(default)]
    pub optional_load: bool,
    /// Optional explicit action overrides as TOML table strings:
    /// `success = "ok"`, `default = "bad"`, etc. (advanced).
    #[serde(default)]
    pub actions: Option<toml::Table>,
}

impl ModuleEntry {
    /// Resolve action table (control flag defaults + optional overrides).
    pub fn resolved_actions(&self) -> [Action; PAM_RETURN_VALUES] {
        let mut actions = self.control.actions();
        if let Some(ref table) = self.actions {
            if let Some(default) = table.get("default").and_then(|v| v.as_str()) {
                if let Some(a) = parse_action(default) {
                    actions = [a; PAM_RETURN_VALUES];
                }
            }
            for (key, val) in table {
                if key == "default" {
                    continue;
                }
                if let Some(code) = return_code_from_name(key) {
                    if let Some(s) = val.as_str() {
                        if let Some(a) = parse_action(s) {
                            actions[code as usize] = a;
                        }
                    }
                }
            }
        }
        actions
    }
}

fn parse_action(s: &str) -> Option<Action> {
    let s = s.to_ascii_lowercase();
    match s.as_str() {
        "ignore" => Some(Action::Ignore),
        "ok" => Some(Action::Ok),
        "done" => Some(Action::Done),
        "bad" => Some(Action::Bad),
        "die" => Some(Action::Die),
        "reset" => Some(Action::Reset),
        _ => {
            if let Ok(n) = s.parse::<u16>() {
                Some(Action::Jump(n))
            } else {
                None
            }
        }
    }
}

fn return_code_from_name(name: &str) -> Option<i32> {
    match name.to_ascii_lowercase().as_str() {
        "success" => Some(PAM_SUCCESS),
        "open_err" => Some(PAM_OPEN_ERR),
        "symbol_err" => Some(PAM_SYMBOL_ERR),
        "service_err" => Some(PAM_SERVICE_ERR),
        "system_err" => Some(PAM_SYSTEM_ERR),
        "buf_err" => Some(PAM_BUF_ERR),
        "perm_denied" => Some(PAM_PERM_DENIED),
        "auth_err" => Some(PAM_AUTH_ERR),
        "cred_insufficient" => Some(PAM_CRED_INSUFFICIENT),
        "authinfo_unavail" => Some(PAM_AUTHINFO_UNAVAIL),
        "user_unknown" => Some(PAM_USER_UNKNOWN),
        "maxtries" => Some(PAM_MAXTRIES),
        "new_authtok_reqd" => Some(PAM_NEW_AUTHTOK_REQD),
        "acct_expired" => Some(PAM_ACCT_EXPIRED),
        "session_err" => Some(PAM_SESSION_ERR),
        "cred_unavail" => Some(PAM_CRED_UNAVAIL),
        "cred_expired" => Some(PAM_CRED_EXPIRED),
        "cred_err" => Some(PAM_CRED_ERR),
        "no_module_data" => Some(PAM_NO_MODULE_DATA),
        "conv_err" => Some(PAM_CONV_ERR),
        "authtok_err" => Some(PAM_AUTHTOK_ERR),
        "authtok_recovery_err" => Some(PAM_AUTHTOK_RECOVERY_ERR),
        "authtok_lock_busy" => Some(PAM_AUTHTOK_LOCK_BUSY),
        "authtok_disable_aging" => Some(PAM_AUTHTOK_DISABLE_AGING),
        "try_again" => Some(PAM_TRY_AGAIN),
        "ignore" => Some(PAM_IGNORE),
        "abort" => Some(PAM_ABORT),
        "authtok_expired" => Some(PAM_AUTHTOK_EXPIRED),
        "module_unknown" => Some(PAM_MODULE_UNKNOWN),
        "bad_item" => Some(PAM_BAD_ITEM),
        "conv_again" => Some(PAM_CONV_AGAIN),
        "incomplete" => Some(PAM_INCOMPLETE),
        "default" => None,
        _ => None,
    }
}

/// Stack type as used in service TOML (`auth`, `account`, `password`, `session`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StackType {
    /// Authentication.
    Auth,
    /// Account management.
    Account,
    /// Password change.
    Password,
    /// Session open/close (same module list; hooks differ).
    Session,
}

impl StackType {
    /// Map to primary dispatch kind for this stack type.
    pub fn primary_kind(self) -> StackKind {
        match self {
            Self::Auth => StackKind::Auth,
            Self::Account => StackKind::Account,
            Self::Password => StackKind::ChAuthTok,
            Self::Session => StackKind::OpenSession,
        }
    }
}

/// Service configuration: one TOML file per service (e.g. `elevate.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    /// Optional metadata.
    #[serde(default)]
    pub service: ServiceMeta,
    /// Auth stack.
    #[serde(default)]
    pub auth: Vec<ModuleEntry>,
    /// Account stack.
    #[serde(default)]
    pub account: Vec<ModuleEntry>,
    /// Password stack.
    #[serde(default)]
    pub password: Vec<ModuleEntry>,
    /// Session stack.
    #[serde(default)]
    pub session: Vec<ModuleEntry>,
}

/// Optional service metadata block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceMeta {
    /// Service name override (defaults to file stem).
    pub name: Option<String>,
    /// Human description.
    pub description: Option<String>,
}

impl ServiceConfig {
    /// Parse service TOML.
    pub fn parse(text: &str) -> PamResult<Self> {
        toml::from_str(text).map_err(|e| {
            PamError::Config(alloc::format!("service.toml parse error: {e}"))
        })
    }

    /// Stack entries for a given kind.
    pub fn stack_for(&self, kind: StackKind) -> &[ModuleEntry] {
        match kind {
            StackKind::Auth | StackKind::SetCred => &self.auth,
            StackKind::Account => &self.account,
            StackKind::ChAuthTok => &self.password,
            StackKind::OpenSession | StackKind::CloseSession => &self.session,
        }
    }

    /// Validate stack sizes against security limits.
    pub fn validate(&self, security: &SecurityConfig) -> PamResult<()> {
        let max = security.max_stack_modules as usize;
        for (name, stack) in [
            ("auth", self.auth.len()),
            ("account", self.account.len()),
            ("password", self.password.len()),
            ("session", self.session.len()),
        ] {
            if stack > max {
                return Err(PamError::Config(alloc::format!(
                    "{name} stack has {stack} modules (max {max})"
                )));
            }
        }
        Ok(())
    }
}

/// Sanitize a service name (strip paths, lowercase) — Linux-PAM compatible.
pub fn sanitize_service_name(name: &str, reject_paths: bool) -> PamResult<String> {
    let base = if let Some(pos) = name.rfind('/') {
        if reject_paths && pos != 0 {
            // Linux-PAM uses the component after the last slash
        }
        &name[pos + 1..]
    } else {
        name
    };
    if base.is_empty() {
        return Err(PamError::InvalidArgument("empty service name".into()));
    }
    if base.contains("..") || base.contains('\0') {
        return Err(PamError::InvalidArgument(
            "illegal service name".into(),
        ));
    }
    Ok(base.to_ascii_lowercase())
}

#[cfg(feature = "std")]
mod std_io {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    impl GlobalConfig {
        /// Load from a filesystem path.
        pub fn load_path(path: impl AsRef<Path>) -> PamResult<Self> {
            let text = fs::read_to_string(path.as_ref()).map_err(|e| {
                PamError::Io(alloc::format!(
                    "read {}: {e}",
                    path.as_ref().display()
                ))
            })?;
            Self::parse(&text)
        }

        /// Load from default locations, or embedded defaults.
        pub fn load_default() -> Self {
            // Configured prefix first (elevate_privilege.toml's [paths]
            // table, e.g. /overlayer/syshub/etc/elevate-pam on Zainium),
            // then classic FHS /etc as a portability fallback for other
            // distros, then CWD for dev trees.
            let configured = format!("{}/elevate-pam.toml", default_conf_dir());
            let candidates = [
                configured.as_str(),
                "/etc/elevate-pam/elevate-pam.toml",
                "/etc/elevate-pam.toml",
                "elevate-pam.toml",
            ];
            for c in candidates {
                if let Ok(cfg) = Self::load_path(c) {
                    return cfg;
                }
            }
            Self::embedded_default()
        }
    }

    impl ServiceConfig {
        /// Load service by name using path layout from global config.
        pub fn load_service(global: &GlobalConfig, service: &str) -> PamResult<Self> {
            let name = sanitize_service_name(service, global.security.reject_service_paths)?;
            let mut candidates: Vec<PathBuf> = Vec::new();
            candidates.push(
                PathBuf::from(&global.paths.services_dir).join(format!("{name}.toml")),
            );
            candidates.push(
                PathBuf::from(&global.paths.vendor_dir).join(format!("{name}.toml")),
            );
            // also allow conf_dir/services/
            candidates.push(
                PathBuf::from(&global.paths.conf_dir)
                    .join("services")
                    .join(format!("{name}.toml")),
            );

            for path in &candidates {
                if path.is_file() {
                    let text = fs::read_to_string(path).map_err(|e| {
                        PamError::Io(alloc::format!("read {}: {e}", path.display()))
                    })?;
                    let cfg = Self::parse(&text)?;
                    cfg.validate(&global.security)?;
                    return Ok(cfg);
                }
            }

            // Fallback: other.toml
            if name != global.paths.default_service {
                return Self::load_service(global, &global.paths.default_service);
            }

            Err(PamError::Config(alloc::format!(
                "no TOML service config for '{name}' (looked in {} and {})",
                global.paths.services_dir,
                global.paths.vendor_dir
            )))
        }
    }
}

#[cfg(feature = "std")]
#[allow(unused_imports)]
pub use std_io::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_build_and_service() {
        let g = GlobalConfig::parse(
            r#"
[build]
shared = true
static = false
standalone = false

[security]
fail_delay_usec = 1000
"#,
        )
        .unwrap();
        assert!(g.build.shared);
        assert!(!g.build.static_);
        assert_eq!(g.build.primary_category(), BuildCategory::Shared);
        assert_eq!(g.security.fail_delay_usec, 1000);

        let s = ServiceConfig::parse(
            r#"
[service]
name = "elevate"
description = "elevate sudo replacement"

[[auth]]
control = "required"
module = "env"
args = ["readenv=1"]

[[auth]]
control = "required"
module = "unix"

[[account]]
control = "required"
module = "unix"

[[session]]
control = "required"
module = "limits"

[[session]]
control = "required"
module = "unix"
"#,
        )
        .unwrap();
        assert_eq!(s.auth.len(), 2);
        assert_eq!(s.auth[1].module, "unix");
        assert_eq!(s.session.len(), 2);
    }

    #[test]
    fn control_actions_sufficient() {
        let a = ControlFlag::Sufficient.actions();
        assert_eq!(a[PAM_SUCCESS as usize], Action::Done);
        assert_eq!(a[PAM_AUTH_ERR as usize], Action::Ignore);
    }
}
