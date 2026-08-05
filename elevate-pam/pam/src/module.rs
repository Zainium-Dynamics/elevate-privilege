//! Module interface and static registry.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::constants::*;
use crate::error::{PamError, PamResult, PamStatus};
use crate::handle::PamHandle;
use crate::types::StackKind;

/// Module identifier (logical name without `pam_` prefix / `.so` suffix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleId(pub String);

impl ModuleId {
    /// Normalize names like `pam_unix.so`, `unix`, `pam_unix` → `unix`.
    pub fn normalize(name: &str) -> Self {
        let mut n = name.trim();
        if let Some(stripped) = n.strip_prefix("pam_") {
            n = stripped;
        }
        if let Some(stripped) = n.strip_suffix(".so") {
            n = stripped;
        }
        // basename if path
        if let Some(pos) = n.rfind('/') {
            n = &n[pos + 1..];
            if let Some(stripped) = n.strip_prefix("pam_") {
                n = stripped;
            }
            if let Some(stripped) = n.strip_suffix(".so") {
                n = stripped;
            }
        }
        Self(String::from(n))
    }

    /// Shared object file name: `pam_<id>.so`.
    pub fn so_name(&self) -> String {
        alloc::format!("pam_{}.so", self.0)
    }

    /// As string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signature of a PAM service module function.
pub type ModuleFn = fn(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus;

/// Hooks exported by a module.
#[derive(Clone, Default)]
pub struct ModuleHooks {
    /// Logical module id.
    pub id: ModuleId,
    /// Authentication.
    pub authenticate: Option<ModuleFn>,
    /// Set credentials.
    pub setcred: Option<ModuleFn>,
    /// Account management.
    pub acct_mgmt: Option<ModuleFn>,
    /// Open session.
    pub open_session: Option<ModuleFn>,
    /// Close session.
    pub close_session: Option<ModuleFn>,
    /// Change auth token.
    pub chauthtok: Option<ModuleFn>,
}

impl Default for ModuleId {
    fn default() -> Self {
        Self(String::from("unknown"))
    }
}

impl ModuleHooks {
    /// Dispatch by stack kind.
    pub fn call(
        &self,
        kind: StackKind,
        pamh: &mut PamHandle,
        flags: i32,
        args: &[String],
    ) -> PamStatus {
        let f = match kind {
            StackKind::Auth => self.authenticate,
            StackKind::SetCred => self.setcred,
            StackKind::Account => self.acct_mgmt,
            StackKind::OpenSession => self.open_session,
            StackKind::CloseSession => self.close_session,
            StackKind::ChAuthTok => self.chauthtok,
        };
        match f {
            Some(func) => func(pamh, flags, args),
            None => PamStatus::new(PAM_MODULE_UNKNOWN),
        }
    }
}

/// Global static module registry (used in static / standalone builds).
#[derive(Default)]
pub struct ModuleRegistry {
    modules: Vec<Arc<ModuleHooks>>,
}

impl ModuleRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Register a module.
    pub fn register(&mut self, hooks: ModuleHooks) {
        // replace if same id
        if let Some(pos) = self.modules.iter().position(|m| m.id == hooks.id) {
            self.modules[pos] = Arc::new(hooks);
        } else {
            self.modules.push(Arc::new(hooks));
        }
    }

    /// Lookup by normalized id.
    pub fn get(&self, id: &ModuleId) -> Option<Arc<ModuleHooks>> {
        self.modules.iter().find(|m| m.id == *id).cloned()
    }

    /// All modules.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<ModuleHooks>> {
        self.modules.iter()
    }
}

/// Thread-safe process-global registry for static modules.
#[cfg(feature = "std")]
pub mod global {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static REGISTRY: Lazy<Mutex<ModuleRegistry>> =
        Lazy::new(|| Mutex::new(ModuleRegistry::new()));

    /// Register into the process-global registry.
    pub fn register(hooks: ModuleHooks) {
        if let Ok(mut g) = REGISTRY.lock() {
            g.register(hooks);
        }
    }

    /// Lookup.
    pub fn get(id: &ModuleId) -> Option<Arc<ModuleHooks>> {
        REGISTRY.lock().ok().and_then(|g| g.get(id))
    }

    /// Install all builtin modules once.
    pub fn ensure_builtins() {
        static ONCE: once_cell::sync::OnceCell<()> = once_cell::sync::OnceCell::new();
        ONCE.get_or_init(|| {
            #[cfg(feature = "builtin_modules")]
            crate::builtin::register_all();
        });
    }
}

/// Resolve module hooks: static registry first, then dynload (if enabled).
#[cfg(feature = "std")]
pub fn resolve_module(
    module_name: &str,
    module_dir: &str,
    category: crate::config::BuildCategory,
) -> PamResult<Arc<ModuleHooks>> {
    let id = ModuleId::normalize(module_name);
    global::ensure_builtins();

    if let Some(h) = global::get(&id) {
        return Ok(h);
    }

    match category {
        crate::config::BuildCategory::Shared => {
            #[cfg(feature = "dynload")]
            {
                crate::loader::load_shared(&id, module_dir)
            }
            #[cfg(not(feature = "dynload"))]
            {
                let _ = module_dir;
                Err(PamError::Module(alloc::format!(
                    "module '{}' not in static registry and dynload disabled",
                    id.as_str()
                )))
            }
        }
        crate::config::BuildCategory::Static | crate::config::BuildCategory::Standalone => {
            Err(PamError::Module(alloc::format!(
                "module '{}' not linked into static/standalone build",
                id.as_str()
            )))
        }
    }
}

/// Helper: check if args contain a flag.
pub fn arg_has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Helper: get key=value from args.
pub fn arg_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let prefix = alloc::format!("{key}=");
    args.iter()
        .find_map(|a| a.strip_prefix(&prefix))
}
