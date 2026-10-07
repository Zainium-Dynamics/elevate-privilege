//! High-level application helpers (Rust-first API).

use crate::config::GlobalConfig;
use crate::conv::PamConv;
use crate::error::PamResult;
use crate::handle::PamHandle;

/// Builder for a PAM transaction.
#[derive(Debug)]
pub struct PamBuilder {
    service: alloc::string::String,
    user: Option<alloc::string::String>,
    confdir: Option<alloc::string::String>,
    global: GlobalConfig,
}

impl PamBuilder {
    /// Start building for a service name.
    pub fn new(service: impl Into<alloc::string::String>) -> Self {
        Self {
            service: service.into(),
            user: None,
            confdir: None,
            global: GlobalConfig::load_default(),
        }
    }

    /// Set target user.
    pub fn user(mut self, user: impl Into<alloc::string::String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Override configuration directory.
    pub fn confdir(mut self, dir: impl Into<alloc::string::String>) -> Self {
        self.confdir = Some(dir.into());
        self
    }

    /// Use an explicit global config.
    pub fn global(mut self, cfg: GlobalConfig) -> Self {
        self.global = cfg;
        self
    }

    /// Finish with a conversation structure.
    pub fn start(self, conv: PamConv) -> PamResult<PamHandle> {
        PamHandle::start(
            &self.service,
            self.user.as_deref(),
            conv,
            self.confdir.as_deref(),
            self.global,
        )
    }
}
