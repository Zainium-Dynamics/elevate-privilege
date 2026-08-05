//! PAM handle — central session state.

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{GlobalConfig, ServiceConfig};
use crate::constants::*;
use crate::conv::PamConv;
use crate::data::DataTable;
use crate::env::PamEnv;
use crate::error::{PamError, PamResult, PamStatus};
use crate::securemem::SecretString;
use crate::types::{ItemType, StackKind};

/// Opaque-to-C application handle. Rust code uses this structure fully.
pub struct PamHandle {
    /// Service name (lowercase).
    pub(crate) service_name: String,
    /// Target user.
    pub(crate) user: Option<String>,
    /// TTY.
    pub(crate) tty: Option<String>,
    /// Remote host.
    pub(crate) rhost: Option<String>,
    /// Remote user.
    pub(crate) ruser: Option<String>,
    /// User prompt.
    pub(crate) user_prompt: Option<String>,
    /// X display.
    pub(crate) xdisplay: Option<String>,
    /// Auth token type label.
    pub(crate) authtok_type: Option<String>,
    /// Current auth token.
    pub(crate) authtok: Option<SecretString>,
    /// Old auth token.
    pub(crate) oldauthtok: Option<SecretString>,
    /// Conversation structure (C ABI).
    pub(crate) conv: PamConv,
    /// Environment.
    pub(crate) env: PamEnv,
    /// Module data.
    pub(crate) data: DataTable,
    /// Loaded service stack config.
    pub(crate) service: ServiceConfig,
    /// Global config snapshot.
    pub(crate) global: GlobalConfig,
    /// Optional confdir override (pam_start_confdir).
    #[allow(dead_code)]
    pub(crate) confdir: Option<String>,
    /// Accumulated fail delay (usec).
    pub(crate) fail_delay_usec: u32,
    /// Last status (for pam_end).
    pub(crate) last_status: i32,
    /// Cached return values per auth handler index (for setcred freeze).
    pub(crate) cached_auth_retvals: Vec<i32>,
    /// Whether caller is treated as application (vs module).
    #[allow(dead_code)]
    pub(crate) caller_is_app: bool,
    /// Currently executing module name (for logging).
    pub(crate) current_module: Option<String>,
}

impl PamHandle {
    /// Start a new PAM session (Rust API).
    pub fn start(
        service_name: &str,
        user: Option<&str>,
        conv: PamConv,
        confdir: Option<&str>,
        global: GlobalConfig,
    ) -> PamResult<Self> {
        let service_name = crate::config::sanitize_service_name(
            service_name,
            global.security.reject_service_paths,
        )?;

        let mut global = global;
        if let Some(dir) = confdir {
            global.paths.services_dir = String::from(dir);
            global.paths.conf_dir = String::from(dir);
        }

        #[cfg(feature = "std")]
        let service = {
            match ServiceConfig::load_service(&global, &service_name) {
                Ok(s) => s,
                Err(e) => {
                    // Try legacy pam.d if enabled
                    #[cfg(feature = "legacy_pamd")]
                    {
                        if global.features.legacy_pamd {
                            if let Ok(s) = crate::legacy_pamd::load_service(&service_name, confdir)
                            {
                                s
                            } else {
                                return Err(e);
                            }
                        } else {
                            return Err(e);
                        }
                    }
                    #[cfg(not(feature = "legacy_pamd"))]
                    {
                        return Err(e);
                    }
                }
            }
        };

        #[cfg(not(feature = "std"))]
        let service = ServiceConfig::default();

        Ok(Self {
            service_name,
            user: user.map(String::from),
            tty: None,
            rhost: None,
            ruser: None,
            user_prompt: Some(String::from("login: ")),
            xdisplay: None,
            authtok_type: None,
            authtok: None,
            oldauthtok: None,
            conv,
            env: PamEnv::new(),
            data: DataTable::new(),
            service,
            global,
            confdir: confdir.map(String::from),
            fail_delay_usec: 0,
            last_status: PAM_SUCCESS,
            cached_auth_retvals: Vec::new(),
            caller_is_app: true,
            current_module: None,
        })
    }

    /// Service name.
    pub fn service(&self) -> &str {
        &self.service_name
    }

    /// User, if set.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Conversation handle.
    pub fn conv(&self) -> &PamConv {
        &self.conv
    }

    /// Global config.
    pub fn global(&self) -> &GlobalConfig {
        &self.global
    }

    /// Service stack config.
    pub fn service_config(&self) -> &ServiceConfig {
        &self.service
    }

    /// Set string item.
    pub fn set_item_str(&mut self, item: ItemType, value: Option<&str>) -> PamResult<()> {
        match item {
            ItemType::Service => {
                if let Some(v) = value {
                    self.service_name = crate::config::sanitize_service_name(
                        v,
                        self.global.security.reject_service_paths,
                    )?;
                }
            }
            ItemType::User => self.user = value.map(String::from),
            ItemType::Tty => self.tty = value.map(String::from),
            ItemType::RHost => self.rhost = value.map(String::from),
            ItemType::RUser => self.ruser = value.map(String::from),
            ItemType::UserPrompt => self.user_prompt = value.map(String::from),
            ItemType::XDisplay => self.xdisplay = value.map(String::from),
            ItemType::AuthTokType => self.authtok_type = value.map(String::from),
            ItemType::AuthTok => {
                self.authtok = value.map(SecretString::from_str_slice);
            }
            ItemType::OldAuthTok => {
                self.oldauthtok = value.map(SecretString::from_str_slice);
            }
            ItemType::Conv | ItemType::FailDelay | ItemType::XAuthData => {
                return Err(PamError::Status(PamStatus::new(PAM_BAD_ITEM)));
            }
        }
        Ok(())
    }

    /// Get string item.
    pub fn get_item_str(&self, item: ItemType) -> Option<&str> {
        match item {
            ItemType::Service => Some(&self.service_name),
            ItemType::User => self.user.as_deref(),
            ItemType::Tty => self.tty.as_deref(),
            ItemType::RHost => self.rhost.as_deref(),
            ItemType::RUser => self.ruser.as_deref(),
            ItemType::UserPrompt => self.user_prompt.as_deref(),
            ItemType::XDisplay => self.xdisplay.as_deref(),
            ItemType::AuthTokType => self.authtok_type.as_deref(),
            ItemType::AuthTok => self.authtok.as_ref().map(|s| s.expose()),
            ItemType::OldAuthTok => self.oldauthtok.as_ref().map(|s| s.expose()),
            _ => None,
        }
    }

    /// Ensure user is set; if not, converse for it.
    pub fn get_user(&mut self, prompt: Option<&str>) -> PamResult<String> {
        if let Some(ref u) = self.user {
            if !u.is_empty() {
                return Ok(u.clone());
            }
        }
        let prompt = prompt.or(self.user_prompt.as_deref()).unwrap_or("login: ");
        #[cfg(feature = "std")]
        {
            let name = crate::conv::conv_echo_on(&self.conv, prompt)?;
            if name.is_empty() {
                return Err(PamError::Status(PamStatus::new(PAM_CONV_ERR)));
            }
            self.user = Some(name.clone());
            Ok(name)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = prompt;
            Err(PamError::Status(PamStatus::new(PAM_SYSTEM_ERR)))
        }
    }

    /// Prompt for auth token (password) if not already set.
    pub fn get_authtok(&mut self, prompt: Option<&str>) -> PamResult<String> {
        if let Some(ref t) = self.authtok {
            if !t.is_empty() {
                return Ok(String::from(t.expose()));
            }
        }
        let prompt = prompt.unwrap_or("Password: ");
        #[cfg(feature = "std")]
        {
            let tok = crate::conv::conv_echo_off(&self.conv, prompt)?;
            self.authtok = Some(SecretString::from_str_slice(&tok));
            Ok(tok)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = prompt;
            Err(PamError::Status(PamStatus::new(PAM_SYSTEM_ERR)))
        }
    }

    /// Put environment entry.
    pub fn putenv(&mut self, name_value: &str) -> PamResult<()> {
        self.env.putenv(name_value)
    }

    /// Get environment value.
    pub fn getenv(&self, name: &str) -> Option<&str> {
        self.env.getenv(name)
    }

    /// Authenticate via stack dispatch.
    pub fn authenticate(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::Auth)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Account management.
    pub fn acct_mgmt(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::Account)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Set credentials.
    pub fn setcred(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::SetCred)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Open session.
    pub fn open_session(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::OpenSession)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Close session.
    pub fn close_session(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::CloseSession)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Change authentication token.
    pub fn chauthtok(&mut self, flags: i32) -> PamResult<()> {
        let status = crate::dispatch::dispatch(self, flags, StackKind::ChAuthTok)?;
        self.last_status = status.code();
        if status.is_success() {
            Ok(())
        } else {
            Err(PamError::Status(status))
        }
    }

    /// Accumulate fail delay.
    pub fn fail_delay(&mut self, usec: u32) -> PamResult<()> {
        self.fail_delay_usec = self.fail_delay_usec.saturating_add(usec);
        Ok(())
    }

    /// End session; consumes handle.
    pub fn end(mut self, status: i32) -> PamResult<()> {
        self.last_status = status;
        self.data.clear_with_status(status);
        self.authtok = None;
        self.oldauthtok = None;
        Ok(())
    }
}

impl Drop for PamHandle {
    fn drop(&mut self) {
        let status = self.last_status | PAM_DATA_SILENT;
        self.data.clear_with_status(status);
        self.authtok = None;
        self.oldauthtok = None;
    }
}
