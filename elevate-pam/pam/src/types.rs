//! Core PAM types (std / no_std friendly).

/// Message style for conversation prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MsgStyle {
    /// Prompt with echo off.
    PromptEchoOff = crate::constants::PAM_PROMPT_ECHO_OFF,
    /// Prompt with echo on.
    PromptEchoOn = crate::constants::PAM_PROMPT_ECHO_ON,
    /// Error message to display.
    ErrorMsg = crate::constants::PAM_ERROR_MSG,
    /// Informational text.
    TextInfo = crate::constants::PAM_TEXT_INFO,
    /// Radio / multi-choice (Linux-PAM).
    RadioType = crate::constants::PAM_RADIO_TYPE,
    /// Binary prompt (Linux-PAM).
    BinaryPrompt = crate::constants::PAM_BINARY_PROMPT,
}

impl MsgStyle {
    /// Parse from raw integer.
    pub fn from_raw(v: i32) -> Option<Self> {
        match v {
            crate::constants::PAM_PROMPT_ECHO_OFF => Some(Self::PromptEchoOff),
            crate::constants::PAM_PROMPT_ECHO_ON => Some(Self::PromptEchoOn),
            crate::constants::PAM_ERROR_MSG => Some(Self::ErrorMsg),
            crate::constants::PAM_TEXT_INFO => Some(Self::TextInfo),
            crate::constants::PAM_RADIO_TYPE => Some(Self::RadioType),
            crate::constants::PAM_BINARY_PROMPT => Some(Self::BinaryPrompt),
            _ => None,
        }
    }

    /// Raw integer for FFI.
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// A single conversation message (owned, Rust side).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Message {
    /// Message style.
    pub style: MsgStyle,
    /// Message text.
    pub text: alloc::string::String,
}

/// A conversation response (owned).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Default)]
pub struct Response {
    /// Response text (may be empty).
    pub text: alloc::string::String,
    /// Currently unused by Linux-PAM; kept for ABI parity.
    pub retcode: i32,
}

/// Which PAM stack is being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StackKind {
    /// Authentication (`pam_authenticate` / `pam_sm_authenticate`).
    Auth = 1,
    /// Credential management (`pam_setcred`).
    SetCred = 2,
    /// Account management (`pam_acct_mgmt`).
    Account = 3,
    /// Open session.
    OpenSession = 4,
    /// Close session.
    CloseSession = 5,
    /// Change authentication token.
    ChAuthTok = 6,
}

impl StackKind {
    /// Short name used in TOML tables (`auth`, `account`, …).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::SetCred => "setcred",
            Self::Account => "account",
            Self::OpenSession => "session_open",
            Self::CloseSession => "session_close",
            Self::ChAuthTok => "password",
        }
    }
}

/// Dispatch action after a module returns (Linux-PAM internal model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Ignore this result for the overall impression.
    Ignore,
    /// Treat as success contribution.
    Ok,
    /// Stack done successfully (sufficient).
    Done,
    /// Record failure; continue stack.
    Bad,
    /// Immediate failure (requisite).
    Die,
    /// Reset impression.
    Reset,
    /// Jump forward N modules (bracket control syntax).
    Jump(u16),
}

impl Action {
    /// Default action for an undefined return code mapping.
    pub const fn default_bad() -> Self {
        Self::Bad
    }
}

/// Item identifiers as a typed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ItemType {
    /// Service name.
    Service = crate::constants::PAM_SERVICE,
    /// User name.
    User = crate::constants::PAM_USER,
    /// TTY.
    Tty = crate::constants::PAM_TTY,
    /// Remote host.
    RHost = crate::constants::PAM_RHOST,
    /// Conversation pointer.
    Conv = crate::constants::PAM_CONV,
    /// Auth token.
    AuthTok = crate::constants::PAM_AUTHTOK,
    /// Old auth token.
    OldAuthTok = crate::constants::PAM_OLDAUTHTOK,
    /// Remote user.
    RUser = crate::constants::PAM_RUSER,
    /// User prompt.
    UserPrompt = crate::constants::PAM_USER_PROMPT,
    /// Fail delay fn.
    FailDelay = crate::constants::PAM_FAIL_DELAY,
    /// X display.
    XDisplay = crate::constants::PAM_XDISPLAY,
    /// X auth data.
    XAuthData = crate::constants::PAM_XAUTHDATA,
    /// Auth token type string.
    AuthTokType = crate::constants::PAM_AUTHTOK_TYPE,
}

impl ItemType {
    /// Parse from raw item id.
    pub fn from_raw(v: i32) -> Option<Self> {
        match v {
            crate::constants::PAM_SERVICE => Some(Self::Service),
            crate::constants::PAM_USER => Some(Self::User),
            crate::constants::PAM_TTY => Some(Self::Tty),
            crate::constants::PAM_RHOST => Some(Self::RHost),
            crate::constants::PAM_CONV => Some(Self::Conv),
            crate::constants::PAM_AUTHTOK => Some(Self::AuthTok),
            crate::constants::PAM_OLDAUTHTOK => Some(Self::OldAuthTok),
            crate::constants::PAM_RUSER => Some(Self::RUser),
            crate::constants::PAM_USER_PROMPT => Some(Self::UserPrompt),
            crate::constants::PAM_FAIL_DELAY => Some(Self::FailDelay),
            crate::constants::PAM_XDISPLAY => Some(Self::XDisplay),
            crate::constants::PAM_XAUTHDATA => Some(Self::XAuthData),
            crate::constants::PAM_AUTHTOK_TYPE => Some(Self::AuthTokType),
            _ => None,
        }
    }
}
