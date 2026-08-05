//! Linux-PAM compatible constants.
//!
//! Values match Linux-PAM 1.7.x (`security/_pam_types.h`) so elevate and other
//! ABI consumers remain binary-compatible.

/// Successful function return.
pub const PAM_SUCCESS: i32 = 0;
/// `dlopen()` failure when loading a service module.
pub const PAM_OPEN_ERR: i32 = 1;
/// Symbol not found.
pub const PAM_SYMBOL_ERR: i32 = 2;
/// Error in service module.
pub const PAM_SERVICE_ERR: i32 = 3;
/// System error.
pub const PAM_SYSTEM_ERR: i32 = 4;
/// Memory buffer error.
pub const PAM_BUF_ERR: i32 = 5;
/// Permission denied.
pub const PAM_PERM_DENIED: i32 = 6;
/// Authentication failure.
pub const PAM_AUTH_ERR: i32 = 7;
/// Insufficient credentials to access authentication data.
pub const PAM_CRED_INSUFFICIENT: i32 = 8;
/// Authentication information unavailable.
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
/// User not known to the authentication module.
pub const PAM_USER_UNKNOWN: i32 = 10;
/// Maximum number of tries reached.
pub const PAM_MAXTRIES: i32 = 11;
/// New authentication token required.
pub const PAM_NEW_AUTHTOK_REQD: i32 = 12;
/// User account has expired.
pub const PAM_ACCT_EXPIRED: i32 = 13;
/// Cannot make/remove session entry.
pub const PAM_SESSION_ERR: i32 = 14;
/// User credentials unavailable.
pub const PAM_CRED_UNAVAIL: i32 = 15;
/// User credentials expired.
pub const PAM_CRED_EXPIRED: i32 = 16;
/// Failure setting user credentials.
pub const PAM_CRED_ERR: i32 = 17;
/// No module-specific data present.
pub const PAM_NO_MODULE_DATA: i32 = 18;
/// Conversation error.
pub const PAM_CONV_ERR: i32 = 19;
/// Authentication token manipulation error.
pub const PAM_AUTHTOK_ERR: i32 = 20;
/// Authentication information cannot be recovered.
pub const PAM_AUTHTOK_RECOVERY_ERR: i32 = 21;
/// Authentication token lock busy.
pub const PAM_AUTHTOK_LOCK_BUSY: i32 = 22;
/// Authentication token aging disabled.
pub const PAM_AUTHTOK_DISABLE_AGING: i32 = 23;
/// Preliminary check by password service failed.
pub const PAM_TRY_AGAIN: i32 = 24;
/// Ignore underlying module.
pub const PAM_IGNORE: i32 = 25;
/// Critical error; abort.
pub const PAM_ABORT: i32 = 26;
/// User's authentication token has expired.
pub const PAM_AUTHTOK_EXPIRED: i32 = 27;
/// Module is not known.
pub const PAM_MODULE_UNKNOWN: i32 = 28;
/// Bad item passed to pam_*_item().
pub const PAM_BAD_ITEM: i32 = 29;
/// Conversation function is event-driven; data not available yet.
pub const PAM_CONV_AGAIN: i32 = 30;
/// Call again to complete authentication stack.
pub const PAM_INCOMPLETE: i32 = 31;

/// Number of defined return values.
pub const PAM_RETURN_VALUES: usize = 32;

// ---- Flags ----

/// Do not generate messages.
pub const PAM_SILENT: i32 = 0x8000;
/// Fail if the user has a null authentication token.
pub const PAM_DISALLOW_NULL_AUTHTOK: i32 = 0x0001;
/// Establish user credentials.
pub const PAM_ESTABLISH_CRED: i32 = 0x0002;
/// Delete user credentials.
pub const PAM_DELETE_CRED: i32 = 0x0004;
/// Reinitialize user credentials.
pub const PAM_REINITIALIZE_CRED: i32 = 0x0008;
/// Extend lifetime of user credentials.
pub const PAM_REFRESH_CRED: i32 = 0x0010;
/// Only change expired authentication tokens.
pub const PAM_CHANGE_EXPIRED_AUTHTOK: i32 = 0x0020;
/// Password service: preliminary checks only.
pub const PAM_PRELIM_CHECK: i32 = 0x4000;
/// Password service: update authentication tokens.
pub const PAM_UPDATE_AUTHTOK: i32 = 0x2000;
/// Suppress messages on data cleanup.
pub const PAM_DATA_SILENT: i32 = 0x4000_0000u32 as i32;
/// Replace a data item.
pub const PAM_DATA_REPLACE: i32 = 0x2000_0000;

// ---- Items ----

/// Service name.
pub const PAM_SERVICE: i32 = 1;
/// User name.
pub const PAM_USER: i32 = 2;
/// TTY name.
pub const PAM_TTY: i32 = 3;
/// Remote host name.
pub const PAM_RHOST: i32 = 4;
/// Conversation structure.
pub const PAM_CONV: i32 = 5;
/// Authentication token (password).
pub const PAM_AUTHTOK: i32 = 6;
/// Old authentication token.
pub const PAM_OLDAUTHTOK: i32 = 7;
/// Remote user name.
pub const PAM_RUSER: i32 = 8;
/// Prompt for getting a username.
pub const PAM_USER_PROMPT: i32 = 9;
/// Fail-delay callback.
pub const PAM_FAIL_DELAY: i32 = 10;
/// X display name.
pub const PAM_XDISPLAY: i32 = 11;
/// X server authentication data.
pub const PAM_XAUTHDATA: i32 = 12;
/// Type string for pam_get_authtok.
pub const PAM_AUTHTOK_TYPE: i32 = 13;

// ---- Message styles ----

/// Prompt, echo off (password).
pub const PAM_PROMPT_ECHO_OFF: i32 = 1;
/// Prompt, echo on.
pub const PAM_PROMPT_ECHO_ON: i32 = 2;
/// Error message.
pub const PAM_ERROR_MSG: i32 = 3;
/// Informational text.
pub const PAM_TEXT_INFO: i32 = 4;
/// Radio / multi-choice (Linux-PAM extension).
pub const PAM_RADIO_TYPE: i32 = 5;
/// Binary prompt (Linux-PAM extension).
pub const PAM_BINARY_PROMPT: i32 = 7;

/// Maximum number of messages in one conversation call.
pub const PAM_MAX_NUM_MSG: usize = 32;
/// Maximum message size.
pub const PAM_MAX_MSG_SIZE: usize = 512;
/// Maximum response size.
pub const PAM_MAX_RESP_SIZE: usize = 512;

/// Default service name used when no specific stack matches.
pub const PAM_DEFAULT_SERVICE: &str = "other";

/// Human-readable error strings indexed by PAM return code.
pub static PAM_ERROR_STRINGS: [&str; PAM_RETURN_VALUES] = [
    "Success",
    "Critical error - immediate abort",
    "Symbol not found",
    "Error in service module",
    "System error",
    "Memory buffer error",
    "Permission denied",
    "Authentication failure",
    "Can not access authentication data due to insufficient credentials",
    "Authentication service cannot retrieve authentication info",
    "User not known to the underlying authentication module",
    "Have exhausted maximum number of retries for service",
    "Authentication token is no longer valid; new one required",
    "User account has expired",
    "Cannot make/remove an entry for the specified session",
    "Authentication service cannot retrieve user credentials",
    "User credentials expired",
    "Failure setting user credentials",
    "No module specific data is present",
    "Conversation error",
    "Authentication token manipulation error",
    "Authentication information cannot be recovered",
    "Authentication token lock busy",
    "Authentication token aging disabled",
    "Preliminary check by password service",
    "Ignore underlying account module",
    "Critical error - immediate abort",
    "Authentication token has expired",
    "Module is unknown",
    "Bad item passed to pam_*_item()",
    "Conversation function is event driven and data is not available yet",
    "The application needs to call this function again",
];

/// Return a static error description for a PAM status code.
#[inline]
pub fn pam_strerror_static(errnum: i32) -> &'static str {
    if errnum >= 0 && (errnum as usize) < PAM_RETURN_VALUES {
        PAM_ERROR_STRINGS[errnum as usize]
    } else {
        "Unknown PAM error"
    }
}
