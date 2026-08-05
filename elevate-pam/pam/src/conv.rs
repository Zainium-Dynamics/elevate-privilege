//! Conversation helpers.

use alloc::string::String;
use alloc::vec::Vec;

use crate::constants::{PAM_CONV_ERR, PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_SUCCESS};
use crate::error::{PamError, PamResult, PamStatus};
use crate::types::{Message, MsgStyle, Response};

/// Trait for Rust-side conversation functions.
pub trait Converser: Send {
    /// Prompt the user with messages; return one response per message that expects input.
    fn converse(&mut self, messages: &[Message]) -> PamResult<Vec<Response>>;
}

/// No-op converser (always fails prompts).
#[derive(Debug, Default)]
pub struct NullConverser;

impl Converser for NullConverser {
    fn converse(&mut self, _messages: &[Message]) -> PamResult<Vec<Response>> {
        Err(PamError::Status(PamStatus::new(PAM_CONV_ERR)))
    }
}

/// Simple in-memory converser for tests (fixed password / username).
#[derive(Debug, Clone)]
pub struct FixedConverser {
    /// Password to return for echo-off prompts.
    pub password: String,
    /// Text for echo-on prompts.
    pub username: String,
}

impl Converser for FixedConverser {
    fn converse(&mut self, messages: &[Message]) -> PamResult<Vec<Response>> {
        let mut out = Vec::with_capacity(messages.len());
        for m in messages {
            let text = match m.style {
                MsgStyle::PromptEchoOff => self.password.clone(),
                MsgStyle::PromptEchoOn => self.username.clone(),
                _ => String::new(),
            };
            out.push(Response { text, retcode: 0 });
        }
        Ok(out)
    }
}

/// C `struct pam_message` (defined here so `conv` does not depend on `ffi`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CPamMessage {
    /// Message style.
    pub msg_style: i32,
    /// NUL-terminated message.
    pub msg: *const core::ffi::c_char,
}

/// C `struct pam_response`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CPamResponse {
    /// Response string.
    pub resp: *mut core::ffi::c_char,
    /// Unused.
    pub resp_retcode: i32,
}

/// C conversation function type (Linux-PAM ABI).
pub type PamConvFn = unsafe extern "C" fn(
    num_msg: i32,
    msg: *mut *const CPamMessage,
    resp: *mut *mut CPamResponse,
    appdata_ptr: *mut core::ffi::c_void,
) -> i32;

/// C `struct pam_conv` mirror.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PamConv {
    /// Function pointer.
    pub conv: Option<PamConvFn>,
    /// Application data.
    pub appdata_ptr: *mut core::ffi::c_void,
}

// SAFETY: pam_conv is a C struct of raw pointers; Send is needed for storage.
unsafe impl Send for PamConv {}

impl Default for PamConv {
    fn default() -> Self {
        Self {
            conv: None,
            appdata_ptr: core::ptr::null_mut(),
        }
    }
}

/// Call a C conversation function with one echo-off prompt.
#[cfg(feature = "std")]
pub fn conv_echo_off(conv: &PamConv, prompt: &str) -> PamResult<String> {
    use std::ffi::{CStr, CString};

    let f = conv
        .conv
        .ok_or_else(|| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
    let c_prompt = CString::new(prompt)
        .map_err(|_| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
    let message = CPamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: c_prompt.as_ptr(),
    };
    let mut msg_ptr: *const CPamMessage = &message;
    let mut resp_ptr: *mut CPamResponse = core::ptr::null_mut();

    // SAFETY: C conversation ABI
    let rc = unsafe {
        f(
            1,
            &mut msg_ptr as *mut *const CPamMessage,
            &mut resp_ptr,
            conv.appdata_ptr,
        )
    };
    if rc != PAM_SUCCESS {
        return Err(PamError::Status(PamStatus::new(if rc == 0 {
            PAM_CONV_ERR
        } else {
            rc
        })));
    }
    if resp_ptr.is_null() {
        return Err(PamError::Status(PamStatus::new(PAM_CONV_ERR)));
    }

    // SAFETY: response allocated by application per PAM contract
    let resp = unsafe { &*resp_ptr };
    let result = if resp.resp.is_null() {
        String::new()
    } else {
        // SAFETY: NUL-terminated C string
        let s = unsafe { CStr::from_ptr(resp.resp) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            libc::free(resp.resp as *mut libc::c_void);
        }
        s
    };
    unsafe {
        libc::free(resp_ptr as *mut libc::c_void);
    }
    Ok(result)
}

/// Call C conversation with echo-on prompt.
#[cfg(feature = "std")]
pub fn conv_echo_on(conv: &PamConv, prompt: &str) -> PamResult<String> {
    use std::ffi::{CStr, CString};

    let f = conv
        .conv
        .ok_or_else(|| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
    let c_prompt = CString::new(prompt)
        .map_err(|_| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
    let message = CPamMessage {
        msg_style: PAM_PROMPT_ECHO_ON,
        msg: c_prompt.as_ptr(),
    };
    let mut msg_ptr: *const CPamMessage = &message;
    let mut resp_ptr: *mut CPamResponse = core::ptr::null_mut();

    let rc = unsafe {
        f(
            1,
            &mut msg_ptr as *mut *const CPamMessage,
            &mut resp_ptr,
            conv.appdata_ptr,
        )
    };
    if rc != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PamError::Status(PamStatus::new(PAM_CONV_ERR)));
    }
    let resp = unsafe { &*resp_ptr };
    let result = if resp.resp.is_null() {
        String::new()
    } else {
        let s = unsafe { CStr::from_ptr(resp.resp) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            libc::free(resp.resp as *mut libc::c_void);
        }
        s
    };
    unsafe {
        libc::free(resp_ptr as *mut libc::c_void);
    }
    Ok(result)
}
