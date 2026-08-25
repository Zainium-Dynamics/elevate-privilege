//! Conversation helpers.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::constants::{PAM_BUF_ERR, PAM_ERROR_MSG, PAM_TEXT_INFO};
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
    let c_prompt =
        CString::new(prompt).map_err(|_| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
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
    let c_prompt =
        CString::new(prompt).map_err(|_| PamError::Status(PamStatus::new(PAM_CONV_ERR)))?;
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

/// Bridge a boxed [`Converser`] into a raw C [`PamConv`], for an
/// *application* (not a module) to hand to
/// [`crate::appl::PamBuilder::start`]. This is the missing piece that lets
/// an app implement the safe [`Converser`] trait instead of writing its own
/// `unsafe extern "C" fn` conversation callback by hand.
///
/// The converser is heap-allocated and ownership moves into the returned
/// `PamConv`'s `appdata_ptr`. Reclaim it with [`free_converser`] once the
/// PAM transaction (`PamHandle::end`) is done — forgetting to call it leaks
/// the converser, it does not corrupt anything, since the pointer is never
/// read again after that point.
#[cfg(feature = "std")]
pub fn pam_conv_from_converser(converser: alloc::boxed::Box<dyn Converser>) -> PamConv {
    let boxed_twice: alloc::boxed::Box<alloc::boxed::Box<dyn Converser>> =
        alloc::boxed::Box::new(converser);
    let appdata_ptr = alloc::boxed::Box::into_raw(boxed_twice) as *mut core::ffi::c_void;
    PamConv {
        conv: Some(converser_trampoline),
        appdata_ptr,
    }
}

/// Reclaim and drop a [`Converser`] previously moved into a `PamConv` by
/// [`pam_conv_from_converser`].
///
/// # Safety
/// `conv.appdata_ptr` must be a pointer produced by
/// [`pam_conv_from_converser`] on this same `conv`, and must not already
/// have been reclaimed by a prior call.
#[cfg(feature = "std")]
pub unsafe fn free_converser(conv: &PamConv) {
    if !conv.appdata_ptr.is_null() {
        drop(unsafe {
            alloc::boxed::Box::from_raw(conv.appdata_ptr as *mut alloc::boxed::Box<dyn Converser>)
        });
    }
}

/// The `PamConvFn` trampoline behind [`pam_conv_from_converser`]. Marshals
/// the C `pam_message` array into `&[Message]`, calls the boxed
/// [`Converser`], then marshals its `Vec<Response>` back into a
/// `libc::malloc`-allocated `pam_response` array — matching the allocator
/// [`conv_echo_off`]/[`conv_echo_on`] above use to free responses coming
/// the *other* direction (module calling an app's conv fn), so either side
/// of this crate frees with `libc::free` consistently.
#[cfg(feature = "std")]
unsafe extern "C" fn converser_trampoline(
    num_msg: i32,
    msg: *mut *const CPamMessage,
    resp: *mut *mut CPamResponse,
    appdata_ptr: *mut core::ffi::c_void,
) -> i32 {
    if appdata_ptr.is_null() || msg.is_null() || resp.is_null() || num_msg < 0 {
        return PAM_CONV_ERR;
    }
    // SAFETY: appdata_ptr was produced by pam_conv_from_converser's
    // Box::into_raw and is still live (caller contract: not yet freed).
    let converser: &mut alloc::boxed::Box<dyn Converser> =
        unsafe { &mut *(appdata_ptr as *mut alloc::boxed::Box<dyn Converser>) };

    let count = num_msg as usize;
    let mut messages = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: PAM contract guarantees `msg` points to `num_msg` valid
        // `*const CPamMessage` entries for the duration of this call.
        let msg_ptr = unsafe { *msg.add(i) };
        if msg_ptr.is_null() {
            return PAM_CONV_ERR;
        }
        let m = unsafe { &*msg_ptr };
        let text = if m.msg.is_null() {
            String::new()
        } else {
            // SAFETY: NUL-terminated C string, valid for the call's duration.
            unsafe { core::ffi::CStr::from_ptr(m.msg) }
                .to_string_lossy()
                .into_owned()
        };
        let style = match m.msg_style {
            s if s == PAM_PROMPT_ECHO_OFF => MsgStyle::PromptEchoOff,
            s if s == PAM_PROMPT_ECHO_ON => MsgStyle::PromptEchoOn,
            s if s == PAM_ERROR_MSG => MsgStyle::ErrorMsg,
            s if s == PAM_TEXT_INFO => MsgStyle::TextInfo,
            _ => return PAM_CONV_ERR,
        };
        messages.push(Message { style, text });
    }

    let responses = match converser.converse(&messages) {
        Ok(r) if r.len() == count => r,
        Ok(_) => return PAM_CONV_ERR, // contract violation: wrong response count
        Err(_) => return PAM_CONV_ERR,
    };

    // SAFETY: allocate with libc::malloc, not Rust's global allocator --
    // the caller (elevate-pam's own conv_echo_off/conv_echo_on, or any
    // other PAM-conformant caller) frees this array and each .resp string
    // with libc::free per the PAM conversation contract.
    let resp_array =
        unsafe { libc::malloc(count * core::mem::size_of::<CPamResponse>()) as *mut CPamResponse };
    if resp_array.is_null() {
        return PAM_BUF_ERR;
    }
    for (i, r) in responses.into_iter().enumerate() {
        let dup = match std::ffi::CString::new(r.text) {
            // SAFETY: strdup mallocs its own copy; caller frees with libc::free.
            Ok(c_text) => unsafe { libc::strdup(c_text.as_ptr()) },
            // NUL byte in response text -- essentially unreachable for real
            // password/text input, but fail the transaction rather than
            // truncate silently. Previously-allocated entries in
            // resp_array are leaked on this rare path rather than
            // unwound, to keep this trampoline simple.
            Err(_) => {
                unsafe { libc::free(resp_array as *mut core::ffi::c_void) };
                return PAM_CONV_ERR;
            }
        };
        unsafe {
            (*resp_array.add(i)).resp = dup;
            (*resp_array.add(i)).resp_retcode = r.retcode;
        }
    }

    unsafe { *resp = resp_array };
    PAM_SUCCESS
}
