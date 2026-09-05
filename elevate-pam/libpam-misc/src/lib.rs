//! Rust port of real Linux-PAM's `libpam_misc` (`misc_conv.c` +
//! `help_env.c` from linux-pam-1.7.2), same C ABI/symbol names so it's a
//! drop-in for anything linking `-lpam_misc` (classic `login`-style
//! text greeters, agreety-alikes, etc).
//!
//! `pam_binary_handler_fn`/`pam_binary_handler_free` are exported (for
//! anyone that just checks they exist / are NULL) but the Solaris-style
//! binary-prompt protocol itself (`pamc_bp_t` and friends) isn't
//! implemented -- PAM_BINARY_PROMPT fails the conversation, exactly
//! upstream's own behavior when no handler is registered (the default,
//! and by far the common case).

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};

use elevate_pam::conv::{CPamMessage, CPamResponse};
use elevate_pam::ffi::PamHandleT;
use elevate_pam::{
    PAM_BINARY_PROMPT, PAM_BUF_ERR, PAM_CONV_ERR, PAM_ERROR_MSG, PAM_PERM_DENIED,
    PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_SUCCESS, PAM_TEXT_INFO,
};

const INPUTSIZE: usize = 512;

// ---- environment helpers (help_env.c) --------------------------------

/// # Safety
/// `dump` must be a NULL-terminated array of `libc::malloc`'d strings, or
/// null, as returned by `pam_getenvlist`. Consumes and frees it.
#[no_mangle]
pub unsafe extern "C" fn pam_misc_drop_env(dump: *mut *mut c_char) -> *mut *mut c_char {
    if dump.is_null() {
        return std::ptr::null_mut();
    }
    let mut i = 0isize;
    loop {
        let entry = unsafe { *dump.offset(i) };
        if entry.is_null() {
            break;
        }
        // Best-effort overwrite before freeing -- these are secrets in
        // the general case (env vars can carry auth tokens).
        let len = unsafe { libc::strlen(entry) };
        unsafe { std::ptr::write_bytes(entry, 0, len) };
        unsafe { libc::free(entry as *mut c_void) };
        i += 1;
    }
    unsafe { libc::free(dump as *mut c_void) };
    std::ptr::null_mut()
}

/// # Safety
/// `pamh` must be a valid handle from `pam_start`. `user_env` must be
/// null or a NULL-terminated array of NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_misc_paste_env(
    pamh: *mut PamHandleT,
    user_env: *const *const c_char,
) -> c_int {
    if user_env.is_null() {
        return PAM_SUCCESS;
    }
    let mut i = 0isize;
    loop {
        let entry = unsafe { *user_env.offset(i) };
        if entry.is_null() {
            break;
        }
        let retval = unsafe { elevate_pam::ffi::pam_putenv(pamh, entry) };
        if retval != PAM_SUCCESS {
            return retval;
        }
        i += 1;
    }
    PAM_SUCCESS
}

/// # Safety
/// `pamh` must be a valid handle from `pam_start`; `name`/`value` must be
/// valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_misc_setenv(
    pamh: *mut PamHandleT,
    name: *const c_char,
    value: *const c_char,
    readonly: c_int,
) -> c_int {
    if name.is_null() || value.is_null() {
        return PAM_BUF_ERR;
    }
    if readonly != 0 {
        let existing = unsafe { elevate_pam::ffi::pam_getenv(pamh, name) };
        if !existing.is_null() {
            return PAM_PERM_DENIED;
        }
    }
    let (Ok(name_s), Ok(value_s)) = (
        unsafe { CStr::from_ptr(name) }.to_str(),
        unsafe { CStr::from_ptr(value) }.to_str(),
    ) else {
        return PAM_BUF_ERR;
    };
    let Ok(combined) = CString::new(format!("{name_s}={value_s}")) else {
        return PAM_BUF_ERR;
    };
    unsafe { elevate_pam::ffi::pam_putenv(pamh, combined.as_ptr()) }
}

// ---- exported globals (misc_conv.c) -----------------------------------

#[no_mangle]
pub static mut pam_misc_conv_warn_time: libc::time_t = 0;
#[no_mangle]
pub static mut pam_misc_conv_die_time: libc::time_t = 0;

static WARN_LINE_DEFAULT: &[u8] = b"...Time is running out...\n\0";
static DIE_LINE_DEFAULT: &[u8] = b"...Sorry, your time is up!\n\0";

#[no_mangle]
pub static mut pam_misc_conv_warn_line: *const c_char = WARN_LINE_DEFAULT.as_ptr().cast();
#[no_mangle]
pub static mut pam_misc_conv_die_line: *const c_char = DIE_LINE_DEFAULT.as_ptr().cast();

#[no_mangle]
pub static mut pam_misc_conv_died: c_int = 0;

#[no_mangle]
pub static mut pam_binary_handler_fn: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int> =
    None;
#[no_mangle]
pub static mut pam_binary_handler_free: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)> = None;

// ---- timeout plumbing --------------------------------------------------

static EXPIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn time_is_up(_sig: c_int) {
    EXPIRED.store(true, Ordering::SeqCst);
}

fn reset_alarm(old: &libc::sigaction) {
    unsafe {
        libc::alarm(0);
        libc::sigaction(libc::SIGALRM, old, std::ptr::null_mut());
    }
}

fn set_alarm(delay: u32, old: &mut libc::sigaction) -> bool {
    let mut new_sig: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut new_sig.sa_mask) };
    new_sig.sa_flags = 0;
    new_sig.sa_sigaction = time_is_up as *const () as usize;
    if unsafe { libc::sigaction(libc::SIGALRM, &new_sig, old) } != 0 {
        return false; // setting signal failed
    }
    // Faithful port of upstream: alarm()'s return is the previous
    // alarm's remaining seconds, not an error code, but misc_conv.c
    // itself treats a nonzero return as failure -- kept as-is.
    if unsafe { libc::alarm(delay) } != 0 {
        unsafe { libc::sigaction(libc::SIGALRM, old, std::ptr::null_mut()) };
        return false;
    }
    true
}

/// Seconds until the next warn/die deadline. 0 = no delay, -1 = expired.
fn get_delay() -> i64 {
    EXPIRED.store(false, Ordering::SeqCst);
    let now = unsafe { libc::time(std::ptr::null_mut()) };

    unsafe {
        if pam_misc_conv_die_time != 0 && now >= pam_misc_conv_die_time {
            eprint!("{}", line_str(pam_misc_conv_die_line));
            pam_misc_conv_died = 1;
            return -1;
        }
        if pam_misc_conv_warn_time != 0 && now >= pam_misc_conv_warn_time {
            eprint!("{}", line_str(pam_misc_conv_warn_line));
            pam_misc_conv_warn_time = 0;
            return if pam_misc_conv_die_time != 0 {
                (pam_misc_conv_die_time - now) as i64
            } else {
                0
            };
        }
        if pam_misc_conv_warn_time != 0 {
            (pam_misc_conv_warn_time - now) as i64
        } else if pam_misc_conv_die_time != 0 {
            (pam_misc_conv_die_time - now) as i64
        } else {
            0
        }
    }
}

unsafe fn line_str(p: *const c_char) -> std::borrow::Cow<'static, str> {
    if p.is_null() {
        return "".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned().into()
}

// ---- terminal line reading ---------------------------------------------

enum ReadOutcome {
    Line(String),
    Eof,
    Error,
}

/// Faithful-ish port of `read_string()` -- echo control via termios,
/// SIGTSTP blocked for the duration, SIGALRM-driven warn/die timeout.
fn read_string(echo: bool, prompt: &str) -> ReadOutcome {
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } != 0;
    let mut term_before: libc::termios = unsafe { std::mem::zeroed() };
    let mut term_tmp: libc::termios = unsafe { std::mem::zeroed() };
    let mut have_term = false;
    let mut oset: libc::sigset_t = unsafe { std::mem::zeroed() };

    if is_tty {
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term_before) } != 0 {
            return ReadOutcome::Error;
        }
        term_tmp = term_before;
        if echo {
            term_tmp.c_lflag |= libc::ICANON | libc::ECHOCTL;
        } else {
            term_tmp.c_lflag &= !libc::ECHO;
        }
        have_term = true;

        let mut nset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut nset);
            libc::sigaddset(&mut nset, libc::SIGTSTP);
            libc::sigprocmask(libc::SIG_BLOCK, &nset, &mut oset);
        }
    }

    let mut delay = get_delay();
    let outcome = loop {
        if delay < 0 {
            break ReadOutcome::Error;
        }
        if have_term {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term_tmp) };
        }
        eprint!("{prompt}");

        let mut old_sig: libc::sigaction = unsafe { std::mem::zeroed() };
        if delay > 0 && !set_alarm(delay as u32, &mut old_sig) {
            break ReadOutcome::Error;
        }

        let mut buf = [0u8; INPUTSIZE];
        let nc: isize = if have_term {
            unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr() as *mut c_void,
                    INPUTSIZE - 1,
                )
            }
        } else {
            // Not a tty: read one byte at a time until a newline (can't
            // safely over-read past the line on a pipe).
            let mut i = 0usize;
            let mut err = false;
            while i < INPUTSIZE - 1 {
                let rv = unsafe {
                    libc::read(libc::STDIN_FILENO, buf[i..].as_mut_ptr() as *mut c_void, 1)
                };
                if rv != 1 {
                    err = rv < 0;
                    break;
                }
                i += 1;
                if buf[i - 1] == b'\n' {
                    break;
                }
            }
            if err { -1 } else { i as isize }
        };

        if have_term {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &term_before) };
            if !echo || EXPIRED.load(Ordering::SeqCst) {
                eprintln!();
            }
        }
        if delay > 0 {
            reset_alarm(&old_sig);
        }

        if EXPIRED.load(Ordering::SeqCst) {
            delay = get_delay();
            continue;
        } else if nc > 0 {
            let mut n = nc as usize;
            if buf[n - 1] == b'\n' {
                n -= 1;
            } else if echo {
                eprintln!();
            }
            let s = String::from_utf8_lossy(&buf[..n]).into_owned();
            buf.iter_mut().for_each(|b| *b = 0); // overwrite, may hold a secret
            break ReadOutcome::Line(s);
        } else if nc == 0 {
            if echo {
                eprintln!();
            }
            break ReadOutcome::Eof;
        } else {
            if echo {
                eprintln!();
            }
            break ReadOutcome::Error;
        }
    };

    if have_term {
        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, &oset, std::ptr::null_mut());
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term_before);
        }
    }
    outcome
}

// ---- the conversation function itself ----------------------------------

unsafe fn make_resp(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => unsafe { libc::strdup(c.as_ptr()) },
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe fn free_partial(replies: &[CPamResponse]) {
    for r in replies {
        if !r.resp.is_null() {
            unsafe { libc::free(r.resp as *mut c_void) };
        }
    }
}

/// # Safety
/// Standard PAM conversation-function contract: `msgm` must point to
/// `num_msg` valid `*const CPamMessage` entries; `response` must be a
/// valid out-pointer. The returned array (and each string in it) is
/// `libc::malloc`-allocated, matching elevate-pam's own internal
/// convention (see `elevate_pam::conv`'s doc comment) -- free with
/// `libc::free`, not Rust's allocator.
#[no_mangle]
pub unsafe extern "C" fn misc_conv(
    num_msg: c_int,
    msgm: *mut *const CPamMessage,
    response: *mut *mut CPamResponse,
    _appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msgm.is_null() || response.is_null() {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    let mut replies: Vec<CPamResponse> = Vec::with_capacity(n);

    for i in 0..n {
        let msg_ptr = unsafe { *msgm.add(i) };
        if msg_ptr.is_null() {
            unsafe { free_partial(&replies) };
            return PAM_CONV_ERR;
        }
        let m = unsafe { &*msg_ptr };
        let text = if m.msg.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(m.msg) }.to_string_lossy().into_owned()
        };

        let mut resp_ptr: *mut c_char = std::ptr::null_mut();
        let style = m.msg_style;
        if style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON {
            match read_string(style == PAM_PROMPT_ECHO_ON, &text) {
                ReadOutcome::Line(s) => resp_ptr = unsafe { make_resp(&s) },
                ReadOutcome::Eof => {}
                ReadOutcome::Error => {
                    unsafe { free_partial(&replies) };
                    return PAM_CONV_ERR;
                }
            }
        } else if style == PAM_ERROR_MSG {
            eprintln!("{text}");
        } else if style == PAM_TEXT_INFO {
            println!("{text}");
        } else if style == PAM_BINARY_PROMPT {
            // No binary-prompt handler support -- see module docs.
            unsafe { free_partial(&replies) };
            return PAM_CONV_ERR;
        } else {
            eprintln!("erroneous conversation ({style})");
            unsafe { free_partial(&replies) };
            return PAM_CONV_ERR;
        }

        replies.push(CPamResponse {
            resp: resp_ptr,
            resp_retcode: 0,
        });
    }

    let arr = unsafe {
        libc::malloc(n * std::mem::size_of::<CPamResponse>()) as *mut CPamResponse
    };
    if arr.is_null() {
        unsafe { free_partial(&replies) };
        return PAM_CONV_ERR;
    }
    for (i, r) in replies.into_iter().enumerate() {
        unsafe { *arr.add(i) = r };
    }
    unsafe { *response = arr };
    PAM_SUCCESS
}
