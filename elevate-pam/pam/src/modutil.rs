//! `<security/pam_modutil.h>` — Linux-PAM's libc-wrapper helpers, as used by
//! third-party compiled PAM modules (e.g. systemd's `pam_systemd.so`) that
//! `dlopen` against `libpam.so.0` at runtime. The header
//! (`include/security/pam_modutil.h`) already declared these 19 symbols;
//! this file is the actual `#[no_mangle]` implementation backing them --
//! without it, any module calling them fails at load time with an
//! undefined-symbol error, even though it compiled fine against the header.
//!
//! `getpwnam`/`getgrnam`/`getspnam` here read Zainium's real passwd/group/
//! shadow files directly (same reasoning as `zainium_passwd.rs` in the
//! greetd fork): libc's own NSS entry points can't be trusted to have been
//! rebuilt from patched-path musl source on every deployment, and this
//! module doesn't go through libc's NSS at all.
//!
//! Returned `passwd`/`group`/`spwd` pointers are intentionally leaked
//! (`Box::into_raw`, never freed): the real Linux-PAM caches them for the
//! handle's lifetime via `pam_set_data`, but this crate's current
//! `pam_set_data`/`pam_get_data` C shim (see `ffi.rs`) doesn't yet wire the
//! C `cleanup` callback through to `DataTable`, so caching+freeing correctly
//! isn't possible without changing that shim too. Session worker processes
//! that dlopen PAM modules are short-lived, one-shot-per-login processes --
//! a handful of leaked passwd/group entries per login is bounded and
//! harmless. Revisit if `pam_set_data`'s cleanup wiring is ever fixed.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::fs;

use crate::constants::*;
use crate::ffi::PamHandleT;

/// C `struct passwd` (musl/glibc-compatible field order).
#[repr(C)]
pub struct Passwd {
    /// Login name.
    pub pw_name: *mut c_char,
    /// Encrypted password (unused on Zainium, shadow holds the real hash).
    pub pw_passwd: *mut c_char,
    /// Numerical user id.
    pub pw_uid: libc::uid_t,
    /// Numerical primary group id.
    pub pw_gid: libc::gid_t,
    /// User info / full name field.
    pub pw_gecos: *mut c_char,
    /// Home directory.
    pub pw_dir: *mut c_char,
    /// Login shell.
    pub pw_shell: *mut c_char,
}

/// C `struct group`.
#[repr(C)]
pub struct Group {
    /// Group name.
    pub gr_name: *mut c_char,
    /// Encrypted group password (unused).
    pub gr_passwd: *mut c_char,
    /// Numerical group id.
    pub gr_gid: libc::gid_t,
    /// NULL-terminated array of member login names.
    pub gr_mem: *mut *mut c_char,
}

/// C `struct spwd` -- not provided by the `libc` crate for musl targets, so
/// defined here directly, matching musl's real `<shadow.h>` layout.
#[repr(C)]
pub struct Spwd {
    /// Login name.
    pub sp_namp: *mut c_char,
    /// Encrypted password.
    pub sp_pwdp: *mut c_char,
    /// Date of last password change (days since epoch).
    pub sp_lstchg: i64,
    /// Minimum password age.
    pub sp_min: i64,
    /// Maximum password age.
    pub sp_max: i64,
    /// Password warning period.
    pub sp_warn: i64,
    /// Password inactivity period.
    pub sp_inact: i64,
    /// Account expiration date (days since epoch).
    pub sp_expire: i64,
    /// Reserved.
    pub sp_flag: u64,
}

/// C `struct pam_modutil_privs` (field order/types must match the header
/// exactly -- callers stack-allocate it directly via the header's
/// `PAM_MODUTIL_DEF_PRIVS` macro, never through Rust).
#[repr(C)]
pub struct ModutilPrivs {
    /// Caller-owned buffer holding the saved supplementary group list.
    pub grplist: *mut libc::gid_t,
    /// Number of groups actually saved into `grplist`.
    pub number_of_groups: c_int,
    /// Capacity of `grplist`, in entries.
    pub allocated: c_int,
    /// Effective gid saved before dropping privileges.
    pub old_gid: libc::gid_t,
    /// Effective uid saved before dropping privileges.
    pub old_uid: libc::uid_t,
    /// Whether privileges are currently dropped.
    pub is_dropped: c_int,
}

/// `enum pam_modutil_redirect_fd::PAM_MODUTIL_IGNORE_FD` (header order) --
/// the only value that skips redirection; `PIPE_FD`/`NULL_FD` are handled
/// identically below (see doc comment on `pam_modutil_sanitize_helper_fds`).
const REDIRECT_IGNORE: c_int = 0;

fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller provides a valid, NUL-terminated C string per the PAM
    // module contract for every parameter this is used on below.
    unsafe { core::ffi::CStr::from_ptr(p) }.to_str().ok()
}

fn leak_cstring(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

struct PwEntry {
    name: String,
    passwd: String,
    uid: u32,
    gid: u32,
    gecos: String,
    dir: String,
    shell: String,
}

struct GrEntry {
    name: String,
    passwd: String,
    gid: u32,
    members: Vec<String>,
}

struct SpEntry {
    name: String,
    pwdp: String,
    lstchg: i64,
    min: i64,
    max: i64,
    warn: i64,
    inact: i64,
    expire: i64,
    flag: u64,
}

fn read_zainium_file(primary: &str, fallback: &str) -> Option<String> {
    fs::read_to_string(primary)
        .or_else(|_| fs::read_to_string(fallback))
        .ok()
}

fn find_passwd(pred: impl Fn(&PwEntry) -> bool) -> Option<PwEntry> {
    let text = read_zainium_file("/overlayer/syshub/etc/passwd", "/etc/passwd")?;
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(7, ':').collect();
        if f.len() < 7 {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
            continue;
        };
        let e = PwEntry {
            name: f[0].to_string(),
            passwd: f[1].to_string(),
            uid,
            gid,
            gecos: f[4].to_string(),
            dir: f[5].to_string(),
            shell: f[6].to_string(),
        };
        if pred(&e) {
            return Some(e);
        }
    }
    None
}

fn find_group(pred: impl Fn(&GrEntry) -> bool) -> Option<GrEntry> {
    let text = read_zainium_file("/overlayer/syshub/etc/group", "/etc/group")?;
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(gid) = f[2].parse::<u32>() else {
            continue;
        };
        let e = GrEntry {
            name: f[0].to_string(),
            passwd: f[1].to_string(),
            gid,
            members: f[3].split(',').filter(|m| !m.is_empty()).map(String::from).collect(),
        };
        if pred(&e) {
            return Some(e);
        }
    }
    None
}

fn find_shadow(pred: impl Fn(&SpEntry) -> bool) -> Option<SpEntry> {
    let text = read_zainium_file("/overlayer/syshub/etc/shadow", "/etc/shadow")?;
    let n = |s: &str| -> i64 { s.parse::<i64>().unwrap_or(-1) };
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(9, ':').collect();
        if f.len() < 2 {
            continue;
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let e = SpEntry {
            name: f[0].to_string(),
            pwdp: f[1].to_string(),
            lstchg: n(get(2)),
            min: n(get(3)),
            max: n(get(4)),
            warn: n(get(5)),
            inact: n(get(6)),
            expire: n(get(7)),
            flag: get(8).parse::<u64>().unwrap_or(0),
        };
        if pred(&e) {
            return Some(e);
        }
    }
    None
}

fn leak_passwd(e: &PwEntry) -> *mut Passwd {
    Box::into_raw(Box::new(Passwd {
        pw_name: leak_cstring(&e.name),
        pw_passwd: leak_cstring(&e.passwd),
        pw_uid: e.uid,
        pw_gid: e.gid,
        pw_gecos: leak_cstring(&e.gecos),
        pw_dir: leak_cstring(&e.dir),
        pw_shell: leak_cstring(&e.shell),
    }))
}

fn leak_group(e: &GrEntry) -> *mut Group {
    let mut mem_ptrs: Vec<*mut c_char> = e.members.iter().map(|m| leak_cstring(m)).collect();
    mem_ptrs.push(ptr::null_mut());
    let gr_mem = Box::into_raw(mem_ptrs.into_boxed_slice()) as *mut *mut c_char;
    Box::into_raw(Box::new(Group {
        gr_name: leak_cstring(&e.name),
        gr_passwd: leak_cstring(&e.passwd),
        gr_gid: e.gid,
        gr_mem,
    }))
}

fn leak_spwd(e: &SpEntry) -> *mut Spwd {
    Box::into_raw(Box::new(Spwd {
        sp_namp: leak_cstring(&e.name),
        sp_pwdp: leak_cstring(&e.pwdp),
        sp_lstchg: e.lstchg,
        sp_min: e.min,
        sp_max: e.max,
        sp_warn: e.warn,
        sp_inact: e.inact,
        sp_expire: e.expire,
        sp_flag: e.flag,
    }))
}

/// `pam_modutil_check_user_in_passwd` -- true if `user_name` appears as the
/// first field of any line in the passwd-format `file_name`.
///
/// # Safety
/// `user_name` and `file_name` must be valid, non-null, NUL-terminated C
/// strings.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_check_user_in_passwd(
    _pamh: *mut PamHandleT,
    user_name: *const c_char,
    file_name: *const c_char,
) -> c_int {
    let (Some(user), Some(path)) = (cstr_to_str(user_name), cstr_to_str(file_name)) else {
        return PAM_SYSTEM_ERR;
    };
    match fs::read_to_string(path) {
        Ok(text) => {
            for line in text.lines() {
                if line.split(':').next() == Some(user) {
                    return PAM_SUCCESS;
                }
            }
            PAM_PERM_DENIED
        }
        Err(_) => PAM_SERVICE_ERR,
    }
}

/// # Safety
/// `user` must be a valid, non-null, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getpwnam(
    _pamh: *mut PamHandleT,
    user: *const c_char,
) -> *mut Passwd {
    let Some(name) = cstr_to_str(user) else {
        return ptr::null_mut();
    };
    find_passwd(|e| e.name == name)
        .as_ref()
        .map(leak_passwd)
        .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getpwuid(
    _pamh: *mut PamHandleT,
    uid: libc::uid_t,
) -> *mut Passwd {
    find_passwd(|e| e.uid == uid)
        .as_ref()
        .map(leak_passwd)
        .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `group` must be a valid, non-null, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getgrnam(
    _pamh: *mut PamHandleT,
    group: *const c_char,
) -> *mut Group {
    let Some(name) = cstr_to_str(group) else {
        return ptr::null_mut();
    };
    find_group(|e| e.name == name)
        .as_ref()
        .map(leak_group)
        .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getgrgid(
    _pamh: *mut PamHandleT,
    gid: libc::gid_t,
) -> *mut Group {
    find_group(|e| e.gid == gid)
        .as_ref()
        .map(leak_group)
        .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `user` must be a valid, non-null, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getspnam(
    _pamh: *mut PamHandleT,
    user: *const c_char,
) -> *mut Spwd {
    let Some(name) = cstr_to_str(user) else {
        return ptr::null_mut();
    };
    find_shadow(|e| e.name == name)
        .as_ref()
        .map(leak_spwd)
        .unwrap_or(ptr::null_mut())
}

fn in_group(pw: &PwEntry, gr: &GrEntry) -> c_int {
    if pw.gid == gr.gid || gr.members.iter().any(|m| m == &pw.name) {
        1
    } else {
        0
    }
}

/// # Safety
/// `user`/`group` must be valid, non-null, NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_user_in_group_nam_nam(
    _pamh: *mut PamHandleT,
    user: *const c_char,
    group: *const c_char,
) -> c_int {
    let (Some(user), Some(group)) = (cstr_to_str(user), cstr_to_str(group)) else {
        return -1;
    };
    let Some(pw) = find_passwd(|e| e.name == user) else {
        return -1;
    };
    let Some(gr) = find_group(|e| e.name == group) else {
        return -1;
    };
    in_group(&pw, &gr)
}

/// # Safety
/// `user` must be a valid, non-null, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_user_in_group_nam_gid(
    _pamh: *mut PamHandleT,
    user: *const c_char,
    group: libc::gid_t,
) -> c_int {
    let Some(user) = cstr_to_str(user) else {
        return -1;
    };
    let Some(pw) = find_passwd(|e| e.name == user) else {
        return -1;
    };
    let Some(gr) = find_group(|e| e.gid == group) else {
        return -1;
    };
    in_group(&pw, &gr)
}

/// # Safety
/// `group` must be a valid, non-null, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_user_in_group_uid_nam(
    _pamh: *mut PamHandleT,
    user: libc::uid_t,
    group: *const c_char,
) -> c_int {
    let Some(group) = cstr_to_str(group) else {
        return -1;
    };
    let Some(pw) = find_passwd(|e| e.uid == user) else {
        return -1;
    };
    let Some(gr) = find_group(|e| e.name == group) else {
        return -1;
    };
    in_group(&pw, &gr)
}

/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_user_in_group_uid_gid(
    _pamh: *mut PamHandleT,
    user: libc::uid_t,
    group: libc::gid_t,
) -> c_int {
    let Some(pw) = find_passwd(|e| e.uid == user) else {
        return -1;
    };
    let Some(gr) = find_group(|e| e.gid == group) else {
        return -1;
    };
    in_group(&pw, &gr)
}

/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_getlogin(_pamh: *mut PamHandleT) -> *const c_char {
    // Not part of the musl-internal-NSS problem this module otherwise works
    // around -- getlogin(3) reads utmp, not passwd/group, so libc's own
    // symbol is fine to call directly here.
    unsafe { libc::getlogin() }
}

/// # Safety
/// `buffer` must point to at least `count` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_read(fd: c_int, buffer: *mut c_char, count: c_int) -> c_int {
    if count <= 0 || buffer.is_null() {
        return 0;
    }
    let mut total: isize = 0;
    while (total as c_int) < count {
        let n = unsafe {
            libc::read(
                fd,
                buffer.add(total as usize) as *mut c_void,
                (count as usize) - (total as usize),
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return -1;
        }
        if n == 0 {
            break;
        }
        total += n;
    }
    total as c_int
}

/// # Safety
/// `buffer` must point to at least `count` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_write(
    fd: c_int,
    buffer: *const c_char,
    count: c_int,
) -> c_int {
    if count <= 0 || buffer.is_null() {
        return 0;
    }
    let mut total: isize = 0;
    while (total as c_int) < count {
        let n = unsafe {
            libc::write(
                fd,
                buffer.add(total as usize) as *const c_void,
                (count as usize) - (total as usize),
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return -1;
        }
        if n == 0 {
            break;
        }
        total += n;
    }
    total as c_int
}

/// Audit subsystem isn't implemented in Zainium -- a no-op success matches
/// systems with audit support compiled out, which real PAM modules already
/// have to tolerate.
///
/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_audit_write(
    _pamh: *mut PamHandleT,
    _kind: c_int,
    _message: *const c_char,
    _retval: c_int,
) -> c_int {
    PAM_SUCCESS
}

/// # Safety
/// `p` and `pw` must be valid, non-null pointers; `p.grplist` must have room
/// for at least `p.allocated` entries if non-null.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_drop_priv(
    _pamh: *mut PamHandleT,
    p: *mut ModutilPrivs,
    pw: *const Passwd,
) -> c_int {
    if p.is_null() || pw.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let p = unsafe { &mut *p };
    let pw = unsafe { &*pw };

    let ngroups = unsafe { libc::getgroups(0, ptr::null_mut()) };
    let ngroups = ngroups.max(0);
    if ngroups > 0 && ngroups <= p.allocated && !p.grplist.is_null() {
        if unsafe { libc::getgroups(ngroups, p.grplist) } < 0 {
            return PAM_SYSTEM_ERR;
        }
        p.number_of_groups = ngroups;
    } else {
        p.number_of_groups = 0;
    }
    p.old_gid = unsafe { libc::getegid() };
    p.old_uid = unsafe { libc::geteuid() };

    if unsafe { libc::setgroups(0, ptr::null()) } != 0 {
        return PAM_SYSTEM_ERR;
    }
    if unsafe { libc::setegid(pw.pw_gid) } != 0 {
        return PAM_SYSTEM_ERR;
    }
    if unsafe { libc::seteuid(pw.pw_uid) } != 0 {
        return PAM_SYSTEM_ERR;
    }
    p.is_dropped = 1;
    PAM_SUCCESS
}

/// # Safety
/// `p` must be a valid, non-null pointer previously populated by
/// [`pam_modutil_drop_priv`].
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_regain_priv(
    _pamh: *mut PamHandleT,
    p: *mut ModutilPrivs,
) -> c_int {
    if p.is_null() {
        return PAM_SYSTEM_ERR;
    }
    let p = unsafe { &mut *p };
    if p.is_dropped == 0 {
        return PAM_SUCCESS;
    }
    // Reverse order of drop_priv: regain uid first (root again), then gid,
    // then restore the full supplementary-group list.
    if unsafe { libc::seteuid(p.old_uid) } != 0 {
        return PAM_SYSTEM_ERR;
    }
    if unsafe { libc::setegid(p.old_gid) } != 0 {
        return PAM_SYSTEM_ERR;
    }
    if p.number_of_groups > 0 && !p.grplist.is_null() {
        if unsafe { libc::setgroups(p.number_of_groups as usize, p.grplist) } != 0 {
            return PAM_SYSTEM_ERR;
        }
    }
    p.is_dropped = 0;
    PAM_SUCCESS
}

/// Simplified: `PIPE_FD` is treated the same as `NULL_FD` (redirected to
/// `/dev/null` rather than a real relay pipe) since nothing in Zainium's PAM
/// stack currently spawns a helper that needs the pipe's other end back --
/// `pam_systemd` itself never calls this. Revisit if a module that actually
/// needs the pipe form shows up.
///
/// # Safety
/// `pamh` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_sanitize_helper_fds(
    _pamh: *mut PamHandleT,
    redirect_stdin: c_int,
    redirect_stdout: c_int,
    redirect_stderr: c_int,
) -> c_int {
    let devnull = CString::new("/dev/null").unwrap();
    for (fd, redirect) in [
        (0, redirect_stdin),
        (1, redirect_stdout),
        (2, redirect_stderr),
    ] {
        if redirect == REDIRECT_IGNORE {
            continue;
        }
        // NULL_FD and PIPE_FD both land here -- see doc comment above.
        let flags = if fd == 0 { libc::O_RDONLY } else { libc::O_WRONLY };
        let nullfd = unsafe { libc::open(devnull.as_ptr(), flags) };
        if nullfd < 0 {
            return PAM_SYSTEM_ERR;
        }
        if unsafe { libc::dup2(nullfd, fd) } < 0 {
            unsafe { libc::close(nullfd) };
            return PAM_SYSTEM_ERR;
        }
        if nullfd != fd {
            unsafe { libc::close(nullfd) };
        }
    }
    PAM_SUCCESS
}

/// `pam_modutil_search_key` -- look up `key` in a `login.defs`-style
/// `KEY value` file (whitespace-separated, `#`-comments, one entry per
/// line). Returns a leaked, owned copy of the value, or null if not found.
///
/// # Safety
/// `file_name` and `key` must be valid, non-null, NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_modutil_search_key(
    _pamh: *mut PamHandleT,
    file_name: *const c_char,
    key: *const c_char,
) -> *mut c_char {
    let (Some(path), Some(key)) = (cstr_to_str(file_name), cstr_to_str(key)) else {
        return ptr::null_mut();
    };
    let Ok(text) = fs::read_to_string(path) else {
        return ptr::null_mut();
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if parts.next() == Some(key) {
            let value = parts.next().unwrap_or("").trim();
            return leak_cstring(value);
        }
    }
    ptr::null_mut()
}
