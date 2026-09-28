//! pam_systemd — register the login session with systemd-logind.
//!
//! Port of `src/login/pam_systemd.c` from systemd 261 (`pam_sm_open_session`
//! and `pam_sm_close_session`). systemd's own `pam_systemd.so` can't be used
//! with elevate-pam: it links Linux-PAM and reads its private `pam_handle_t`.
//!
//! logind is reached over its Varlink socket, the path pam_systemd itself
//! tries first. Since v258 logind tracks the session leader by pidfd, so no
//! session fifo has to be held open.
//!
//! Not ported: the D-Bus fallback (pam_systemd only needs it for logind older
//! than v258, or for `systemd.memory_max`-style scope limits passed as PAM
//! data), areas (`area=`, `$XDG_AREA`), JSON user records (users come from
//! NSS, whose records carry no umask/env/rlimit/capability settings), the
//! default `CAP_WAKE_ALARM` ambient capability, and the OSC 3008 terminal
//! context sequence.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::constants::{PAM_SERVICE_ERR, PAM_SESSION_ERR, PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};
use crate::types::ItemType;

const LOGIN_VARLINK_ADDRESS: &str = "/run/systemd/io.systemd.Login";

/// `LOGIN_SLOW_BUS_CALL_TIMEOUT_USEC`
const LOGIN_SLOW_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest Varlink message we accept (sd-varlink's `VARLINK_BUFFER_MAX`).
const VARLINK_BUFFER_MAX: usize = 16 * 1024 * 1024;

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("systemd"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(open_session),
        close_session: Some(close_session),
        chauthtok: None,
    }
}

fn status(code: i32) -> PamStatus {
    PamStatus::new(code)
}

fn debug_log(pamh: &PamHandle, debug: bool, msg: &str) {
    if debug {
        crate::log::debug(pamh, msg);
    }
}

// ---- arguments -------------------------------------------------------------

#[derive(Default)]
struct Args {
    class: Option<String>,
    type_: Option<String>,
    desktop: Option<String>,
    area: Option<String>,
    debug: bool,
}

fn parse_argv(pamh: &PamHandle, args: &[String]) -> Args {
    let mut a = Args::default();

    for arg in args {
        if let Some(p) = arg.strip_prefix("class=") {
            a.class = Some(p.to_string());
        } else if let Some(p) = arg.strip_prefix("type=") {
            a.type_ = Some(p.to_string());
        } else if let Some(p) = arg.strip_prefix("desktop=") {
            a.desktop = Some(p.to_string());
        } else if let Some(p) = arg.strip_prefix("area=") {
            if !p.is_empty() && !filename_is_valid(p) {
                crate::log::warn(
                    pamh,
                    &format!("Area name specified among PAM module parameters is not valid, ignoring: {p}"),
                );
            } else {
                a.area = Some(p.to_string());
            }
        } else if arg == "debug" {
            a.debug = true;
        } else if let Some(p) = arg.strip_prefix("debug=") {
            match parse_boolean(p) {
                Some(b) => a.debug = b,
                None => crate::log::warn(
                    pamh,
                    &format!("Failed to parse debug= argument, ignoring: {p}"),
                ),
            }
        } else if arg.starts_with("default-capability-bounding-set=")
            || arg.starts_with("default-capability-ambient-set=")
        {
            crate::log::warn(
                pamh,
                &format!("Capability sets are not supported by this pam_systemd, ignoring: {arg}"),
            );
        } else {
            crate::log::warn(pamh, &format!("Unknown parameter '{arg}', ignoring."));
        }
    }

    a
}

/// systemd's `parse_boolean()`.
fn parse_boolean(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

/// systemd's `filename_is_valid()`.
fn filename_is_valid(p: &str) -> bool {
    !p.is_empty() && p != "." && p != ".." && !p.contains('/') && p.len() <= 255
}

// ---- environment -----------------------------------------------------------

/// Look up `key` in the PAM environment first, then the process environment
/// (the latter skipped under AT_SECURE, like `secure_getenv()`), so session
/// properties can also be set from a unit file's `Environment=`.
fn getenv_harder(pamh: &PamHandle, key: &str, fallback: Option<&str>) -> Option<String> {
    if let Some(v) = pamh.getenv(key) {
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }

    // SAFETY: getauxval has no preconditions.
    let secure = unsafe { libc::getauxval(libc::AT_SECURE) } != 0;
    if !secure {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }

    fallback.map(String::from)
}

fn getenv_harder_bool(pamh: &PamHandle, key: &str, fallback: bool) -> bool {
    let Some(v) = getenv_harder(pamh, key, None) else {
        return fallback;
    };
    parse_boolean(&v).unwrap_or_else(|| {
        crate::log::warn(
            pamh,
            &format!("Failed to parse environment variable value '{v}' of '{key}', falling back to using '{fallback}'."),
        );
        fallback
    })
}

fn getenv_harder_uint32(pamh: &PamHandle, key: &str, fallback: u32) -> u32 {
    let Some(v) = getenv_harder(pamh, key, None) else {
        return fallback;
    };
    v.parse().unwrap_or_else(|_| {
        crate::log::warn(
            pamh,
            &format!("Failed to parse environment variable value '{v}' of '{key}' as unsigned integer, falling back to using {fallback}."),
        );
        fallback
    })
}

/// Set `key=value` in the PAM environment, or unset `key` if `value` is empty.
fn update_environment(pamh: &mut PamHandle, key: &str, value: &str) -> Result<(), PamStatus> {
    if value.is_empty() {
        if pamh.getenv(key).is_none() {
            return Ok(());
        }
        if let Err(e) = pamh.putenv(key) {
            crate::log::warn(
                pamh,
                &format!("Failed to unset {key} environment variable: {e}"),
            );
            return Err(status(PAM_SERVICE_ERR));
        }
        return Ok(());
    }

    if let Err(e) = pamh.putenv(&format!("{key}={value}")) {
        crate::log::error(
            pamh,
            &format!("Failed to set environment variable {key}: {e}"),
        );
        return Err(status(PAM_SERVICE_ERR));
    }
    Ok(())
}

// ---- user ------------------------------------------------------------------

struct User {
    uid: u32,
    home: String,
}

fn acquire_user(pamh: &PamHandle) -> Result<User, PamStatus> {
    let Some(name) = pamh.user().filter(|u| !u.is_empty()) else {
        crate::log::error(pamh, "User name not valid.");
        return Err(status(PAM_SERVICE_ERR));
    };

    let c_name = CString::new(name).map_err(|_| status(PAM_SERVICE_ERR))?;
    // SAFETY: c_name is a valid NUL-terminated string; the passwd entry is
    // copied out before any other libc call can overwrite it.
    unsafe {
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            crate::log::error(pamh, &format!("Failed to get user record of '{name}'."));
            return Err(status(PAM_USER_UNKNOWN));
        }
        Ok(User {
            uid: (*pw).pw_uid,
            home: CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned(),
        })
    }
}

#[derive(PartialEq)]
enum Disposition {
    Intrinsic,
    System,
    Dynamic,
    Regular,
}

/// `user_record_disposition()` for a record without an explicit disposition.
fn user_disposition(uid: u32) -> Disposition {
    match uid {
        0 | 65534 => Disposition::Intrinsic,
        1..=999 => Disposition::System,
        61184..=65519 => Disposition::Dynamic,
        _ => Disposition::Regular,
    }
}

// ---- session context -------------------------------------------------------

struct SessionContext {
    service: String,
    type_: String,
    class: String,
    desktop: String,
    seat: String,
    vtnr: u32,
    tty: String,
    display: String,
    extra_device_access: Vec<String>,
    remote: bool,
    remote_user: String,
    remote_host: String,
    area: String,
    incomplete: bool,
}

/// systemd's `is_localhost()`.
fn is_localhost(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    h == "localhost"
        || h == "localhost.localdomain"
        || h.ends_with(".localhost")
        || h.ends_with(".localhost.localdomain")
}

fn skip_dev_prefix(tty: &str) -> String {
    tty.strip_prefix("/dev/").unwrap_or(tty).to_string()
}

/// `vtnr_from_tty()`: "ttyN" with N in 1..=63.
fn vtnr_from_tty(tty: &str) -> Option<u32> {
    let n: u32 = tty.strip_prefix("tty")?.parse().ok()?;
    (1..=63).contains(&n).then_some(n)
}

fn display_is_local(display: &str) -> bool {
    let b = display.as_bytes();
    b.len() >= 2 && b[0] == b':' && b[1].is_ascii_digit()
}

fn socket_from_display(display: &str) -> Option<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;

    if !display_is_local(display) {
        return None;
    }
    let digits: String = display[1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let path = format!("/tmp/.X11-unix/X{digits}");

    // Abstract socket first, then the filesystem one.
    let abstract_addr = SocketAddr::from_abstract_name(path.as_bytes()).ok()?;
    match UnixStream::connect_addr(&abstract_addr) {
        Ok(s) => Some(s),
        Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => UnixStream::connect(&path).ok(),
        Err(_) => None,
    }
}

/// Controlling tty of `pid` as a device number, from /proc/PID/stat.
fn get_ctty_devnr(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    // state ppid pgrp session tty_nr
    let tty_nr: u64 = rest.split_whitespace().nth(4)?.parse().ok()?;
    (tty_nr != 0).then_some(tty_nr)
}

/// Deduce the X server from the display socket, and from its controlling tty
/// the VT it runs on.
fn get_seat_from_display(display: &str) -> Option<u32> {
    let sock = socket_from_display(display)?;

    let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
    let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len describe a valid, writable ucred buffer.
    let r = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return None;
    }

    let devnr = get_ctty_devnr(cred.pid)?;
    let major = (devnr >> 8) & 0xfff;
    let minor = (devnr & 0xff) | ((devnr >> 12) & 0xfff00);
    let link = fs::read_link(format!("/sys/dev/char/{major}:{minor}")).ok()?;
    vtnr_from_tty(link.file_name()?.to_str()?)
}

fn session_context_mangle(pamh: &PamHandle, c: &mut SessionContext, uid: u32, debug: bool) {
    let disposition = user_disposition(uid);

    if c.service == "systemd-user" {
        // The "systemd-user" PAM stack: patch the class to 'manager' if not set.
        c.type_ = "unspecified".into();
        if c.class.is_empty() {
            c.class = if disposition == Disposition::Regular {
                "manager"
            } else {
                "manager-early"
            }
            .into();
        }
        c.tty.clear();
    } else if c.tty.contains(':') {
        // A tty with a colon is usually an X11 display, placed there to show up in utmp.
        if c.display.is_empty() {
            c.display = core::mem::take(&mut c.tty);
        }
        c.tty.clear();
    } else if c.tty == "cron" {
        c.type_ = "unspecified".into();
        if c.class.is_empty() {
            c.class = "background".into();
        }
        c.tty.clear();
    } else if c.tty == "ssh" {
        c.type_ = "tty".into();
        if c.class.is_empty() {
            c.class = "user".into();
        }
        c.tty.clear();
    } else if !c.tty.is_empty() {
        c.tty = skip_dev_prefix(&c.tty);
    }

    if !c.display.is_empty() && c.vtnr == 0 {
        if c.seat.is_empty() {
            if let Some(v) = get_seat_from_display(&c.display) {
                c.seat = "seat0".into();
                c.vtnr = v;
            }
        } else if c.seat == "seat0" {
            if let Some(v) = get_seat_from_display(&c.display) {
                c.vtnr = v;
            }
        }
    }

    if !c.seat.is_empty() && c.seat != "seat0" && c.vtnr != 0 {
        debug_log(
            pamh,
            debug,
            &format!(
                "Ignoring vtnr {} for {} which is not seat0.",
                c.vtnr, c.seat
            ),
        );
        c.vtnr = 0;
    }

    if c.type_.is_empty() {
        c.type_ = if !c.display.is_empty() {
            "x11"
        } else if !c.tty.is_empty() {
            "tty"
        } else {
            "unspecified"
        }
        .into();
        debug_log(
            pamh,
            debug,
            &format!("Automatically chose session type '{}'.", c.type_),
        );
    }

    if !c.area.is_empty() {
        crate::log::warn(
            pamh,
            &format!(
                "Areas are not supported by this pam_systemd, ignoring area '{}'.",
                c.area
            ),
        );
        c.area.clear();
    }

    if c.class.is_empty() {
        c.class = if c.type_ == "unspecified" {
            "background"
        } else {
            "user"
        }
        .into();

        // For non-regular users: root may log in before systemd-user-sessions,
        // and non-graphical sessions run without a service manager.
        match disposition {
            Disposition::Intrinsic | Disposition::System | Disposition::Dynamic => {
                if c.class == "user" {
                    c.class = if uid == 0 {
                        "user-early"
                    } else if matches!(c.type_.as_str(), "x11" | "wayland" | "mir") {
                        "user"
                    } else {
                        "user-light"
                    }
                    .into();
                } else if c.class == "background" {
                    c.class = "background-light".into();
                }
            }
            Disposition::Regular => {}
        }

        debug_log(
            pamh,
            debug,
            &format!("Automatically chose session class '{}'.", c.class),
        );
    }

    if c.incomplete {
        if c.class == "user" {
            c.class = "user-incomplete".into();
        } else {
            crate::log::warn(
                pamh,
                &format!(
                    "PAM session of class '{}' is incomplete, which is not supported, ignoring.",
                    c.class
                ),
            );
        }
    }

    c.remote = !c.remote_host.is_empty() && !is_localhost(&c.remote_host);
}

// ---- Varlink ---------------------------------------------------------------

fn varlink_connect() -> std::io::Result<UnixStream> {
    let s = UnixStream::connect(LOGIN_VARLINK_ADDRESS)?;
    s.set_read_timeout(Some(LOGIN_SLOW_CALL_TIMEOUT))?;
    s.set_write_timeout(Some(LOGIN_SLOW_CALL_TIMEOUT))?;
    Ok(s)
}

/// Write all of `buf` with MSG_NOSIGNAL, so a peer hangup can't SIGPIPE the caller.
fn send_all(s: &UnixStream, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: buf is a valid readable slice for its length.
        let n = unsafe {
            libc::send(
                s.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// One Varlink method call: `{"method":…,"parameters":…}\0`, then read the
/// NUL-terminated reply. Returns `Err` for transport failures, and the reply's
/// `error` name (if any) alongside its `parameters`.
fn varlink_call(
    s: &mut UnixStream,
    method: &str,
    parameters: Json,
) -> Result<(Option<String>, Json), String> {
    let call = Json::Obj(alloc::vec![
        ("method".into(), Json::Str(method.into())),
        ("parameters".into(), parameters),
    ]);
    let mut out = call.encode();
    out.push('\0');
    send_all(s, out.as_bytes()).map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => return Err("connection closed by logind".into()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        };
        if let Some(end) = chunk[..n].iter().position(|&b| b == 0) {
            buf.extend_from_slice(&chunk[..end]);
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > VARLINK_BUFFER_MAX {
            return Err("reply too large".into());
        }
    }

    let text = core::str::from_utf8(&buf).map_err(|_| "reply is not UTF-8".to_string())?;
    let reply = Json::parse(text)?;
    let error = reply.get("error").and_then(Json::as_str).map(String::from);
    let params = reply
        .get("parameters")
        .cloned()
        .unwrap_or(Json::Obj(Vec::new()));
    Ok((error, params))
}

// ---- registration ----------------------------------------------------------

struct Registered {
    runtime_dir: Option<String>,
}

fn validate_runtime_directory(pamh: &PamHandle, path: &str, uid: u32) -> bool {
    let ok = if !path.starts_with('/') {
        crate::log::error(
            pamh,
            &format!("Provided runtime directory '{path}' is not absolute."),
        );
        false
    } else {
        match fs::symlink_metadata(path) {
            Err(e) => {
                crate::log::error(
                    pamh,
                    &format!("Failed to stat() runtime directory '{path}': {e}"),
                );
                false
            }
            Ok(m) if !m.is_dir() => {
                crate::log::error(
                    pamh,
                    &format!("Runtime directory '{path}' is not actually a directory."),
                );
                false
            }
            Ok(m) if m.uid() != uid => {
                crate::log::error(
                    pamh,
                    &format!("Runtime directory '{path}' is not owned by UID {uid}, as it should."),
                );
                false
            }
            Ok(_) => true,
        }
    };

    if !ok {
        crate::log::warn(
            pamh,
            "Not setting $XDG_RUNTIME_DIR, as the directory is not in order.",
        );
    }
    ok
}

fn register_session(
    pamh: &mut PamHandle,
    c: &mut SessionContext,
    uid: u32,
    debug: bool,
) -> Result<Option<Registered>, PamStatus> {
    // We don't register session class none with logind.
    if c.class == "none" {
        debug_log(
            pamh,
            debug,
            "Skipping logind registration for session class none.",
        );
        return Ok(None);
    }

    // Make most of this a NOP on non-logind systems.
    if fs::metadata("/run/systemd/seats/").is_err() {
        debug_log(
            pamh,
            debug,
            "Skipping logind registration as logind is not running.",
        );
        return Ok(None);
    }

    let pid = std::process::id();
    debug_log(
        pamh,
        debug,
        &format!(
            "Asking logind to create session: uid={uid} pid={pid} service={} type={} class={} desktop={} seat={} vtnr={} tty={} display={} remote={} remote_user={} remote_host={}",
            c.service, c.type_, c.class, c.desktop, c.seat, c.vtnr, c.tty, c.display,
            if c.remote { "yes" } else { "no" }, c.remote_user, c.remote_host,
        ),
    );

    let mut s = varlink_connect().map_err(|e| {
        crate::log::error(
            pamh,
            &format!("Failed to connect to logind via Varlink: {e}"),
        );
        status(PAM_SESSION_ERR)
    })?;

    let mut p: Vec<(String, Json)> = Vec::new();
    let put_str = |p: &mut Vec<(String, Json)>, k: &str, v: &str| {
        if !v.is_empty() {
            p.push((k.into(), Json::Str(v.into())));
        }
    };
    p.push(("UID".into(), Json::Num(uid.to_string())));
    p.push((
        "PID".into(),
        Json::Obj(alloc::vec![("pid".into(), Json::Num(pid.to_string()))]),
    ));
    put_str(&mut p, "Service", &c.service);
    p.push(("Type".into(), Json::Str(c.type_.clone())));
    p.push(("Class".into(), Json::Str(c.class.clone())));
    put_str(&mut p, "Desktop", &c.desktop);
    put_str(&mut p, "Seat", &c.seat);
    if c.vtnr != 0 {
        p.push(("VTNr".into(), Json::Num(c.vtnr.to_string())));
    }
    put_str(&mut p, "TTY", &c.tty);
    put_str(&mut p, "Display", &c.display);
    p.push(("Remote".into(), Json::Bool(c.remote)));
    put_str(&mut p, "RemoteUser", &c.remote_user);
    put_str(&mut p, "RemoteHost", &c.remote_host);
    if !c.extra_device_access.is_empty() {
        p.push((
            "ExtraDeviceAccess".into(),
            Json::Arr(
                c.extra_device_access
                    .iter()
                    .map(|d| Json::Str(d.clone()))
                    .collect(),
            ),
        ));
    }

    let (error, reply) = varlink_call(&mut s, "io.systemd.Login.CreateSession", Json::Obj(p))
        .map_err(|e| {
            crate::log::error(
                pamh,
                &format!("Failed to issue io.systemd.Login.CreateSession varlink call: {e}"),
            );
            status(PAM_SERVICE_ERR)
        })?;
    drop(s);

    if let Some(error) = error {
        if error == "io.systemd.Login.AlreadySessionMember" {
            // We are already in a session, don't do anything.
            debug_log(pamh, debug, &format!("Not creating session: {error}"));
            return Ok(None);
        }
        crate::log::error(
            pamh,
            &format!("Varlink call io.systemd.Login.CreateSession failed: {error}"),
        );
        return Err(status(PAM_SERVICE_ERR));
    }

    let id = reply.get("Id").and_then(Json::as_str).map(String::from);
    let runtime_path = reply
        .get("RuntimePath")
        .and_then(Json::as_str)
        .map(String::from);
    let original_uid = reply.get("UID").and_then(Json::as_u32);
    let (Some(id), Some(runtime_path), Some(original_uid)) = (id, runtime_path, original_uid)
    else {
        crate::log::error(
            pamh,
            "Failed to parse CreateSession() reply: missing Id, RuntimePath or UID.",
        );
        return Err(status(PAM_SERVICE_ERR));
    };
    let real_seat = reply
        .get("Seat")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let real_vtnr = reply.get("VTNr").and_then(Json::as_u32).unwrap_or(0);

    debug_log(
        pamh,
        debug,
        &format!(
            "Reply from logind: id={id} runtime_path={runtime_path} seat={real_seat} vtnr={real_vtnr} original_uid={original_uid}"
        ),
    );

    update_environment(pamh, "XDG_SESSION_ID", &id)?;

    // We might have gotten type/class/desktop from module parameters rather
    // than the environment; export them so session processes can rely on them.
    update_environment(pamh, "XDG_SESSION_TYPE", &c.type_)?;
    update_environment(pamh, "XDG_SESSION_CLASS", &c.class)?;
    update_environment(pamh, "XDG_SESSION_DESKTOP", &c.desktop)?;
    update_environment(
        pamh,
        "XDG_SESSION_EXTRA_DEVICE_ACCESS",
        &c.extra_device_access.join(":"),
    )?;
    update_environment(pamh, "XDG_SEAT", &real_seat)?;
    if real_vtnr > 0 {
        update_environment(pamh, "XDG_VTNR", &real_vtnr.to_string())?;
    }

    // Don't set $XDG_RUNTIME_DIR if the user we authenticated for isn't the
    // session's original user, so privileged apps don't clobber it.
    let runtime_dir = (original_uid == uid && validate_runtime_directory(pamh, &runtime_path, uid))
        .then_some(runtime_path);

    crate::log::info(
        pamh,
        &format!(
            "New session {id} of user uid {uid} (class {}, type {}, seat {}, vt {real_vtnr}).",
            c.class,
            c.type_,
            if real_seat.is_empty() {
                "-"
            } else {
                &real_seat
            },
        ),
    );

    c.vtnr = real_vtnr;
    c.seat = real_seat;
    Ok(Some(Registered { runtime_dir }))
}

/// Propagate `shell.*` service credentials into the environment.
fn import_shell_credentials(pamh: &mut PamHandle, debug: bool) -> Result<(), PamStatus> {
    const PROPAGATE: [(&str, &str); 3] = [
        ("shell.prompt.prefix", "SHELL_PROMPT_PREFIX"),
        ("shell.prompt.suffix", "SHELL_PROMPT_SUFFIX"),
        ("shell.welcome", "SHELL_WELCOME"),
    ];

    let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") else {
        return Ok(());
    };
    for (credential, varname) in PROPAGATE {
        match fs::read_to_string(format!("{dir}/{credential}")) {
            Ok(value) => {
                if let Err(e) = pamh.putenv(&format!("{varname}={value}")) {
                    crate::log::error(
                        pamh,
                        &format!("Failed to set environment variable {varname}: {e}"),
                    );
                    return Err(status(PAM_SERVICE_ERR));
                }
            }
            Err(e) => debug_log(
                pamh,
                debug,
                &format!("Failed to read credential '{credential}', ignoring: {e}"),
            ),
        }
    }
    Ok(())
}

fn setup_environment(
    pamh: &mut PamHandle,
    user: &User,
    runtime_directory: Option<&str>,
) -> Result<(), PamStatus> {
    update_environment(pamh, "XDG_AREA", "")?;
    update_environment(pamh, "HOME", &user.home)?;

    let Some(runtime) = runtime_directory else {
        return Ok(());
    };
    update_environment(pamh, "XDG_RUNTIME_DIR", runtime)?;

    // Export the user bus address, matching what dbus.socket sets for the
    // user manager, but only if the socket is actually there.
    let bus = format!("{runtime}/bus");
    match fs::symlink_metadata(&bus) {
        Ok(_) => update_environment(
            pamh,
            "DBUS_SESSION_BUS_ADDRESS",
            &format!("unix:path={bus}"),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            crate::log::warn(
                pamh,
                &format!("Failed to check if {runtime}/bus exists, ignoring: {e}"),
            );
            Ok(())
        }
    }
}

// ---- hooks -----------------------------------------------------------------

fn open_session(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    match open_session_inner(pamh, args) {
        Ok(()) => status(PAM_SUCCESS),
        Err(s) => s,
    }
}

fn open_session_inner(pamh: &mut PamHandle, args: &[String]) -> Result<(), PamStatus> {
    let a = parse_argv(pamh, args);
    let debug = a.debug;
    debug_log(pamh, debug, "pam-systemd: initializing...");

    let user = acquire_user(pamh)?;

    let item = |pamh: &PamHandle, i: ItemType| pamh.get_item_str(i).unwrap_or("").to_string();
    let extra = getenv_harder(pamh, "XDG_SESSION_EXTRA_DEVICE_ACCESS", None);

    let mut c = SessionContext {
        service: item(pamh, ItemType::Service),
        display: item(pamh, ItemType::XDisplay),
        tty: item(pamh, ItemType::Tty),
        remote_user: item(pamh, ItemType::RUser),
        remote_host: item(pamh, ItemType::RHost),
        seat: getenv_harder(pamh, "XDG_SEAT", None).unwrap_or_default(),
        vtnr: getenv_harder_uint32(pamh, "XDG_VTNR", 0),
        type_: getenv_harder(pamh, "XDG_SESSION_TYPE", a.type_.as_deref()).unwrap_or_default(),
        class: getenv_harder(pamh, "XDG_SESSION_CLASS", a.class.as_deref()).unwrap_or_default(),
        desktop: getenv_harder(pamh, "XDG_SESSION_DESKTOP", a.desktop.as_deref())
            .unwrap_or_default(),
        area: getenv_harder(pamh, "XDG_AREA", a.area.as_deref()).unwrap_or_default(),
        incomplete: getenv_harder_bool(pamh, "XDG_SESSION_INCOMPLETE", false),
        extra_device_access: extra
            .map(|e| e.split(':').map(String::from).collect())
            .unwrap_or_default(),
        remote: false,
    };

    session_context_mangle(pamh, &mut c, user.uid, debug);

    let registered = register_session(pamh, &mut c, user.uid, debug)?;

    import_shell_credentials(pamh, debug)?;

    let runtime_dir = registered.as_ref().and_then(|r| r.runtime_dir.as_deref());
    setup_environment(pamh, &user, runtime_dir)
}

fn close_session(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let debug = parse_argv(pamh, args).debug;
    debug_log(pamh, debug, "pam-systemd: shutting down...");

    let Some(id) = pamh.getenv("XDG_SESSION_ID").map(String::from) else {
        return status(PAM_SUCCESS);
    };

    let mut s = match varlink_connect() {
        Ok(s) => s,
        Err(e) => {
            crate::log::error(
                pamh,
                &format!("Failed to connect to logind via Varlink: {e}"),
            );
            return status(PAM_SESSION_ERR);
        }
    };

    let params = Json::Obj(alloc::vec![("Id".into(), Json::Str(id))]);
    match varlink_call(&mut s, "io.systemd.Login.ReleaseSession", params) {
        Err(e) => {
            crate::log::error(
                pamh,
                &format!("Failed to issue io.systemd.Login.ReleaseSession varlink call: {e}"),
            );
            status(PAM_SERVICE_ERR)
        }
        Ok((Some(error), _)) => {
            crate::log::error(
                pamh,
                &format!("Varlink call io.systemd.Login.ReleaseSession failed: {error}"),
            );
            status(PAM_SERVICE_ERR)
        }
        Ok((None, _)) => status(PAM_SUCCESS),
    }
}

// ---- minimal JSON (Varlink payloads only) ----------------------------------

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    /// Kept as its literal text; converted on access.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn as_u32(&self) -> Option<u32> {
        match self {
            Json::Num(n) => n.parse().ok(),
            // sd-json accepts integers encoded as strings too.
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    fn encode(&self) -> String {
        let mut out = String::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => encode_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.encode_into(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    encode_str(k, out);
                    out.push(':');
                    v.encode_into(out);
                }
                out.push('}');
            }
        }
    }

    fn parse(text: &str) -> Result<Json, String> {
        let mut p = Parser {
            s: text.as_bytes(),
            pos: 0,
            depth: 0,
        };
        let v = p.value()?;
        p.ws();
        if p.pos != p.s.len() {
            return Err("trailing data after JSON reply".into());
        }
        Ok(v)
    }
}

fn encode_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), String> {
        if self.s[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(format!("invalid JSON at offset {}", self.pos))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.expect(b"true").map(|_| Json::Bool(true)),
            Some(b'f') => self.expect(b"false").map(|_| Json::Bool(false)),
            Some(b'n') => self.expect(b"null").map(|_| Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("invalid JSON at offset {}", self.pos)),
        }
    }

    fn nest(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > 64 {
            return Err("JSON nested too deeply".into());
        }
        Ok(())
    }

    fn object(&mut self) -> Result<Json, String> {
        self.nest()?;
        self.pos += 1;
        let mut fields = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key at offset {}", self.pos));
            }
            let k = self.string()?;
            self.ws();
            self.expect(b":")?;
            let v = self.value()?;
            fields.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.nest()?;
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at offset {}", self.pos)),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos += 1;
        }
        let text = core::str::from_utf8(&self.s[start..self.pos]).map_err(|_| "bad number")?;
        Ok(Json::Num(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self
            .s
            .get(self.pos..self.pos + 4)
            .ok_or("truncated \\u escape")?;
        let h = core::str::from_utf8(h).map_err(|_| "bad \\u escape")?;
        let v = u32::from_str_radix(h, 16).map_err(|_| "bad \\u escape")?;
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while !matches!(self.peek(), Some(b'"' | b'\\') | None) {
                self.pos += 1;
            }
            out.push_str(core::str::from_utf8(&self.s[start..self.pos]).map_err(|_| "bad UTF-8")?);
            match self.peek() {
                None => return Err("unterminated JSON string".into()),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                _ => {}
            }
            self.pos += 1;
            let esc = self.peek().ok_or("truncated escape")?;
            self.pos += 1;
            match esc {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let mut cp = self.hex4()?;
                    if (0xd800..0xdc00).contains(&cp) {
                        self.expect(b"\\u")?;
                        let lo = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&lo) {
                            return Err("bad surrogate pair".into());
                        }
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    }
                    out.push(char::from_u32(cp).ok_or("bad \\u escape")?);
                }
                _ => return Err(format!("bad escape at offset {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let v = Json::parse(
            r#"{"parameters":{"Id":"c1","RuntimePath":"/run/user/199","UID":199,"Seat":"seat0","VTNr":1,"Class":"greeter","Type":"tty"}}"#,
        )
        .unwrap();
        let p = v.get("parameters").unwrap();
        assert_eq!(p.get("Id").and_then(Json::as_str), Some("c1"));
        assert_eq!(p.get("UID").and_then(Json::as_u32), Some(199));
        assert_eq!(p.get("VTNr").and_then(Json::as_u32), Some(1));

        let e = Json::parse(r#"{"error":"io.systemd.Login.AlreadySessionMember","parameters":{}}"#)
            .unwrap();
        assert_eq!(
            e.get("error").and_then(Json::as_str),
            Some("io.systemd.Login.AlreadySessionMember")
        );

        let s = Json::Obj(alloc::vec![(
            "k".into(),
            Json::Str("a\"b\\c\n\u{1}".into())
        )]);
        let back = Json::parse(&s.encode()).unwrap();
        assert_eq!(back.get("k").and_then(Json::as_str), Some("a\"b\\c\n\u{1}"));
        assert_eq!(Json::parse(r#""😀""#).unwrap().as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn helpers() {
        assert_eq!(vtnr_from_tty("tty1"), Some(1));
        assert_eq!(vtnr_from_tty("tty64"), None);
        assert_eq!(vtnr_from_tty("ttyS0"), None);
        assert!(is_localhost("LOCALHOST."));
        assert!(is_localhost("foo.localhost"));
        assert!(!is_localhost("example.com"));
        assert_eq!(skip_dev_prefix("/dev/tty2"), "tty2");
        assert!(display_is_local(":0"));
        assert!(!display_is_local("host:0"));
        assert_eq!(parse_boolean("Yes"), Some(true));
        assert!(!filename_is_valid(".."));
    }
}
