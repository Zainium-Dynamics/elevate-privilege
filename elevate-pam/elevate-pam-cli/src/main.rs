//! Standalone elevate-pam CLI — authenticate a user against a service stack.
//!
//! Build category: **standalone** (modules embedded via builtins).

use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::os::raw::{c_int, c_void};
use std::ptr;

use elevate_pam::appl::PamBuilder;
use elevate_pam::config::{BuildCategory, BuildConfig, GlobalConfig};
use elevate_pam::constants::*;
use elevate_pam::conv::{CPamMessage, CPamResponse, PamConv};

fn usage() {
    eprintln!(
        "elevate-pam {ver} — production PAM (TOML, shared/static/standalone)\n\
         \n\
         Usage:\n\
           elevate-pam check <service> [user]\n\
           elevate-pam version\n\
           elevate-pam categories\n\
         \n\
         Config: TOML only (see elevate-pam.toml and /etc/elevate-pam/services/*.toml)",
        ver = elevate_pam::VERSION
    );
}

extern "C" fn cli_conv(
    num_msg: c_int,
    msg: *mut *const CPamMessage,
    resp: *mut *mut CPamResponse,
    _appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    let table = unsafe {
        libc::calloc(n, core::mem::size_of::<CPamResponse>()) as *mut CPamResponse
    };
    if table.is_null() {
        return PAM_BUF_ERR;
    }

    for i in 0..n {
        let m = unsafe { &**msg.add(i) };
        let text = if m.msg.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(m.msg) }
                .to_string_lossy()
                .into_owned()
        };
        let answer = match m.msg_style {
            PAM_PROMPT_ECHO_OFF => {
                eprint!("{text}");
                let _ = io::stderr().flush();
                match rpassword_read() {
                    Ok(s) => s,
                    Err(_) => {
                        free_resp_table(table, i);
                        return PAM_CONV_ERR;
                    }
                }
            }
            PAM_PROMPT_ECHO_ON => {
                eprint!("{text}");
                let _ = io::stderr().flush();
                let mut line = String::new();
                if io::stdin().read_line(&mut line).is_err() {
                    free_resp_table(table, i);
                    return PAM_CONV_ERR;
                }
                line.trim_end_matches(['\n', '\r']).to_string()
            }
            PAM_ERROR_MSG => {
                eprintln!("{text}");
                String::new()
            }
            PAM_TEXT_INFO => {
                eprintln!("{text}");
                String::new()
            }
            _ => String::new(),
        };
        let c = match CString::new(answer) {
            Ok(c) => c,
            Err(_) => {
                free_resp_table(table, i);
                return PAM_CONV_ERR;
            }
        };
        unsafe {
            (*table.add(i)).resp = c.into_raw();
            (*table.add(i)).resp_retcode = 0;
        }
    }
    unsafe {
        *resp = table;
    }
    PAM_SUCCESS
}

fn free_resp_table(table: *mut CPamResponse, upto: usize) {
    for i in 0..upto {
        unsafe {
            let r = *table.add(i);
            if !r.resp.is_null() {
                let _ = CString::from_raw(r.resp);
            }
        }
    }
    unsafe {
        libc::free(table as *mut c_void);
    }
}

fn rpassword_read() -> io::Result<String> {
    // Minimal no-echo read via termios
    use std::os::fd::AsRawFd;
    let fd = io::stdin().as_raw_fd();
    let mut old = unsafe { core::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        // not a tty — read with echo
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    let mut new = old;
    new.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    unsafe {
        libc::tcsetattr(fd, libc::TCSAFLUSH, &new);
    }
    let mut line = String::new();
    let res = io::stdin().read_line(&mut line);
    unsafe {
        libc::tcsetattr(fd, libc::TCSAFLUSH, &old);
    }
    eprintln!();
    res?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        std::process::exit(2);
    }
    match args[0].as_str() {
        "version" | "-V" | "--version" => {
            println!(
                "elevate-pam {} (Linux-PAM ABI {}.{})",
                elevate_pam::VERSION,
                elevate_pam::LINUX_PAM_COMPAT_MAJOR,
                elevate_pam::LINUX_PAM_COMPAT_MINOR
            );
        }
        "categories" => {
            let g = GlobalConfig::load_default();
            println!("shared     = {}", g.build.shared);
            println!("static     = {}", g.build.static_);
            println!("standalone = {}", g.build.standalone);
            println!("primary    = {:?}", g.build.primary_category());
        }
        "check" => {
            if args.len() < 2 {
                usage();
                std::process::exit(2);
            }
            let service = args[1].clone();
            let user = args.get(2).cloned();
            let mut global = GlobalConfig::load_default();
            // standalone category for CLI
            global.build = BuildConfig {
                shared: false,
                static_: false,
                standalone: true,
            };
            assert_eq!(global.build.primary_category(), BuildCategory::Standalone);

            // Prefer local config/services during dev
            if std::path::Path::new("config/services").is_dir() {
                global.paths.services_dir = "config/services".into();
                global.paths.conf_dir = "config".into();
            }

            let conv = PamConv {
                conv: Some(cli_conv),
                appdata_ptr: ptr::null_mut(),
            };
            let mut builder = PamBuilder::new(service).global(global);
            if let Some(u) = user {
                builder = builder.user(u);
            }
            let mut pamh = match builder.start(conv) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("pam_start failed: {e}");
                    std::process::exit(1);
                }
            };
            match pamh.authenticate(0) {
                Ok(()) => {
                    if let Err(e) = pamh.acct_mgmt(0) {
                        eprintln!("account: {e}");
                        std::process::exit(1);
                    }
                    println!("OK");
                    let _ = pamh.end(PAM_SUCCESS);
                }
                Err(e) => {
                    eprintln!("auth failed: {e}");
                    let _ = pamh.end(PAM_AUTH_ERR);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}
