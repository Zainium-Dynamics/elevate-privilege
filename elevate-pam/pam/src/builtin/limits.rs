//! pam_limits — apply resource limits from limits.conf (session open).

use alloc::string::String;
use std::fs;
use std::io::{BufRead, BufReader};

use crate::constants::{PAM_SESSION_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("limits"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(open_session),
        close_session: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        chauthtok: None,
    }
}

fn open_session(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let default_conf = elevate_paths::get().limits_conf();
    let conf = arg_value(args, "conf").unwrap_or(&default_conf);
    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };

    if let Err(e) = apply_limits(&user, conf) {
        crate::log::warn(pamh, &format!("limits: {e}"));
        // non-fatal by default
        if args.iter().any(|a| a == "fatal") {
            return PamStatus::new(PAM_SESSION_ERR);
        }
    }
    PamStatus::new(PAM_SUCCESS)
}

fn apply_limits(user: &str, conf: &str) -> Result<(), String> {
    let f = fs::File::open(conf).map_err(|e| e.to_string())?;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let domain = parts[0];
        if domain != "*" && domain != user && !domain.starts_with('@') {
            continue;
        }
        // @group matching skipped for brevity unless domain == user or *
        let limit_type = parts[1]; // soft/hard/-
        let item = parts[2];
        let value = parts[3];
        if let Err(e) = set_one_limit(limit_type, item, value) {
            // continue other limits
            let _ = e;
        }
    }
    Ok(())
}

fn set_one_limit(limit_type: &str, item: &str, value: &str) -> Result<(), String> {
    let resource = match item {
        "nofile" => libc::RLIMIT_NOFILE,
        "nproc" => libc::RLIMIT_NPROC,
        "fsize" => libc::RLIMIT_FSIZE,
        "data" => libc::RLIMIT_DATA,
        "stack" => libc::RLIMIT_STACK,
        "core" => libc::RLIMIT_CORE,
        "rss" => libc::RLIMIT_RSS,
        "as" | "memlock" => {
            if item == "memlock" {
                libc::RLIMIT_MEMLOCK
            } else {
                libc::RLIMIT_AS
            }
        }
        "cpu" => libc::RLIMIT_CPU,
        _ => return Ok(()), // unsupported item — ignore
    };

    let val: u64 = if value == "unlimited" || value == "infinity" {
        libc::RLIM_INFINITY
    } else {
        value
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?
    };

    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::getrlimit(resource, &mut rlim) != 0 {
            return Err("getrlimit failed".into());
        }
    }

    match limit_type {
        "soft" => rlim.rlim_cur = val as libc::rlim_t,
        "hard" => rlim.rlim_max = val as libc::rlim_t,
        "-" => {
            rlim.rlim_cur = val as libc::rlim_t;
            rlim.rlim_max = val as libc::rlim_t;
        }
        _ => return Ok(()),
    }

    // ensure soft <= hard when both finite
    if rlim.rlim_max != libc::RLIM_INFINITY && rlim.rlim_cur > rlim.rlim_max {
        rlim.rlim_cur = rlim.rlim_max;
    }

    unsafe {
        if libc::setrlimit(resource, &rlim) != 0 {
            return Err(format!("setrlimit {item} failed"));
        }
    }
    Ok(())
}
