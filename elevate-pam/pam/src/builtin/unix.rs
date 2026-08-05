//! Builtin `unix` module — shadow/passwd authentication.
//!
//! Production path:
//! 1. Resolve user via `getpwnam`
//! 2. Read password hash from shadow (`getspnam`) when available
//! 3. Verify with `crypt` (libcrypt) for $y$, $6$, $5$, $1$, …
//! 4. Account aging checks on `acct_mgmt`

use alloc::string::{String, ToString};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{BufRead, BufReader};

use crate::constants::*;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("unix"),
        authenticate: Some(authenticate),
        setcred: Some(setcred),
        acct_mgmt: Some(acct_mgmt),
        open_session: Some(session_ok),
        close_session: Some(session_ok),
        chauthtok: Some(chauthtok),
    }
}

fn authenticate(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };

    if user.starts_with('+') || user.starts_with('-') {
        return PamStatus::new(PAM_USER_UNKNOWN);
    }

    let hash = match password_hash(&user) {
        Ok(Some(h)) => h,
        Ok(None) => return PamStatus::new(PAM_USER_UNKNOWN),
        Err(_) => return PamStatus::new(PAM_AUTHINFO_UNAVAIL),
    };

    // Locked account: hash starts with ! or *
    if hash.starts_with('!') || hash.starts_with('*') {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    // Empty password
    if hash.is_empty() {
        if flags & PAM_DISALLOW_NULL_AUTHTOK != 0 {
            return PamStatus::new(PAM_AUTH_ERR);
        }
        // nullok
        if arg_has(args, "nullok") || arg_has(args, "nullok_secure") {
            return PamStatus::new(PAM_SUCCESS);
        }
        return PamStatus::new(PAM_AUTH_ERR);
    }

    let tok = match pamh.get_authtok(None) {
        Ok(t) => t,
        Err(e) => return e.to_status(),
    };

    if tok.is_empty() && (flags & PAM_DISALLOW_NULL_AUTHTOK != 0) {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    match verify_password(&tok, &hash) {
        Ok(true) => PamStatus::new(PAM_SUCCESS),
        Ok(false) => PamStatus::new(PAM_AUTH_ERR),
        Err(_) => PamStatus::new(PAM_AUTHINFO_UNAVAIL),
    }
}

fn setcred(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    PamStatus::new(PAM_SUCCESS)
}

fn acct_mgmt(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };
    match account_status(&user) {
        AccountStatus::Ok => PamStatus::new(PAM_SUCCESS),
        AccountStatus::Expired => PamStatus::new(PAM_ACCT_EXPIRED),
        AccountStatus::NewAuthTok => PamStatus::new(PAM_NEW_AUTHTOK_REQD),
        AccountStatus::Unknown => PamStatus::new(PAM_USER_UNKNOWN),
        AccountStatus::Error => PamStatus::new(PAM_AUTHINFO_UNAVAIL),
    }
}

fn session_ok(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    PamStatus::new(PAM_SUCCESS)
}

fn chauthtok(_pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    // Full password change requires setuid helpers; report not implemented
    // for the builtin stub — pam-unix crate can provide full support.
    PamStatus::new(PAM_AUTHTOK_ERR)
}

enum AccountStatus {
    Ok,
    Expired,
    NewAuthTok,
    Unknown,
    #[allow(dead_code)]
    Error,
}

fn password_hash(user: &str) -> Result<Option<String>, ()> {
    // Prefer shadow
    if let Some(h) = read_shadow_hash(user)? {
        return Ok(Some(h));
    }
    // Fallback passwd
    read_passwd_hash(user)
}

fn read_shadow_hash(user: &str) -> Result<Option<String>, ()> {
    parse_colon_file(&elevate_paths::get().shadow_file(), user, 1)
}

fn read_passwd_hash(user: &str) -> Result<Option<String>, ()> {
    let c_user = CString::new(user).map_err(|_| ())?;
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            return parse_colon_file(&elevate_paths::get().passwd_file(), user, 1);
        }
        let hash = CStr::from_ptr((*pw).pw_passwd).to_string_lossy().into_owned();
        if hash == "x" || hash == "*" {
            return parse_colon_file(&elevate_paths::get().shadow_file(), user, 1);
        }
        Ok(Some(hash))
    }
}

fn parse_colon_file(path: &str, user: &str, field: usize) -> Result<Option<String>, ()> {
    let f = fs::File::open(path).map_err(|_| ())?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line.map_err(|_| ())?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        if name != user {
            continue;
        }
        let mut val = None;
        for (i, p) in parts.enumerate() {
            if i + 1 == field {
                val = Some(p.to_string());
                break;
            }
        }
        return Ok(val);
    }
    Ok(None)
}

fn account_status(user: &str) -> AccountStatus {
    let shadow_path = elevate_paths::get().shadow_file();
    let Ok(f) = fs::File::open(&shadow_path) else {
        // no shadow — if user exists in passwd, ok
        return if user_exists_passwd(user) {
            AccountStatus::Ok
        } else {
            AccountStatus::Unknown
        };
    };
    let reader = BufReader::new(f);
    for line in reader.lines().flatten() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first().copied() != Some(user) {
            continue;
        }
        // expire field (index 7), days since epoch
        if fields.len() > 7 && !fields[7].is_empty() {
            if let Ok(expire_days) = fields[7].parse::<i64>() {
                let now_days = now_days_since_epoch();
                if expire_days >= 0 && now_days > expire_days {
                    return AccountStatus::Expired;
                }
            }
        }
        // password aging: lstchg (2), max (4)
        if fields.len() > 4 {
            let lstchg: i64 = fields[2].parse().unwrap_or(-1);
            let max: i64 = fields[4].parse().unwrap_or(-1);
            if lstchg >= 0 && max > 0 {
                let now = now_days_since_epoch();
                if now > lstchg + max {
                    return AccountStatus::NewAuthTok;
                }
            }
        }
        return AccountStatus::Ok;
    }
    if user_exists_passwd(user) {
        AccountStatus::Ok
    } else {
        AccountStatus::Unknown
    }
}

fn user_exists_passwd(user: &str) -> bool {
    let Ok(c) = CString::new(user) else {
        return false;
    };
    unsafe { !libc::getpwnam(c.as_ptr()).is_null() }
}

fn now_days_since_epoch() -> i64 {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ts / 86_400
}

/// Verify password — **elevate-crypto** first (Argon2/bcrypt/legacy + OpenSSL RNG),
/// then system `crypt(3)` for exotic shadow formats.
fn verify_password(plain: &str, hash: &str) -> Result<bool, ()> {
    #[cfg(feature = "elevate_crypto")]
    {
        if let Ok(v) = elevate_crypto::verify_password(plain, hash) {
            return Ok(v);
        }
    }

    let c_plain = CString::new(plain).map_err(|_| ())?;
    let c_hash = CString::new(hash).map_err(|_| ())?;

    extern "C" {
        fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
    }

    unsafe {
        let result = crypt(c_plain.as_ptr(), c_hash.as_ptr());
        if result.is_null() {
            return Ok(false);
        }
        let out = CStr::from_ptr(result).to_string_lossy();
        Ok(ct_eq_bytes(out.as_bytes(), hash.as_bytes()))
    }
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    #[cfg(feature = "elevate_crypto")]
    {
        return elevate_crypto::ct_eq(a, b);
    }
    #[cfg(not(feature = "elevate_crypto"))]
    {
        if a.len() != b.len() {
            return false;
        }
        let mut v = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            v |= x ^ y;
        }
        v == 0
    }
}
