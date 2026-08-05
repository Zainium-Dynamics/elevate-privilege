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
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

use crate::constants::*;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};
use crate::types::ItemType;

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

    // use_first_pass: only ever use an already-set AUTHTOK item (from an
    // earlier module in the same auth stack) -- never converse for one.
    // try_first_pass is the default behavior of get_authtok() already
    // (reuse if set, prompt otherwise), so it needs no special handling.
    let tok = if arg_has(args, "use_first_pass") {
        match pamh.get_item_str(ItemType::AuthTok) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => return PamStatus::new(PAM_AUTH_ERR),
        }
    } else {
        match pamh.get_authtok(None) {
            Ok(t) => t,
            Err(e) => return e.to_status(),
        }
    };

    if tok.is_empty() && (flags & PAM_DISALLOW_NULL_AUTHTOK != 0) {
        return PamStatus::new(PAM_AUTH_ERR);
    }

    let result = verify_password(&tok, &hash);
    if arg_has(args, "debug") {
        crate::log::debug(pamh, &format!("unix: authenticate('{user}') -> {result:?}"));
    }
    match result {
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

/// Real password-change flow, matching upstream `pam_unix`'s two-call
/// protocol (`PAM_PRELIM_CHECK` then `PAM_UPDATE_AUTHTOK`).
///
/// Supported args: `nullok`/`nullok_secure`, `use_authtok`, `use_first_pass`,
/// `minlen=N`, `remember=N` (history, see `opasswd_file()`),
/// `blowfish`/`bcrypt` (+ `rounds=N` as bcrypt cost), `debug`, `quiet`.
/// Not supported (documented, not silent): `sha256`/`sha512`/`md5`/
/// `yescrypt` hash-algorithm selection for *creating* new hashes --
/// elevate-crypto's sha-crypt backend is explicitly verification-only (see
/// its module doc); new hashes always go through argon2id
/// (`elevate_crypto::hash_password`, this project's `password_preferred`)
/// unless `blowfish`/`bcrypt` is requested. Also not supported: `audit`,
/// `nodelay`, `broken_shadow`, `authtok_type=`, `nis`.
fn chauthtok(pamh: &mut PamHandle, flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };
    let debug = arg_has(args, "debug");
    let quiet = arg_has(args, "quiet");

    if flags & PAM_PRELIM_CHECK != 0 {
        if user == "root" {
            // Upstream: root may change any password without proving the old one.
            return PamStatus::new(PAM_SUCCESS);
        }
        let hash = match password_hash(&user) {
            Ok(Some(h)) => h,
            Ok(None) => return PamStatus::new(PAM_USER_UNKNOWN),
            Err(_) => return PamStatus::new(PAM_AUTHINFO_UNAVAIL),
        };
        if hash.is_empty() && (arg_has(args, "nullok") || arg_has(args, "nullok_secure")) {
            return PamStatus::new(PAM_SUCCESS);
        }

        let old = if arg_has(args, "use_first_pass") || arg_has(args, "use_authtok") {
            match pamh.get_item_str(ItemType::AuthTok) {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => return PamStatus::new(PAM_AUTHTOK_RECOVERY_ERR),
            }
        } else {
            match crate::conv::conv_echo_off(pamh.conv(), "(current) UNIX password: ") {
                Ok(t) => t,
                Err(_) => return PamStatus::new(PAM_AUTHTOK_RECOVERY_ERR),
            }
        };

        return match verify_password(&old, &hash) {
            Ok(true) => {
                let _ = pamh.set_item_str(ItemType::OldAuthTok, Some(&old));
                PamStatus::new(PAM_SUCCESS)
            }
            Ok(false) => PamStatus::new(PAM_AUTH_ERR),
            Err(_) => PamStatus::new(PAM_AUTHINFO_UNAVAIL),
        };
    }

    if flags & PAM_UPDATE_AUTHTOK == 0 {
        // Called with neither phase flag: nothing to do.
        return PamStatus::new(PAM_AUTHTOK_ERR);
    }

    let new_plain = if arg_has(args, "use_authtok") {
        match pamh.get_item_str(ItemType::AuthTok) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => return PamStatus::new(PAM_AUTHTOK_RECOVERY_ERR),
        }
    } else {
        let first = match crate::conv::conv_echo_off(pamh.conv(), "New UNIX password: ") {
            Ok(t) => t,
            Err(_) => return PamStatus::new(PAM_AUTHTOK_ERR),
        };
        let second = match crate::conv::conv_echo_off(pamh.conv(), "Retype new UNIX password: ") {
            Ok(t) => t,
            Err(_) => return PamStatus::new(PAM_AUTHTOK_ERR),
        };
        if first != second {
            if !quiet {
                crate::log::warn(pamh, "unix: password mismatch on retype");
            }
            return PamStatus::new(PAM_AUTHTOK_ERR);
        }
        first
    };

    let minlen: usize = arg_value(args, "minlen")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if new_plain.len() < minlen {
        if !quiet {
            crate::log::warn(
                pamh,
                &format!("unix: new password shorter than minlen={minlen}"),
            );
        }
        return PamStatus::new(PAM_AUTHTOK_ERR);
    }

    let remember: usize = arg_value(args, "remember")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if remember > 0 && password_in_history(&user, &new_plain) {
        if !quiet {
            crate::log::warn(pamh, "unix: new password matches a recently used password");
        }
        return PamStatus::new(PAM_AUTHTOK_ERR);
    }

    let new_hash = match hash_new_password(&new_plain, args) {
        Ok(h) => h,
        Err(_) => return PamStatus::new(PAM_AUTHTOK_ERR),
    };

    if let Err(e) = write_shadow_hash(&user, &new_hash) {
        crate::log::error(
            pamh,
            &format!("unix: failed to update shadow for '{user}': {e}"),
        );
        return PamStatus::new(PAM_AUTHTOK_ERR);
    }
    if remember > 0 {
        if let Err(e) = record_password_history(&user, &new_hash, remember) {
            crate::log::warn(
                pamh,
                &format!("unix: failed to update password history: {e}"),
            );
        }
    }
    if debug {
        crate::log::debug(pamh, &format!("unix: password updated for '{user}'"));
    }
    PamStatus::new(PAM_SUCCESS)
}

fn hash_new_password(plain: &str, args: &[String]) -> Result<String, ()> {
    #[cfg(feature = "elevate_crypto")]
    {
        if arg_has(args, "blowfish") || arg_has(args, "bcrypt") {
            let cost: u32 = arg_value(args, "rounds")
                .and_then(|s| s.parse().ok())
                .unwrap_or(12);
            return elevate_crypto::hash_password_bcrypt(plain, cost).map_err(|_| ());
        }
        elevate_crypto::hash_password(plain).map_err(|_| ())
    }
    #[cfg(not(feature = "elevate_crypto"))]
    {
        let _ = args;
        let _ = plain;
        Err(())
    }
}

/// Lock file guarding concurrent shadow writes (create_new sidecar, same
/// convention as `elevate-umbra`'s `FileLock`). A handful of short retries
/// tolerate a lock briefly held by a concurrent `passwd`/PAM transaction.
struct ShadowLock {
    lock_path: String,
}

impl ShadowLock {
    fn acquire(target_path: &str) -> Result<Self, String> {
        let lock_path = format!("{target_path}.lock");
        for attempt in 0..10 {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(Self { lock_path }),
                Err(_) if attempt < 9 => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => return Err(format!("cannot lock {lock_path}: {e}")),
            }
        }
        Err(format!("cannot lock {lock_path}: timed out"))
    }
}

impl Drop for ShadowLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn write_shadow_hash(user: &str, new_hash: &str) -> Result<(), String> {
    let path = elevate_paths::get().shadow_file();
    let _lock = ShadowLock::acquire(&path)?;

    let text = fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let today = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / 86_400) as i64;

    let out = rewrite_shadow_text(&text, user, new_hash, today)
        .ok_or_else(|| format!("user '{user}' not found in {path}"))?;
    fs::write(&path, &out).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

/// Replace `user`'s hash (field 1) and `lstchg` (field 2) in shadow(5)
/// text, preserving every other field/line verbatim. `None` if `user`
/// isn't present. Pure and filesystem-free so it's directly unit-testable.
fn rewrite_shadow_text(text: &str, user: &str, new_hash: &str, today: i64) -> Option<String> {
    let mut found = false;
    let mut out = String::with_capacity(text.len() + new_hash.len());
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&user) && fields.len() >= 9 {
            found = true;
            let mut rebuilt: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
            rebuilt[1] = new_hash.to_string();
            rebuilt[2] = today.to_string();
            out.push_str(&rebuilt.join(":"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    found.then_some(out)
}

/// Parse `opasswd(5)`-style text (`user:hash1,hash2,...` per line) and
/// return `user`'s stored hashes, most recent first. Pure and
/// filesystem-free so it's directly unit-testable.
fn opasswd_hashes_for<'a>(text: &'a str, user: &str) -> Vec<&'a str> {
    for line in text.lines() {
        if let Some((name, hashes)) = line.split_once(':') {
            if name == user {
                return hashes
                    .split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

fn password_in_history(user: &str, plain: &str) -> bool {
    let path = elevate_paths::get().opasswd_file();
    let Ok(text) = fs::read_to_string(&path) else {
        return false;
    };
    for h in opasswd_hashes_for(&text, user) {
        #[cfg(feature = "elevate_crypto")]
        if elevate_crypto::verify_password(plain, h).unwrap_or(false) {
            return true;
        }
        #[cfg(not(feature = "elevate_crypto"))]
        let _ = h;
    }
    false
}

/// Insert `new_hash` at the front of `user`'s history, capped at
/// `remember` entries, rewriting the full opasswd(5) text. Pure and
/// filesystem-free so it's directly unit-testable.
fn opasswd_update_text(text: &str, user: &str, new_hash: &str, remember: usize) -> String {
    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some((name, hashes)) = line.split_once(':') {
            entries.push((
                name.to_string(),
                hashes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            ));
        }
    }

    let mut found = false;
    for (name, hashes) in entries.iter_mut() {
        if name == user {
            found = true;
            hashes.insert(0, new_hash.to_string());
            hashes.truncate(remember);
        }
    }
    if !found {
        entries.push((user.to_string(), vec![new_hash.to_string()]));
    }

    let mut out = String::new();
    for (name, hashes) in &entries {
        out.push_str(name);
        out.push(':');
        out.push_str(&hashes.join(","));
        out.push('\n');
    }
    out
}

fn record_password_history(user: &str, new_hash: &str, remember: usize) -> Result<(), String> {
    let path = elevate_paths::get().opasswd_file();
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let out = opasswd_update_text(&existing, user, new_hash, remember);

    if let Some(parent) = std::path::Path::new(&path).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(())
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
        let hash = CStr::from_ptr((*pw).pw_passwd)
            .to_string_lossy()
            .into_owned();
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
    for line in reader.lines().map_while(Result::ok) {
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
        elevate_crypto::ct_eq(a, b)
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

#[cfg(test)]
mod tests {
    use super::*;

    const SHADOW: &str = "\
alice:$argon2id$old:19000:0:99999:7:::\n\
bob:$argon2id$otherhash:19000:0:99999:7:::\n\
# a comment line, preserved verbatim\n\
charlie:!:19000:0:99999:7:::\n";

    #[test]
    fn rewrite_shadow_text_replaces_hash_and_lstchg_only() {
        let out = rewrite_shadow_text(SHADOW, "bob", "$argon2id$newhash", 19500).unwrap();
        let bob_line = out.lines().find(|l| l.starts_with("bob:")).unwrap();
        assert_eq!(bob_line, "bob:$argon2id$newhash:19500:0:99999:7:::");
        // Untouched lines (including the comment) survive verbatim.
        assert!(out.contains("alice:$argon2id$old:19000:0:99999:7:::"));
        assert!(out.contains("# a comment line, preserved verbatim"));
        assert!(out.contains("charlie:!:19000:0:99999:7:::"));
    }

    #[test]
    fn rewrite_shadow_text_none_for_unknown_user() {
        assert!(rewrite_shadow_text(SHADOW, "nobody", "x", 1).is_none());
    }

    #[test]
    fn rewrite_shadow_text_ignores_short_malformed_lines() {
        // Fewer than 9 fields: line is passed through, not treated as a match.
        let text = "bob:onlytwofields\n";
        assert!(rewrite_shadow_text(text, "bob", "newhash", 1).is_none());
    }

    #[test]
    fn opasswd_hashes_for_parses_and_splits() {
        let text = "alice:h1,h2,h3\nbob:h4\n";
        assert_eq!(opasswd_hashes_for(text, "alice"), vec!["h1", "h2", "h3"]);
        assert_eq!(opasswd_hashes_for(text, "bob"), vec!["h4"]);
        assert!(opasswd_hashes_for(text, "nobody").is_empty());
    }

    #[test]
    fn opasswd_update_text_prepends_and_caps_at_remember() {
        let text = "alice:h1,h2\n";
        let out = opasswd_update_text(text, "alice", "h3", 2);
        assert_eq!(opasswd_hashes_for(&out, "alice"), vec!["h3", "h1"]);
    }

    #[test]
    fn opasswd_update_text_creates_new_user_entry() {
        let out = opasswd_update_text("", "alice", "h1", 3);
        assert_eq!(opasswd_hashes_for(&out, "alice"), vec!["h1"]);
    }

    #[test]
    fn opasswd_update_text_leaves_other_users_untouched() {
        let text = "alice:h1\nbob:h2,h3\n";
        let out = opasswd_update_text(text, "alice", "h_new", 5);
        assert_eq!(opasswd_hashes_for(&out, "bob"), vec!["h2", "h3"]);
    }

    #[test]
    fn hash_new_password_default_is_not_bcrypt_prefixed() {
        let h = hash_new_password("correct horse battery staple", &[]).unwrap();
        assert!(
            !h.starts_with("$2"),
            "default hash should be argon2id, not bcrypt: {h}"
        );
    }

    #[test]
    fn hash_new_password_bcrypt_arg_produces_bcrypt_hash() {
        let args = vec!["bcrypt".to_string(), "rounds=4".to_string()];
        let h = hash_new_password("correct horse battery staple", &args).unwrap();
        assert!(h.starts_with("$2"), "expected a bcrypt hash, got: {h}");
    }
}
