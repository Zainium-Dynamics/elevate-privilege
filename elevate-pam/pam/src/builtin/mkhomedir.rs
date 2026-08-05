//! pam_mkhomedir — create a user's home directory (from skel) at session
//! open, if it doesn't already exist. See `pam_mkhomedir(8)`.

use alloc::string::String;
use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::constants::{PAM_SESSION_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("mkhomedir"),
        authenticate: None,
        setcred: None,
        acct_mgmt: None,
        open_session: Some(create_home),
        close_session: None,
        chauthtok: None,
    }
}

struct Passwd {
    dir: String,
    uid: u32,
    gid: u32,
}

fn lookup_passwd(user: &str) -> Option<Passwd> {
    let c_user = std::ffi::CString::new(user).ok()?;
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            return None;
        }
        let dir = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        Some(Passwd {
            dir,
            uid: (*pw).pw_uid,
            gid: (*pw).pw_gid,
        })
    }
}

fn create_home(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let silent = arg_has(args, "silent");
    let debug = arg_has(args, "debug");

    let user = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_SUCCESS),
    };

    let Some(pw) = lookup_passwd(&user) else {
        return PamStatus::new(PAM_SUCCESS);
    };

    let home = PathBuf::from(&pw.dir);
    if home.as_os_str().is_empty() || home.exists() {
        return PamStatus::new(PAM_SUCCESS);
    }

    let umask: u32 = arg_value(args, "umask")
        .and_then(|s| u32::from_str_radix(s, 8).ok())
        .unwrap_or(0o022);
    let skel = arg_value(args, "skel")
        .map(String::from)
        .unwrap_or_else(|| elevate_paths::get().skel_dir());
    let mode = 0o777 & !umask;

    if let Err(e) = build_home(&home, Path::new(&skel), pw.uid, pw.gid, mode) {
        crate::log::warn(pamh, &format!("mkhomedir: {e}"));
        if arg_has(args, "fatal") {
            return PamStatus::new(PAM_SESSION_ERR);
        }
        return PamStatus::new(PAM_SUCCESS);
    }

    if !silent {
        crate::log::info(
            pamh,
            &format!("mkhomedir: created home directory for '{user}'"),
        );
    }
    if debug {
        crate::log::debug(pamh, &format!("mkhomedir: skel={skel} umask={umask:04o}"));
    }
    PamStatus::new(PAM_SUCCESS)
}

fn build_home(home: &Path, skel: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    fs::create_dir_all(home).map_err(|e| format!("mkdir {}: {e}", home.display()))?;
    fs::set_permissions(home, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", home.display()))?;
    chown(home, uid, gid)?;

    if skel.is_dir() {
        copy_skel(skel, home, uid, gid)?;
    }
    Ok(())
}

fn copy_skel(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let entries = fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("readdir: {e}"))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {}: {e}", src_path.display()))?;

        if meta.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| format!("mkdir {}: {e}", dst_path.display()))?;
            let mode = meta.permissions().mode() & 0o7777;
            fs::set_permissions(&dst_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {e}", dst_path.display()))?;
            chown(&dst_path, uid, gid)?;
            copy_skel(&src_path, &dst_path, uid, gid)?;
        } else if meta.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|e| {
                format!("copy {} -> {}: {e}", src_path.display(), dst_path.display())
            })?;
            let mode = meta.permissions().mode() & 0o7777;
            fs::set_permissions(&dst_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {e}", dst_path.display()))?;
            chown(&dst_path, uid, gid)?;
        } else if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(&src_path) {
                let _ = std::os::unix::fs::symlink(&target, &dst_path);
                lchown(&dst_path, uid, gid)?;
            }
        }
    }
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "invalid path".to_string())?;
    // SAFETY: c_path is a valid NUL-terminated string for the lifetime of this call.
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        Err(format!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn lchown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "invalid path".to_string())?;
    // SAFETY: c_path is a valid NUL-terminated string for the lifetime of this call.
    let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        Err(format!(
            "lchown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_home_creates_dir_mode_and_copies_skel() {
        let base = tempfile::tempdir().unwrap();
        let skel = base.path().join("skel");
        fs::create_dir_all(skel.join("subdir")).unwrap();
        fs::write(skel.join(".bashrc"), b"# hi\n").unwrap();
        fs::write(skel.join("subdir/file"), b"contents\n").unwrap();

        let home = base.path().join("newhome");
        // SAFETY: reading our own uid/gid, no arguments to misuse.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

        build_home(&home, &skel, uid, gid, 0o700).unwrap();

        assert!(home.join(".bashrc").is_file());
        assert!(home.join("subdir/file").is_file());
        assert_eq!(fs::read(home.join("subdir/file")).unwrap(), b"contents\n");

        let mode = fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn build_home_without_skel_still_creates_dir() {
        let base = tempfile::tempdir().unwrap();
        let home = base.path().join("bare-home");
        let missing_skel = base.path().join("no-such-skel");
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

        build_home(&home, &missing_skel, uid, gid, 0o755).unwrap();
        assert!(home.is_dir());
    }
}
