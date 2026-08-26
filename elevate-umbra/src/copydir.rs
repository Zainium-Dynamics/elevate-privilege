//! Recursive directory copy with ownership transfer.
//! Port of shadow-4.17.2 `lib/copydir.c` for skel directory handling.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Recursively copy `src` directory contents into `dst`.
/// Sets ownership of all copied files/dirs to `new_uid:new_gid`.
pub fn copy_tree(src: &Path, dst: &Path, new_uid: u32, new_gid: u32) -> Result<(), String> {
    if !src.is_dir() {
        return Err(format!("source '{}' is not a directory", src.display()));
    }

    // Create destination if it doesn't exist
    if !dst.exists() {
        fs::create_dir_all(dst)
            .map_err(|e| format!("failed to create {}: {}", dst.display(), e))?;
    }
    // The recursion below only chowns *entries under* dst as it copies them
    // -- dst itself (the home directory) was never chowned, leaving it
    // root-owned.
    chown_path(dst, new_uid, new_gid)?;

    let entries =
        fs::read_dir(src).map_err(|e| format!("failed to read {}: {}", src.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("readdir error: {}", e))?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {}: {}", src_path.display(), e))?;

        if meta.is_dir() {
            // Recurse into subdirectory
            fs::create_dir_all(&dst_path)
                .map_err(|e| format!("mkdir {}: {}", dst_path.display(), e))?;

            // Preserve permissions
            let mode = meta.permissions().mode() & 0o7777;
            fs::set_permissions(&dst_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {}", dst_path.display(), e))?;

            // Set ownership
            chown_path(&dst_path, new_uid, new_gid)?;

            // Recurse
            copy_tree(&src_path, &dst_path, new_uid, new_gid)?;
        } else if meta.is_file() {
            // Copy file
            fs::copy(&src_path, &dst_path).map_err(|e| {
                format!(
                    "copy {} -> {}: {}",
                    src_path.display(),
                    dst_path.display(),
                    e
                )
            })?;

            // Preserve permissions
            let mode = meta.permissions().mode() & 0o7777;
            fs::set_permissions(&dst_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {}", dst_path.display(), e))?;

            // Set ownership
            chown_path(&dst_path, new_uid, new_gid)?;
        } else if meta.file_type().is_symlink() {
            // Copy symlink
            if let Ok(target) = fs::read_link(&src_path) {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(&target, &dst_path);
                }
                // lchown for symlinks
                lchown_path(&dst_path, new_uid, new_gid)?;
            }
        }
        // Skip special files (devices, sockets, etc.)
    }

    Ok(())
}

/// Default skeleton files, embedded rather than read from an on-disk
/// `/etc/skel/` (this system doesn't ship one — see config.rs's `skel_dir()`
/// comment). `--skel <dir>` / a real `/etc/skel/` still takes priority in
/// `useradd`; this is only the fallback when neither exists, so a fresh
/// home directory isn't silently empty.
const SKEL_BASHRC: &str = "\
# ~/.bashrc\n\
[ -z \"$PS1\" ] && return\n\
PS1='\\u@\\h:\\w\\$ '\n\
alias ll='ls -la'\n\
alias grep='grep --color=auto'\n";

const SKEL_BASH_PROFILE: &str = "\
# ~/.bash_profile\n\
[ -f ~/.bashrc ] && . ~/.bashrc\n";

const SKEL_PROFILE: &str = "\
# ~/.profile\n\
[ -n \"$BASH_VERSION\" ] && [ -f ~/.bashrc ] && . ~/.bashrc\n";

/// Populate a freshly created home directory with default dotfiles when no
/// real skel directory exists to copy from. Not a port of any shadow-4.17.2
/// file — real shadow always assumes `/etc/skel/` exists on disk; this
/// covers the case where it doesn't.
pub fn write_default_skel(dst: &Path, uid: u32, gid: u32) -> Result<(), String> {
    if !dst.exists() {
        fs::create_dir_all(dst)
            .map_err(|e| format!("failed to create {}: {}", dst.display(), e))?;
    }
    chown_path(dst, uid, gid)?;

    for (name, contents) in [
        (".bashrc", SKEL_BASHRC),
        (".bash_profile", SKEL_BASH_PROFILE),
        (".profile", SKEL_PROFILE),
    ] {
        let path = dst.join(name);
        fs::write(&path, contents).map_err(|e| format!("write {}: {}", path.display(), e))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod {}: {}", path.display(), e))?;
        chown_path(&path, uid, gid)?;
    }

    Ok(())
}

/// Change ownership of a path (chown).
fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "invalid path for chown".to_string())?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        Err(format!(
            "chown {}:{}  {}: {}",
            uid,
            gid,
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Change ownership of a symlink (lchown).
fn lchown_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "invalid path for lchown".to_string())?;
    let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        Err(format!(
            "lchown {}:{} {}: {}",
            uid,
            gid,
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Recursively remove a directory tree (port of shadow `remove_tree.c`).
pub fn remove_tree(root: &Path, remove_root: bool) -> Result<(), String> {
    if !root.is_dir() {
        return Err(format!("'{}' is not a directory", root.display()));
    }

    let entries =
        fs::read_dir(root).map_err(|e| format!("failed to read {}: {}", root.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("readdir error: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            remove_tree(&path, true)?;
        } else {
            fs::remove_file(&path)
                .map_err(|e| format!("failed to remove {}: {}", path.display(), e))?;
        }
    }

    if remove_root {
        fs::remove_dir(root).map_err(|e| format!("failed to rmdir {}: {}", root.display(), e))?;
    }

    Ok(())
}
