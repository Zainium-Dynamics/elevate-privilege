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
