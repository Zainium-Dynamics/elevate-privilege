//! Lockfile management for /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct FileLock {
    lock_path: PathBuf,
    _file: File,
}

impl FileLock {
    /// Acquire an exclusive lock file (e.g. `/overlayer/syshub/etc/passwd.lock`).
    pub fn acquire(target_path: &Path) -> Result<Self, String> {
        let lock_path = target_path.with_extension(format!(
            "{}.lock",
            target_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
        ));

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| format!("cannot acquire lock {}: {}", lock_path.display(), e))?;

        let mut lock = Self {
            lock_path,
            _file: file,
        };

        // Write PID into lockfile
        let pid = std::process::id();
        let _ = writeln!(lock._file, "{}", pid);

        Ok(lock)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}
