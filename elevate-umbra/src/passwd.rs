//! Parser and manager for /etc/passwd format:
//! name:password:uid:gid:gecos:directory:shell

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub passwd: String, // 'x' if shadowed
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

impl PasswdEntry {
    pub fn parse_line(line: &str) -> Option<Self> {
        if line.len() > crate::config::PASSWD_ENTRY_MAX_LENGTH {
            return None;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            return None;
        }
        Some(Self {
            name: parts[0].to_string(),
            passwd: parts[1].to_string(),
            uid: parts[2].parse().ok()?,
            gid: parts[3].parse().ok()?,
            gecos: parts[4].to_string(),
            dir: parts[5].to_string(),
            shell: parts[6].to_string(),
        })
    }

    pub fn to_line(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.name, self.passwd, self.uid, self.gid, self.gecos, self.dir, self.shell
        )
    }
}

pub struct PasswdFile;

impl PasswdFile {
    pub fn load(path: &Path) -> Result<Vec<PasswdEntry>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path).map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(entry) = PasswdEntry::parse_line(trimmed) {
                entries.push(entry);
            } else {
                eprintln!("warning: invalid line {} in {}", line_no + 1, path.display());
            }
        }
        Ok(entries)
    }

    pub fn save(path: &Path, entries: &[PasswdEntry]) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("failed to open {} for writing: {}", path.display(), e))?;

        for entry in entries {
            writeln!(file, "{}", entry.to_line()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
