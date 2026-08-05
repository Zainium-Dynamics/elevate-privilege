//! Parser and manager for /etc/group format:
//! group_name:password:gid:user_list

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub passwd: String, // 'x' if shadowed
    pub gid: u32,
    pub members: Vec<String>,
}

impl GroupEntry {
    pub fn parse_line(line: &str) -> Option<Self> {
        if line.len() > crate::config::PASSWD_ENTRY_MAX_LENGTH {
            return None;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            return None;
        }
        let members = if parts[3].trim().is_empty() {
            Vec::new()
        } else {
            parts[3].split(',').map(|s| s.trim().to_string()).collect()
        };

        Some(Self {
            name: parts[0].to_string(),
            passwd: parts[1].to_string(),
            gid: parts[2].parse().ok()?,
            members,
        })
    }

    pub fn to_line(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.name,
            self.passwd,
            self.gid,
            self.members.join(",")
        )
    }
}

pub struct GroupFile;

impl GroupFile {
    pub fn load(path: &Path) -> Result<Vec<GroupEntry>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file =
            File::open(path).map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(entry) = GroupEntry::parse_line(trimmed) {
                entries.push(entry);
            } else {
                eprintln!(
                    "warning: invalid group line {} in {}",
                    line_no + 1,
                    path.display()
                );
            }
        }
        Ok(entries)
    }

    pub fn save(path: &Path, entries: &[GroupEntry]) -> Result<(), String> {
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
