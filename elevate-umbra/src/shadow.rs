//! Parser and manager for /etc/shadow format:
//! name:hash:lstchg:min:max:warn:inact:expire:flag

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    pub hash: String,
    pub lstchg: Option<i64>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub warn: Option<i64>,
    pub inact: Option<i64>,
    pub expire: Option<i64>,
    pub flag: Option<u64>,
}

impl ShadowEntry {
    pub fn parse_line(line: &str) -> Option<Self> {
        if line.len() > crate::config::PASSWD_ENTRY_MAX_LENGTH {
            return None;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 9 {
            return None;
        }

        let parse_opt_i64 = |s: &str| -> Option<i64> {
            if s.is_empty() { None } else { s.parse().ok() }
        };
        let parse_opt_u64 = |s: &str| -> Option<u64> {
            if s.is_empty() { None } else { s.parse().ok() }
        };

        Some(Self {
            name: parts[0].to_string(),
            hash: parts[1].to_string(),
            lstchg: parse_opt_i64(parts[2]),
            min: parse_opt_i64(parts[3]),
            max: parse_opt_i64(parts[4]),
            warn: parse_opt_i64(parts[5]),
            inact: parse_opt_i64(parts[6]),
            expire: parse_opt_i64(parts[7]),
            flag: parse_opt_u64(parts[8]),
        })
    }

    pub fn to_line(&self) -> String {
        let fmt_opt_i64 = |o: Option<i64>| o.map(|v| v.to_string()).unwrap_or_default();
        let fmt_opt_u64 = |o: Option<u64>| o.map(|v| v.to_string()).unwrap_or_default();

        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.name,
            self.hash,
            fmt_opt_i64(self.lstchg),
            fmt_opt_i64(self.min),
            fmt_opt_i64(self.max),
            fmt_opt_i64(self.warn),
            fmt_opt_i64(self.inact),
            fmt_opt_i64(self.expire),
            fmt_opt_u64(self.flag)
        )
    }

    pub fn current_days() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (secs / 86400) as i64
    }
}

pub struct ShadowFile;

impl ShadowFile {
    pub fn load(path: &Path) -> Result<Vec<ShadowEntry>, String> {
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
            if let Some(entry) = ShadowEntry::parse_line(trimmed) {
                entries.push(entry);
            } else {
                eprintln!("warning: invalid shadow line {} in {}", line_no + 1, path.display());
            }
        }
        Ok(entries)
    }

    pub fn save(path: &Path, entries: &[ShadowEntry]) -> Result<(), String> {
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
