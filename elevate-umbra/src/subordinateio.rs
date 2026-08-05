//! Subordinate ID management (/etc/subuid & /etc/subgid).
//! Port of shadow-4.17.2 `lib/subordinateio.c`.
//!
//! File format: USERNAME:START_ID:COUNT

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIdEntry {
    pub owner: String,
    pub start_id: u32,
    pub count: u32,
}

impl SubIdEntry {
    pub fn parse(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() >= 3 {
            let owner = parts[0].trim().to_string();
            let start_id = parts[1].trim().parse().ok()?;
            let count = parts[2].trim().parse().ok()?;
            Some(SubIdEntry {
                owner,
                start_id,
                count,
            })
        } else {
            None
        }
    }

    pub fn to_line(&self) -> String {
        format!("{}:{}:{}", self.owner, self.start_id, self.count)
    }
}

pub struct SubIdFile;

impl SubIdFile {
    pub fn load(path: &Path) -> Result<Vec<SubIdEntry>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path).map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
        let mut entries = Vec::new();
        for line in BufReader::new(file).lines().flatten() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(entry) = SubIdEntry::parse(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub fn save(path: &Path, entries: &[SubIdEntry]) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
        for entry in entries {
            writeln!(file, "{}", entry.to_line())
                .map_err(|e| format!("write error {}: {}", path.display(), e))?;
        }
        Ok(())
    }

    /// Assign sub-IDs for a new user if not already present.
    pub fn add_user_range(path: &Path, owner: &str, min_id: u32, max_id: u32, range_count: u32) -> Result<SubIdEntry, String> {
        let mut entries = Self::load(path)?;
        if let Some(existing) = entries.iter().find(|e| e.owner == owner) {
            return Ok(existing.clone());
        }

        let next_start = entries
            .iter()
            .map(|e| e.start_id + e.count)
            .max()
            .unwrap_or(min_id);

        let start_id = if next_start + range_count <= max_id {
            next_start
        } else {
            return Err("out of subordinate IDs".to_string());
        };

        let new_entry = SubIdEntry {
            owner: owner.to_string(),
            start_id,
            count: range_count,
        };

        entries.push(new_entry.clone());
        Self::save(path, &entries)?;
        Ok(new_entry)
    }

    /// Remove sub-IDs for a user.
    pub fn remove_user_range(path: &Path, owner: &str) -> Result<(), String> {
        let mut entries = Self::load(path)?;
        entries.retain(|e| e.owner != owner);
        Self::save(path, &entries)
    }
}
