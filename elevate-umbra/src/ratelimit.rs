//! Anti-Brute-Force Progressive Delay & Cyber Attack Mitigation Engine.
//! Protects sulogin, passwd, elevate, and PAM modules against dictionary / brute-force attacks.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn ratelimit_file_path() -> PathBuf {
    PathBuf::from(elevate_paths::get().etc_dir()).join("auth_ratelimit.db")
}

#[derive(Debug, Clone)]
struct FailRecord {
    pub count: u32,
    pub last_attempt: u64,
}

fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record a failed login attempt and enforce progressive delays.
/// Returns the delay in seconds that was enforced.
pub fn enforce_failed_attempt_delay(target_name: &str) -> u32 {
    let now = current_time_secs();
    let db_path = ratelimit_file_path();

    let mut records: HashMap<String, FailRecord> = HashMap::new();

    if db_path.exists() {
        if let Ok(file) = File::open(&db_path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts.len() >= 3 {
                    let user = parts[0].to_string();
                    let count: u32 = parts[1].parse().unwrap_or(0);
                    let last: u64 = parts[2].parse().unwrap_or(0);
                    records.insert(
                        user,
                        FailRecord {
                            count,
                            last_attempt: last,
                        },
                    );
                }
            }
        }
    }

    let mut record = records.get(target_name).cloned().unwrap_or(FailRecord {
        count: 0,
        last_attempt: 0,
    });

    // If last attempt was more than 1 hour (3600s) ago, reset fail count
    if now.saturating_sub(record.last_attempt) > 3600 {
        record.count = 0;
    }

    record.count += 1;
    record.last_attempt = now;

    records.insert(target_name.to_string(), record.clone());

    // Save back to db file safely
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&db_path)
    {
        for (u, r) in &records {
            let _ = writeln!(file, "{}:{}:{}", u, r.count, r.last_attempt);
        }
    }

    // Determine progressive delay based on attack frequency
    let delay_secs = if record.count >= 5 {
        // High severity / persistent brute-force attempt: 5 minutes (300 seconds)
        300
    } else if record.count >= 3 {
        // Medium severity: 30 seconds delay
        30
    } else {
        0
    };

    if delay_secs > 0 {
        crate::audit::audit_crit(
            "ratelimit",
            &format!(
                "BRUTE-FORCE ATTACK MITIGATION: {} failed attempts for '{}'. Enforcing {}s penalty delay.",
                record.count, target_name, delay_secs
            ),
        );
        thread::sleep(Duration::from_secs(delay_secs as u64));
    }

    delay_secs
}

/// Reset failure count upon successful authentication.
pub fn clear_failed_attempts(target_name: &str) {
    let db_path = ratelimit_file_path();
    if !db_path.exists() {
        return;
    }
    let mut records: HashMap<String, FailRecord> = HashMap::new();
    if let Ok(file) = File::open(&db_path) {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let parts: Vec<&str> = line.trim().split(':').collect();
            if parts.len() >= 3 {
                let user = parts[0].to_string();
                let count: u32 = parts[1].parse().unwrap_or(0);
                let last: u64 = parts[2].parse().unwrap_or(0);
                if user != target_name {
                    records.insert(
                        user,
                        FailRecord {
                            count,
                            last_attempt: last,
                        },
                    );
                }
            }
        }
    }
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&db_path)
    {
        for (u, r) in &records {
            let _ = writeln!(file, "{}:{}:{}", u, r.count, r.last_attempt);
        }
    }
}
