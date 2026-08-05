//! Defaults configuration for useradd command.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UseraddDefaults {
    pub group: u32,
    pub home_prefix: String,
    pub inactive: Option<i64>,
    pub expire: Option<String>,
    pub shell: String,
    pub skel: String,
    pub create_mail_spool: bool,
}

impl Default for UseraddDefaults {
    fn default() -> Self {
        Self {
            group: 100, // default users group GID
            home_prefix: "/home".to_string(),
            inactive: None,
            expire: None,
            shell: format!("{}/sh", elevate_paths::get().bindir),
            skel: elevate_paths::get().skel_dir(),
            create_mail_spool: false,
        }
    }
}

impl UseraddDefaults {
    pub fn load(path: &Path) -> Self {
        let mut defaults = Self::default();
        if !path.exists() {
            return defaults;
        }

        if let Ok(file) = File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, val)) = line.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"');
                    match key {
                        "GROUP" => {
                            if let Ok(g) = val.parse() {
                                defaults.group = g;
                            }
                        }
                        "HOME" => defaults.home_prefix = val.to_string(),
                        "INACTIVE" => defaults.inactive = val.parse().ok(),
                        "EXPIRE" => {
                            defaults.expire = if val.is_empty() {
                                None
                            } else {
                                Some(val.to_string())
                            }
                        }
                        "SHELL" => defaults.shell = val.to_string(),
                        "SKEL" => defaults.skel = val.to_string(),
                        "CREATE_MAIL_SPOOL" => {
                            defaults.create_mail_spool = val.eq_ignore_ascii_case("yes")
                        }
                        _ => {}
                    }
                }
            }
        }
        defaults
    }
}
