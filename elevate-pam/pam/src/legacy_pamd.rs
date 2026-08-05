//! Optional bridge: parse classic Linux-PAM `/etc/pam.d/*` line format
//! into [`ServiceConfig`] TOML structures.
//!
//! Runtime configuration for elevate-pam itself remains TOML-first; this
//! module exists only for migration / drop-in compatibility.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::fs;
use std::path::PathBuf;

use crate::config::{ControlFlag, ModuleEntry, ServiceConfig};
use crate::error::{PamError, PamResult};

/// Load a service from classic pam.d locations.
pub fn load_service(service: &str, confdir: Option<&str>) -> PamResult<ServiceConfig> {
    let name = service.to_ascii_lowercase();
    let mut paths = Vec::new();
    if let Some(dir) = confdir {
        paths.push(PathBuf::from(dir).join(&name));
        paths.push(PathBuf::from(dir).join(format!("{name}.toml"))); // ignore non-pamd
    }
    // Zainium: configured prefix preferred, fall back to plain /etc/pam.d
    let prefix = &elevate_paths::get().prefix;
    paths.push(PathBuf::from(format!("{prefix}/etc/pam.d/{name}")));
    paths.push(PathBuf::from(format!(
        "{prefix}/etc/elevate-pam/legacy-pamd/{name}"
    )));
    paths.push(PathBuf::from(format!("/etc/pam.d/{name}")));
    paths.push(PathBuf::from(format!(
        "/etc/elevate-pam/legacy-pamd/{name}"
    )));

    for p in paths {
        // skip .toml in this legacy path
        if p.extension().and_then(|e| e.to_str()) == Some("toml") {
            continue;
        }
        if p.is_file() {
            let text = fs::read_to_string(&p)
                .map_err(|e| PamError::Io(alloc::format!("read {}: {e}", p.display())))?;
            return parse_pamd(&text);
        }
    }
    Err(PamError::Config(alloc::format!(
        "legacy pam.d service '{name}' not found"
    )))
}

/// Parse pam.d file content.
pub fn parse_pamd(text: &str) -> PamResult<ServiceConfig> {
    let mut cfg = ServiceConfig::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // continuation with trailing \
        let line = line.trim_end_matches('\\').trim();
        let mut optional_load = false;
        let mut parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        // service-name form in pam.conf: service type control module args
        // pam.d form: type control module args
        let type_idx = if parts.len() >= 4
            && !matches!(
                parts[0],
                "auth"
                    | "account"
                    | "password"
                    | "session"
                    | "-auth"
                    | "-account"
                    | "-password"
                    | "-session"
            ) {
            1
        } else {
            0
        };
        if parts.len() < type_idx + 3 {
            continue;
        }
        let mut type_tok = parts[type_idx];
        if let Some(stripped) = type_tok.strip_prefix('-') {
            optional_load = true;
            type_tok = stripped;
        }
        let control_tok = parts[type_idx + 1];
        let module_tok = parts[type_idx + 2];
        let args: Vec<String> = parts[type_idx + 3..]
            .iter()
            .map(|s| String::from(*s))
            .collect();

        let control = ControlFlag::parse(control_tok).unwrap_or(ControlFlag::Required);
        let entry = ModuleEntry {
            control,
            module: String::from(module_tok),
            args,
            optional_load,
            actions: None,
        };
        match type_tok {
            "auth" => cfg.auth.push(entry),
            "account" => cfg.account.push(entry),
            "password" => cfg.password.push(entry),
            "session" => cfg.session.push(entry),
            _ => {}
        }
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_elevate_style() {
        let text = r#"
# comment
auth       required     pam_env.so readenv=1
auth       required     pam_unix.so
account    required     pam_unix.so
password   required     pam_unix.so
session    required     pam_limits.so
session    required     pam_unix.so
"#;
        let cfg = parse_pamd(text).unwrap();
        assert_eq!(cfg.auth.len(), 2);
        assert_eq!(cfg.session.len(), 2);
        assert_eq!(cfg.auth[0].module, "pam_env.so");
        assert_eq!(cfg.auth[0].args, vec!["readenv=1".to_string()]);
    }
}
