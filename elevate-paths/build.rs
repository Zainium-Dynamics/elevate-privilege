//! Prints the resolved `elevate_privilege.toml` configuration at the start of
//! every workspace build (via `cargo:warning=`, which cargo always surfaces
//! to the terminal), and re-runs whenever that file changes.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("elevate-paths must live directly under the workspace root")
        .to_path_buf()
}

fn main() {
    let toml_path = workspace_root().join("elevate_privilege.toml");
    println!("cargo:rerun-if-changed={}", toml_path.display());
    println!("cargo:rerun-if-env-changed=ELEVATE_PRIVILEGE_TOML");
    println!("cargo:rerun-if-env-changed=SYSHUB_PREFIX");
    println!("cargo:rerun-if-env-changed=SYSHUB_ETC");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());

    match std::fs::read_to_string(&toml_path) {
        Ok(text) => match text.parse::<toml::Value>() {
            Ok(value) => {
                let prefix = value
                    .get("paths")
                    .and_then(|p| p.get("prefix"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("/overlayer/syshub (compiled-in default)");
                println!(
                    "cargo:warning=elevate-privilege config: {} (prefix={prefix}, target={target})",
                    toml_path.display()
                );
            }
            Err(e) => {
                println!(
                    "cargo:warning=elevate-privilege config: failed to parse {}: {e} \
                     — falling back to compiled-in defaults",
                    toml_path.display()
                );
            }
        },
        Err(_) => {
            println!(
                "cargo:warning=elevate-privilege config: {} not found — \
                 falling back to compiled-in defaults (prefix=/overlayer/syshub, target={target})",
                toml_path.display()
            );
        }
    }
}
