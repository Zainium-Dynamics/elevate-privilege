//! vipw / vigr CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;
use std::process::Command;

fn main() {
    let prog_name = env::args().next().unwrap_or_default();
    let is_vigr = prog_name.ends_with("vigr") || env::args().any(|a| a == "-g" || a == "--group");
    let is_shadow = env::args().any(|a| a == "-s" || a == "--shadow");

    let target_path = if is_vigr {
        if is_shadow {
            gshadow_path()
        } else {
            group_path()
        }
    } else {
        if is_shadow {
            shadow_path()
        } else {
            passwd_path()
        }
    };

    println!("Editing {} safely with lockfile...", target_path.display());

    let _lock = match FileLock::acquire(&target_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vipw: {}", e);
            std::process::exit(1);
        }
    };

    let editor = env::var("EDITOR")
        .or_else(|_| env::var("VISUAL"))
        .unwrap_or_else(|_| "/bin/vi".to_string());

    let status = Command::new(&editor).arg(&target_path).status();

    match status {
        Ok(s) if s.success() => println!("Finished editing {}", target_path.display()),
        Ok(s) => eprintln!("vipw: editor exited with status {}", s),
        Err(e) => eprintln!("vipw: failed to execute editor '{}': {}", editor, e),
    }
}
