//! grpunconv CLI — convert gshadow group passwords back to /etc/group format for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/grpunconv.c`.

use elevate_umbra::*;
use std::fs;

fn main() {
    audit::openlog("grpunconv");

    let group_p = group_path();
    let gshadow_p = gshadow_path();

    if !gshadow_p.exists() {
        println!("grpunconv: gshadow file does not exist, nothing to do.");
        return;
    }

    let _lock_g = FileLock::acquire(&group_p).unwrap_or_else(|e| {
        eprintln!("grpunconv: {}", e);
        std::process::exit(E_NOPERM);
    });
    let _lock_gs = FileLock::acquire(&gshadow_p).unwrap_or_else(|e| {
        eprintln!("grpunconv: {}", e);
        std::process::exit(E_NOPERM);
    });

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();

    for gr in &mut group_entries {
        if let Some(gs) = gshadow_entries.iter().find(|g| g.name == gr.name) {
            gr.passwd = gs.passwd.clone();
        }
    }

    GroupFile::save(&group_p, &group_entries).unwrap_or_else(|e| {
        eprintln!("grpunconv: failed to save group: {}", e);
        std::process::exit(1);
    });

    // Delete gshadow file
    if let Err(e) = fs::remove_file(&gshadow_p) {
        eprintln!(
            "grpunconv: warning: failed to remove gshadow file {}: {}",
            gshadow_p.display(),
            e
        );
    } else {
        println!("grpunconv: removed gshadow file {}.", gshadow_p.display());
    }

    println!("grpunconv: unshadow group conversion complete.");
    audit::audit_info("grpunconv", "converted gshadow passwords back to group");
    audit::closelog();
}
