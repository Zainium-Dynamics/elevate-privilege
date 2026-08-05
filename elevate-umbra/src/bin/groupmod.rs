//! groupmod CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("groupmod");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: groupmod [options] GROUP");
        eprintln!("Options:");
        eprintln!("  -g, --gid GID         new group ID");
        eprintln!("  -n, --new-name NAME   new group name");
        std::process::exit(E_USAGE);
    }

    let mut groupname = String::new();
    let mut new_gid: Option<u32> = None;
    let mut new_name: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-g" | "--gid" => {
                i += 1;
                if i < args.len() {
                    new_gid = args[i].parse().ok();
                }
            }
            "-n" | "--new-name" => {
                i += 1;
                if i < args.len() {
                    new_name = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') => groupname = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    if groupname.is_empty() {
        eprintln!("groupmod: group name required");
        std::process::exit(E_USAGE);
    }

    if let Some(ref nn) = new_name {
        if let Err(reason) = chkname::is_valid_group_name(nn) {
            eprintln!("groupmod: invalid new group name '{}': {}", nn, reason);
            audit::audit_user_op("groupmod", "mod_group", &groupname, None, false);
            std::process::exit(E_BAD_ARG);
        }
    }

    let group_p = group_path();
    let gshadow_p = gshadow_path();

    let _lock = match FileLock::acquire(&group_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("groupmod: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let mut gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();

    let g_idx = group_entries.iter().position(|e| e.name == groupname);
    if g_idx.is_none() {
        eprintln!("groupmod: group '{}' does not exist", groupname);
        audit::audit_user_op("groupmod", "mod_group", &groupname, None, false);
        std::process::exit(E_NOTFOUND);
    }
    let g_idx = g_idx.unwrap();

    // Check new name for conflicts BEFORE mutating
    let updated_name = if let Some(ref nn) = new_name {
        if group_entries.iter().any(|e| e.name == *nn) {
            eprintln!("groupmod: group '{}' already exists", nn);
            std::process::exit(E_NAME_IN_USE);
        }
        nn.clone()
    } else {
        groupname.clone()
    };

    let group = &mut group_entries[g_idx];
    if let Some(g) = new_gid {
        group.gid = g;
    }
    if new_name.is_some() {
        group.name = updated_name.clone();
    }

    if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
        gs.name = updated_name.clone();
    }

    if let Err(e) = GroupFile::save(&group_p, &group_entries) {
        eprintln!("groupmod: failed to update group: {}", e);
        std::process::exit(1);
    }
    if gshadow_p.exists() {
        let _ = GshadowFile::save(&gshadow_p, &gshadow_entries);
    }

    audit::audit_user_op("groupmod", "mod_group", &updated_name, new_gid, true);
    println!("groupmod: updated group '{}'", updated_name);
    audit::closelog();
}
