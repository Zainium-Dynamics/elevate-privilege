//! groupadd CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("groupadd");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: groupadd [options] GROUP");
        eprintln!("Options:");
        eprintln!("  -g, --gid GID         group ID");
        std::process::exit(E_USAGE);
    }

    let mut groupname = String::new();
    let mut custom_gid: Option<u32> = None;
    let login_defs = LoginDefs::load_default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-g" | "--gid" => {
                i += 1;
                if i < args.len() {
                    custom_gid = args[i].parse().ok();
                }
            }
            arg if !arg.starts_with('-') => groupname = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    if groupname.is_empty() {
        eprintln!("groupadd: group name required");
        std::process::exit(E_USAGE);
    }

    if let Err(reason) = chkname::is_valid_group_name(&groupname) {
        eprintln!("groupadd: invalid group name '{}': {}", groupname, reason);
        audit::audit_user_op("groupadd", "add_group", &groupname, None, false);
        std::process::exit(E_BAD_ARG);
    }

    let group_p = group_path();
    let _lock = match FileLock::acquire(&group_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("groupadd: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    if group_entries.iter().any(|e| e.name == groupname) {
        eprintln!("groupadd: group '{}' already exists", groupname);
        audit::audit_user_op("groupadd", "add_group", &groupname, None, false);
        std::process::exit(E_NAME_IN_USE);
    }

    let min_gid = login_defs.gid_min();
    let max_gid = login_defs.gid_max();

    let next_gid = custom_gid.unwrap_or_else(|| {
        group_entries
            .iter()
            .map(|e| e.gid)
            .filter(|&gid| gid >= min_gid && gid <= max_gid)
            .max()
            .map(|g| g + 1)
            .unwrap_or(min_gid)
    });

    group_entries.push(GroupEntry {
        name: groupname.clone(),
        passwd: "x".to_string(),
        gid: next_gid,
        members: Vec::new(),
    });

    if let Err(e) = GroupFile::save(&group_p, &group_entries) {
        eprintln!("groupadd: failed to update group: {}", e);
        std::process::exit(1);
    }

    audit::audit_user_op("groupadd", "add_group", &groupname, Some(next_gid), true);
    println!("groupadd: created group '{}' (gid={})", groupname, next_gid);
    audit::closelog();
}
