//! gpasswd CLI — group password administration for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/gpasswd.c`.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: gpasswd [options] GROUP");
        eprintln!("Options:");
        eprintln!("  -a USER    add USER to GROUP");
        eprintln!("  -d USER    remove USER from GROUP");
        eprintln!("  -r         remove group password");
        eprintln!("  -R         restrict access to GROUP");
        eprintln!("  -A ADMIN   set administrators");
        eprintln!("  -M MEMBER  set members");
        std::process::exit(E_USAGE);
    }

    let mut groupname = String::new();
    let mut add_user: Option<String> = None;
    let mut del_user: Option<String> = None;
    let mut remove_pass = false;
    let mut restrict_access = false;
    let mut set_admins: Option<String> = None;
    let mut set_members: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => { i += 1; if i < args.len() { add_user = Some(args[i].clone()); } }
            "-d" => { i += 1; if i < args.len() { del_user = Some(args[i].clone()); } }
            "-r" => remove_pass = true,
            "-R" => restrict_access = true,
            "-A" => { i += 1; if i < args.len() { set_admins = Some(args[i].clone()); } }
            "-M" => { i += 1; if i < args.len() { set_members = Some(args[i].clone()); } }
            arg if !arg.starts_with('-') => groupname = arg.to_string(),
            _ => {}
        }
        i += 1;
    }

    if groupname.is_empty() {
        eprintln!("gpasswd: group name required");
        std::process::exit(E_USAGE);
    }

    audit::openlog("gpasswd");

    let group_p = group_path();
    let gshadow_p = gshadow_path();
    let _lock_g = FileLock::acquire(&group_p).unwrap_or_else(|e| { eprintln!("gpasswd: {}", e); std::process::exit(1); });
    let _lock_gs = FileLock::acquire(&gshadow_p).unwrap_or_else(|e| { eprintln!("gpasswd: {}", e); std::process::exit(1); });

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let mut gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();

    let grp = group_entries.iter_mut().find(|e| e.name == groupname);
    if grp.is_none() {
        eprintln!("gpasswd: group '{}' does not exist", groupname);
        std::process::exit(E_NOTFOUND);
    }
    let grp = grp.unwrap();

    if let Some(user) = add_user {
        if !grp.members.contains(&user) {
            grp.members.push(user.clone());
        }
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            if !gs.members.contains(&user) { gs.members.push(user.clone()); }
        }
        audit::audit_info("gpasswd", &format!("added user '{}' to group '{}'", user, groupname));
    }

    if let Some(user) = del_user {
        grp.members.retain(|m| m != &user);
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.members.retain(|m| m != &user);
        }
        audit::audit_info("gpasswd", &format!("removed user '{}' from group '{}'", user, groupname));
    }

    if remove_pass {
        grp.passwd = String::new();
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.passwd = String::new();
        }
        audit::audit_info("gpasswd", &format!("removed password for group '{}'", groupname));
    }

    if restrict_access {
        grp.passwd = "!".to_string();
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.passwd = "!".to_string();
        }
    }

    if let Some(admins) = set_admins {
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.admins = admins.split(',').map(|s| s.trim().to_string()).collect();
        }
    }

    if let Some(members) = set_members {
        grp.members = members.split(',').map(|s| s.trim().to_string()).collect();
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.members = members.split(',').map(|s| s.trim().to_string()).collect();
        }
    }

    GroupFile::save(&group_p, &group_entries).unwrap_or_else(|e| { eprintln!("gpasswd: {}", e); std::process::exit(1); });
    GshadowFile::save(&gshadow_p, &gshadow_entries).unwrap_or_else(|e| { eprintln!("gpasswd: {}", e); std::process::exit(1); });
    audit::closelog();
}
