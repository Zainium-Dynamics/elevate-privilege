//! groupmems CLI — group membership administration for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/groupmems.c`.

use elevate_umbra::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: groupmems -g GROUP [options]");
        eprintln!("Options:");
        eprintln!("  -a USER    add USER to group");
        eprintln!("  -d USER    delete USER from group");
        eprintln!("  -p         purge all members from group");
        eprintln!("  -l         list members of group");
        std::process::exit(E_USAGE);
    }

    let mut groupname = String::new();
    let mut add_user: Option<String> = None;
    let mut del_user: Option<String> = None;
    let mut purge = false;
    let mut list = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-g" => {
                i += 1;
                if i < args.len() {
                    groupname = args[i].clone();
                }
            }
            "-a" => {
                i += 1;
                if i < args.len() {
                    add_user = Some(args[i].clone());
                }
            }
            "-d" => {
                i += 1;
                if i < args.len() {
                    del_user = Some(args[i].clone());
                }
            }
            "-p" => purge = true,
            "-l" => list = true,
            _ => {}
        }
        i += 1;
    }

    if groupname.is_empty() {
        eprintln!("groupmems: group name required (-g GROUP)");
        std::process::exit(E_USAGE);
    }

    audit::openlog("groupmems");

    let group_p = group_path();
    let gshadow_p = gshadow_path();

    if list {
        let group_entries = GroupFile::load(&group_p).unwrap_or_default();
        if let Some(grp) = group_entries.iter().find(|e| e.name == groupname) {
            if grp.members.is_empty() {
                println!("(no members)");
            } else {
                println!("{}", grp.members.join(" "));
            }
        } else {
            eprintln!("groupmems: group '{}' does not exist", groupname);
            std::process::exit(E_NOTFOUND);
        }
        return;
    }

    let _lock_g = FileLock::acquire(&group_p).unwrap_or_else(|e| {
        eprintln!("groupmems: {}", e);
        std::process::exit(1);
    });

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let mut gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();

    let grp = group_entries.iter_mut().find(|e| e.name == groupname);
    if grp.is_none() {
        eprintln!("groupmems: group '{}' does not exist", groupname);
        std::process::exit(E_NOTFOUND);
    }
    let grp = grp.unwrap();

    if let Some(user) = add_user {
        if !grp.members.contains(&user) {
            grp.members.push(user.clone());
        }
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            if !gs.members.contains(&user) {
                gs.members.push(user.clone());
            }
        }
        audit::audit_info(
            "groupmems",
            &format!("added '{}' to group '{}'", user, groupname),
        );
    }

    if let Some(user) = del_user {
        grp.members.retain(|m| m != &user);
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.members.retain(|m| m != &user);
        }
        audit::audit_info(
            "groupmems",
            &format!("removed '{}' from group '{}'", user, groupname),
        );
    }

    if purge {
        grp.members.clear();
        if let Some(gs) = gshadow_entries.iter_mut().find(|e| e.name == groupname) {
            gs.members.clear();
        }
        audit::audit_info(
            "groupmems",
            &format!("purged all members from group '{}'", groupname),
        );
    }

    GroupFile::save(&group_p, &group_entries).unwrap_or_else(|e| {
        eprintln!("groupmems: {}", e);
        std::process::exit(1);
    });
    GshadowFile::save(&gshadow_p, &gshadow_entries).unwrap_or_else(|e| {
        eprintln!("groupmems: {}", e);
        std::process::exit(1);
    });
    audit::closelog();
}
