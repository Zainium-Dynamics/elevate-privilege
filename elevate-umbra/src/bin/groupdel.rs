//! groupdel CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;

fn main() {
    audit::openlog("groupdel");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: groupdel GROUP");
        std::process::exit(E_USAGE);
    }

    let groupname = &args[1];

    let group_p = group_path();
    let _lock = match FileLock::acquire(&group_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("groupdel: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let grp = group_entries.iter().find(|e| e.name == *groupname);
    if grp.is_none() {
        eprintln!("groupdel: group '{}' does not exist", groupname);
        audit::audit_user_op("groupdel", "del_group", groupname, None, false);
        std::process::exit(E_NOTFOUND);
    }
    let gid = grp.map(|g| g.gid);

    group_entries.retain(|e| e.name != *groupname);

    if let Err(e) = GroupFile::save(&group_p, &group_entries) {
        eprintln!("groupdel: failed to update group: {}", e);
        std::process::exit(1);
    }

    audit::audit_user_op("groupdel", "del_group", groupname, gid, true);
    println!("groupdel: deleted group '{}'", groupname);
    audit::closelog();
}
