//! useradd CLI implementation for ZainiumOS syshub.

use elevate_umbra::*;
use std::env;
use std::path::Path;

fn main() {
    audit::openlog("useradd");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: useradd [options] LOGIN");
        eprintln!("Options:");
        eprintln!("  -u, --uid UID         user ID");
        eprintln!("  -g, --gid GID         group name or ID");
        eprintln!("  -d, --home DIR        home directory");
        eprintln!("  -s, --shell SHELL     login shell");
        eprintln!("  -c, --comment COMMENT GECOS comment field");
        eprintln!("  -m, --create-home     create the user's home directory");
        eprintln!("  -k, --skel SKEL_DIR   skeleton directory for new home");
        std::process::exit(E_USAGE);
    }

    let mut username = String::new();
    let mut custom_uid: Option<u32> = None;
    let mut custom_gid: Option<u32> = None;
    let mut custom_home: Option<String> = None;
    let mut custom_shell: Option<String> = None;
    let mut custom_skel: Option<String> = None;
    let mut comment = String::new();
    let mut create_home = false;

    let defaults = UseraddDefaults::load(&useradd_defaults_path());
    let login_defs = LoginDefs::load_default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--uid" => {
                i += 1;
                if i < args.len() {
                    custom_uid = args[i].parse().ok();
                }
            }
            "-g" | "--gid" => {
                i += 1;
                if i < args.len() {
                    custom_gid = args[i].parse().ok();
                }
            }
            "-d" | "--home" => {
                i += 1;
                if i < args.len() {
                    custom_home = Some(args[i].clone());
                }
            }
            "-s" | "--shell" => {
                i += 1;
                if i < args.len() {
                    custom_shell = Some(args[i].clone());
                }
            }
            "-c" | "--comment" => {
                i += 1;
                if i < args.len() {
                    comment = args[i].clone();
                }
            }
            "-m" | "--create-home" => {
                create_home = true;
            }
            "-k" | "--skel" => {
                i += 1;
                if i < args.len() {
                    custom_skel = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') => {
                username = arg.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    if username.is_empty() {
        eprintln!("useradd: username required");
        std::process::exit(E_USAGE);
    }

    // Name validation
    if let Err(reason) = chkname::is_valid_user_name(&username) {
        eprintln!("useradd: invalid user name '{}': {}", username, reason);
        audit::audit_user_op("useradd", "add", &username, None, false);
        std::process::exit(E_BAD_ARG);
    }

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    let _lock_p = match FileLock::acquire(&passwd_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("useradd: {}", e);
            std::process::exit(E_NOPERM);
        }
    };
    let _lock_s = match FileLock::acquire(&shadow_p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("useradd: {}", e);
            std::process::exit(E_NOPERM);
        }
    };

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();

    if passwd_entries.iter().any(|e| e.name == username) {
        eprintln!("useradd: user '{}' already exists", username);
        audit::audit_user_op("useradd", "add", &username, None, false);
        std::process::exit(E_NAME_IN_USE);
    }

    let min_uid = login_defs.uid_min();
    let max_uid = login_defs.uid_max();

    let next_uid = custom_uid.unwrap_or_else(|| {
        passwd_entries
            .iter()
            .map(|e| e.uid)
            .filter(|&uid| uid >= min_uid && uid <= max_uid)
            .max()
            .map(|u| u + 1)
            .unwrap_or(min_uid)
    });

    // Check if UID in use
    if custom_uid.is_some() && passwd_entries.iter().any(|e| e.uid == next_uid) {
        eprintln!("useradd: UID {} already in use", next_uid);
        audit::audit_user_op("useradd", "add", &username, Some(next_uid), false);
        std::process::exit(E_UID_IN_USE);
    }

    let gid = custom_gid.unwrap_or(defaults.group);
    let home = custom_home.unwrap_or_else(|| format!("{}/{}", defaults.home_prefix, username));
    let shell = custom_shell.unwrap_or(defaults.shell);
    let should_create_home = create_home || login_defs.create_home();

    passwd_entries.push(PasswdEntry {
        name: username.clone(),
        passwd: "x".to_string(),
        uid: next_uid,
        gid,
        gecos: comment,
        dir: home.clone(),
        shell,
    });

    shadow_entries.push(ShadowEntry {
        name: username.clone(),
        hash: "!".to_string(), // Locked initial password
        lstchg: Some(ShadowEntry::current_days()),
        min: Some(login_defs.pass_min_days()),
        max: Some(login_defs.pass_max_days()),
        warn: Some(login_defs.pass_warn_age()),
        inact: defaults.inactive,
        expire: None,
        flag: None,
    });

    if let Err(e) = PasswdFile::save(&passwd_p, &passwd_entries) {
        eprintln!("useradd: failed to update passwd: {}", e);
        std::process::exit(E_GRP_UPDATE);
    }
    if let Err(e) = ShadowFile::save(&shadow_p, &shadow_entries) {
        eprintln!("useradd: failed to update shadow: {}", e);
        std::process::exit(E_GRP_UPDATE);
    }

    if should_create_home {
        let skel_dir = custom_skel.unwrap_or(defaults.skel);
        let skel_path = Path::new(&skel_dir);
        let home_path = Path::new(&home);

        if skel_path.is_dir() {
            if let Err(e) = copydir::copy_tree(skel_path, home_path, next_uid, gid) {
                eprintln!(
                    "useradd: warning: failed to copy skel from {}: {}",
                    skel_dir, e
                );
            }
        } else {
            if let Err(e) = std::fs::create_dir_all(home_path) {
                eprintln!(
                    "useradd: warning: cannot create home directory {}: {}",
                    home, e
                );
            }
        }
    }

    // Assign subordinate UIDs and GIDs (subuid / subgid)
    let subuid_p = subuid_path();
    let subgid_p = subgid_path();
    let _ = SubIdFile::add_user_range(&subuid_p, &username, 100000, 600100000, 65536);
    let _ = SubIdFile::add_user_range(&subgid_p, &username, 100000, 600100000, 65536);

    audit::audit_user_op("useradd", "add", &username, Some(next_uid), true);
    println!("useradd: created user '{}' (uid={})", username, next_uid);
    audit::closelog();
}
