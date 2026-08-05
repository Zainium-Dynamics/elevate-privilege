//! grpconv CLI — convert unshadowed group passwords to gshadow format for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/grpconv.c`.

use elevate_umbra::*;

fn main() {
    audit::openlog("grpconv");

    let group_p = group_path();
    let gshadow_p = gshadow_path();

    let _lock_g = FileLock::acquire(&group_p).unwrap_or_else(|e| {
        eprintln!("grpconv: {}", e);
        std::process::exit(E_NOPERM);
    });
    let _lock_gs = FileLock::acquire(&gshadow_p).unwrap_or_else(|e| {
        eprintln!("grpconv: {}", e);
        std::process::exit(E_NOPERM);
    });

    let mut group_entries = GroupFile::load(&group_p).unwrap_or_default();
    let mut gshadow_entries = GshadowFile::load(&gshadow_p).unwrap_or_default();

    let mut changed = false;

    for gr in &mut group_entries {
        if gr.passwd != "x" && !gr.passwd.is_empty() {
            let pass = gr.passwd.clone();
            gr.passwd = "x".to_string();

            if let Some(gs) = gshadow_entries.iter_mut().find(|g| g.name == gr.name) {
                gs.passwd = pass;
                gs.members = gr.members.clone();
            } else {
                gshadow_entries.push(GshadowEntry {
                    name: gr.name.clone(),
                    passwd: pass,
                    admins: Vec::new(),
                    members: gr.members.clone(),
                });
            }
            changed = true;
        } else if !gshadow_entries.iter().any(|g| g.name == gr.name) {
            gshadow_entries.push(GshadowEntry {
                name: gr.name.clone(),
                passwd: "!".to_string(),
                admins: Vec::new(),
                members: gr.members.clone(),
            });
            changed = true;
        }
    }

    if changed {
        GroupFile::save(&group_p, &group_entries).unwrap_or_else(|e| {
            eprintln!("grpconv: failed to save group: {}", e);
            std::process::exit(1);
        });
        GshadowFile::save(&gshadow_p, &gshadow_entries).unwrap_or_else(|e| {
            eprintln!("grpconv: failed to save gshadow: {}", e);
            std::process::exit(1);
        });
        println!("grpconv: gshadow group conversion complete.");
        audit::audit_info("grpconv", "converted group passwords to gshadow format");
    } else {
        println!("grpconv: no changes required.");
    }

    audit::closelog();
}
