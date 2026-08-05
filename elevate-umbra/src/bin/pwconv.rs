//! pwconv CLI — convert unshadowed passwords to shadow format for ZainiumOS syshub.
//! Port of shadow-4.17.2 `src/pwconv.c`.

use elevate_umbra::*;

fn main() {
    audit::openlog("pwconv");

    let passwd_p = passwd_path();
    let shadow_p = shadow_path();

    let _lock_p = FileLock::acquire(&passwd_p).unwrap_or_else(|e| {
        eprintln!("pwconv: {}", e);
        std::process::exit(E_NOPERM);
    });
    let _lock_s = FileLock::acquire(&shadow_p).unwrap_or_else(|e| {
        eprintln!("pwconv: {}", e);
        std::process::exit(E_NOPERM);
    });

    let mut passwd_entries = PasswdFile::load(&passwd_p).unwrap_or_default();
    let mut shadow_entries = ShadowFile::load(&shadow_p).unwrap_or_default();
    let login_defs = LoginDefs::load_default();

    let mut changed = false;

    for pw in &mut passwd_entries {
        // If password is not shadowed ('x'), move hash to shadow
        if pw.passwd != "x" && !pw.passwd.is_empty() {
            let hash = pw.passwd.clone();
            pw.passwd = "x".to_string();

            if let Some(se) = shadow_entries.iter_mut().find(|s| s.name == pw.name) {
                se.hash = hash;
                se.lstchg = Some(ShadowEntry::current_days());
            } else {
                shadow_entries.push(ShadowEntry {
                    name: pw.name.clone(),
                    hash,
                    lstchg: Some(ShadowEntry::current_days()),
                    min: Some(login_defs.pass_min_days()),
                    max: Some(login_defs.pass_max_days()),
                    warn: Some(login_defs.pass_warn_age()),
                    inact: None,
                    expire: None,
                    flag: None,
                });
            }
            changed = true;
        } else if !shadow_entries.iter().any(|s| s.name == pw.name) {
            // Ensure shadow entry exists even if passwd entry had 'x'
            shadow_entries.push(ShadowEntry {
                name: pw.name.clone(),
                hash: "!".to_string(),
                lstchg: Some(ShadowEntry::current_days()),
                min: Some(login_defs.pass_min_days()),
                max: Some(login_defs.pass_max_days()),
                warn: Some(login_defs.pass_warn_age()),
                inact: None,
                expire: None,
                flag: None,
            });
            changed = true;
        }
    }

    if changed {
        PasswdFile::save(&passwd_p, &passwd_entries).unwrap_or_else(|e| {
            eprintln!("pwconv: failed to save passwd: {}", e);
            std::process::exit(1);
        });
        ShadowFile::save(&shadow_p, &shadow_entries).unwrap_or_else(|e| {
            eprintln!("pwconv: failed to save shadow: {}", e);
            std::process::exit(1);
        });
        println!("pwconv: shadow password conversion complete.");
        audit::audit_info("pwconv", "converted passwords to shadow format");
    } else {
        println!("pwconv: no changes required.");
    }

    audit::closelog();
}
