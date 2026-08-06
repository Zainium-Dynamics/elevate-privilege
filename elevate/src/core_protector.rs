//! Zainium Zero-Trust Core Protector
//!
//! This module blocks destructive commands (rm, rmdir, mv, shred, unlink)
//! and copy commands (cp, rsync) when they attempt to target Zainium OS's
//! immutable core layers (/overlayer/syshub, /overlayer/zaisys) -- either
//! as source (copying core-OS files out) or destination (copying files
//! into the core OS).
//!
//! IMPORTANT LIMITATION (please read):
//! This check only applies to commands that gain root privileges through
//! `elevate`/`elev`. It cannot stop destructive operations run directly
//! from an already-open root shell, access gained by modifying permissions
//! via `chmod`/`chown`, or any other route (e.g. deleting a file via
//! Python/Perl). This is a "defense in depth" layer -- for guaranteed,
//! unbypassable protection, OS-level immutability (e.g. a read-only bind
//! mount, or the equivalent of `chattr +i`) should be used alongside it.
//!
//! The root user is NOT exempt from this check, as requested.

use std::ffi::OsStr;
use std::path::Path;

/// These paths are Zainium OS's immutable core layers. Neither these paths
/// themselves nor anything underneath them may be modified/deleted by a
/// destructive command. Derived from `elevate_privilege.toml`'s configured
/// `prefix` (defaults to `/overlayer`, `/overlayer/syshub`, `/overlayer/zaisys`).
fn protected_prefixes() -> Vec<String> {
    elevate_paths::get().protected_layers()
}

/// These commands are considered dangerous to the core OS layers -- they
/// can delete, move, or securely wipe files/directories (rm, rmdir, mv,
/// shred, unlink), or copy files into/out of a protected path (cp, rsync).
/// For copy commands, ANY argument under a protected prefix is blocked --
/// this covers both directions: copying a core-OS file elsewhere
/// (exfiltration/backup) and copying an outside file into the core OS
/// (tampering/injection) -- since `check_command` below already checks
/// every argument, not just the last one.
const PROTECTED_COMMANDS: &[&str] = &["rm", "rmdir", "mv", "shred", "unlink", "cp", "rsync"];

/// Only these EXACT command lines (binary base name "zex" + arguments) are
/// allowed as an override -- the legitimate system-upgrade use case, where
/// syshub's old files legitimately need to be replaced/deleted.
///
/// Every pattern here is one that can ONLY touch syshub (never userland) --
/// confirmed against zex's real CLI (`zex/src/cmd/upgrade/main.rs`,
/// `zex/src/cmd/update/main.rs`): `syshub`'s `-u`/`--u`/`--upgrade` are all
/// clap aliases for the same flag, and `update --syshub-only` scopes the
/// combined updater to syshub alone (with or without `-y`/`--yes`).
///
/// Deliberately NOT included: bare `zex update` / `zex update --yes` (these
/// also touch userland, so they're not an exclusively-syshub pattern), and
/// any `zex uland ...` / `zex update --uland-only` form (these never touch
/// syshub at all, so they need no override here -- listing them would only
/// widen this allowlist without a reason tied to the core-protector's job).
///
/// NOTE: if the upgrade command's arguments differ at all from one of these
/// exact patterns (extra flags, different order), the override will NOT
/// match -- this is intentionally strict so that nobody can easily use
/// "upgrade" as an excuse to bypass protection.
const UPGRADE_OVERRIDE_PATTERNS: &[&[&str]] = &[
    &["syshub", "-u"],
    &["syshub", "--u"],
    &["syshub", "--upgrade"],
    &["update", "--syshub-only"],
    &["update", "--syshub-only", "-y"],
    &["update", "--syshub-only", "--yes"],
];

/// Result indicating whether a command is allowed or blocked.
pub enum CoreProtectorVerdict {
    Allowed,
    Blocked { offending_path: String },
}

/// Extracts the command's base name (stripping any path prefix), so that
/// both "/bin/rm" and "rm" match the same way.
fn base_name(arg0: &OsStr) -> String {
    Path::new(arg0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| arg0.to_string_lossy().into_owned())
}

/// Checks whether the given path (or its normalized form) is equal to, or
/// falls "underneath", one of the protected prefixes.
///
/// This only does a textual prefix-match (it does not resolve symlinks) --
/// so the command's argument is checked as given (after lexical
/// normalization). There is a symlink-based bypass risk (e.g. if a symlink
/// elsewhere points at a protected path) -- in production, combining this
/// with `fs::canonicalize` should also be considered if symlink attacks are
/// a concern.
fn path_is_protected(raw_arg: &OsStr) -> Option<String> {
    let arg_str = raw_arg.to_string_lossy();

    // Only treat arguments that look like absolute paths as paths
    // (ignore flags like "-rf").
    if !arg_str.starts_with('/') {
        return None;
    }

    // Lexical normalization: strip trailing slashes so that
    // "/overlayer/" also matches "/overlayer".
    let normalized = arg_str.trim_end_matches('/');

    for prefix in &protected_prefixes() {
        if normalized == prefix {
            return Some(arg_str.into_owned());
        }
        // Prefix match: any sub-path starting with protected_path + "/"
        // is also protected (e.g. /overlayer/syshub/bin/ls).
        let prefix_with_slash = format!("{prefix}/");
        if normalized.starts_with(&prefix_with_slash) {
            return Some(arg_str.into_owned());
        }
    }

    None
}

/// Checks whether this exact command matches one of the "zex syshub ..."
/// upgrade override patterns (see `UPGRADE_OVERRIDE_PATTERNS`).
fn matches_upgrade_override(command_base: &str, args: &[std::ffi::OsString]) -> bool {
    if command_base != "zex" {
        return false;
    }
    let rest: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    UPGRADE_OVERRIDE_PATTERNS.iter().any(|pattern| {
        rest.len() == pattern.len() && rest.iter().zip(*pattern).all(|(a, b)| a == b)
    })
}

/// Main entry point: checks the given command (binary path/name +
/// arguments) against the Zero-Trust Core Protector.
///
/// `command_arg0` -- the binary being run (e.g. "/bin/rm" or "rm")
/// `args`         -- all remaining arguments to the command
pub fn check_command(command_arg0: &OsStr, args: &[std::ffi::OsString]) -> CoreProtectorVerdict {
    let base = base_name(command_arg0);

    // This check only applies to the protected command set.
    if !PROTECTED_COMMANDS.contains(&base.as_str()) {
        return CoreProtectorVerdict::Allowed;
    }

    // Legitimate upgrade override -- an exact "zex syshub -u" command is
    // exempt from this check. (Note: this check's own base command is
    // "zex", not "rm" -- so it is currently unreachable against the
    // destructive-commands list above; the override is kept explicit here
    // as a documentation/extension point, in case "zex" itself becomes a
    // wrapper around a destructive-equivalent operation in the future. For
    // now, if "zex syshub -u" itself invokes "rm" internally, the
    // per-argument check below is what applies.)
    if matches_upgrade_override(&base, args) {
        return CoreProtectorVerdict::Allowed;
    }

    for arg in args {
        if let Some(offending_path) = path_is_protected(arg) {
            return CoreProtectorVerdict::Blocked { offending_path };
        }
    }

    CoreProtectorVerdict::Allowed
}

/// Prints a critical error and immediately exits the process.
/// This function never returns.
pub fn abort_with_violation(offending_path: &str) -> ! {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "Zainium Security Violation: Modification of Core OS layers is strictly prohibited"
    );
    let _ = writeln!(std::io::stderr(), "Blocked path: {offending_path}");
    let _ = writeln!(
        std::io::stderr(),
        "This action was blocked by the Zero-Trust Core Protector, even though you are root."
    );
    std::process::exit(77); // EX_NOPERM-style exit code, distinct from normal sudo errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn blocks_exact_match() {
        let verdict = check_command(OsStr::new("rm"), &args(&["-rf", "/overlayer"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn blocks_nested_path() {
        let verdict = check_command(
            OsStr::new("/bin/rm"),
            &args(&["-rf", "/overlayer/syshub/bin/ls"]),
        );
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn blocks_zaisys() {
        let verdict = check_command(OsStr::new("rm"), &args(&["/overlayer/zaisys/kernel"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn allows_unrelated_path() {
        let verdict = check_command(OsStr::new("rm"), &args(&["-rf", "/home/user/tmp"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Allowed));
    }

    #[test]
    fn allows_non_destructive_command() {
        let verdict = check_command(OsStr::new("cat"), &args(&["/overlayer/syshub/etc/passwd"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Allowed));
    }

    #[test]
    fn does_not_false_positive_on_similar_prefix() {
        // "/overlayer-backup" should NOT match "/overlayer" prefix check.
        let verdict = check_command(OsStr::new("rm"), &args(&["-rf", "/overlayer-backup"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Allowed));
    }

    #[test]
    fn handles_trailing_slash() {
        let verdict = check_command(OsStr::new("rm"), &args(&["-rf", "/overlayer/"]));
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn blocks_cp_out_of_syshub() {
        // Exfiltrating/backing up a core-OS file elsewhere.
        let verdict = check_command(
            OsStr::new("cp"),
            &args(&["/overlayer/syshub/bin/elevate", "/home/user/backup"]),
        );
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn blocks_cp_into_syshub() {
        // Tampering with / injecting a file into the core OS.
        let verdict = check_command(
            OsStr::new("cp"),
            &args(&["/home/user/evil", "/overlayer/syshub/bin/ls"]),
        );
        assert!(matches!(verdict, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn blocks_rsync_either_direction() {
        let out = check_command(
            OsStr::new("rsync"),
            &args(&["-a", "/overlayer/zaisys/kernel", "/tmp/leak"]),
        );
        assert!(matches!(out, CoreProtectorVerdict::Blocked { .. }));

        let into = check_command(
            OsStr::new("/bin/rsync"),
            &args(&["-a", "/tmp/evil/", "/overlayer/syshub/lib/"]),
        );
        assert!(matches!(into, CoreProtectorVerdict::Blocked { .. }));
    }

    #[test]
    fn allows_unrelated_cp() {
        let verdict = check_command(
            OsStr::new("cp"),
            &args(&["/home/user/a.txt", "/home/user/b.txt"]),
        );
        assert!(matches!(verdict, CoreProtectorVerdict::Allowed));
    }

    #[test]
    fn upgrade_override_matches_all_syshub_patterns() {
        for pattern in &[
            &["syshub", "-u"][..],
            &["syshub", "--u"][..],
            &["syshub", "--upgrade"][..],
            &["update", "--syshub-only"][..],
            &["update", "--syshub-only", "-y"][..],
            &["update", "--syshub-only", "--yes"][..],
        ] {
            assert!(
                matches_upgrade_override("zex", &args(pattern)),
                "expected override to match: zex {}",
                pattern.join(" ")
            );
        }
    }

    #[test]
    fn upgrade_override_rejects_uland_patterns() {
        // uland never touches syshub -- it must NOT be treated as a
        // core-protector override, even though it's a legitimate zex command.
        for pattern in &[
            &["uland", "-u"][..],
            &["uland", "--u"][..],
            &["uland", "--upgrade"][..],
            &["update", "--uland-only"][..],
        ] {
            assert!(
                !matches_upgrade_override("zex", &args(pattern)),
                "override must NOT match uland-only command: zex {}",
                pattern.join(" ")
            );
        }
    }

    #[test]
    fn upgrade_override_rejects_bare_and_mixed_update() {
        // Bare "zex update" (and "--yes" alone) touches BOTH syshub and
        // userland -- not an exclusively-syshub pattern, so it stays out of
        // this allowlist on purpose (see UPGRADE_OVERRIDE_PATTERNS doc).
        for pattern in &[
            &["update"][..],
            &["update", "--yes"][..],
            &["update", "-y"][..],
        ] {
            assert!(
                !matches_upgrade_override("zex", &args(pattern)),
                "override must NOT match ambiguous command: zex {}",
                pattern.join(" ")
            );
        }
    }
}
