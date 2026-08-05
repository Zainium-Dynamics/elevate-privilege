//! Built-in modules always available in static / standalone (and as fallback in shared).

mod access;
mod debug;
mod deny;
mod echo;
mod env;
mod exec;
mod faildelay;
mod faillock;
mod issue;
mod limits;
mod localuser;
mod mail;
mod mkhomedir;
mod motd;
mod nologin;
mod permit;
mod rootok;
mod securetty;
mod shells;
mod succeed_if;
mod umask;
mod unix;
mod usertype;
mod warn;
mod wheel;

use crate::module::{global, ModuleHooks, ModuleId};

/// Register all builtin modules into the process registry.
pub fn register_all() {
    register_one(permit::hooks());
    register_one(deny::hooks());
    register_one(rootok::hooks());
    register_one(unix::hooks());
    register_one(env::hooks());
    register_one(limits::hooks());
    register_one(wheel::hooks());
    register_one(nologin::hooks());
    register_one(securetty::hooks());
    register_one(shells::hooks());
    register_one(motd::hooks());
    register_one(umask::hooks());
    register_one(exec::hooks());
    register_one(succeed_if::hooks());
    register_one(mail::hooks());
    register_one(faildelay::hooks());
    register_one(warn::hooks());
    register_one(issue::hooks());
    register_one(localuser::hooks());
    register_one(usertype::hooks());
    register_one(echo::hooks());
    register_one(debug::hooks());
    register_one(access::hooks());
    register_one(faillock::hooks());
    register_one(mkhomedir::hooks());

    // aliases without path
    register_alias("pam_permit.so", "permit");
    register_alias("pam_deny.so", "deny");
    register_alias("pam_unix.so", "unix");
    register_alias("pam_env.so", "env");
    register_alias("pam_limits.so", "limits");
    register_alias("pam_rootok.so", "rootok");
    register_alias("pam_wheel.so", "wheel");
    register_alias("pam_nologin.so", "nologin");
    register_alias("pam_securetty.so", "securetty");
    register_alias("pam_shells.so", "shells");
    register_alias("pam_motd.so", "motd");
    register_alias("pam_umask.so", "umask");
    register_alias("pam_exec.so", "exec");
    register_alias("pam_succeed_if.so", "succeed_if");
    register_alias("pam_mail.so", "mail");
    register_alias("pam_faildelay.so", "faildelay");
    register_alias("pam_warn.so", "warn");
    register_alias("pam_issue.so", "issue");
    register_alias("pam_localuser.so", "localuser");
    register_alias("pam_usertype.so", "usertype");
    register_alias("pam_echo.so", "echo");
    register_alias("pam_debug.so", "debug");
    register_alias("pam_access.so", "access");
    register_alias("pam_faillock.so", "faillock");
    register_alias("pam_mkhomedir.so", "mkhomedir");
}

fn register_one(hooks: ModuleHooks) {
    global::register(hooks);
}

fn register_alias(alias: &str, canonical: &str) {
    if let Some(h) = global::get(&ModuleId::normalize(canonical)) {
        let mut copy = (*h).clone();
        copy.id = ModuleId::normalize(alias);
        global::register(copy);
    }
}
