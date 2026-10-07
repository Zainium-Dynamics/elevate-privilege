# elevate-pam

A Linux-PAM implementation in Rust. It follows Linux-PAM: the same four
stacks (auth, account, session, password), the same C `pam_*` ABI so existing
Linux-PAM modules can load, and modules named and behaving like the usual
`pam_unix`, `pam_env`, `pam_limits`, `pam_faillock` and so on. The one big
difference is that service stacks are TOML files instead of `/etc/pam.d` text
(the old format can still be read if you build with the `legacy_pamd` feature).

It's used by [elevate](https://github.com/Zainium-Dynamics/elevate), but
nothing here depends on it.

Status: works for the stacks we use it for, but it's young. `chauthtok` in the
builtin `pam_unix` is not finished (it returns `PAM_AUTHTOK_ERR`), so be
careful with password-change stacks. See [SECURITY.md](SECURITY.md).

## What's here

```
pam/              the engine, built as libelevate_pam (rlib, cdylib, staticlib)
libpam-abi/       libpam.so.0-compatible shim
libpam-misc/      pam_misc helpers
elevate-pam-cli/  small CLI
pam-*/            modules built as loadable pam_*.so (unix, env, limits, ...)
helpers/          unix_chkpwd
etc/              example config and service stacks
include/security/ C headers
```

Builtin modules (compiled into the library): `access`, `debug`, `deny`, `echo`,
`env`, `exec`, `faildelay`, `faillock`, `issue`, `limits`, `localuser`, `mail`,
`mkhomedir`, `motd`, `namespace`, `nologin`, `permit`, `rootok`, `securetty`,
`shells`, `succeed_if`, `systemd`, `tally2`, `umask`, `unix`, `usertype`,
`warn`, `wheel`. Some of them also exist as separate `pam-*` crates if you'd
rather load them as `.so` files.

## Building

```sh
make            # release build of everything
make test
```

Passwords are checked with [elevate-crypto](https://github.com/Zainium-Dynamics/elevate-crypto),
which cargo pulls from git. If you'd rather not depend on it:

```sh
cargo build --release -p elevate-pam --no-default-features \
  --features std,dynload,syslog,secure_mem,fail_delay,builtin_modules
```

The core also builds without `std` (`make check-nostd`).

## Configuration

The main config is `elevate-pam.toml`. elevate-pam uses the first one it finds:

1. the file named by `$ELEVATE_PAM_CONFIG`
2. `/etc/elevate-pam/elevate-pam.toml`
3. `/etc/elevate-pam.toml`
4. `./elevate-pam.toml`

Where everything lives is set in its `[paths]` table. You only need to set what
differs from the defaults, and anything you leave out is worked out from
`prefix`:

```toml
[paths]
prefix = "/opt/pam"
# etc_dir    = "<prefix>/etc"
# conf_dir   = "<etc_dir>/elevate-pam"      # services/, services.d/
# module_dir = "<prefix>/lib/security"      # pam_*.so
# vendor_dir = "<prefix>/lib/elevate-pam/services"
# var_dir    = "<prefix>/var/run/elevate"   # faillock, tallylog, timestamps
```

With no config file it uses the normal layout (`/etc`, `/lib/security`, ...).
There's a commented example in
[etc/elevate-pam/elevate-pam.toml](etc/elevate-pam/elevate-pam.toml) and sample
stacks in [etc/elevate-pam/services/](etc/elevate-pam/services).

A service stack looks like this (`services/other.toml`):

```toml
[service]
name = "other"

[[auth]]
control = "required"
module = "unix"

[[account]]
control = "required"
module = "unix"
```

## Installing

```sh
sudo make install                    # /lib, /etc, /bin
make install DESTDIR=$PWD/pkg        # stage it for a package
make install PREFIX=/opt/pam         # relocated, writes prefix into the config
```

For a relocated install, point programs at the config with
`ELEVATE_PAM_CONFIG=/opt/pam/etc/elevate-pam/elevate-pam.toml`.

## License

MIT OR Apache-2.0, see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
