# zainium-logind-session

Registers a real **logind** session for a process, then `exec`s it.

## Why this exists

systemd ships `pam_systemd.so` to do this from inside the PAM session stack.
On Zainium that module can never work: it has libpam statically linked in and
reads the `pam_handle_t` it is handed using **Linux-PAM's** internal struct
layout, while Zainium's PAM is `elevate-pam` — a from-scratch Rust
implementation whose `PamHandle` is a Rust struct with a completely different
layout. Worse, the stack lists it as `session optional`, so the mismatch failed
*silently*:

- no logind session was ever created for the greeter or the user session
- `libseat`'s logind backend found nothing → cosmic-comp died with
  `Failed to acquire session`
- NetworkManager logged `session-monitor: failed to create systemd-logind
  monitor: -2` for the same underlying reason

## What it does

Exactly what `pam_systemd.so` would have done, over the same D-Bus API, without
being a PAM module. `CreateSession` is **root-only**, so it has to run where
pam_systemd runs — inside the display manager, before privileges are dropped:

1. greetd's session worker forks, does `setgroups`/`setgid`, and execs this
   helper **still as root**
2. `org.freedesktop.login1.Manager.CreateSession`
3. keeps the returned **fifo fd** open — that fd *is* the session's lifetime,
   logind tears the session down the moment the last copy closes, which is why
   this `exec`s rather than forks, and why the fd is duped clear of `FD_CLOEXEC`
4. exports `XDG_SESSION_ID`, `XDG_RUNTIME_DIR`, `XDG_SEAT`, `XDG_VTNR` from
   logind's reply
5. `setuid`s to the session user, re-arms `PR_SET_PDEATHSIG`, execs the command

    zainium-logind-session --uid UID [--class CLASS] [--service NAME]
                           [--tty TTYN] -- COMMAND [ARGS...]

`XDG_SESSION_TYPE`, `XDG_SEAT`, `XDG_VTNR`, `XDG_SESSION_DESKTOP` still come
from the environment (greetd's PAM env).

Registration failures are logged (journal + stderr) and ignored — matching the
`session optional` semantics it replaces. Failing to `setuid` is never ignored:
the helper exits rather than run a session as root.

## Build

    ./build.sh [SYSHUB_DIR] [OUT]

## Caller

`greetd/src/session/worker.rs` (child branch, before `setuid`). If the helper
is missing, greetd falls back to its normal `setuid` + exec path.
