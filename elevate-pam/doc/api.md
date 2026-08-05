# API overview

## Rust

```rust
use elevate_pam::appl::PamBuilder;
use elevate_pam::conv::PamConv;

let pamh = PamBuilder::new("elevate")
    .user("alice")
    .start(conv)?;
pamh.authenticate(0)?;
pamh.acct_mgmt(0)?;
pamh.open_session(0)?;
// …
pamh.end(0)?;
```

## C (Linux-PAM compatible)

```c
pam_start("elevate", user, &conv, &pamh);
pam_authenticate(pamh, 0);
pam_acct_mgmt(pamh, 0);
pam_open_session(pamh, 0);
pam_close_session(pamh, 0);
pam_end(pamh, status);
```

## Config types

- `GlobalConfig` — `elevate-pam.toml`
- `ServiceConfig` — `/etc/elevate-pam/services/<name>.toml`
- `BuildConfig` — `shared` / `static` / `standalone` booleans

## Control flags

| Flag | Semantics |
|------|-----------|
| required | Fail recorded; continue; final fail if any failed |
| requisite | Fail immediate |
| sufficient | Success short-circuits if no prior required fail |
| optional | Only matters if no other decision |
| include / substack | Nested service load |
