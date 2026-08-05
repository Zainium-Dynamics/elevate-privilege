# Contributing to elevate-pam

## Principles

1. **Security first** — authentication code is TCB. Prefer explicit, reviewed unsafe.
2. **TOML only** for configuration — never add JSON.
3. **std + no_std** stay unified; gate OS code with features.
4. **Linux-PAM ABI** stability for elevate and C consumers.

## Dev loop

```bash
cargo test -p elevate-pam
cargo build -p elevate-pam --release
make check-nostd
```

## Style

- Edition 2021, MSRV 1.85
- `unsafe_op_in_unsafe_fn` style comments on unsafe blocks
- No `cargo --all-features` assumptions for security-sensitive flags
