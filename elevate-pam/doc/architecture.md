# Architecture

## Layers

1. **C ABI (`ffi`)** — Linux-PAM 1.7 symbols for elevate and C apps.
2. **Application Rust API (`appl`, `handle`)** — safe wrappers.
3. **Dispatch** — stack evaluation (`required` / `requisite` / `sufficient` / `optional` / include).
4. **Modules** — builtin registry + optional `dlopen` (`loader`).
5. **Config** — TOML only (`GlobalConfig`, `ServiceConfig`).

## Build categories

```
elevate-pam.toml [build]
  shared     → cdylib + dynload
  static     → modules in archive / registry only
  standalone → CLI embeds registry (no external .so)
```

## Data flow (authenticate)

```
pam_start → load service TOML → PamHandle
pam_authenticate → dispatch(Auth)
  for each ModuleEntry:
    resolve_module (builtin | dlopen)
    call pam_sm_authenticate equivalent
    apply control actions → impression/status
fail_delay if failure
return status
```

## Elevate integration

elevate does **not** link `-lpam`. It `dlopen`s `libpam.so.0` at runtime. Installing elevate-pam as that soname (or `LD_LIBRARY_PATH`) is sufficient.
