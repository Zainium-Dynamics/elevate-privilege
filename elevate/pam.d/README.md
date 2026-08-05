# Legacy pam.d samples (optional)

Production on Zainium uses **elevate-pam TOML** stacks:

```
/etc/elevate-pam/services/elevate.toml
/etc/elevate-pam/services/elev.toml
/etc/elevate-pam/services/elev-l.toml
```

These classic pam.d files are kept only as a readable mirror of the same
policy for operators who still have a transitional `libpam` install.

elevate itself loads **`libelevate_pam.so`** (see `src/pam/dynload.rs`),
not a hard-coded path into this directory.
