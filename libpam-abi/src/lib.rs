//! No new code -- this crate exists purely so `cargo build` also produces
//! a `libpam.so` (see `build.rs` for the `libpam.so.0` SONAME). The
//! `#[no_mangle] extern "C"` PAM functions themselves all live in
//! `elevate-pam`; `no_mangle` is exactly what keeps them from being
//! dead-code-eliminated once statically linked in here.
pub use elevate_pam::*;
