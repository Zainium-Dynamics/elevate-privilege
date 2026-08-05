//! Translation layer for user-facing strings.
//!
//! No gettext catalog is wired up (no `po/` directory, no `msgfmt` build
//! step) — these macros simply format the string as-is. `xlat!` mirrors
//! `format!` (or a bare string when no interpolation args are given),
//! `xlat_write!` mirrors `write!`, and `xlat_println!` mirrors the
//! crate's non-panicking `println_ignore_io_error!`.

macro_rules! xlat {
    ($fmt:expr) => {
        $fmt
    };
    ($fmt:expr, $($args:tt)*) => {
        format!($fmt, $($args)*)
    };
}

macro_rules! xlat_write {
    ($($args:tt)*) => {
        write!($($args)*)
    };
}

macro_rules! xlat_println {
    ($($args:tt)*) => {
        println_ignore_io_error!($($args)*)
    };
}
