//! elevate-crypto is pure Rust. Only optional system `libcrypt` for shadow formats.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_FEATURE_SYSTEM_CRYPT").is_ok() {
        // Optional: glibc crypt in libcrypt; musl may provide crypt in libc.
        println!("cargo:rustc-link-lib=dylib=crypt");
    }
}
