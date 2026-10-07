fn main() {
    // glibc moved crypt(3) to libcrypt; musl may provide it in libc.
    // Link libcrypt when present for password verification.
    println!("cargo:rustc-link-lib=dylib=crypt");
    println!("cargo:rerun-if-changed=build.rs");
}
