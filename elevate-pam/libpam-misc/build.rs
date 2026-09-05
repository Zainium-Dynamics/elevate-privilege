fn main() {
    // Same reasoning as libpam-abi/build.rs: bake the real SONAME in at
    // link time instead of shipping cargo's default "libpam_misc.so".
    println!("cargo:rustc-link-arg=-Wl,-soname,libpam_misc.so.0");
}
