fn main() {
    // Bake the real SONAME in at link time -- so the dynamic linker's
    // DT_NEEDED resolution in anything that links this .so sees
    // "libpam.so.0", not cargo's default (which would be "libpam.so",
    // taken from the on-disk filename with no version at all).
    println!("cargo:rustc-link-arg=-Wl,-soname,libpam.so.0");
}
