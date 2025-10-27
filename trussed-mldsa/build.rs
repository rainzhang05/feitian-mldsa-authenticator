fn main() {
    // Compile the C implementation of ML‑DSA.  The C sources live under
    // mldsa-native/ and expose stub functions for key generation and signing.
    let mut build = cc::Build::new();
    build.include("mldsa-native");
    build.file("mldsa-native/mldsa.c");
    build.flag_if_supported("-O2");
    build.flag_if_supported("-fPIC");
    build.compile("mldsa_native");
    println!("cargo:rerun-if-changed=mldsa-native/mldsa.c");
    println!("cargo:rerun-if-changed=mldsa-native/mldsa.h");
}