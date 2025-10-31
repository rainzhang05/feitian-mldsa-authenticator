use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=UHID_HEADER");

    let header = env::var("UHID_HEADER").unwrap_or_else(|_| "linux/uhid.h".to_string());
    let header_contents = format!("#include <{}>\n", header);

    let mut builder = bindgen::Builder::default()
        .header_contents("uhid_wrapper.h", &header_contents)
        .allowlist_type("uhid_.*")
        .allowlist_var("UHID_.*")
        .allowlist_var("HID_MAX_DESCRIPTOR_SIZE")
        .allowlist_var("BUS_.*")
        .derive_default(true)
        .layout_tests(false)
        .generate_inline_functions(false);

    if let Ok(clang_args) = env::var("BINDGEN_EXTRA_CLANG_ARGS") {
        for arg in clang_args.split_whitespace() {
            builder = builder.clang_arg(arg);
        }
    }

    let bindings = builder
        .generate()
        .expect("unable to generate uhid bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    bindings
        .write_to_file(out_path.join("uhid_bindings.rs"))
        .expect("write bindings");
}
