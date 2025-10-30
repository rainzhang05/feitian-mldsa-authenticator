use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR")).join("..")
}

fn target_subdir() -> String {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    match (os.as_str(), arch.as_str()) {
        ("linux", "aarch64") => "linux-aarch64".to_string(),
        ("linux", "x86_64") => "linux-x86_64".to_string(),
        _ => panic!("unsupported prebuilt liboqs target {os}-{arch}"),
    }
}

fn lib_directory(root: &Path) -> PathBuf {
    root.join("prebuilt_liboqs")
        .join(target_subdir())
        .join("lib")
}

fn include_directory(root: &Path) -> PathBuf {
    root.join("prebuilt_liboqs")
        .join(target_subdir())
        .join("include")
}

fn ensure_symbol(lib: &Path, symbol: &str) {
    let mut cmd = Command::new("nm");
    let is_shared = lib
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.contains(".so"))
        .unwrap_or(false);
    if is_shared {
        cmd.arg("-D");
    }
    let output = cmd
        .arg(lib)
        .output()
        .unwrap_or_else(|e| panic!("failed to invoke nm on {}: {e}", lib.display()));
    if !output.status.success() {
        panic!("nm reported an error while inspecting {}", lib.display());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains(symbol) {
        panic!("symbol {symbol} not found in {}", lib.display());
    }
}

enum LibraryKind {
    Static,
    Dynamic,
}

const SHARED_CANDIDATES: &[&str] = &[
    "liboqs.so",
    "liboqs.so.0.15.0-rc1",
    "liboqs.so.9",
    "liboqs.so.0.14.1-dev",
    "liboqs.so.8",
];

fn select_library(lib_dir: &Path) -> (PathBuf, LibraryKind) {
    let static_lib = lib_dir.join("liboqs.a");
    if static_lib.exists() {
        return (static_lib, LibraryKind::Static);
    }
    for candidate in SHARED_CANDIDATES.iter().map(|name| lib_dir.join(name)) {
        if let Ok(meta) = candidate.metadata() {
            if meta.len() > 1024 {
                return (candidate, LibraryKind::Dynamic);
            }
        }
    }
    panic!(
        "neither liboqs.a nor a usable liboqs.so variant found under {}",
        lib_dir.display()
    );
}

fn main() {
    let root = workspace_root();
    let lib_dir = lib_directory(&root);
    if !lib_dir.exists() {
        panic!("liboqs lib directory missing: {}", lib_dir.display());
    }

    let (link_target, kind) = select_library(&lib_dir);
    match kind {
        LibraryKind::Static => {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=static=oqs");
        }
        LibraryKind::Dynamic => {
            let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
            for name in SHARED_CANDIDATES {
                let source = lib_dir.join(name);
                if let Ok(meta) = source.metadata() {
                    if meta.len() > 0 {
                        let target_path = out_dir.join(name);
                        fs::copy(&source, &target_path)
                            .unwrap_or_else(|e| panic!("failed to stage {name}: {e}"));
                    }
                }
            }
            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=dylib=oqs");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", out_dir.display());
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
        }
    }

    ensure_symbol(&link_target, "OQS_SIG_ml_dsa_44_sign");
    ensure_symbol(&link_target, "OQS_SIG_ml_dsa_65_sign");
    ensure_symbol(&link_target, "OQS_SIG_ml_dsa_87_sign");

    let include_dir = include_directory(&root);
    let config = include_dir.join("oqs/oqsconfig.h");
    println!("cargo:rerun-if-changed={}", config.display());
    let contents = fs::read_to_string(&config)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config.display()));
    if let Some(line) = contents.lines().find(|l| l.contains("OQS_VERSION_TEXT")) {
        println!("cargo:warning=detected liboqs version {line}");
    }
}
