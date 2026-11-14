use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=CRONET_LIB_DIR");
    println!("cargo:rustc-check-cfg=cfg(cronet_static)");

    let Some(directory) = env::var_os("CRONET_LIB_DIR").map(PathBuf::from) else {
        return;
    };
    if !directory.is_dir() {
        panic!("CRONET_LIB_DIR is not a directory: {}", directory.display());
    }

    let Some(archive) = find(&directory, &["libcronet.a", "cronet.lib", "libcronet.lib"]) else {
        panic!(
            "CRONET_LIB_DIR={} holds no static libcronet.a/cronet.lib; \
             unset it to load libcronet at runtime instead",
            directory.display()
        );
    };

    if archive.metadata().map(|meta| meta.len()).unwrap_or(0) < 4 * 1024 * 1024 {
        println!(
            "cargo:warning={} is far smaller than a static Cronet archive; \
             an import library for the shared Cronet cannot be linked in",
            archive.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rerun-if-changed={}", archive.display());
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("libcronet.a");
    println!("cargo:rustc-link-lib=static:+verbatim={name}");
    println!("cargo:rustc-cfg=cronet_static");
    emit_linkage(&directory);
}

fn find(directory: &Path, names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .map(|name| directory.join(name))
        .find(|path| path.is_file())
}

fn emit_linkage(directory: &Path) {
    let link_file = directory.join("cronet.link");
    let mut libraries = false;
    if let Ok(text) = std::fs::read_to_string(&link_file) {
        println!("cargo:rerun-if-changed={}", link_file.display());
        for line in text.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("lib=") {
                println!("cargo:rustc-link-lib={name}");
                libraries = true;
            } else if let Some(name) = line.strip_prefix("framework=") {
                println!("cargo:rustc-link-lib=framework={name}");
                libraries = true;
            } else if let Some(flag) = line.strip_prefix("arg=") {
                println!("cargo:rustc-link-arg={flag}");
            }
        }
    }
    if !libraries {
        for name in default_libraries() {
            println!("cargo:rustc-link-lib={name}");
        }
    }
}

fn default_libraries() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            "ws2_32", "crypt32", "bcrypt", "advapi32", "user32", "ole32", "oleaut32", "shell32",
            "shlwapi", "iphlpapi", "secur32", "dbghelp", "winmm", "userenv", "version", "psapi",
            "wintrust", "rpcrt4",
        ]
    } else if cfg!(target_os = "linux") {
        &["dl", "pthread", "m"]
    } else {
        &[]
    }
}
