use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

// src/layout.rs re-emitted as assembler symbols, so the shims address the measured map.
#[allow(dead_code)]
mod layout {
    include!("src/layout.rs");
}
#[allow(unused_imports)]
use layout::*;

fn run(command: &mut Command) {
    let status = command.status().expect("failed to execute assembler tool");
    assert!(status.success(), "assembler tool failed");
}

fn write_layout(path: &Path) {
    let mut out = String::from("# Generated from src/layout.rs by build.rs.\n");
    for (name, value) in layout::SYMBOLS {
        out.push_str(&format!(".set {name}, {value:#x}\n"));
    }
    // A processor count, so not one of the u64 addresses the macro above emits.
    out.push_str(&format!(".set MAX_VCPUS, {:#x}\n", layout::MAX_VCPUS));
    fs::write(path, out).expect("write layout.inc");
}

fn assemble(out: &Path, name: &str) -> PathBuf {
    let object = out.join(format!("{name}.o"));
    run(Command::new("as")
        .args(["--64", "-I", "src", "-I"])
        .arg(out)
        .arg("-o")
        .arg(&object)
        .arg(format!("src/{name}.S")));
    object
}

fn flatten(out: &Path, name: &str) {
    let object = assemble(out, name);
    run(Command::new("objcopy")
        .args(["-O", "binary", "-j", ".reset"])
        .arg(&object)
        .arg(out.join(format!("{name}.bin"))));
}

/// The same macros, assembled into an ordinary object the crate's tests link
/// against and call. Building it always, rather than only under cfg(test),
/// keeps a shim that no longer assembles from reaching a release.
fn harness(out: &Path) {
    let object = assemble(out, "harness");
    let archive = out.join("libcvmshim.a");
    let _ = fs::remove_file(&archive);
    run(Command::new("ar").arg("crs").arg(&archive).arg(&object));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=cvmshim");
}

fn main() {
    println!("cargo:rerun-if-changed=src/reset.S");
    println!("cargo:rerun-if-changed=src/snp_reset.S");
    println!("cargo:rerun-if-changed=src/madt.inc");
    println!("cargo:rerun-if-changed=src/map.inc");
    println!("cargo:rerun-if-changed=src/harness.S");
    println!("cargo:rerun-if-changed=src/layout.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    write_layout(&out.join("layout.inc"));
    flatten(&out, "reset");
    flatten(&out, "snp_reset");
    harness(&out);
}
