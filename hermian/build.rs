//! Builds the `hermian-ebpf` crate for `bpfel-unknown-none` and exposes the
//! resulting object path to the daemon via `HERMIAN_EBPF_OBJECT`.
//!
//! Two build strategies are attempted in order:
//!
//! 1. A stable toolchain with the `bpfel-unknown-none` target installed.
//! 2. A nightly toolchain with `rust-src`, using `-Zbuild-std=core`.
//!
//! Both require `bpf-linker` on PATH.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn rustup(args: &[&str]) -> Option<String> {
    let out = Command::new("rustup").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn toolchain_has_target() -> bool {
    rustup(&["target", "list", "--installed"])
        .map(|s| s.lines().any(|l| l.trim() == "bpfel-unknown-none"))
        .unwrap_or(false)
}

fn nightly_available() -> bool {
    rustup(&["toolchain", "list"])
        .map(|s| s.lines().any(|l| l.trim_start().starts_with("nightly")))
        .unwrap_or(false)
}

fn nightly_has_rust_src() -> bool {
    rustup(&["component", "list", "--installed", "--toolchain", "nightly"])
        .map(|s| s.lines().any(|l| l.trim().starts_with("rust-src")))
        .unwrap_or(false)
}

fn bpf_linker_available() -> bool {
    Command::new("bpf-linker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A cargo invocation that does not inherit the outer build's toolchain pins or
/// rustflags (those are for the host target and break the BPF target).
fn clean_cargo() -> Command {
    let mut cmd = Command::new("cargo");
    for var in [
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "CARGO",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn build_ebpf(ebpf_dir: &Path, out_dir: &Path) -> Result<PathBuf, String> {
    if !bpf_linker_available() {
        return Err("bpf-linker not found on PATH (cargo install bpf-linker)".into());
    }
    let target_dir = out_dir.join("ebpf-target");
    let target_dir_s = target_dir.to_string_lossy().into_owned();
    let artifact = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("hermian-ebpf");

    let mut attempts: Vec<String> = Vec::new();

    if toolchain_has_target() {
        let status = clean_cargo()
            .current_dir(ebpf_dir)
            .args([
                "build",
                "--release",
                "--target",
                "bpfel-unknown-none",
                "--target-dir",
                &target_dir_s,
            ])
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() && artifact.exists() {
            return Ok(artifact);
        }
        attempts.push("stable + bpfel-unknown-none target".into());
    }

    if nightly_available() {
        if !nightly_has_rust_src() {
            attempts.push("nightly present but missing rust-src component".into());
        } else {
            let status = clean_cargo()
                .current_dir(ebpf_dir)
                .args([
                    "+nightly",
                    "build",
                    "--release",
                    "-Zbuild-std=core",
                    "--target",
                    "bpfel-unknown-none",
                    "--target-dir",
                    &target_dir_s,
                ])
                .status()
                .map_err(|e| e.to_string())?;
            if status.success() && artifact.exists() {
                return Ok(artifact);
            }
            attempts.push("nightly + -Zbuild-std=core".into());
        }
    }

    Err(format!(
        "tried: {}",
        if attempts.is_empty() {
            "nothing (no usable toolchain)".to_string()
        } else {
            attempts.join("; ")
        }
    ))
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let ebpf_dir = manifest_dir.join("../hermian-ebpf");

    println!("cargo:rerun-if-env-changed=HERMIAN_EBPF_PREBUILT");
    // A pre-built object (from a release pipeline or a host with a newer LLVM)
    // skips the BPF toolchain requirement entirely. The object is
    // target-independent, so it may be produced on any machine.
    if let Some(prebuilt) = env::var_os("HERMIAN_EBPF_PREBUILT") {
        let p = PathBuf::from(prebuilt);
        if !p.is_file() {
            panic!("HERMIAN_EBPF_PREBUILT={} is not a file", p.display());
        }
        println!("cargo:rerun-if-changed={}", p.display());
        println!("cargo:rustc-env=HERMIAN_EBPF_OBJECT={}", p.display());
        return;
    }

    let obj_path = match build_ebpf(&ebpf_dir, &out_dir) {
        Ok(p) => p,
        Err(why) => panic!(
            "\n\nhermian-ebpf build failed ({why}).\n\
             One of the following is required on the build host:\n  \
             a) rustup target add bpfel-unknown-none && cargo install bpf-linker\n  \
             b) rustup toolchain install nightly --component rust-src && cargo install bpf-linker\n"
        ),
    };

    println!("cargo:rustc-env=HERMIAN_EBPF_OBJECT={}", obj_path.display());
    println!("cargo:rerun-if-changed=../hermian-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../hermian-ebpf/Cargo.toml");
}
