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

enum BuildError {
    /// No usable BPF toolchain: falling back to the vendored object is fine.
    NoToolchain(String),
    /// A toolchain ran and the build failed: most likely an error in
    /// hermian-ebpf itself. Falling back would silently ship an object that
    /// doesn't match the source (and may not match `RawExec`'s layout).
    Failed(String),
}

fn build_ebpf(ebpf_dir: &Path, out_dir: &Path) -> Result<PathBuf, BuildError> {
    if !bpf_linker_available() {
        return Err(BuildError::NoToolchain(
            "bpf-linker not found on PATH (cargo install bpf-linker)".into(),
        ));
    }
    let target_dir = out_dir.join("ebpf-target");
    let target_dir_s = target_dir.to_string_lossy().into_owned();
    let artifact = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("hermian-ebpf");

    let mut attempts: Vec<String> = Vec::new();
    let mut ran = false;

    if toolchain_has_target() {
        ran = true;
        let status = clean_cargo()
            .current_dir(ebpf_dir)
            .args([
                "build",
                "--release",
                "--target",
                "bpfel-unknown-none",
                "--target-dir",
                &target_dir_s,
                "--locked",
            ])
            .status()
            .map_err(|e| BuildError::NoToolchain(e.to_string()))?;
        if status.success() && artifact.exists() {
            return Ok(artifact);
        }
        attempts.push("stable + bpfel-unknown-none target".into());
    }

    if nightly_available() {
        if !nightly_has_rust_src() {
            attempts.push("nightly present but missing rust-src component".into());
        } else {
            ran = true;
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
                    "--locked",
                ])
                .status()
                .map_err(|e| BuildError::NoToolchain(e.to_string()))?;
            if status.success() && artifact.exists() {
                return Ok(artifact);
            }
            attempts.push("nightly + -Zbuild-std=core".into());
        }
    }

    let why = format!(
        "tried: {}",
        if attempts.is_empty() {
            "nothing (no usable toolchain)".to_string()
        } else {
            attempts.join("; ")
        }
    );
    Err(if ran {
        BuildError::Failed(why)
    } else {
        BuildError::NoToolchain(why)
    })
}

#[derive(PartialEq)]
enum SourceMode {
    /// Build from source if a toolchain exists, else use the vendored object.
    Auto,
    /// `HERMIAN_EBPF_FROM_SOURCE=1`: build from source or fail (CI).
    Force,
    /// `HERMIAN_EBPF_FROM_SOURCE=0`: always use the vendored object.
    Never,
}

fn source_mode() -> SourceMode {
    match env::var("HERMIAN_EBPF_FROM_SOURCE").ok().as_deref() {
        None | Some("") => SourceMode::Auto,
        Some("0") | Some("false") | Some("no") => SourceMode::Never,
        Some(_) => SourceMode::Force,
    }
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
        let given = PathBuf::from(prebuilt);
        // include_bytes! resolves relative paths against src/ebpf.rs, not the
        // package dir, so hand it an absolute path.
        let p = given
            .canonicalize()
            .unwrap_or_else(|_| panic!("HERMIAN_EBPF_PREBUILT={} is not a file", given.display()));
        if !p.is_file() {
            panic!("HERMIAN_EBPF_PREBUILT={} is not a file", p.display());
        }
        println!("cargo:rerun-if-changed={}", p.display());
        println!("cargo:rustc-env=HERMIAN_EBPF_OBJECT={}", p.display());
        return;
    }

    // Order of preference:
    //   1. build from source when a BPF toolchain is present (developers);
    //   2. the vendored object in hermian-ebpf/prebuilt (release builds and
    //      hosts whose LLVM is too old for bpf-linker);
    //   3. fail with instructions.
    // HERMIAN_EBPF_FROM_SOURCE=1 forces (1) and refuses to fall back, so CI
    // can prove the vendored object is up to date; =0 skips straight to (2).
    // A toolchain that runs but fails to compile is an error, not a reason
    // to fall back.
    let vendored = ebpf_dir.join("prebuilt/hermian-ebpf.o");
    println!("cargo:rerun-if-changed={}", vendored.display());
    println!("cargo:rerun-if-env-changed=HERMIAN_EBPF_FROM_SOURCE");
    let mode = source_mode();

    let result = if mode == SourceMode::Never {
        Err(BuildError::NoToolchain("HERMIAN_EBPF_FROM_SOURCE=0".into()))
    } else {
        build_ebpf(&ebpf_dir, &out_dir)
    };
    let obj_path = match result {
        Ok(p) => p,
        Err(BuildError::Failed(why)) if mode != SourceMode::Force => panic!(
            "\n\nhermian-ebpf failed to compile ({why}).\n\
             Not falling back to the vendored object: it would no longer match the source.\n\
             Fix the error, or build with HERMIAN_EBPF_FROM_SOURCE=0 to use \
             hermian-ebpf/prebuilt/hermian-ebpf.o on purpose.\n"
        ),
        Err(BuildError::NoToolchain(why)) if vendored.is_file() && mode != SourceMode::Force => {
            println!("cargo:warning=hermian-ebpf: no BPF toolchain ({why}); using vendored hermian-ebpf/prebuilt/hermian-ebpf.o");
            vendored
        }
        Err(BuildError::Failed(why) | BuildError::NoToolchain(why)) => panic!(
            "\n\nhermian-ebpf build failed ({why}) and no vendored object was found.\n\
             One of the following is required on the build host:\n  \
             a) rustup target add bpfel-unknown-none && cargo install bpf-linker\n  \
             b) rustup toolchain install nightly --component rust-src && cargo install bpf-linker\n  \
             c) HERMIAN_EBPF_PREBUILT=/path/to/hermian-ebpf.o\n"
        ),
    };

    println!("cargo:rustc-env=HERMIAN_EBPF_OBJECT={}", obj_path.display());
    println!("cargo:rerun-if-changed=../hermian-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../hermian-ebpf/Cargo.toml");
}
