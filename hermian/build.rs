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

fn nightly() -> String {
    env::var("HERMIAN_EBPF_NIGHTLY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nightly".to_string())
}

fn nightly_available() -> bool {
    let want = nightly();
    rustup(&["toolchain", "list"])
        .map(|s| s.lines().any(|l| l.trim_start().starts_with(&want)))
        .unwrap_or(false)
}

fn nightly_has_rust_src() -> bool {
    rustup(&[
        "component",
        "list",
        "--installed",
        "--toolchain",
        &nightly(),
    ])
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
    NoToolchain(String),
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
            let toolchain = format!("+{}", nightly());
            let status = clean_cargo()
                .current_dir(ebpf_dir)
                .args([
                    toolchain.as_str(),
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
            attempts.push(format!("{} + -Zbuild-std=core", nightly()));
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
    Auto,
    Force,
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
    if let Some(prebuilt) = env::var_os("HERMIAN_EBPF_PREBUILT") {
        let given = PathBuf::from(prebuilt);
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
             a) rustup toolchain install nightly --component rust-src, plus bpf-linker\n     \
                (set HERMIAN_EBPF_NIGHTLY to use a specific dated nightly)\n  \
             b) HERMIAN_EBPF_PREBUILT=/path/to/hermian-ebpf.o\n"
        ),
    };

    println!("cargo:rustc-env=HERMIAN_EBPF_OBJECT={}", obj_path.display());
    println!("cargo:rerun-if-changed=../hermian-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../hermian-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!("cargo:rerun-if-env-changed=HERMIAN_EBPF_NIGHTLY");
}
