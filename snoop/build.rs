//! Build script for the snoop binary.
//!
//! On Linux: compiles `snoop-ebpf` for `bpfel-unknown-none` using the nightly
//! toolchain and copies the resulting object to `$OUT_DIR/snoop-ebpf` so that
//! `loader.rs` can embed it with `include_bytes_aligned!`.
//!
//! On other hosts: no-op so developers on macOS get full IDE support without
//! needing a BPF toolchain installed.
//!
//! In all cases, the short git SHA is embedded as `GIT_SHA` so that
//! `--version` can display it.

use std::{path::Path, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embed git short SHA for `--version` output.  Falls back to "unknown"
    // when building outside a git repository (e.g. from a tarball).
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=GIT_SHA={sha}");

    // Re-run this script if the git HEAD changes (new commit or branch switch).
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");

    // Only attempt the eBPF build when compiling *for* Linux.
    // CARGO_CFG_TARGET_OS is set by Cargo to the target OS (not the host OS),
    // so cross-compilation works correctly too.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }

    let out_dir = std::env::var("OUT_DIR")?;
    // The embedded object must be a flat file at this path — loader.rs uses
    // include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoop-ebpf")).
    let out_file = Path::new(&out_dir).join("snoop-ebpf");

    if std::env::var("SNOOP_SKIP_EBPF_BUILD").is_ok() {
        // CI check / fmt / clippy jobs run on stable without nightly installed.
        // Write an empty stub so that loader.rs compiles; the stub is never
        // loaded at runtime in those jobs.
        std::fs::write(&out_file, b"")?;
        return Ok(());
    }

    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../snoop-ebpf")
    );

    // Use a subdirectory of OUT_DIR as CARGO_TARGET_DIR so aya-build's cargo
    // invocation does not collide with the flat file we need at OUT_DIR/snoop-ebpf.
    let ebpf_target_dir = Path::new(&out_dir).join("ebpf-target");

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent")?;

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--package",
            "snoop-ebpf",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .env("CARGO_TARGET_DIR", &ebpf_target_dir)
        // Don't inherit host RUSTFLAGS — they may contain flags invalid for BPF.
        .env_remove("RUSTFLAGS")
        .current_dir(workspace_root)
        .status()?;

    if !status.success() {
        return Err("cargo +nightly build (snoop-ebpf) failed".into());
    }

    // Copy the compiled ELF object to the flat path expected by loader.rs.
    let compiled = ebpf_target_dir
        .join("bpfel-unknown-none")
        .join("debug")
        .join("snoop-ebpf");

    std::fs::copy(&compiled, &out_file).map_err(|e| {
        format!(
            "failed to copy eBPF object from {} to {}: {e}",
            compiled.display(),
            out_file.display()
        )
    })?;

    Ok(())
}
