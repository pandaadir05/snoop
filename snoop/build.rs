//! Build script for the snoop binary.
//!
//! Resolution order for the embedded eBPF object:
//!
//! 1. `SNOOP_SKIP_EBPF_BUILD` is set → write an empty stub (used by CI
//!    fmt/clippy/test jobs that run on stable without a nightly toolchain).
//! 2. `SNOOP_EBPF_OBJ` is set → copy that file verbatim into `OUT_DIR`.
//!    CI build jobs use this after running `cargo xtask build-ebpf` so the
//!    eBPF object is only compiled once, not again inside this script.
//! 3. Neither is set → compile `snoop-ebpf` inline via
//!    `rustup run nightly cargo build …` (local developer workflow when
//!    invoking `cargo build` directly instead of `cargo xtask run`).
//!
//! In all cases the resulting file lives at `$OUT_DIR/snoop-ebpf` so that
//! `loader.rs` can embed it with `include_bytes_aligned!`.
//!
//! The short git SHA is always embedded as `GIT_SHA` for `--version`.

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

    // eBPF programs only exist on Linux.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }

    let out_dir = std::env::var("OUT_DIR")?;
    // loader.rs embeds the object at exactly this path via include_bytes_aligned!
    let out_file = Path::new(&out_dir).join("snoop-ebpf");

    // ── 1. stub mode ──────────────────────────────────────────────────────────
    if std::env::var("SNOOP_SKIP_EBPF_BUILD").is_ok() {
        std::fs::write(&out_file, b"")?;
        return Ok(());
    }

    // ── 2. pre-built object ───────────────────────────────────────────────────
    if let Ok(obj_path) = std::env::var("SNOOP_EBPF_OBJ") {
        println!("cargo:rerun-if-changed={obj_path}");
        std::fs::copy(&obj_path, &out_file).map_err(|e| {
            format!("failed to copy SNOOP_EBPF_OBJ ({obj_path}) to {}: {e}", out_file.display())
        })?;
        return Ok(());
    }

    // ── 3. inline build (dev fallback) ────────────────────────────────────────
    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../snoop-ebpf")
    );

    // Place the eBPF build artifacts in a subdirectory so that they never
    // collide with the flat file we need at OUT_DIR/snoop-ebpf.
    let ebpf_target_dir = Path::new(&out_dir).join("ebpf-target");

    // CARGO_MANIFEST_DIR is <workspace>/snoop; the workspace root is one level up.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent")?;

    // `cargo +nightly` requires the rustup proxy and is silently ignored when
    // $CARGO points to a concrete toolchain binary.  `rustup run nightly cargo`
    // always selects the nightly toolchain regardless of environment.
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
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
        return Err("rustup run nightly cargo build (snoop-ebpf) failed".into());
    }

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
