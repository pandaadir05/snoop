//! Build orchestration for snoop.
//!
//! Usage:
//! ```text
//! cargo xtask build-ebpf [--release]
//! cargo xtask run [-- <snoop args>…]
//! ```
//!
//! `build-ebpf` compiles `snoop-ebpf` for `bpfel-unknown-none` using the
//! nightly toolchain declared in `snoop-ebpf/rust-toolchain.toml`.  The
//! compiled object is written to
//! `target/bpfel-unknown-none/{debug,release}/snoop-ebpf`.
//!
//! `run` calls `build-ebpf` first, then `cargo run -p snoop` forwarding any
//! extra arguments.  This is the single command a developer needs on Linux.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Build orchestration for snoop")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Compile the snoop-ebpf crate for bpfel-unknown-none.
    BuildEbpf(BuildEbpfArgs),
    /// Build the eBPF programs then run the snoop binary.
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
struct BuildEbpfArgs {
    /// Build in release mode.
    #[arg(long)]
    release: bool,
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Build the eBPF programs in release mode before running.
    #[arg(long)]
    release: bool,

    /// Arguments forwarded verbatim to the snoop binary.
    #[arg(last = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::BuildEbpf(args) => build_ebpf(args.release),
        Cmd::Run(args) => run(args.release, &args.args),
    }
}

/// Compile `snoop-ebpf` for `bpfel-unknown-none`.
///
/// Requires nightly Rust and `bpf-linker` (`cargo install bpf-linker`).
fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root);
    cmd.args([
        "+nightly",
        "build",
        "--package",
        "snoop-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    // Propagate RUSTFLAGS from the environment (e.g. -C linker=bpf-linker).
    // Don't inherit the host RUSTFLAGS blindly — they may contain flags that
    // are invalid for the BPF target.
    cmd.env_remove("RUSTFLAGS");

    let status = cmd
        .status()
        .context("failed to spawn `cargo +nightly build`")?;
    check_status(status, "cargo build (ebpf)")
}

/// Build eBPF programs, then run the snoop binary.
fn run(release: bool, extra_args: &[String]) -> Result<()> {
    build_ebpf(release)?;

    let workspace_root = workspace_root();
    let profile = if release { "release" } else { "debug" };

    // Tell the snoop binary where to find the compiled eBPF object.
    let ebpf_obj = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("snoop-ebpf");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root);
    cmd.args(["run", "--package", "snoop"]);
    if release {
        cmd.arg("--release");
    }
    cmd.env("SNOOP_EBPF_OBJ", ebpf_obj);
    if !extra_args.is_empty() {
        cmd.arg("--");
        cmd.args(extra_args);
    }

    let status = cmd.status().context("failed to spawn `cargo run`")?;
    check_status(status, "cargo run")
}

fn check_status(status: ExitStatus, what: &str) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("{what} exited with {}", status.code().unwrap_or(-1))
    }
}

/// Returns the workspace root directory (the directory containing the
/// top-level `Cargo.toml`).
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for xtask itself is `<workspace>/xtask`.
    // Walk up one level to reach the workspace root.
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback: assume we're in `<workspace>/xtask` at runtime.
            env::current_dir()
                .expect("cannot determine current directory")
                .join("xtask")
        });

    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}
