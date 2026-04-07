//! Build script for the snoop binary.
//!
//! On Linux: delegates to `aya-build` which compiles `snoop-ebpf` for
//! `bpfel-unknown-none` and makes the object bytes available via
//! `include_bytes_aligned!` in `loader.rs`.
//!
//! On other hosts: no-op so developers on macOS get full IDE support without
//! needing a BPF toolchain installed.
//!
//! In all cases, the short git SHA is embedded as `GIT_SHA` so that
//! `--version` can display it.

use std::process::Command;

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
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        let packages = [aya_build::Package {
            name: "snoop-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../snoop-ebpf"),
            no_default_features: false,
            features: &[],
        }];
        aya_build::build_ebpf(packages, aya_build::Toolchain::Nightly)?;
    }
    Ok(())
}
