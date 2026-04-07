//! Build script for the snoop binary.
//!
//! On Linux: delegates to `aya-build` which compiles `snoop-ebpf` for
//! `bpfel-unknown-none` and makes the object bytes available via
//! `include_bytes_aligned!` in `loader.rs`.
//!
//! On other hosts: no-op so developers on macOS get full IDE support without
//! needing a BPF toolchain installed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
