//! eBPF programs for snoop.
//!
//! This crate is compiled as a `[[bin]]` for `bpfel-unknown-none` (little-endian
//! BPF) using a nightly toolchain.  bpf-linker links all program sections into a
//! single ELF object that aya loads at runtime.
//!
//! All real program code is gated on `#[cfg(target_arch = "bpf")]` so the host
//! workspace build produces a trivial empty binary for IDE support and
//! type-checking without a BPF toolchain.
//!
//! Build with:
//! ```text
//! cargo xtask build-ebpf
//! ```

// On BPF targets: freestanding, no standard library, no traditional entry point.
// On host targets: use std normally so the dummy main() compiles without a
// custom panic handler.
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod maps;
#[cfg(target_arch = "bpf")]
mod programs;

// no_std binaries must supply a panic handler.  In BPF programs panics are
// unreachable at runtime — the verifier rejects loops and the generated code
// never calls panic infrastructure.  We use unreachable_unchecked() instead
// of loop {} because the 5.15 verifier (used by WSL2) rejects the self-loop
// instruction that loop {} compiles to.
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// Host-only stub so `cargo build` succeeds outside the BPF toolchain.
#[cfg(not(target_arch = "bpf"))]
fn main() {}
