//! eBPF programs for snoop.
//!
//! This crate is compiled for `bpfel-unknown-none` (little-endian BPF) using
//! a nightly toolchain.  All real program code is gated on
//! `#[cfg(target_arch = "bpf")]` so the host workspace build succeeds for
//! IDE support and type-checking without a BPF toolchain.
//!
//! Build with:
//! ```text
//! cargo xtask build-ebpf
//! ```
#![no_std]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod maps;
#[cfg(target_arch = "bpf")]
mod programs;
