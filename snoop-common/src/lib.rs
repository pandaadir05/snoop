//! Types shared between the snoop userspace binary and eBPF programs.
//!
//! This crate is `no_std`-compatible so that eBPF programs can import it
//! without pulling in the standard library.
#![no_std]
