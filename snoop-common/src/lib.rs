//! Types shared between the snoop userspace binary and eBPF programs.
//!
//! All types in this crate are `#[repr(C)]` so the layout is identical on
//! both sides of the eBPF/userspace boundary.  The crate is `no_std` so that
//! it can be imported from `snoop-ebpf` without pulling in the standard
//! library.
#![no_std]

mod event;
mod syscall_nr;

pub use event::{SyscallEnterData, SyscallEvent};
pub use syscall_nr::SyscallNr;
