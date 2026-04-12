//! Types shared between the snoop userspace binary and eBPF programs.
//!
//! All types in this crate are `#[repr(C)]` so the layout is identical on
//! both sides of the eBPF/userspace boundary.  The crate is `no_std` so that
//! it can be imported from `snoop-ebpf` without pulling in the standard
//! library.
#![no_std]

mod event;
mod lib_event;
mod syscall_nr;

pub use event::{ARGV_EXTRA_MAX, SyscallEnterData, SyscallEvent, PATH_MAX_LEN, SOCKADDR_MAX_LEN};
pub use lib_event::{LibCallEvent, LibFunc, TLS_DATA_MAX};
pub use syscall_nr::SyscallNr;
