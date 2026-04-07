//! eBPF map definitions shared between the tracepoint programs.
//!
//! Maps are declared as statics with the `#[map]` attribute.  Aya loads them
//! by name from the ELF object file.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, RingBuf},
};
use snoop_common::{SyscallEnterData, SyscallEvent};

/// Ring buffer used to forward completed `SyscallEvent`s to userspace.
///
/// 4 MiB is enough for ~26 000 outstanding events before the consumer
/// stalls.  Userspace drains this in a tight async loop.
#[map]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Per-thread scratch storage: keyed by `(pid << 32) | tid` (the value
/// returned by `bpf_get_current_pid_tgid()`).  The `sys_enter` program
/// stores entry data here; `sys_exit` retrieves it to build the full event.
///
/// 8 192 entries: handles up to ~8 K concurrent in-flight syscalls, which
/// is more than enough for any single traced process tree.
#[map]
pub(crate) static SYSCALL_ENTER: HashMap<u64, SyscallEnterData> =
    HashMap::with_max_entries(8192, 0);

/// Optional PID filter.  Element 0 holds the target PID; 0 means "trace
/// all processes".  Userspace sets this before attaching the programs.
#[map]
pub(crate) static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

// Ensure the types are the right size so the verifier and userspace agree.
const _: () = {
    // SyscallEvent must fit inside the ring buffer in one shot.
    assert!(core::mem::size_of::<SyscallEvent>() < 512);
};
