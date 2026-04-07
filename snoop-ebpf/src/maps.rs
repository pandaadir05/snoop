//! eBPF map definitions shared between the tracepoint programs.
//!
//! Maps are declared as statics with the `#[map]` attribute.  Aya loads them
//! by name from the ELF object file.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use snoop_common::{SyscallEnterData, SyscallEvent, PATH_MAX_LEN};

/// Ring buffer used to forward completed `SyscallEvent`s to userspace.
///
/// 4 MiB is enough for ~17 000 outstanding events (each ~248 bytes) before
/// the consumer stalls.  Userspace drains this in a tight async loop.
#[map]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Per-thread scratch storage keyed by `bpf_get_current_pid_tgid()`.
/// The `sys_enter` program stores entry data here; `sys_exit` retrieves it.
///
/// 8 192 entries handles up to ~8 K concurrent in-flight syscalls.
#[map]
pub(crate) static SYSCALL_ENTER: HashMap<u64, SyscallEnterData> =
    HashMap::with_max_entries(8192, 0);

/// Optional PID filter.  Element 0 holds the target PID; 0 means trace all.
/// Userspace sets this before attaching the programs.
#[map]
pub(crate) static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Per-CPU scratch buffer used to read path strings from user memory without
/// consuming the 512-byte BPF stack.  One entry of PATH_MAX_LEN bytes per CPU.
#[map]
pub(crate) static PATH_BUF: PerCpuArray<[u8; PATH_MAX_LEN]> =
    PerCpuArray::with_max_entries(1, 0);

// Compile-time size guard: SyscallEvent must fit in the ring buffer in one shot.
const _: () = {
    assert!(core::mem::size_of::<SyscallEvent>() < 512);
};
