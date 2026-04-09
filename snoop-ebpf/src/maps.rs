//! eBPF map definitions shared between the tracepoint programs.
//!
//! Maps are declared as statics with the `#[map]` attribute.  Aya loads them
//! by name from the ELF object file.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use snoop_common::{
    LibCallEvent, SyscallEnterData, SyscallEvent, PATH_MAX_LEN, SOCKADDR_MAX_LEN, TLS_DATA_MAX,
};

/// Ring buffer used to forward completed `SyscallEvent`s to userspace.
///
/// 4 MiB is enough for ~10 000 outstanding events (each ~408 bytes) before
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

/// Optional primary PID filter.  Element 0 holds the target PID; 0 means
/// trace all.  Userspace sets this before attaching the programs.
#[map]
pub(crate) static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Follow-children flag.  Element 0 is non-zero when `--follow` is active.
/// When set, `sys_exit` inserts child PIDs from fork/clone into `EXTRA_PIDS`
/// so they are traced automatically.
#[map]
pub(crate) static FOLLOW_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// Set of additional PIDs to trace beyond `TARGET_PID`.  Populated at runtime
/// by `sys_exit` when follow mode is active and a fork/clone succeeds.
/// Value is always 1 (the map is used as a hash set keyed by PID).
#[map]
pub(crate) static EXTRA_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch buffer used to read path strings from user memory without
/// consuming the 512-byte BPF stack.  One entry of PATH_MAX_LEN bytes per CPU.
#[map]
pub(crate) static PATH_BUF: PerCpuArray<[u8; PATH_MAX_LEN]> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch buffer used to read sockaddr structs from user memory.
/// Sized to SOCKADDR_MAX_LEN (28 bytes — enough for IPv6 sockaddr_in6).
#[map]
pub(crate) static SOCKADDR_BUF: PerCpuArray<[u8; SOCKADDR_MAX_LEN]> =
    PerCpuArray::with_max_entries(1, 0);

// ── uprobe / library-call maps ────────────────────────────────────────────────

/// Ring buffer for completed `LibCallEvent`s from uprobe/uretprobe programs.
/// 2 MiB is enough for ~5 600 pending events (each ~364 bytes).
#[map]
pub(crate) static LIB_EVENTS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

/// Per-thread scratch for `ssl_write_enter` / `ssl_read_enter`.
/// Stores the buffer pointer and length so the exit probe can read the data.
#[map]
pub(crate) static SSL_ENTER: HashMap<u64, SslEnterData> = HashMap::with_max_entries(4096, 0);

/// Per-thread scratch for the ltrace entry probes.
/// Stores args and entry timestamp so the exit probe can emit a full event.
#[map]
pub(crate) static LTRACE_ENTER: HashMap<u64, LtraceEnterData> = HashMap::with_max_entries(4096, 0);

/// Per-CPU scratch buffer used to read TLS plaintext from user memory.
/// Sized to TLS_DATA_MAX to avoid putting 256 bytes on the BPF stack.
#[map]
pub(crate) static TLS_BUF: PerCpuArray<[u8; TLS_DATA_MAX]> = PerCpuArray::with_max_entries(1, 0);

/// Entry data saved by SSL uprobe at function entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SslEnterData {
    /// Pointer to the user-space data buffer (buf arg).
    pub buf_ptr: u64,
    /// Declared buffer length (num arg).
    pub num: u64,
    /// Entry timestamp (bpf_ktime_get_ns).
    pub enter_ns: u64,
    /// Process name at call site.
    pub comm: [u8; 16],
}

/// Entry data saved by ltrace uprobe at function entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LtraceEnterData {
    /// Register arguments at function entry.
    pub args: [u64; 6],
    /// Entry timestamp.
    pub enter_ns: u64,
    /// Process name at call site.
    pub comm: [u8; 16],
}

// Compile-time size guard: SyscallEvent must fit in the ring buffer in one shot.
const _: () = {
    assert!(core::mem::size_of::<SyscallEvent>() < 512);
};

// LibCallEvent must also fit (364 bytes — well under 512).
const _: () = {
    assert!(core::mem::size_of::<LibCallEvent>() < 512);
};
