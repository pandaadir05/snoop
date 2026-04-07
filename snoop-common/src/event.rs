//! Wire types that cross the eBPF/userspace boundary.

/// Data recorded at syscall entry and stored in the per-tid scratch map
/// inside the eBPF program.  Not sent to userspace directly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEnterData {
    /// Process ID (tgid in kernel terms).
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// User ID of the calling thread.
    pub uid: u32,
    /// Group ID of the calling thread.
    pub gid: u32,
    /// Raw syscall number (architecture-specific).
    pub syscall_nr: i64,
    /// Up to six raw arguments as passed in registers.
    pub args: [u64; 6],
    /// `bpf_ktime_get_ns()` timestamp at syscall entry.
    pub enter_ns: u64,
    /// Null-terminated process name (`task_struct->comm`, max 16 bytes).
    pub comm: [u8; 16],
}

/// A complete syscall event emitted to the ring buffer after `sys_exit`.
///
/// The layout must stay stable — changing field order or sizes breaks the
/// ring-buffer consumer without a coordinated update to both sides.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    /// Process ID (tgid).
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Raw syscall number.
    pub syscall_nr: i64,
    /// Raw register arguments (up to six).
    pub args: [u64; 6],
    /// Return value (negative errno on error).
    pub ret: i64,
    /// `bpf_ktime_get_ns()` at syscall entry.
    pub enter_ns: u64,
    /// `bpf_ktime_get_ns()` at syscall exit.
    pub exit_ns: u64,
    /// Process name at the time of the call.
    pub comm: [u8; 16],
}

impl SyscallEvent {
    /// Duration of the syscall in nanoseconds.
    #[inline]
    pub fn duration_ns(&self) -> u64 {
        self.exit_ns.saturating_sub(self.enter_ns)
    }
}
