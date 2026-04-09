//! Wire types that cross the eBPF/userspace boundary.

/// Maximum bytes captured for a path or command-name string argument.
///
/// 256 bytes covers nearly all real-world paths (Linux PATH_MAX is 4096, but
/// executable and config paths are almost always under 200 chars).  The field
/// lives in ring-buffer memory, not on the BPF stack, so size is not a
/// verifier concern.  Total SyscallEvent ≈ 408 bytes, well under the ring
/// buffer's 4 MiB capacity.
pub const PATH_MAX_LEN: usize = 256;

/// Raw bytes of a `struct sockaddr` — enough for IPv4, IPv6, and UNIX.
/// IPv4 sockaddr_in  = 16 bytes
/// IPv6 sockaddr_in6 = 28 bytes
/// UNIX sockaddr_un  = up to 110 bytes (108-byte path + 2 header bytes)
pub const SOCKADDR_MAX_LEN: usize = 28;

/// Data recorded at syscall entry and stored in the per-tid scratch map
/// inside the eBPF program.  Not sent to userspace directly.
///
/// Kept deliberately small (≤ 96 bytes) so copying it onto the BPF stack
/// in `sys_exit` remains well within the 512-byte limit.
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
///
/// Total size: ~248 bytes.  The BPF program writes this directly into ring
/// buffer memory via `RingBuf::reserve()` to avoid consuming the 512-byte
/// BPF stack.
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
    /// Bytes of the first string argument captured by `bpf_probe_read_user_str`.
    /// Valid bytes are `path[0..path_len]`.  Not null-terminated on the
    /// userspace side (use `path_len` as the bound).
    pub path: [u8; PATH_MAX_LEN],
    /// Number of valid bytes in `path`.  0 means no string was captured.
    pub path_len: u16,
    /// Raw bytes of the `struct sockaddr` argument for socket syscalls
    /// (connect, bind, accept, getpeername, getsockname).
    /// Valid bytes are `sockaddr[0..sockaddr_len]`.
    pub sockaddr: [u8; SOCKADDR_MAX_LEN],
    /// Number of valid bytes in `sockaddr`.  0 means no address was captured.
    pub sockaddr_len: u8,
    /// Reserved / alignment padding.
    pub _pad: [u8; 5],
}

impl SyscallEvent {
    /// Duration of the syscall in nanoseconds.
    #[inline]
    pub fn duration_ns(&self) -> u64 {
        self.exit_ns.saturating_sub(self.enter_ns)
    }

    /// Returns the captured path as a UTF-8 string slice, or `None` if no
    /// path was captured or the bytes are not valid UTF-8.
    #[inline]
    pub fn path_str(&self) -> Option<&str> {
        if self.path_len == 0 {
            return None;
        }
        let end = self.path_len as usize;
        // Strip trailing null byte that bpf_probe_read_user_str includes.
        let bytes = &self.path[..end];
        let trimmed = bytes.strip_suffix(b"\0").unwrap_or(bytes);
        core::str::from_utf8(trimmed).ok()
    }

    /// Returns the raw sockaddr bytes, or an empty slice if none were captured.
    #[inline]
    pub fn sockaddr_bytes(&self) -> &[u8] {
        let len = self.sockaddr_len as usize;
        if len == 0 || len > SOCKADDR_MAX_LEN {
            return &[];
        }
        &self.sockaddr[..len]
    }
}
