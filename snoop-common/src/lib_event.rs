//! Wire types for uprobe-based library-call tracing.
//!
//! Sent through the `LIB_EVENTS` ring buffer (separate from the syscall
//! `EVENTS` buffer so neither path starves the other).

/// Maximum bytes of TLS plaintext captured per `SSL_write` / `SSL_read` call.
pub const TLS_DATA_MAX: usize = 256;

/// Identifies which library function produced the event.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LibFunc {
    /// `SSL_write(ssl, buf, num)` — outbound TLS plaintext.
    SslWrite = 0,
    /// `SSL_read(ssl, buf, num)` — inbound TLS plaintext.
    SslRead = 1,
    /// `malloc(size)` → ptr
    Malloc = 2,
    /// `free(ptr)` → void
    Free = 3,
    /// `calloc(nmemb, size)` → ptr
    Calloc = 4,
    /// `realloc(ptr, size)` → new_ptr
    Realloc = 5,
}

impl LibFunc {
    /// Try to construct a `LibFunc` from its raw discriminant byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::SslWrite),
            1 => Some(Self::SslRead),
            2 => Some(Self::Malloc),
            3 => Some(Self::Free),
            4 => Some(Self::Calloc),
            5 => Some(Self::Realloc),
            _ => None,
        }
    }

    /// Return the canonical display name for this function.
    pub fn name(self) -> &'static str {
        match self {
            Self::SslWrite => "SSL_write",
            Self::SslRead => "SSL_read",
            Self::Malloc => "malloc",
            Self::Free => "free",
            Self::Calloc => "calloc",
            Self::Realloc => "realloc",
        }
    }
}

/// A completed library function call, emitted to `LIB_EVENTS` at return.
///
/// Layout is `#[repr(C)]` and must be identical between the eBPF programs
/// (which write it) and userspace (which reads it).
///
/// Total size: 4+4+1+3+8+8+16+48+8+256+2+6 = 364 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LibCallEvent {
    /// Process ID (tgid).
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Which function (discriminant of [`LibFunc`]).
    pub func: u8,
    /// Alignment padding — always zero.
    pub _pad: [u8; 3],
    /// `bpf_ktime_get_ns()` at function entry.
    pub enter_ns: u64,
    /// `bpf_ktime_get_ns()` at function return.
    pub exit_ns: u64,
    /// Process name at call time (from `task_struct->comm`).
    pub comm: [u8; 16],
    /// Register arguments saved at function entry (args[0..5]).
    pub args: [u64; 6],
    /// Return value (cast to i64; negative means error for SSL functions).
    pub ret: i64,
    /// Captured data bytes (TLS plaintext, or zeroes for non-data functions).
    pub data: [u8; TLS_DATA_MAX],
    /// Number of valid bytes in `data`.  0 for non-TLS functions.
    pub data_len: u16,
    /// Trailing alignment padding — always zero.
    pub _pad2: [u8; 6],
}

impl LibCallEvent {
    /// Duration of the call in nanoseconds.
    #[inline]
    pub fn duration_ns(&self) -> u64 {
        self.exit_ns.saturating_sub(self.enter_ns)
    }

    /// Decode the `func` byte to a [`LibFunc`], or `None` if unknown.
    #[inline]
    pub fn lib_func(&self) -> Option<LibFunc> {
        LibFunc::from_u8(self.func)
    }
}
