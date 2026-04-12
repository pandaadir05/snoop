//! Syscall argument decoding.
//!
//! Converts a raw `SyscallEvent` into a human-readable representation.
//! Each well-known syscall has a dedicated formatter that interprets the
//! raw register arguments (`args[0..5]`) as the proper C types.
//!
//! For unknown syscalls the raw hex values are shown.

mod args;
mod names;

pub use args::decode_args;
pub use names::syscall_name;

use snoop_common::{SyscallEvent, SyscallNr};

/// A decoded syscall ready for display.
#[derive(Debug)]
pub struct DecodedEvent {
    /// Timestamp offset from process start in milliseconds (best-effort).
    pub timestamp_ns: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID (equals pid for single-threaded processes).
    pub tid: u32,
    /// Process name (up to 15 chars, null-terminated).
    pub comm: String,
    /// Syscall name, e.g. `"openat"`.
    pub name: &'static str,
    /// Formatted argument list, e.g. `r#"AT_FDCWD, "/etc/passwd", O_RDONLY"#`.
    pub args_str: String,
    /// Return value formatted as a signed decimal or `-ERRNO`.
    pub ret_str: String,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
}

impl DecodedEvent {
    /// Decode a raw `SyscallEvent` into a `DecodedEvent`.
    ///
    /// When `decode_args` is `false`, arguments are shown as raw hex.
    pub fn from_event(event: &SyscallEvent, decode: bool) -> Self {
        let nr = SyscallNr(event.syscall_nr);
        let name = syscall_name(nr);
        // path_str is the captured first string argument (e.g. the pathname
        // for openat).  It is None when the eBPF program did not capture one.
        let path_str = event.path_str();
        let path_truncated = event.path_truncated();
        let sockaddr_bytes = event.sockaddr_bytes();
        let argv_extra = event.argv_extra_bytes();
        let args_str = if decode {
            decode_args(nr, &event.args, event.ret, path_str, path_truncated, sockaddr_bytes, argv_extra)
        } else {
            format_raw_args(&event.args)
        };

        Self {
            timestamp_ns: event.enter_ns,
            pid: event.pid,
            tid: event.tid,
            comm: comm_to_string(&event.comm),
            name,
            args_str,
            ret_str: format_ret(event.ret),
            duration_ns: event.duration_ns(),
        }
    }
}

/// Format the return value as `N` (success) or `-ERRNO (name)` (error).
pub fn format_ret(ret: i64) -> String {
    if ret >= 0 {
        return ret.to_string();
    }
    // Negative return → errno.
    let errno = (-ret) as u32;
    let name = errno_name(errno);
    format!("-{errno} ({name})")
}

/// Convert a null-terminated `[u8; 16]` comm field to a `String`.
pub fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn format_raw_args(args: &[u64; 6]) -> String {
    args.iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Map a Linux errno number to its name.
fn errno_name(errno: u32) -> &'static str {
    match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        28 => "ENOSPC",
        29 => "ESPIPE",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        37 => "ENOLCK",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        42 => "ENOMSG",
        43 => "EIDRM",
        61 => "ENODATA",
        62 => "ETIME",
        63 => "ENOSR",
        67 => "ENOLINK",
        71 => "EPROTO",
        72 => "EMULTIHOP",
        74 => "EBADMSG",
        75 => "EOVERFLOW",
        84 => "EILSEQ",
        95 => "EOPNOTSUPP",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        104 => "ECONNRESET",
        105 => "ENOBUFS",
        106 => "EISCONN",
        107 => "ENOTCONN",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        125 => "ECANCELED",
        _ => "E?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_nul_terminated() {
        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"nginx");
        assert_eq!(comm_to_string(&comm), "nginx");
    }

    #[test]
    fn comm_full_16_bytes() {
        let comm = [b'a'; 16];
        assert_eq!(comm_to_string(&comm).len(), 16);
    }

    #[test]
    fn ret_positive() {
        assert_eq!(format_ret(5), "5");
    }

    #[test]
    fn ret_enoent() {
        assert_eq!(format_ret(-2), "-2 (ENOENT)");
    }
}
