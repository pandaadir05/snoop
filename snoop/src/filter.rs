//! Event filtering logic.
//!
//! Filtering is applied in userspace after events arrive from the ring buffer.
//! Kernel-side PID filtering is handled separately (TARGET_PID map).

use snoop_common::{SyscallEvent, SyscallNr};

// A few syscall numbers not yet in snoop_common (will migrate there later).
const NR_CREAT: SyscallNr = SyscallNr(85);
const NR_SOCKETPAIR: SyscallNr = SyscallNr(53);
const NR_SHUTDOWN: SyscallNr = SyscallNr(48);

/// The set of syscalls considered file-system operations.
const FS_SYSCALLS: &[SyscallNr] = &[
    SyscallNr::OPEN,
    SyscallNr::OPENAT,
    NR_CREAT,
    SyscallNr::READ,
    SyscallNr::WRITE,
    SyscallNr::PREAD64,
    SyscallNr::PWRITE64,
    SyscallNr::CLOSE,
    SyscallNr::STAT,
    SyscallNr::FSTAT,
    SyscallNr::LSTAT,
    SyscallNr::FSTATAT,
    SyscallNr::STATX,
    SyscallNr::LSEEK,
    SyscallNr::RENAME,
    SyscallNr::RENAMEAT,
    SyscallNr::MKDIR,
    SyscallNr::MKDIRAT,
    SyscallNr::RMDIR,
    SyscallNr::UNLINK,
    SyscallNr::UNLINKAT,
    SyscallNr::SYMLINK,
    SyscallNr::READLINK,
    SyscallNr::GETCWD,
    SyscallNr::CHDIR,
    SyscallNr::FCHDIR,
    SyscallNr::GETDENTS64,
    SyscallNr::TRUNCATE,
    SyscallNr::FTRUNCATE,
    SyscallNr::FALLOCATE,
    SyscallNr::FSYNC,
    SyscallNr::FDATASYNC,
    SyscallNr::DUP,
    SyscallNr::DUP2,
    SyscallNr::DUP3,
    SyscallNr::PIPE,
    SyscallNr::PIPE2,
    SyscallNr::FCNTL,
    SyscallNr::IOCTL,
    SyscallNr::SENDFILE,
    SyscallNr::SPLICE,
    SyscallNr::INOTIFY_INIT1,
    SyscallNr::MEMFD_CREATE,
];

/// The set of syscalls considered network operations.
const NET_SYSCALLS: &[SyscallNr] = &[
    SyscallNr::SOCKET,
    NR_SOCKETPAIR,
    SyscallNr::BIND,
    SyscallNr::LISTEN,
    SyscallNr::ACCEPT,
    SyscallNr::ACCEPT4,
    SyscallNr::CONNECT,
    SyscallNr::SENDTO,
    SyscallNr::RECVFROM,
    SyscallNr::SENDMSG,
    SyscallNr::RECVMSG,
    SyscallNr::GETSOCKNAME,
    SyscallNr::GETPEERNAME,
    SyscallNr::SETSOCKOPT,
    SyscallNr::GETSOCKOPT,
    NR_SHUTDOWN,
];

/// Configures which events are forwarded to the output layer.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Only pass file-system syscalls through.
    pub category_files: bool,
    /// Only pass network syscalls through.
    pub category_net: bool,
    /// Drop events whose duration is below this threshold (nanoseconds).
    pub slow_threshold_ns: Option<u64>,
    /// If `Some`, only pass syscalls whose name matches one of these strings.
    pub syscall_allowlist: Option<Vec<String>>,
    /// Do not decode arguments — pass raw hex to the output layer.
    pub no_decode: bool,
}

impl Filter {
    /// Returns `true` if the event passes all active filters.
    pub fn accepts(&self, event: &SyscallEvent) -> bool {
        let nr = SyscallNr(event.syscall_nr);

        if self.category_files && !FS_SYSCALLS.contains(&nr) {
            return false;
        }

        if self.category_net && !NET_SYSCALLS.contains(&nr) {
            return false;
        }

        if let Some(threshold) = self.slow_threshold_ns {
            if event.duration_ns() < threshold {
                return false;
            }
        }

        if let Some(ref names) = self.syscall_allowlist {
            let name = crate::decode::syscall_name(nr);
            if !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(syscall_nr: i64, duration_ns: u64) -> SyscallEvent {
        SyscallEvent {
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_nr,
            args: [0; 6],
            ret: 0,
            enter_ns: 1000,
            exit_ns: 1000 + duration_ns,
            comm: [0; 16],
            path: [0; 128],
            path_len: 0,
            sockaddr: [0; 28],
            sockaddr_len: 0,
            _pad: [0; 5],
        }
    }

    fn open_filter() -> Filter {
        Filter {
            category_files: false,
            category_net: false,
            slow_threshold_ns: None,
            syscall_allowlist: None,
            no_decode: false,
        }
    }

    #[test]
    fn no_filter_accepts_all() {
        let f = open_filter();
        assert!(f.accepts(&make_event(SyscallNr::OPENAT.0, 100)));
        assert!(f.accepts(&make_event(SyscallNr::CONNECT.0, 100)));
        assert!(f.accepts(&make_event(SyscallNr::FUTEX.0, 100)));
    }

    #[test]
    fn files_filter_rejects_network() {
        let f = Filter { category_files: true, ..open_filter() };
        assert!(f.accepts(&make_event(SyscallNr::OPENAT.0, 100)));
        assert!(!f.accepts(&make_event(SyscallNr::CONNECT.0, 100)));
    }

    #[test]
    fn slow_filter() {
        let f = Filter {
            slow_threshold_ns: Some(10_000_000), // 10 ms
            ..open_filter()
        };
        assert!(!f.accepts(&make_event(SyscallNr::READ.0, 1_000)));
        assert!(f.accepts(&make_event(SyscallNr::READ.0, 20_000_000)));
    }
}
