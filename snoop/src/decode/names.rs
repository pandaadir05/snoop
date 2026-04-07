//! Syscall number → name mapping for x86_64.

use snoop_common::SyscallNr;

/// Returns the canonical name for a syscall number, or `"unknown"` for
/// unrecognised numbers.  Call sites that need the raw number for display
/// should call `format!("syscall_{}", nr.0)` themselves.
pub fn syscall_name(nr: SyscallNr) -> &'static str {
    match nr.0 {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        28 => "madvise",
        32 => "dup",
        33 => "dup2",
        35 => "nanosleep",
        39 => "getpid",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        72 => "fcntl",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        101 => "ptrace",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        109 => "setpgid",
        110 => "getppid",
        111 => "getpgrp",
        112 => "setsid",
        157 => "prctl",
        158 => "arch_prctl",
        186 => "gettid",
        202 => "futex",
        217 => "getdents64",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        247 => "waitid",
        257 => "openat",
        258 => "mkdirat",
        262 => "fstatat",
        263 => "unlinkat",
        264 => "renameat",
        275 => "splice",
        276 => "tee",
        281 => "epoll_pwait",
        283 => "timerfd_create",
        285 => "fallocate",
        288 => "accept4",
        289 => "signalfd4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        294 => "inotify_init1",
        302 => "prlimit64",
        318 => "getrandom",
        319 => "memfd_create",
        322 => "execveat",
        332 => "statx",
        435 => "clone3",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::SyscallNr;

    #[test]
    fn known_syscalls() {
        assert_eq!(syscall_name(SyscallNr::READ), "read");
        assert_eq!(syscall_name(SyscallNr::OPENAT), "openat");
        assert_eq!(syscall_name(SyscallNr::EXIT_GROUP), "exit_group");
    }

    #[test]
    fn unknown_syscall() {
        assert_eq!(syscall_name(SyscallNr(9999)), "unknown");
    }
}
