//! Well-known syscall numbers for x86_64.
//!
//! Many constants are only referenced by the userspace decoder on Linux;
//! suppress the dead_code lint for other compile targets.
#![allow(dead_code)]
//!
//! These constants are used by both the eBPF side (to categorise events at
//! capture time if needed) and by the userspace side for argument decoding.
//! Only the syscalls decoded by snoop are listed here; for everything else
//! the raw number is shown.

/// Typed wrapper around a raw syscall number so call sites are explicit.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyscallNr(pub i64);

// --- x86_64 syscall table (relevant subset) ---
impl SyscallNr {
    pub const READ: Self = Self(0);
    pub const WRITE: Self = Self(1);
    pub const OPEN: Self = Self(2);
    pub const CLOSE: Self = Self(3);
    pub const STAT: Self = Self(4);
    pub const FSTAT: Self = Self(5);
    pub const LSTAT: Self = Self(6);
    pub const LSEEK: Self = Self(8);
    pub const MMAP: Self = Self(9);
    pub const MPROTECT: Self = Self(10);
    pub const MUNMAP: Self = Self(11);
    pub const BRK: Self = Self(12);
    pub const RT_SIGACTION: Self = Self(13);
    pub const RT_SIGPROCMASK: Self = Self(14);
    pub const IOCTL: Self = Self(16);
    pub const PREAD64: Self = Self(17);
    pub const PWRITE64: Self = Self(18);
    pub const PIPE: Self = Self(22);
    pub const SELECT: Self = Self(23);
    pub const DUP: Self = Self(32);
    pub const DUP2: Self = Self(33);
    pub const SOCKET: Self = Self(41);
    pub const CONNECT: Self = Self(42);
    pub const ACCEPT: Self = Self(43);
    pub const SENDTO: Self = Self(44);
    pub const RECVFROM: Self = Self(45);
    pub const SENDMSG: Self = Self(46);
    pub const RECVMSG: Self = Self(47);
    pub const BIND: Self = Self(49);
    pub const LISTEN: Self = Self(50);
    pub const GETSOCKNAME: Self = Self(51);
    pub const GETPEERNAME: Self = Self(52);
    pub const CLONE: Self = Self(56);
    pub const FORK: Self = Self(57);
    pub const VFORK: Self = Self(58);
    pub const EXECVE: Self = Self(59);
    pub const EXIT: Self = Self(60);
    pub const WAIT4: Self = Self(61);
    pub const KILL: Self = Self(62);
    pub const FCNTL: Self = Self(72);
    pub const GETCWD: Self = Self(79);
    pub const CHDIR: Self = Self(80);
    pub const FCHDIR: Self = Self(81);
    pub const RENAME: Self = Self(82);
    pub const MKDIR: Self = Self(83);
    pub const RMDIR: Self = Self(84);
    pub const UNLINK: Self = Self(87);
    pub const SYMLINK: Self = Self(88);
    pub const READLINK: Self = Self(89);
    pub const GETUID: Self = Self(102);
    pub const GETGID: Self = Self(104);
    pub const GETEUID: Self = Self(107);
    pub const GETEGID: Self = Self(108);
    pub const GETPID: Self = Self(39);
    pub const GETPPID: Self = Self(110);
    pub const GETTID: Self = Self(186);
    pub const FUTEX: Self = Self(202);
    pub const SCHED_YIELD: Self = Self(24);
    pub const NANOSLEEP: Self = Self(35);
    pub const ACCEPT4: Self = Self(288);
    pub const DUP3: Self = Self(292);
    pub const PIPE2: Self = Self(293);
    pub const OPENAT: Self = Self(257);
    pub const MKDIRAT: Self = Self(258);
    pub const UNLINKAT: Self = Self(263);
    pub const RENAMEAT: Self = Self(264);
    pub const FSTATAT: Self = Self(262);
    pub const EXECVEAT: Self = Self(322);
    pub const CLONE3: Self = Self(435);
    pub const EXIT_GROUP: Self = Self(231);
    pub const EPOLL_CREATE1: Self = Self(291);
    pub const EPOLL_CTL: Self = Self(233);
    pub const EPOLL_WAIT: Self = Self(232);
    pub const EPOLL_PWAIT: Self = Self(281);
    pub const STATX: Self = Self(332);
    pub const GETDENTS64: Self = Self(217);
    pub const PRLIMIT64: Self = Self(302);
    pub const GETRANDOM: Self = Self(318);

    pub const MEMFD_CREATE: Self = Self(319);
    pub const FTRUNCATE: Self = Self(77);
    pub const TRUNCATE: Self = Self(76);
    pub const FALLOCATE: Self = Self(285);
    pub const FSYNC: Self = Self(74);
    pub const FDATASYNC: Self = Self(75);
    pub const SENDFILE: Self = Self(40);
    pub const SPLICE: Self = Self(275);
    pub const TEE: Self = Self(276);
    pub const MADVISE: Self = Self(28);
    pub const ARCH_PRCTL: Self = Self(158);
    pub const SETSOCKOPT: Self = Self(54);
    pub const GETSOCKOPT: Self = Self(55);
    pub const SETSID: Self = Self(112);
    pub const SETPGID: Self = Self(109);
    pub const GETPGRP: Self = Self(111);
    pub const PRCTL: Self = Self(157);
    pub const PTRACE: Self = Self(101);
    pub const WAITID: Self = Self(247);
    pub const EVENTFD2: Self = Self(290);
    pub const SIGNALFD4: Self = Self(289);
    pub const TIMERFD_CREATE: Self = Self(283);
    pub const INOTIFY_INIT1: Self = Self(294);
    pub const CREAT: Self = Self(85);
    pub const SHUTDOWN: Self = Self(48);
    pub const SOCKETPAIR: Self = Self(53);
    pub const READV: Self = Self(19);
    pub const WRITEV: Self = Self(20);
    pub const SYMLINKAT: Self = Self(266);
    pub const READLINKAT: Self = Self(267);
    pub const FACCESSAT: Self = Self(269);
    pub const UTIMENSAT: Self = Self(280);
    pub const PSELECT6: Self = Self(270);
    pub const PPOLL: Self = Self(271);
    pub const SENDMMSG: Self = Self(307);
    pub const RECVMMSG: Self = Self(299);
    pub const MREMAP: Self = Self(25);
    pub const MSYNC: Self = Self(26);
    pub const MLOCK: Self = Self(149);
    pub const MUNLOCK: Self = Self(150);
}
