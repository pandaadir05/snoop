//! Per-syscall argument formatters.
//!
//! Each formatter receives the raw `args[0..5]` register values and the
//! return value, and returns a human-readable argument string.
//!
//! The argument values are pointer-sized integers as delivered by the kernel.
//! Path arguments and sockaddr structs are captured by the eBPF programs via
//! `bpf_probe_read_user_str` / `bpf_probe_read_user_bytes` and passed in
//! alongside the raw register values; they fall back to hex addresses when
//! not available.

use snoop_common::SyscallNr;

/// Format the arguments for a syscall given its number, raw register args,
/// return value, an optional captured path string, and optional sockaddr bytes.
///
/// `path` is `Some(&str)` when the eBPF program captured the first string arg.
/// `sockaddr` is the raw bytes of the `struct sockaddr` argument when captured.
/// Both fall back to showing the raw pointer address when not available.
pub fn decode_args(
    nr: SyscallNr,
    args: &[u64; 6],
    ret: i64,
    path: Option<&str>,
    sockaddr: &[u8],
) -> String {
    match nr {
        SyscallNr::READ | SyscallNr::WRITE => fmt_read_write(args),
        SyscallNr::OPEN => fmt_open(args, path),
        SyscallNr::OPENAT => fmt_openat(args, path),
        SyscallNr::CLOSE => fmt_close(args),
        SyscallNr::PREAD64 | SyscallNr::PWRITE64 => fmt_pread_pwrite(args),
        SyscallNr::LSEEK => fmt_lseek(args),
        SyscallNr::STAT | SyscallNr::LSTAT => fmt_stat(args, path),
        SyscallNr::FSTAT => fmt_fstat(args),
        SyscallNr::FSTATAT => fmt_fstatat(args, path),
        SyscallNr::STATX => fmt_statx(args, path),
        SyscallNr::MMAP => fmt_mmap(args),
        SyscallNr::MPROTECT => fmt_mprotect(args),
        SyscallNr::MUNMAP => fmt_munmap(args),
        SyscallNr::BRK => fmt_brk(args),
        SyscallNr::SOCKET => fmt_socket(args),
        SyscallNr::CONNECT | SyscallNr::BIND => fmt_connect_bind(args, sockaddr),
        SyscallNr::ACCEPT | SyscallNr::ACCEPT4 => fmt_accept(args, sockaddr),
        SyscallNr::SENDTO => fmt_sendto(args),
        SyscallNr::RECVFROM => fmt_recvfrom(args, ret),
        SyscallNr::SENDMSG | SyscallNr::SENDMMSG => fmt_sendmsg(args),
        SyscallNr::RECVMSG | SyscallNr::RECVMMSG => fmt_recvmsg(args),
        SyscallNr::LISTEN => fmt_listen(args),
        SyscallNr::GETSOCKNAME | SyscallNr::GETPEERNAME => fmt_getname(args, sockaddr),
        SyscallNr::SETSOCKOPT | SyscallNr::GETSOCKOPT => fmt_sockopt(args),
        SyscallNr::SOCKETPAIR => fmt_socketpair(args),
        SyscallNr::FORK | SyscallNr::VFORK => String::new(),
        SyscallNr::CLONE => fmt_clone(args),
        SyscallNr::CLONE3 => fmt_clone3(args),
        SyscallNr::EXECVE => fmt_execve(args, path),
        SyscallNr::EXECVEAT => fmt_execveat(args, path),
        SyscallNr::EXIT | SyscallNr::EXIT_GROUP => fmt_exit(args),
        SyscallNr::WAIT4 => fmt_wait4(args),
        SyscallNr::WAITID => fmt_waitid(args),
        SyscallNr::KILL => fmt_kill(args),
        SyscallNr::FCNTL => fmt_fcntl(args),
        SyscallNr::DUP => fmt_dup(args),
        SyscallNr::DUP2 | SyscallNr::DUP3 => fmt_dup2(args),
        SyscallNr::PIPE | SyscallNr::PIPE2 => fmt_pipe(args),
        SyscallNr::FUTEX => fmt_futex(args),
        SyscallNr::GETCWD => fmt_getcwd(args),
        SyscallNr::CHDIR => fmt_chdir(args, path),
        SyscallNr::FCHDIR => fd(args[0]),
        SyscallNr::MKDIR | SyscallNr::MKDIRAT => fmt_mkdir(args, path),
        SyscallNr::UNLINK | SyscallNr::UNLINKAT => fmt_unlink(args, path),
        SyscallNr::RENAME | SyscallNr::RENAMEAT => fmt_rename(args, path),
        SyscallNr::IOCTL => fmt_ioctl(args),
        SyscallNr::FALLOCATE => fmt_fallocate(args),
        SyscallNr::FTRUNCATE => fmt_ftruncate(args),
        SyscallNr::TRUNCATE => fmt_truncate(args, path),
        SyscallNr::FSYNC | SyscallNr::FDATASYNC => fd(args[0]),
        SyscallNr::MADVISE => fmt_madvise(args),
        SyscallNr::SENDFILE => fmt_sendfile(args),
        SyscallNr::SPLICE => fmt_splice(args),
        SyscallNr::MEMFD_CREATE => fmt_memfd_create(args),
        SyscallNr::GETDENTS64 => fmt_getdents64(args),
        SyscallNr::GETPID
        | SyscallNr::GETPPID
        | SyscallNr::GETTID
        | SyscallNr::GETUID
        | SyscallNr::GETEUID
        | SyscallNr::GETGID
        | SyscallNr::GETEGID
        | SyscallNr::SCHED_YIELD => String::new(),
        SyscallNr::NANOSLEEP => fmt_nanosleep(args),
        SyscallNr::GETRANDOM => fmt_getrandom(args),
        SyscallNr::PRCTL => fmt_prctl(args),
        SyscallNr::EPOLL_CTL => fmt_epoll_ctl(args),
        SyscallNr::EPOLL_WAIT | SyscallNr::EPOLL_PWAIT => fmt_epoll_wait(args),
        SyscallNr::READV | SyscallNr::WRITEV => fmt_readv(args),
        SyscallNr::MREMAP => fmt_mremap(args),
        SyscallNr::MSYNC => fmt_msync(args),
        SyscallNr::PRLIMIT64 => fmt_prlimit(args),
        // Everything else: raw hex.
        _ => fmt_raw(args),
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn ptr(addr: u64) -> String {
    if addr == 0 {
        "NULL".to_owned()
    } else {
        format!("{addr:#x}")
    }
}

/// Format a pointer argument: show the captured string if available, fall
/// back to the hex address otherwise.
fn path_or_ptr(addr: u64, path: Option<&str>) -> String {
    match path {
        Some(s) => format!("\"{}\"", s.escape_default()),
        None => ptr(addr),
    }
}

fn fd(n: u64) -> String {
    (n as i64).to_string()
}

fn at_fd(n: u64) -> String {
    match n as i64 {
        -100 => "AT_FDCWD".to_owned(),
        n => n.to_string(),
    }
}

fn open_flags(flags: u64) -> String {
    let f = flags as i32;
    let mut parts: Vec<&str> = Vec::new();
    match f & 3 {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => parts.push("O_RDWR"),
    }
    if f & 0o100 != 0 {
        parts.push("O_CREAT");
    }
    if f & 0o200 != 0 {
        parts.push("O_EXCL");
    }
    if f & 0o400 != 0 {
        parts.push("O_NOCTTY");
    }
    if f & 0o1000 != 0 {
        parts.push("O_TRUNC");
    }
    if f & 0o2000 != 0 {
        parts.push("O_APPEND");
    }
    if f & 0o4000 != 0 {
        parts.push("O_NONBLOCK");
    }
    if f & 0o40000 != 0 {
        parts.push("O_DIRECTORY");
    }
    if f & 0o100000 != 0 {
        parts.push("O_NOFOLLOW");
    }
    if f & 0o2000000 != 0 {
        parts.push("O_CLOEXEC");
    }
    if parts.is_empty() {
        format!("{flags:#o}")
    } else {
        parts.join("|")
    }
}

fn prot_flags(prot: u64) -> String {
    if prot == 0 {
        return "PROT_NONE".to_owned();
    }
    let mut parts: Vec<&str> = Vec::new();
    if prot & 1 != 0 {
        parts.push("PROT_READ");
    }
    if prot & 2 != 0 {
        parts.push("PROT_WRITE");
    }
    if prot & 4 != 0 {
        parts.push("PROT_EXEC");
    }
    parts.join("|")
}

fn mmap_flags(flags: u64) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("MAP_SHARED");
    }
    if flags & 0x02 != 0 {
        parts.push("MAP_PRIVATE");
    }
    if flags & 0x20 != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if flags & 0x10 != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & 0x100 != 0 {
        parts.push("MAP_GROWSDOWN");
    }
    if flags & 0x800 != 0 {
        parts.push("MAP_NORESERVE");
    }
    if flags & 0x4000 != 0 {
        parts.push("MAP_POPULATE");
    }
    if parts.is_empty() {
        format!("{flags:#x}")
    } else {
        parts.join("|")
    }
}

fn socket_domain(d: u64) -> &'static str {
    match d {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        10 => "AF_INET6",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        _ => "AF_?",
    }
}

fn socket_type(t: u64) -> String {
    let base = match t & 0xf {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        5 => "SOCK_SEQPACKET",
        _ => "SOCK_?",
    };
    let mut flags = String::new();
    if t & 0o4000 != 0 {
        flags.push_str("|SOCK_NONBLOCK");
    }
    if t & 0o2000000 != 0 {
        flags.push_str("|SOCK_CLOEXEC");
    }
    format!("{base}{flags}")
}

fn futex_op(op: u64) -> &'static str {
    match op & 0x7f {
        0 => "FUTEX_WAIT",
        1 => "FUTEX_WAKE",
        2 => "FUTEX_FD",
        3 => "FUTEX_REQUEUE",
        4 => "FUTEX_CMP_REQUEUE",
        5 => "FUTEX_WAKE_OP",
        9 => "FUTEX_LOCK_PI",
        10 => "FUTEX_UNLOCK_PI",
        128 => "FUTEX_WAIT_PRIVATE",
        129 => "FUTEX_WAKE_PRIVATE",
        _ => "FUTEX_?",
    }
}

fn fmt_raw(args: &[u64; 6]) -> String {
    args.iter()
        .filter(|&&a| a != 0)
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ── per-syscall formatters ─────────────────────────────────────────────────

fn fmt_read_write(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), args[2])
}

fn fmt_open(args: &[u64; 6], path: Option<&str>) -> String {
    format!("{}, {}", path_or_ptr(args[0], path), open_flags(args[1]))
}

fn fmt_openat(args: &[u64; 6], path: Option<&str>) -> String {
    format!(
        "{}, {}, {}",
        at_fd(args[0]),
        path_or_ptr(args[1], path),
        open_flags(args[2])
    )
}

fn fmt_close(args: &[u64; 6]) -> String {
    fd(args[0])
}

fn fmt_pread_pwrite(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}",
        fd(args[0]),
        ptr(args[1]),
        args[2],
        args[3]
    )
}

fn fmt_lseek(args: &[u64; 6]) -> String {
    let whence = match args[2] {
        0 => "SEEK_SET",
        1 => "SEEK_CUR",
        2 => "SEEK_END",
        _ => "SEEK_?",
    };
    format!("{}, {}, {whence}", fd(args[0]), args[1] as i64)
}

fn fmt_stat(args: &[u64; 6], path: Option<&str>) -> String {
    format!("{}, {}", path_or_ptr(args[0], path), ptr(args[1]))
}

fn fmt_fstat(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), ptr(args[1]))
}

fn fmt_fstatat(args: &[u64; 6], path: Option<&str>) -> String {
    format!(
        "{}, {}, {}",
        at_fd(args[0]),
        path_or_ptr(args[1], path),
        ptr(args[2])
    )
}

fn fmt_statx(args: &[u64; 6], path: Option<&str>) -> String {
    format!(
        "{}, {}, {:#x}, {:#x}, {}",
        at_fd(args[0]),
        path_or_ptr(args[1], path),
        args[2],
        args[3],
        ptr(args[4]),
    )
}

fn fmt_mmap(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}, {}, {:#x}",
        ptr(args[0]),
        args[1],
        prot_flags(args[2]),
        mmap_flags(args[3]),
        fd(args[4]),
        args[5]
    )
}

fn fmt_mprotect(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", ptr(args[0]), args[1], prot_flags(args[2]))
}

fn fmt_munmap(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), args[1])
}

fn fmt_brk(args: &[u64; 6]) -> String {
    ptr(args[0])
}

fn fmt_socket(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}",
        socket_domain(args[0]),
        socket_type(args[1]),
        args[2]
    )
}

fn fmt_connect_bind(args: &[u64; 6], sockaddr: &[u8]) -> String {
    let addr = format_sockaddr(sockaddr, args[1]);
    format!("{}, {}, {}", fd(args[0]), addr, args[2])
}

/// Format a sockaddr struct.  Falls back to a hex pointer when the bytes
/// are not available or the address family is unknown.
fn format_sockaddr(bytes: &[u8], fallback_ptr: u64) -> String {
    if bytes.len() < 2 {
        return ptr(fallback_ptr);
    }
    // sa_family is the first two bytes, little-endian on x86_64/aarch64.
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        // AF_INET = 2: struct sockaddr_in { u16 family; u16 port; u32 addr; … }
        2 if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let a = bytes[4];
            let b = bytes[5];
            let c = bytes[6];
            let d = bytes[7];
            format!("{a}.{b}.{c}.{d}:{port}")
        }
        // AF_INET6 = 10: struct sockaddr_in6 { u16 family; u16 port; u32 flow; u8 addr[16]; … }
        10 if bytes.len() >= 20 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            // Format the 16-byte IPv6 address as groups of u16 big-endian.
            let groups: [u16; 8] = core::array::from_fn(|i| {
                u16::from_be_bytes([bytes[8 + i * 2], bytes[8 + i * 2 + 1]])
            });
            let addr = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                groups[0],
                groups[1],
                groups[2],
                groups[3],
                groups[4],
                groups[5],
                groups[6],
                groups[7],
            );
            format!("[{addr}]:{port}")
        }
        // AF_UNIX = 1: struct sockaddr_un { u16 family; char path[108]; }
        1 if bytes.len() >= 3 => {
            let path_bytes = &bytes[2..];
            let end = path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len());
            let path = core::str::from_utf8(&path_bytes[..end]).unwrap_or("?");
            format!("\"{}\"", path)
        }
        _ => ptr(fallback_ptr),
    }
}

fn fmt_accept(args: &[u64; 6], sockaddr: &[u8]) -> String {
    format!(
        "{}, {}, {}",
        fd(args[0]),
        format_sockaddr(sockaddr, args[1]),
        ptr(args[2])
    )
}

fn fmt_sendto(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {:#x}, {}, {}",
        fd(args[0]),
        ptr(args[1]),
        args[2],
        args[3],
        ptr(args[4]),
        args[5]
    )
}

fn fmt_recvfrom(args: &[u64; 6], ret: i64) -> String {
    let received = if ret >= 0 {
        ret.to_string()
    } else {
        "err".to_owned()
    };
    format!(
        "{}, {}, {} [received {received}], {:#x}, {}, {}",
        fd(args[0]),
        ptr(args[1]),
        args[2],
        args[3],
        ptr(args[4]),
        ptr(args[5])
    )
}

fn fmt_listen(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), args[1])
}

fn fmt_getname(args: &[u64; 6], sockaddr: &[u8]) -> String {
    format!(
        "{}, {}, {}",
        fd(args[0]),
        format_sockaddr(sockaddr, args[1]),
        ptr(args[2])
    )
}

fn fmt_sockopt(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}, {}",
        fd(args[0]),
        args[1],
        args[2],
        ptr(args[3]),
        args[4]
    )
}

fn fmt_clone(args: &[u64; 6]) -> String {
    let flags = args[0];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x0100 != 0 {
        parts.push("CLONE_VM");
    }
    if flags & 0x0200 != 0 {
        parts.push("CLONE_FS");
    }
    if flags & 0x0400 != 0 {
        parts.push("CLONE_FILES");
    }
    if flags & 0x0800 != 0 {
        parts.push("CLONE_SIGHAND");
    }
    if flags & 0x4000 != 0 {
        parts.push("CLONE_PTRACE");
    }
    if flags & 0x8000 != 0 {
        parts.push("CLONE_VFORK");
    }
    if flags & 0x10000 != 0 {
        parts.push("CLONE_PARENT");
    }
    if flags & 0x20000 != 0 {
        parts.push("CLONE_THREAD");
    }
    if flags & 0x80000 != 0 {
        parts.push("CLONE_NEWNS");
    }
    if flags & 0x200000 != 0 {
        parts.push("CLONE_NEWPID");
    }
    if flags & 0x400000 != 0 {
        parts.push("CLONE_NEWNET");
    }
    let flags_str = if parts.is_empty() {
        format!("{flags:#x}")
    } else {
        parts.join("|")
    };
    format!("{flags_str}, {}, {}", ptr(args[1]), ptr(args[2]))
}

fn fmt_clone3(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), args[1])
}

fn fmt_execve(args: &[u64; 6], path: Option<&str>) -> String {
    format!(
        "{}, {}, {}",
        path_or_ptr(args[0], path),
        ptr(args[1]),
        ptr(args[2])
    )
}

fn fmt_execveat(args: &[u64; 6], path: Option<&str>) -> String {
    format!(
        "{}, {}, {}, {}, {:#x}",
        at_fd(args[0]),
        path_or_ptr(args[1], path),
        ptr(args[2]),
        ptr(args[3]),
        args[4],
    )
}

fn fmt_exit(args: &[u64; 6]) -> String {
    (args[0] as i32).to_string()
}

fn fmt_wait4(args: &[u64; 6]) -> String {
    let pid = args[0] as i32;
    format!("{pid}, {}, {:#x}, {}", ptr(args[1]), args[2], ptr(args[3]))
}

fn fmt_waitid(args: &[u64; 6]) -> String {
    let idtype = match args[0] {
        0 => "P_ALL",
        1 => "P_PID",
        2 => "P_PGID",
        _ => "P_?",
    };
    format!("{idtype}, {}, {}, {:#x}", args[1], ptr(args[2]), args[3])
}

fn fmt_kill(args: &[u64; 6]) -> String {
    format!("{}, {}", args[0] as i32, args[1] as i32)
}

fn fmt_fcntl(args: &[u64; 6]) -> String {
    let cmd = match args[1] {
        0 => "F_DUPFD",
        1 => "F_GETFD",
        2 => "F_SETFD",
        3 => "F_GETFL",
        4 => "F_SETFL",
        6 => "F_SETLK",
        7 => "F_SETLKW",
        8 => "F_GETLK",
        1030 => "F_DUPFD_CLOEXEC",
        _ => "F_?",
    };
    if args[2] != 0 {
        format!("{}, {cmd}, {:#x}", fd(args[0]), args[2])
    } else {
        format!("{}, {cmd}", fd(args[0]))
    }
}

fn fmt_dup(args: &[u64; 6]) -> String {
    fd(args[0])
}

fn fmt_dup2(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), fd(args[1]))
}

fn fmt_pipe(args: &[u64; 6]) -> String {
    ptr(args[0])
}

fn fmt_futex(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", ptr(args[0]), futex_op(args[1]), args[2])
}

fn fmt_getcwd(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), args[1])
}

fn fmt_chdir(args: &[u64; 6], path: Option<&str>) -> String {
    path_or_ptr(args[0], path)
}

fn fmt_mkdir(args: &[u64; 6], path: Option<&str>) -> String {
    format!("{}, {:#o}", path_or_ptr(args[0], path), args[1])
}

fn fmt_unlink(args: &[u64; 6], path: Option<&str>) -> String {
    path_or_ptr(args[0], path)
}

fn fmt_rename(args: &[u64; 6], path: Option<&str>) -> String {
    // path captures the first argument; the second is always a hex pointer
    format!("{}, {}", path_or_ptr(args[0], path), ptr(args[1]))
}

fn fmt_ioctl(args: &[u64; 6]) -> String {
    format!("{}, {:#x}, {:#x}", fd(args[0]), args[1], args[2])
}

fn fmt_fallocate(args: &[u64; 6]) -> String {
    format!(
        "{}, {:#x}, {}, {}",
        fd(args[0]),
        args[1],
        args[2] as i64,
        args[3]
    )
}

fn fmt_getrandom(args: &[u64; 6]) -> String {
    let flags = args[2];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 {
        parts.push("GRND_NONBLOCK");
    }
    if flags & 2 != 0 {
        parts.push("GRND_RANDOM");
    }
    let flags_str = if parts.is_empty() {
        "0".to_owned()
    } else {
        parts.join("|")
    };
    format!("{}, {}, {flags_str}", ptr(args[0]), args[1])
}

fn fmt_prctl(args: &[u64; 6]) -> String {
    let op = match args[0] {
        1 => "PR_SET_PDEATHSIG",
        2 => "PR_GET_PDEATHSIG",
        4 => "PR_GET_DUMPABLE",
        5 => "PR_SET_DUMPABLE",
        6 => "PR_GET_UNALIGN",
        7 => "PR_SET_UNALIGN",
        15 => "PR_SET_NAME",
        16 => "PR_GET_NAME",
        22 => "PR_SET_SECCOMP",
        23 => "PR_GET_SECCOMP",
        38 => "PR_SET_NO_NEW_PRIVS",
        39 => "PR_GET_NO_NEW_PRIVS",
        _ => "PR_?",
    };
    format!("{op}, {:#x}", args[1])
}

fn fmt_epoll_ctl(args: &[u64; 6]) -> String {
    let op = match args[1] {
        1 => "EPOLL_CTL_ADD",
        2 => "EPOLL_CTL_DEL",
        3 => "EPOLL_CTL_MOD",
        _ => "EPOLL_CTL_?",
    };
    format!("{}, {op}, {}, {}", fd(args[0]), fd(args[2]), ptr(args[3]))
}

fn fmt_epoll_wait(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}",
        fd(args[0]),
        ptr(args[1]),
        args[2],
        args[3] as i32
    )
}

fn fmt_sendmsg(args: &[u64; 6]) -> String {
    let flags = args[2];
    format!("{}, {}, {:#x}", fd(args[0]), ptr(args[1]), flags)
}

fn fmt_recvmsg(args: &[u64; 6]) -> String {
    let flags = args[2];
    format!("{}, {}, {:#x}", fd(args[0]), ptr(args[1]), flags)
}

fn fmt_socketpair(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}",
        socket_domain(args[0]),
        socket_type(args[1]),
        args[2],
        ptr(args[3])
    )
}

fn fmt_ftruncate(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), args[1] as i64)
}

fn fmt_truncate(args: &[u64; 6], path: Option<&str>) -> String {
    format!("{}, {}", path_or_ptr(args[0], path), args[1] as i64)
}

fn fmt_madvise(args: &[u64; 6]) -> String {
    let advice = match args[2] {
        0 => "MADV_NORMAL",
        1 => "MADV_RANDOM",
        2 => "MADV_SEQUENTIAL",
        3 => "MADV_WILLNEED",
        4 => "MADV_DONTNEED",
        8 => "MADV_FREE",
        9 => "MADV_REMOVE",
        10 => "MADV_DONTFORK",
        11 => "MADV_DOFORK",
        12 => "MADV_MERGEABLE",
        13 => "MADV_UNMERGEABLE",
        14 => "MADV_HUGEPAGE",
        15 => "MADV_NOHUGEPAGE",
        16 => "MADV_DONTDUMP",
        17 => "MADV_DODUMP",
        _ => "MADV_?",
    };
    format!("{}, {}, {advice}", ptr(args[0]), args[1])
}

fn fmt_sendfile(args: &[u64; 6]) -> String {
    format!(
        "{}, {}, {}, {}",
        fd(args[0]),
        fd(args[1]),
        ptr(args[2]),
        args[3]
    )
}

fn fmt_splice(args: &[u64; 6]) -> String {
    // splice(fd_in, off_in, fd_out, off_out, len, flags)
    let flags = args[5];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 {
        parts.push("SPLICE_F_MOVE");
    }
    if flags & 2 != 0 {
        parts.push("SPLICE_F_NONBLOCK");
    }
    if flags & 4 != 0 {
        parts.push("SPLICE_F_MORE");
    }
    let flags_str = if parts.is_empty() {
        "0".to_owned()
    } else {
        parts.join("|")
    };
    format!(
        "{}, {}, {}, {}, {}, {flags_str}",
        fd(args[0]),
        ptr(args[1]),
        fd(args[2]),
        ptr(args[3]),
        args[4]
    )
}

fn fmt_memfd_create(args: &[u64; 6]) -> String {
    let flags = args[1];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 {
        parts.push("MFD_CLOEXEC");
    }
    if flags & 2 != 0 {
        parts.push("MFD_ALLOW_SEALING");
    }
    let flags_str = if parts.is_empty() {
        "0".to_owned()
    } else {
        parts.join("|")
    };
    format!("{}, {flags_str}", ptr(args[0]))
}

fn fmt_getdents64(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), args[2])
}

fn fmt_nanosleep(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), ptr(args[1]))
}

fn fmt_readv(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), args[2])
}

fn fmt_mremap(args: &[u64; 6]) -> String {
    let flags = args[3];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 {
        parts.push("MREMAP_MAYMOVE");
    }
    if flags & 2 != 0 {
        parts.push("MREMAP_FIXED");
    }
    let flags_str = if parts.is_empty() {
        format!("{flags:#x}")
    } else {
        parts.join("|")
    };
    format!("{}, {}, {}, {flags_str}", ptr(args[0]), args[1], args[2])
}

fn fmt_msync(args: &[u64; 6]) -> String {
    let flags = args[2];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 {
        parts.push("MS_ASYNC");
    }
    if flags & 2 != 0 {
        parts.push("MS_INVALIDATE");
    }
    if flags & 4 != 0 {
        parts.push("MS_SYNC");
    }
    let flags_str = if parts.is_empty() {
        "0".to_owned()
    } else {
        parts.join("|")
    };
    format!("{}, {}, {flags_str}", ptr(args[0]), args[1])
}

fn fmt_prlimit(args: &[u64; 6]) -> String {
    let resource = match args[1] {
        0 => "RLIMIT_CPU",
        1 => "RLIMIT_FSIZE",
        2 => "RLIMIT_DATA",
        3 => "RLIMIT_STACK",
        4 => "RLIMIT_CORE",
        5 => "RLIMIT_RSS",
        6 => "RLIMIT_NPROC",
        7 => "RLIMIT_NOFILE",
        8 => "RLIMIT_MEMLOCK",
        9 => "RLIMIT_AS",
        10 => "RLIMIT_LOCKS",
        11 => "RLIMIT_SIGPENDING",
        12 => "RLIMIT_MSGQUEUE",
        13 => "RLIMIT_NICE",
        14 => "RLIMIT_RTPRIO",
        _ => "RLIMIT_?",
    };
    format!(
        "{}, {resource}, {}, {}",
        args[0] as i32,
        ptr(args[2]),
        ptr(args[3])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_ipv4_localhost_80() {
        // AF_INET=2, port=80 (0x0050 big-endian), addr=127.0.0.1
        let bytes: [u8; 8] = [
            0x02, 0x00, // AF_INET, little-endian
            0x00, 0x50, // port 80, big-endian
            127, 0, 0, 1, // 127.0.0.1
        ];
        assert_eq!(format_sockaddr(&bytes, 0), "127.0.0.1:80");
    }

    #[test]
    fn sockaddr_ipv4_any_443() {
        let bytes: [u8; 8] = [
            0x02, 0x00, 0x01, 0xBB, // port 443
            0, 0, 0, 0, // 0.0.0.0
        ];
        assert_eq!(format_sockaddr(&bytes, 0), "0.0.0.0:443");
    }

    #[test]
    fn sockaddr_unix_path() {
        let mut bytes = vec![0x01, 0x00]; // AF_UNIX
        bytes.extend_from_slice(b"/var/run/docker.sock\0");
        assert_eq!(format_sockaddr(&bytes, 0), "\"/var/run/docker.sock\"");
    }

    #[test]
    fn sockaddr_empty_falls_back_to_ptr() {
        assert_eq!(format_sockaddr(&[], 0x7fff1234), "0x7fff1234");
    }

    #[test]
    fn sockaddr_unknown_family_falls_back_to_ptr() {
        let bytes = [0xFF, 0xFF, 0x00, 0x50]; // AF_MAX or unknown
        assert_eq!(format_sockaddr(&bytes, 0xdeadbeef), "0xdeadbeef");
    }

    #[test]
    fn open_flags_rdonly() {
        assert_eq!(open_flags(0), "O_RDONLY");
    }

    #[test]
    fn open_flags_creat_rdwr() {
        // O_RDWR | O_CREAT | O_TRUNC
        assert_eq!(open_flags(0o1102), "O_RDWR|O_CREAT|O_TRUNC");
    }

    #[test]
    fn lseek_whence_symbolic() {
        let mut args = [0u64; 6];
        args[0] = 3; // fd
        args[1] = 0; // offset
        args[2] = 2; // SEEK_END
        assert_eq!(fmt_lseek(&args), "3, 0, SEEK_END");
    }

    #[test]
    fn mmap_prot_flags() {
        assert_eq!(prot_flags(3), "PROT_READ|PROT_WRITE");
        assert_eq!(prot_flags(0), "PROT_NONE");
        assert_eq!(prot_flags(4), "PROT_EXEC");
    }

    #[test]
    fn socket_domain_and_type() {
        assert_eq!(socket_domain(2), "AF_INET");
        assert_eq!(socket_type(1), "SOCK_STREAM");
        // SOCK_STREAM=1, SOCK_CLOEXEC=0o2000000=0x80000
        assert_eq!(socket_type(0x80001), "SOCK_STREAM|SOCK_CLOEXEC");
    }

    #[test]
    fn futex_op_names() {
        assert_eq!(futex_op(0), "FUTEX_WAIT");
        assert_eq!(futex_op(1), "FUTEX_WAKE");
        // FUTEX_WAIT_PRIVATE = FUTEX_WAIT | FUTEX_PRIVATE_FLAG (0x80)
        // The match masks with 0x7f so 128 → 0 → FUTEX_WAIT
        assert_eq!(futex_op(128), "FUTEX_WAIT");
    }
}
