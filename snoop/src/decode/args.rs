//! Per-syscall argument formatters.
//!
//! Each formatter receives the raw `args[0..5]` register values and the
//! return value, and returns a human-readable argument string.
//!
//! The argument values are pointer-sized integers as delivered by the kernel.
//! For pointer arguments (paths, buffers) we only have the *address* — actual
//! contents were captured by `bpf_probe_read_user` in the eBPF programs and
//! are not yet plumbed through.  The address is shown as a hex pointer for
//! now; string arguments will be added in a follow-up that extends
//! `SyscallEvent` with an inline string buffer.

use snoop_common::SyscallNr;

/// Format the arguments for a syscall given its number, raw register args,
/// and return value.
pub fn decode_args(nr: SyscallNr, args: &[u64; 6], ret: i64) -> String {
    match nr {
        SyscallNr::READ | SyscallNr::WRITE => fmt_read_write(args),
        SyscallNr::OPEN => fmt_open(args),
        SyscallNr::OPENAT => fmt_openat(args),
        SyscallNr::CLOSE => fmt_close(args),
        SyscallNr::PREAD64 | SyscallNr::PWRITE64 => fmt_pread_pwrite(args),
        SyscallNr::LSEEK => fmt_lseek(args),
        SyscallNr::STAT | SyscallNr::LSTAT => fmt_stat(args),
        SyscallNr::FSTAT => fmt_fstat(args),
        SyscallNr::FSTATAT => fmt_fstatat(args),
        SyscallNr::STATX => fmt_statx(args),
        SyscallNr::MMAP => fmt_mmap(args),
        SyscallNr::MPROTECT => fmt_mprotect(args),
        SyscallNr::MUNMAP => fmt_munmap(args),
        SyscallNr::BRK => fmt_brk(args),
        SyscallNr::SOCKET => fmt_socket(args),
        SyscallNr::CONNECT | SyscallNr::BIND => fmt_connect_bind(args),
        SyscallNr::ACCEPT | SyscallNr::ACCEPT4 => fmt_accept(args),
        SyscallNr::SENDTO => fmt_sendto(args),
        SyscallNr::RECVFROM => fmt_recvfrom(args, ret),
        SyscallNr::LISTEN => fmt_listen(args),
        SyscallNr::GETSOCKNAME | SyscallNr::GETPEERNAME => fmt_getname(args),
        SyscallNr::SETSOCKOPT | SyscallNr::GETSOCKOPT => fmt_sockopt(args),
        SyscallNr::CLONE => fmt_clone(args),
        SyscallNr::CLONE3 => fmt_clone3(args),
        SyscallNr::EXECVE => fmt_execve(args),
        SyscallNr::EXECVEAT => fmt_execveat(args),
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
        SyscallNr::CHDIR | SyscallNr::FCHDIR => fmt_chdir(args),
        SyscallNr::MKDIR | SyscallNr::MKDIRAT => fmt_mkdir(args),
        SyscallNr::UNLINK | SyscallNr::UNLINKAT => fmt_unlink(args),
        SyscallNr::RENAME | SyscallNr::RENAMEAT => fmt_rename(args),
        SyscallNr::IOCTL => fmt_ioctl(args),
        SyscallNr::FALLOCATE => fmt_fallocate(args),
        SyscallNr::GETRANDOM => fmt_getrandom(args),
        SyscallNr::PRCTL => fmt_prctl(args),
        SyscallNr::EPOLL_CTL => fmt_epoll_ctl(args),
        SyscallNr::EPOLL_WAIT | SyscallNr::EPOLL_PWAIT => fmt_epoll_wait(args),
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
    if f & 0o100 != 0 { parts.push("O_CREAT"); }
    if f & 0o200 != 0 { parts.push("O_EXCL"); }
    if f & 0o400 != 0 { parts.push("O_NOCTTY"); }
    if f & 0o1000 != 0 { parts.push("O_TRUNC"); }
    if f & 0o2000 != 0 { parts.push("O_APPEND"); }
    if f & 0o4000 != 0 { parts.push("O_NONBLOCK"); }
    if f & 0o40000 != 0 { parts.push("O_DIRECTORY"); }
    if f & 0o100000 != 0 { parts.push("O_NOFOLLOW"); }
    if f & 0o2000000 != 0 { parts.push("O_CLOEXEC"); }
    if parts.is_empty() {
        format!("{flags:#o}")
    } else {
        parts.join("|")
    }
}

fn prot_flags(prot: u64) -> String {
    if prot == 0 { return "PROT_NONE".to_owned(); }
    let mut parts: Vec<&str> = Vec::new();
    if prot & 1 != 0 { parts.push("PROT_READ"); }
    if prot & 2 != 0 { parts.push("PROT_WRITE"); }
    if prot & 4 != 0 { parts.push("PROT_EXEC"); }
    parts.join("|")
}

fn mmap_flags(flags: u64) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x01 != 0 { parts.push("MAP_SHARED"); }
    if flags & 0x02 != 0 { parts.push("MAP_PRIVATE"); }
    if flags & 0x20 != 0 { parts.push("MAP_ANONYMOUS"); }
    if flags & 0x10 != 0 { parts.push("MAP_FIXED"); }
    if flags & 0x100 != 0 { parts.push("MAP_GROWSDOWN"); }
    if flags & 0x800 != 0 { parts.push("MAP_NORESERVE"); }
    if flags & 0x4000 != 0 { parts.push("MAP_POPULATE"); }
    if parts.is_empty() { format!("{flags:#x}") } else { parts.join("|") }
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
    if t & 0o4000 != 0 { flags.push_str("|SOCK_NONBLOCK"); }
    if t & 0o2000000 != 0 { flags.push_str("|SOCK_CLOEXEC"); }
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

fn fmt_open(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), open_flags(args[1]))
}

fn fmt_openat(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", at_fd(args[0]), ptr(args[1]), open_flags(args[2]))
}

fn fmt_close(args: &[u64; 6]) -> String {
    fd(args[0])
}

fn fmt_pread_pwrite(args: &[u64; 6]) -> String {
    format!("{}, {}, {}, {}", fd(args[0]), ptr(args[1]), args[2], args[3])
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

fn fmt_stat(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), ptr(args[1]))
}

fn fmt_fstat(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), ptr(args[1]))
}

fn fmt_fstatat(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", at_fd(args[0]), ptr(args[1]), ptr(args[2]))
}

fn fmt_statx(args: &[u64; 6]) -> String {
    format!("{}, {}, {:#x}, {:#x}, {}", at_fd(args[0]), ptr(args[1]), args[2], args[3], ptr(args[4]))
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
    format!("{}, {}, {}", socket_domain(args[0]), socket_type(args[1]), args[2])
}

fn fmt_connect_bind(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), args[2])
}

fn fmt_accept(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), ptr(args[2]))
}

fn fmt_sendto(args: &[u64; 6]) -> String {
    format!("{}, {}, {}, {:#x}, {}, {}", fd(args[0]), ptr(args[1]), args[2], args[3], ptr(args[4]), args[5])
}

fn fmt_recvfrom(args: &[u64; 6], ret: i64) -> String {
    let received = if ret >= 0 { ret.to_string() } else { "err".to_owned() };
    format!("{}, {}, {} [received {received}], {:#x}, {}, {}", fd(args[0]), ptr(args[1]), args[2], args[3], ptr(args[4]), ptr(args[5]))
}

fn fmt_listen(args: &[u64; 6]) -> String {
    format!("{}, {}", fd(args[0]), args[1])
}

fn fmt_getname(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", fd(args[0]), ptr(args[1]), ptr(args[2]))
}

fn fmt_sockopt(args: &[u64; 6]) -> String {
    format!("{}, {}, {}, {}, {}", fd(args[0]), args[1], args[2], ptr(args[3]), args[4])
}

fn fmt_clone(args: &[u64; 6]) -> String {
    let flags = args[0];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x0100 != 0 { parts.push("CLONE_VM"); }
    if flags & 0x0200 != 0 { parts.push("CLONE_FS"); }
    if flags & 0x0400 != 0 { parts.push("CLONE_FILES"); }
    if flags & 0x0800 != 0 { parts.push("CLONE_SIGHAND"); }
    if flags & 0x4000 != 0 { parts.push("CLONE_PTRACE"); }
    if flags & 0x8000 != 0 { parts.push("CLONE_VFORK"); }
    if flags & 0x10000 != 0 { parts.push("CLONE_PARENT"); }
    if flags & 0x20000 != 0 { parts.push("CLONE_THREAD"); }
    if flags & 0x80000 != 0 { parts.push("CLONE_NEWNS"); }
    if flags & 0x200000 != 0 { parts.push("CLONE_NEWPID"); }
    if flags & 0x400000 != 0 { parts.push("CLONE_NEWNET"); }
    let flags_str = if parts.is_empty() { format!("{flags:#x}") } else { parts.join("|") };
    format!("{flags_str}, {}, {}", ptr(args[1]), ptr(args[2]))
}

fn fmt_clone3(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), args[1])
}

fn fmt_execve(args: &[u64; 6]) -> String {
    format!("{}, {}, {}", ptr(args[0]), ptr(args[1]), ptr(args[2]))
}

fn fmt_execveat(args: &[u64; 6]) -> String {
    format!("{}, {}, {}, {}, {:#x}", at_fd(args[0]), ptr(args[1]), ptr(args[2]), ptr(args[3]), args[4])
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

fn fmt_chdir(args: &[u64; 6]) -> String {
    ptr(args[0])
}

fn fmt_mkdir(args: &[u64; 6]) -> String {
    format!("{}, {:#o}", ptr(args[0]), args[1])
}

fn fmt_unlink(args: &[u64; 6]) -> String {
    ptr(args[0])
}

fn fmt_rename(args: &[u64; 6]) -> String {
    format!("{}, {}", ptr(args[0]), ptr(args[1]))
}

fn fmt_ioctl(args: &[u64; 6]) -> String {
    format!("{}, {:#x}, {:#x}", fd(args[0]), args[1], args[2])
}

fn fmt_fallocate(args: &[u64; 6]) -> String {
    format!("{}, {:#x}, {}, {}", fd(args[0]), args[1], args[2] as i64, args[3])
}

fn fmt_getrandom(args: &[u64; 6]) -> String {
    let flags = args[2];
    let mut parts: Vec<&str> = Vec::new();
    if flags & 1 != 0 { parts.push("GRND_NONBLOCK"); }
    if flags & 2 != 0 { parts.push("GRND_RANDOM"); }
    let flags_str = if parts.is_empty() { "0".to_owned() } else { parts.join("|") };
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
    format!("{}, {}, {}, {}", fd(args[0]), ptr(args[1]), args[2], args[3] as i32)
}
