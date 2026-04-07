# ROADMAP

## v0.1 — Launch target

### Core tracing
- [x] `sys_enter` / `sys_exit` tracepoints via aya on `raw_syscalls`
- [x] Ring-buffer event path from eBPF to userspace
- [x] Spawn mode: `snoop <cmd> [args…]` — fork/exec target, trace from birth
- [x] Attach mode: `snoop -p <pid>` — attach to running process
- [ ] Follow mode: `snoop -p <pid> --follow` — trace process tree (intercept clone/fork)
- [x] Graceful exit on target process termination

### Argument decoding (top 40 syscalls)
- [x] openat / open / creat — path, flags, mode
- [x] read / write / pread64 / pwrite64 — fd, count, offset
- [x] close — fd
- [x] connect / bind / accept / accept4 — fd, sockaddr ptr, addrlen
- [x] sendto / recvfrom / sendmsg / recvmsg — fd, size, flags
- [x] execve / execveat — path, argv (first N args)
- [x] mmap / mmap2 / munmap / mprotect — addr, len, prot, flags
- [x] clone / clone3 / fork / vfork — flags (render as symbolic)
- [x] wait4 / waitid — pid, options
- [x] futex — op, val
- [x] stat / fstat / lstat / statx — path / fd
- [x] ioctl — fd, request (decode common requests)
- [x] brk / sbrk
- [x] exit / exit_group — status code
- [x] pipe / pipe2 / dup / dup2 / dup3
- [x] socket / socketpair — domain, type, protocol (symbolic)
- [x] lseek — fd, offset, whence (symbolic)
- [x] getcwd / chdir / fchdir
- [x] getpid / getppid / gettid / getuid / getgid

### Output modes
- [x] `--raw`: strace-compatible single-line output (default when stdout is not a TTY)
- [x] TUI (default when stdout is a TTY):
  - [x] Header bar: pid / comm / event count / elapsed
  - [x] Syscall stream panel (scrollable, color-coded by category)
  - [x] Top-syscalls panel (sorted by count, with percentages)
  - [x] Status / keybind footer
  - [x] Pause/resume (`Space`)
  - [x] Quit (`q`)
  - [x] Search / filter bar (`/`)
  - [x] Category filter toggle (`f`)

### Filtering
- [x] `--files`: only file-system syscalls
- [x] `--net`: only network syscalls
- [x] `--slow <ms>`: only syscalls taking longer than the threshold
- [x] `--syscall <name>`: only the named syscall(s) (repeatable)
- [x] `--no-decode`: skip argument decoding (pure raw hex args)

### Packaging / ops
- [x] Flamegraph export: `--flamegraph out.svg` (inferno crate, uses timing data)
- [x] `CAP_BPF` / root check with a clear error message and suggestion
- [x] `--version` output with git SHA embedded at build time
- [ ] `cargo install` works on Linux x86_64 and aarch64

## v0.2 — Post-launch

- [ ] "Explain" mode: semantic grouping (HTTP GET, config load, etc.)
- [ ] Record & replay: `snoop record … > trace.snoop`, `snoop view trace.snoop`
- [ ] Diff mode: `snoop diff good.snoop bad.snoop`
- [ ] Container / Kubernetes awareness (`--docker`, `--pod`)
- [ ] uprobe-based library-call tracing (absorb ltrace)
- [ ] TLS decryption via uprobes on `SSL_write` / `SSL_read`
- [ ] Kernel-side PID filtering (avoid ring-buffer saturation on busy hosts)
- [ ] aarch64 CI and release artifacts
- [ ] Follow mode: trace process tree via clone/fork interception

## Technical debt / known limitations

- Spawn mode has an inherent race: eBPF attaches after exec, so the very first
  few syscalls of a process may be missed. Fix: use `ptrace(PTRACE_TRACEME)`
  to stall the child until eBPF is loaded.
- Argument decoding for pointer-heavy syscalls (execve argv, sendmsg iov) reads
  from userspace via `bpf_probe_read_user`; long strings are truncated at 128 bytes.
- No kernel-side PID filter yet — all syscalls are forwarded to userspace and
  filtered there. High-frequency workloads may saturate the ring buffer.
- sockaddr structs (connect/bind/accept) are decoded as raw pointers; a future
  pass using a second BPF read could render IP:port strings.
