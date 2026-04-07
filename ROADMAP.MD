# ROADMAP

## v0.1 — Launch target

### Core tracing
- [ ] `sys_enter` / `sys_exit` tracepoints via aya on `raw_syscalls`
- [ ] Ring-buffer event path from eBPF to userspace
- [ ] Spawn mode: `snoop <cmd> [args…]` — fork/exec target, trace from birth
- [ ] Attach mode: `snoop -p <pid>` — attach to running process
- [ ] Follow mode: `snoop -p <pid> --follow` — trace process tree (intercept clone/fork)
- [ ] Graceful exit on target process termination

### Argument decoding (top 40 syscalls)
- [ ] openat / open / creat — path, flags, mode
- [ ] read / write / pread64 / pwrite64 — fd, count, offset
- [ ] close — fd
- [ ] connect / bind / accept / accept4 — sockaddr decode (IPv4/IPv6/UNIX)
- [ ] sendto / recvfrom / sendmsg / recvmsg — fd, size, flags
- [ ] execve / execveat — path, argv (first N args)
- [ ] mmap / mmap2 / munmap / mprotect — addr, len, prot, flags
- [ ] clone / clone3 / fork / vfork — flags (render as symbolic)
- [ ] wait4 / waitid — pid, options
- [ ] futex — op, val
- [ ] stat / fstat / lstat / statx — path / fd
- [ ] ioctl — fd, request (decode common requests)
- [ ] brk / sbrk
- [ ] exit / exit_group — status code
- [ ] pipe / pipe2 / dup / dup2 / dup3
- [ ] socket / socketpair — domain, type, protocol (symbolic)
- [ ] lseek — fd, offset, whence (symbolic)
- [ ] getcwd / chdir / fchdir
- [ ] getpid / getppid / gettid / getuid / getgid

### Output modes
- [ ] `--raw`: strace-compatible single-line output (default when stdout is not a TTY)
- [ ] TUI (default when stdout is a TTY):
  - [ ] Header bar: pid / comm / event count / elapsed
  - [ ] Syscall stream panel (scrollable, color-coded by category)
  - [ ] Top-syscalls panel (sorted by count, with percentages)
  - [ ] Status / keybind footer
  - [ ] Pause/resume (`Space`)
  - [ ] Quit (`q`)
  - [ ] Search / filter bar (`/`)
  - [ ] Category filter toggle (`f`)

### Filtering
- [ ] `--files`: only file-system syscalls
- [ ] `--net`: only network syscalls
- [ ] `--slow <ms>`: only syscalls taking longer than the threshold
- [ ] `--syscall <name>`: only the named syscall(s) (repeatable)
- [ ] `--no-decode`: skip argument decoding (pure raw hex args)

### Packaging / ops
- [ ] Flamegraph export: `--flamegraph out.svg` (inferno crate, uses timing data)
- [ ] `CAP_BPF` / root check with a clear error message and suggestion
- [ ] `--version` output with git SHA embedded at build time
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

## Technical debt / known limitations

- Spawn mode has an inherent race: eBPF attaches after exec, so the very first
  few syscalls of a process may be missed. Fix: use `ptrace(PTRACE_TRACEME)`
  to stall the child until eBPF is loaded.
- Argument decoding for pointer-heavy syscalls (execve argv, sendmsg iov) reads
  from userspace via `bpf_probe_read_user`; long strings are truncated at 256 bytes.
- No kernel-side PID filter yet — all syscalls are forwarded to userspace and
  filtered there. High-frequency workloads may saturate the ring buffer.
