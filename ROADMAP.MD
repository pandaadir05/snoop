# ROADMAP

## v0.1 — Launch target

### Core tracing
- [x] `sys_enter` / `sys_exit` tracepoints via aya on `raw_syscalls`
- [x] Ring-buffer event path from eBPF to userspace
- [x] Spawn mode: `snoop <cmd> [args…]` — fork/exec target, trace from birth
- [x] Attach mode: `snoop -p <pid>` — attach to running process
- [x] Follow mode: `snoop -p <pid> --follow` — trace process tree (intercept clone/fork)
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
- [x] `cargo install` works on Linux x86_64 and aarch64 (release workflow publishes musl binaries)

## v0.2 — Post-launch

- [x] Record & replay: `snoop record -p PID -o trace.snoop`, `snoop view trace.snoop`
- [x] JSON output: `--json` (JSON Lines, pipe to jq)
- [x] sockaddr decode: connect/bind show `127.0.0.1:8080` instead of raw pointer
- [x] "Explain" mode: semantic grouping — `--explain` groups open/read/close, socket I/O, execve, fork into one-liner activities
- [x] Diff mode: `snoop diff a.snoop b.snoop`
- [x] Container / Kubernetes awareness (`--docker <name|id>`, `--pod <pod> [-n <namespace>]`)
- [x] uprobe-based library-call tracing (absorb ltrace) — `--ltrace` traces malloc/free/calloc/realloc
- [x] TLS decryption via uprobes on `SSL_write` / `SSL_read` — `--tls` captures plaintext inline
- [x] Kernel-side PID filtering — sys_enter drops non-target events before they reach the ring buffer
- [x] aarch64 CI job (cross-compile check + eBPF bpf{el,eb}-unknown-none jobs)

## v0.3 — Quality of life

- [x] Fix spawn-mode race: hold child with `ptrace(PTRACE_TRACEME)` until eBPF loads
- [x] Increase `PATH_MAX_LEN` 128 → 256 bytes (covers deep/long paths)
- [x] `--count` mode: per-syscall summary table on exit (like `strace -c`)
- [ ] Argument string truncation still occurs at 256 bytes for truly long paths
- [ ] execve argv / sendmsg iov: only first argument string is captured
- [ ] `--output-file`: tee raw/JSON output to a file while the TUI runs
