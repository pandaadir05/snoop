# snoop

A syscall tracer for Linux built on eBPF. Think strace, but with a live TUI,
smart filters, human-readable argument decoding, and output that doesn't make
you want to reach for awk.

```
$ sudo snoop curl https://example.com
[   0.001] curl(1234/1234)  openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 4  <0.031ms>
[   0.002] curl(1234/1234)  read(4, 0x7f3a1c000b20, 4096) = 4096  <0.012ms>
[   0.003] curl(1234/1234)  socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5  <0.008ms>
[   0.004] curl(1234/1234)  connect(5, 93.184.216.34:443) = 0  <42.187ms>
[   0.046] curl(1234/1234)  sendto(5, 0x55a3bc001b40, 78, MSG_NOSIGNAL) = 78  <0.011ms>
```

Or drop into the full-screen TUI and watch everything live:

```
 snoop  pid:1234  comm:curl  events:142  elapsed:0.341s
┌── syscall stream ─────────────────────────────────────┐┌── top syscalls ─────────┐
│ [  0.001] curl  openat("/etc/ssl/…") = 4  <0.031ms>  ││ syscall       count  pct│
│ [  0.002] curl  read(4, …) = 4096                    ││ read            38  26.8%│
│ [  0.003] curl  socket(AF_INET, …) = 5               ││ write           21  14.8%│
│ [  0.004] curl  connect(5, 93.184.216.34:443) = 0    ││ openat          18  12.7%│
│ [  0.046] curl  sendto(5, …) = 78                    ││ mmap            14   9.9%│
└───────────────────────────────────────────────────────┘└─────────────────────────┘
 [q]uit  [Space]pause  [/]search  [f]iles  [n]et  [c]lear  [↑↓]scroll  [G]bottom
```

## Why snoop

strace works, but it was designed for a different era. snoop is built on eBPF,
which means kernel-level tracing with negligible overhead — no ptrace, no
stopping your process, no signal noise. Arguments are decoded into readable
strings rather than raw hex. The TUI updates in real time, filters apply
instantly, and the whole trace can be saved to disk and replayed later without
root.

## Features

- Live full-screen TUI with a real-time top-syscalls panel
- strace-compatible single-line output (`--raw`) for piping
- JSON Lines output (`--json`) for `jq` and log ingestion
- Explain mode (`--explain`) — groups syscalls into semantic activity summaries
- Filter by category: `--files`, `--net`
- Filter by latency: `--slow 10` (only calls over 10 ms)
- Filter by name: `--syscall openat --syscall read`
- Argument decoding for 60+ syscalls — paths, flags, socket addresses
- Attach to a running process (`-p PID`) or spawn a new one (`snoop <cmd>`)
- Follow forked children with `--follow`
- Container-aware: `--docker <name>` and `--pod <name>` target all processes
  inside a container without knowing their PIDs
- TLS plaintext capture via uprobes on `SSL_write` / `SSL_read` (`--tls`)
- Heap allocation tracing (`--ltrace`) — `malloc` / `free` / `calloc` / `realloc`
- Record a trace to disk (`snoop record`) and replay it later (`snoop view`)
- Compare two trace files (`snoop diff`) to spot performance regressions
- Flamegraph SVG export (`--flamegraph out.svg`)
- No kernel modules, no C toolchain — the eBPF programs are pure Rust (aya)
  and are embedded in the binary at build time

## Requirements

- Linux kernel 5.8 or later (BPF ring buffer support)
- `x86_64` or `aarch64`
- Root or `CAP_BPF` + `CAP_PERFMON`

## Installation

### Pre-built binary

```bash
curl -L https://github.com/pandaadir05/snoop/releases/latest/download/snoop-x86_64-linux.tar.gz \
  | tar -xz
sudo install -m755 snoop /usr/local/bin/snoop
```

For aarch64, replace `x86_64` with `aarch64`.

### From source

```bash
# Requires Rust stable (userspace) + Rust nightly (eBPF target)
cargo install --git https://github.com/pandaadir05/snoop snoop
```

The build script compiles the eBPF programs automatically — no C toolchain or
kernel headers needed.

## Usage

### Spawn and trace a command

```bash
sudo snoop ls /etc
sudo snoop -- nginx -g 'daemon off;'
```

### Attach to a running process

```bash
sudo snoop -p $(pidof postgres)
sudo snoop -p 1234 --follow        # also trace forked children
```

### Trace a Docker container

```bash
sudo snoop --docker my-nginx       # container name or ID
sudo snoop --docker abc123def456
```

### Trace a Kubernetes pod

```bash
sudo snoop --pod my-app-pod
sudo snoop --pod my-app-pod --namespace production
```

### Filter the output

```bash
# File-system syscalls only
sudo snoop -p 1234 --files

# Network syscalls only
sudo snoop -p 1234 --net

# Calls slower than 5 ms
sudo snoop -p 1234 --slow 5

# Only openat and read
sudo snoop -p 1234 --syscall openat --syscall read
```

### Explain mode — semantic summaries

Instead of one line per syscall, `--explain` groups activity into readable
summaries:

```bash
sudo snoop -p 1234 --explain
```

```
READ   /etc/passwd          ↓1.2 KB   (2 calls, 0.80ms)
NET    127.0.0.1:5432       ↑512 B ↓4.0 KB   (18.20ms)
EXEC   /usr/bin/python3
```

### TLS decryption

```bash
# Capture SSL_write / SSL_read plaintext (requires OpenSSL in the target)
sudo snoop -p 1234 --tls
```

### Heap allocation tracing

```bash
sudo snoop -p 1234 --ltrace
```

### Record and replay

```bash
# Record to a file (requires root)
sudo snoop record -p 1234 -o trace.snoop

# Replay later — no root needed
snoop view trace.snoop
snoop view trace.snoop --files --slow 5 --json | jq 'select(.name=="read")'
```

### Compare two traces

```bash
sudo snoop record -p 1234 -o before.snoop
# ... deploy change ...
sudo snoop record -p 1234 -o after.snoop

snoop diff before.snoop after.snoop
```

```
SYSCALL COUNTS
  read      1200 → 1800  (+50.0%)  ▲
  openat     340 →  210  (-38.2%)  ▼

DURATION REGRESSIONS (median)
  read      0.02ms → 0.08ms  (+300%)

ONLY IN after
  statx (4x)
```

### JSON output

```bash
sudo snoop -p 1234 --json | jq 'select(.name == "connect")'
```

### Export a flamegraph

```bash
sudo snoop -p 1234 --flamegraph syscalls.svg
xdg-open syscalls.svg
```

## All flags

```
  -p, --pid <PID>           Attach to a running process
      --follow              Trace forked children (requires --pid)
      --docker <NAME|ID>    Trace all processes in a Docker container
      --pod <POD>           Trace all processes in a Kubernetes pod
  -n, --namespace <NS>      Kubernetes namespace (default: default)

      --raw                 One-line strace-compatible output
      --json                JSON Lines — one object per syscall
      --explain             Semantic activity summaries

      --files               File-system syscalls only
      --net                 Network syscalls only
      --slow <MILLIS>       Only calls slower than threshold
      --syscall <NAME>      Only this syscall (repeatable)
      --no-decode           Raw hex arguments, no decoding

      --tls                 Capture TLS plaintext via SSL_write/SSL_read uprobes
      --ltrace              Trace malloc/free/calloc/realloc

      --flamegraph <PATH>   Write flamegraph SVG on exit
      --ebpf-obj <PATH>     Override embedded eBPF object [$SNOOP_EBPF_OBJ]
```

## TUI keybindings

| Key | Action |
|---|---|
| `q` | Quit |
| `Space` | Pause / resume |
| `/` | Incremental search |
| `f` | Toggle file-system filter |
| `n` | Toggle network filter |
| `c` | Clear event list |
| `Enter` | Show detail popup for selected event |
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `G` / `End` | Jump to latest event |
| `g` / `Home` | Jump to oldest event |

## How it works

snoop attaches eBPF programs to the `raw_syscalls/sys_enter` and
`raw_syscalls/sys_exit` tracepoints. On entry it records the syscall number
and arguments into a per-thread scratch map; on exit it reads the return value,
pairs it with the entry data, and writes a complete event to a ring buffer. The
userspace daemon reads from the ring buffer via an async file descriptor and
pushes events through the filter and decode pipeline before rendering them.

```
kernel                               userspace
──────                               ─────────
raw_syscalls/sys_enter  ──►  SYSCALL_ENTER map (per-tid scratch)
raw_syscalls/sys_exit   ──►  EVENTS ring buffer (4 MiB)
                                  │
                             AsyncFd reader (tokio)
                                  │
                       ┌──────────┴──────────┐
                   RawOutput             TuiApp
                 (one line/syscall)   (ratatui TUI)
```

The eBPF programs are written in Rust using [aya](https://github.com/aya-rs/aya)
and compiled to BPF bytecode at build time. The resulting object is embedded
directly in the snoop binary, so there are no runtime file dependencies and no
kernel headers required.

## Building from source

```bash
# Clone the repo
git clone https://github.com/pandaadir05/snoop
cd snoop

# Install Rust nightly (needed for the BPF target only)
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker (links the eBPF object — no LLVM installation needed)
cargo install bpf-linker --no-default-features

# Build eBPF programs
cargo xtask build-ebpf

# Build the userspace binary
cargo build --release

# Run
sudo ./target/release/snoop -p $$
```

For development there is a shortcut that builds the eBPF programs and runs
snoop in one step:

```bash
cargo xtask run -- -p $$
```

Formatting and linting:

```bash
cargo fmt --all
cargo clippy --workspace --exclude snoop-ebpf -- -D warnings
cargo test --workspace --exclude snoop-ebpf
```

## Stack

| Layer | Crate |
|---|---|
| eBPF programs | `aya-ebpf` |
| eBPF loader | `aya` |
| TUI | `ratatui` + `crossterm` |
| CLI | `clap` (derive) |
| Async runtime | `tokio` |
| Flamegraph | `inferno` |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
