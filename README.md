# snoop

A modern syscall tracer for Linux.

Think `strace`, but built on eBPF — no ptrace overhead, a real TUI, smart
per-category filters, and argument decoding that looks like C source instead
of raw hex.

```
$ sudo snoop curl https://example.com
[  0.001] curl(123456/123456)  openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 4 <0.031ms>
[  0.002] curl(123456/123456)  read(4, 0x7f3a1c000b20, 4096) = 4096 <0.012ms>
[  0.003] curl(123456/123456)  socket(AF_INET, SOCK_STREAM, 0) = 5 <0.008ms>
[  0.004] curl(123456/123456)  connect(5, 0x7ffd2e1c3490, 16) = 0 <42.187ms>
[  0.046] curl(123456/123456)  sendto(5, 0x55a3bc001b40, 78, 0x0, NULL, 0) = 78 <0.011ms>
```

Or drop into the full TUI:

```
 snoop  pid:123456  comm:curl  events:142  elapsed:0.341s
┌── syscall stream ────────────────────────────────┐┌── top syscalls ────────┐
│ [  0.001] curl         openat(…) = 4  <0.031ms> ││ syscall      count  pct│
│ [  0.002] curl         read(4, …) = 4096         ││ read           38 26.8%│
│ [  0.003] curl         socket(AF_INET, …) = 5    ││ write          21 14.8%│
│ [  0.004] curl         connect(5, …) = 0         ││ openat         18 12.7%│
│ [  0.046] curl         sendto(5, …) = 78         ││ mmap           14  9.9%│
└──────────────────────────────────────────────────┘└────────────────────────┘
 [q]uit  [Space]pause  [/]search  [f]iles  [n]et  [c]lear  [↑↓]scroll  [G]bottom
```

## Features

| Feature | Status |
|---|---|
| eBPF tracing (no ptrace, no overhead) | |
| Spawn mode — `snoop <cmd>` | |
| Attach mode — `snoop -p <pid>` | |
| Follow children — `--follow` | |
| Full-screen TUI with live top-syscalls | |
| strace-compatible raw output | |
| File-system filter (`--files`) | |
| Network filter (`--net`) | |
| Slow-syscall filter (`--slow <ms>`) | |
| Named-syscall filter (`--syscall openat`) | |
| Argument decoding for 60+ syscalls | |
| Path strings in openat/execve/stat/… | |
| Flamegraph SVG export (`--flamegraph`) | |
| Git SHA in `--version` | |
| Record & replay (`snoop record` / `snoop view`) | |
| JSON output (`--json`) | |

## Requirements

- Linux kernel **5.8+** (BPF ring buffer)
- `x86_64` or `aarch64`
- Root or `CAP_BPF` + `CAP_PERFMON`

## Installation

### Pre-built binary

```bash
# Replace X.Y.Z with the latest release tag
curl -L https://github.com/pandaadir05/snoop/releases/latest/download/snoop-x86_64-linux.tar.gz \
  | tar -xz
sudo install -m755 snoop /usr/local/bin/snoop
```

### From source

```bash
# Requires Rust stable + nightly (for the BPF target)
cargo install --git https://github.com/pandaadir05/snoop snoop
```

> The build script compiles the eBPF programs automatically using
> `cargo +nightly build` for `bpfel-unknown-none` — no C toolchain needed.

## Usage

```
snoop [OPTIONS] <-p PID | CMD [ARGS]>
```

### Spawn and trace a command

```bash
sudo snoop ls /etc
sudo snoop -- nginx -g 'daemon off;'
```

### Attach to a running process

```bash
sudo snoop -p $(pidof nginx)
sudo snoop -p 1234 --follow   # also trace children
```

### Filter output

```bash
# Only file-system syscalls
sudo snoop -p 1234 --files

# Only network syscalls
sudo snoop -p 1234 --net

# Only syscalls slower than 10 ms
sudo snoop -p 1234 --slow 10

# Only openat and read
sudo snoop -p 1234 --syscall openat --syscall read
```

### Export a flamegraph

```bash
sudo snoop -p 1234 --flamegraph out.svg
# Opens in browser:
xdg-open out.svg
```

### Record and replay

```bash
# Record to a file
sudo snoop record -p 1234 -o trace.snoop

# Inspect later (no root needed)
snoop view trace.snoop
snoop view trace.snoop --files --slow 5
```

### Raw / pipe-friendly output

```bash
# Force single-line output (auto-selected when stdout is not a TTY)
sudo snoop -p 1234 --raw

# JSON — one object per line
sudo snoop -p 1234 --json | jq 'select(.name == "openat")'
```

### All flags

```
  -p, --pid <PID>           Attach to an existing process
      --follow              Also trace children (clone/fork)
      --raw                 One-line strace-compatible output
      --json                JSON output (one object per syscall)
      --files               Only file-system syscalls
      --net                 Only network syscalls
      --slow <MILLIS>       Only syscalls slower than threshold
      --syscall <NAME>      Only this syscall (repeatable)
      --no-decode           Show raw hex arguments
      --flamegraph <PATH>   Write SVG flamegraph on exit
      --record <PATH>       Record trace to file
      --ebpf-obj <PATH>     Override embedded eBPF object [$SNOOP_EBPF_OBJ]
```

## TUI keybindings

| Key | Action |
|---|---|
| `q` | Quit |
| `Space` | Pause / resume stream |
| `/` | Incremental syscall search |
| `f` | Toggle file-system filter |
| `n` | Toggle network filter |
| `c` | Clear event list |
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `G` / `End` | Jump to latest event |
| `g` / `Home` | Jump to oldest event |

## Architecture

```
  kernel                        userspace
  ──────                        ─────────
  raw_syscalls/sys_enter  ──►  SYSCALL_ENTER map (per-tid scratch)
  raw_syscalls/sys_exit   ──►  EVENTS ring buffer (4 MiB)
                                    │
                               AsyncFd consumer (tokio)
                                    │
                         ┌──────────┴──────────┐
                     RawOutput             TuiApp
                   (one line/syscall)   (ratatui TUI)
```

eBPF programs are compiled from pure Rust (`aya`) — no C toolchain, no
kernel headers.  The compiled object is embedded in the binary at build
time so there is no runtime file dependency.

## Stack

| Layer | Crate |
|---|---|
| eBPF | `aya-ebpf` |
| Userspace eBPF loader | `aya` |
| TUI | `ratatui` + `crossterm` |
| CLI | `clap` (derive) |
| Async runtime | `tokio` |
| Flamegraph | `inferno` |

## Contributing

```bash
# Build everything (eBPF + userspace) on Linux:
cargo xtask build-ebpf
cargo build

# Run and format checks:
cargo fmt --all
cargo clippy --workspace --exclude snoop-ebpf -- -D warnings
cargo test --workspace --exclude snoop-ebpf

# Run snoop itself (builds eBPF first):
cargo xtask run -- -p $$
```

See [ROADMAP.MD](ROADMAP.MD) for planned features and [DEVLOG.MD](DEVLOG.MD)
for the development history.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
