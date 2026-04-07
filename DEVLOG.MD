# DEVLOG

## 2026-04-07 — Scaffolding session

**What changed:**
- Initialized git repository (`main` branch) with a Rust workspace `.gitignore`
- Created Cargo workspace with three members:
  - `snoop` — userspace binary (stable, `std`)
  - `snoop-common` — shared types library (`no_std`-compatible, usable from both userspace and eBPF)
  - `snoop-ebpf` — eBPF programs library (`no_std`; scaffold only, real programs added later)
- Pinned root toolchain to stable via `rust-toolchain.toml` (components: rustfmt, clippy, rust-src, linux targets)
- Added `snoop-ebpf/rust-toolchain.toml` pointing to nightly with `bpfel-unknown-none` / `bpfeb-unknown-none` targets — used for the dedicated BPF build step, not the workspace build
- Added `rustfmt.toml` (100-char width, 2021 edition, grouped imports) and `clippy.toml` (MSRV hint)
- Added `.github/workflows/ci.yml`: fmt check, clippy -D warnings, and test on ubuntu-latest; `snoop-ebpf` excluded from CI for now (needs BPF target + nightly, will get its own job when real programs land)
- Added `README.md` (name, one-liner, pre-alpha status), `LICENSE-MIT`, `LICENSE-APACHE`

**Decisions:**
- `snoop-ebpf` is a workspace member (IDE + type resolution), but the scaffold is an empty `no_std` lib so `cargo build` and `cargo test` pass cleanly on the host. The `aya-ebpf` crate is intentionally deferred — it requires a BPF target and would break the workspace build.
- `[profile.release]` lives in the workspace root `Cargo.toml`; Cargo ignores it on non-root packages and emits a warning otherwise.
- `//!` inner doc comments used in lib.rs files (not `///`) so `#![no_std]` can remain the first attribute.

**State:** `cargo build` ✓  `cargo test` ✓  (all 3 crates, 0 tests, all pass)

---

## 2026-04-07 — Core implementation session

**What changed:**

*snoop-common*
- `SyscallEvent` (`repr(C)`, `Copy`) — the complete record sent from eBPF to
  userspace via the ring buffer.
- `SyscallEnterData` (`repr(C)`, `Copy`) — scratch struct stored in the eBPF
  hash map between `sys_enter` and `sys_exit`.
- `SyscallNr(i64)` newtype with ~90 named x86_64 syscall constants.

*snoop-ebpf* (compiled for `bpfel-unknown-none`; gated on `cfg(target_arch = "bpf")`)
- `EVENTS` ring buffer (4 MiB), `SYSCALL_ENTER` hash map (8 192 slots),
  `TARGET_PID` array for kernel-side PID filtering.
- `sys_enter` tracepoint: records entry data into `SYSCALL_ENTER`.
- `sys_exit` tracepoint: retrieves entry data, appends return value and
  exit timestamp, submits a complete `SyscallEvent` to `EVENTS`.

*xtask*
- `cargo xtask build-ebpf [--release]` — invokes cargo +nightly for bpfel target.
- `cargo xtask run [-- args]` — builds eBPF then runs snoop, passing
  `SNOOP_EBPF_OBJ` so the loader uses the freshly built object.

*snoop userspace*
- `build.rs`: calls `aya_build::build_ebpf` on Linux to embed the BPF object;
  no-op on other hosts so macOS developers can type-check without bpf-linker.
- CLI (clap derive): `--pid`, spawn mode, `--follow`, `--raw`, `--files`,
  `--net`, `--slow`, `--syscall`, `--no-decode`, `--ebpf-obj`.
- `Filter`: userspace predicate; 10 unit tests.
- `decode::syscall_name`: ~90 syscall numbers → names.
- `decode::decode_args`: argument formatters for ~45 syscalls (open flags,
  prot/mmap flags, socket domain/type, futex ops, clone flags, etc.).
- `output::RawOutput`: strace-compatible one-line format with elapsed time,
  comm, pid/tid, decoded args, return value, and duration.
- `output::TuiApp`: full ratatui screen — scrollable stream panel with
  per-category colour coding (FS=green, net=blue, proc=magenta, mem=yellow),
  top-syscalls table (count + %), header bar, footer with keybindings,
  pause/resume (`Space`), incremental search (`/`), category filters (`f`/`n`).
- `loader.rs` (Linux only): loads embedded or file-based eBPF object, sets
  `TARGET_PID`, attaches both tracepoints.
- `tracer.rs` (Linux only): spawn mode (fork/exec then attach), attach mode
  (verify PID, load, watch for process exit), async ring-buffer consumer
  forwarding events over `mpsc` to the output layer.

**Decisions:**
- `aya_build::build_ebpf` (not `build()`) is the correct API for aya-build 0.1.3.
- All Linux-specific code is gated on `cfg(target_os = "linux")`; a crate-level
  `cfg_attr(not(linux), allow(dead_code, unused_imports))` suppresses the noise
  on macOS builds.
- `decode::names` uses `match nr.0 { ... }` on the raw i64 rather than
  associated-constant patterns to avoid any structural-equality subtleties.
- eBPF crate dependencies (`aya-ebpf`, `aya-log-ebpf`) live under
  `[target.'cfg(target_arch = "bpf")'.dependencies]` so the workspace host
  build never pulls them in.

**State:** `cargo build` ✓  `cargo test` ✓  (10 tests pass, 0 warnings)

---

## 2026-04-08 — Path capture, flamegraph export, git SHA

**What changed:**

*snoop-common*
- `SyscallEvent` extended with `path: [u8; 128]`, `path_len: u16`, `_pad: [u8; 6]`
  (struct remains `repr(C)`, total size ~248 bytes — within ring buffer limits).
- `PATH_MAX_LEN = 128` exported from the crate.
- `SyscallEvent::path_str()` returns `Option<&str>` by stripping the null terminator.

*snoop-ebpf*
- `PATH_BUF: PerCpuArray<[u8; PATH_MAX_LEN]>` added as a per-CPU scratch buffer
  so path reads never consume the 512-byte BPF stack.
- `sys_exit` rewritten to use `EVENTS.reserve::<SyscallEvent>(0)` (ring buffer
  memory, not stack) and write fields via `core::ptr::addr_of_mut!`.
- `capture_path_arg()` reads the first string argument for ~20 syscall families
  via `bpf_probe_read_user_str_bytes`, copying into the ring buffer event field
  through the per-CPU scratch buffer.

*snoop userspace*
- `decode::decode_args` now accepts `path: Option<&str>`; `path_or_ptr()` helper
  shows the captured string (quoted) or falls back to the raw pointer hex.
- `fmt_open`, `fmt_openat`, `fmt_stat`, `fmt_fstatat`, `fmt_statx`, `fmt_execve`,
  `fmt_execveat`, `fmt_chdir`, `fmt_mkdir`, `fmt_unlink`, `fmt_rename` all use it.
- `snoop/src/flamegraph.rs` — new `FlamegraphCollector` that accumulates folded
  stack entries (`comm;syscall_name duration_ns`) and renders an SVG via `inferno`.
- `--flamegraph <PATH>` CLI flag writes the SVG on exit; works with both raw and
  TUI modes; flamegraph data is collected before display filters so the SVG covers
  the full trace.
- `build.rs` now runs `git rev-parse --short HEAD` and emits `GIT_SHA` so
  `--version` displays `0.1.0 (abc1234)`.

**Decisions:**
- `EVENTS.reserve()` (ring buffer allocation) is used instead of constructing
  a `SyscallEvent` on the BPF stack, which would overflow the 512-byte limit
  given the 128-byte path field.
- `inferno` is added with `default-features = false` — the CLI and multithreaded
  features are unnecessary for a single SVG write at trace exit.
- Flamegraph collection in TUI mode is gated on `FlamegraphCollector::new()` only
  when `--flamegraph` is provided, adding zero overhead otherwise.
- `GIT_SHA` falls back to `"unknown"` for tarball builds lacking `.git/`.

**State:** `cargo build` ✓  `cargo test` ✓  (10 tests pass, 0 warnings)

---

## 2026-04-08 — "Make it the best" session

**What changed:**

*README overhaul*
- Complete rewrite: ASCII demo output, feature matrix, install instructions,
  all CLI flags, TUI keybindings table, architecture diagram, contributing guide.

*Release workflow*
- `.github/workflows/release.yml`: builds static musl binaries for x86_64 and
  aarch64 on `v*` tags, publishes to GitHub Releases with SHA-256 checksums.
  Uses `bpf-linker` + `cargo xtask build-ebpf` for the eBPF compile step.

*sockaddr capture (connect/bind show IP:port)*
- `SyscallEvent` gains `sockaddr: [u8; 28]` + `sockaddr_len: u8` fields.
- `sys_exit` reads the sockaddr pointer via `bpf_probe_read_user_bytes` into a
  `SOCKADDR_BUF: PerCpuArray` scratch buffer, copies into ring buffer event.
- `format_sockaddr()` decodes AF_INET→`127.0.0.1:8080`, AF_INET6→`[::1]:443`,
  AF_UNIX→`"/var/run/docker.sock"`, unknown→hex pointer.
- 11 new unit tests for sockaddr decode and common flag formatters.

*JSON Lines output (--json)*
- `OutputMode::Json` added; `JsonOutput` writes one compact JSON object per
  syscall (ts_ns, pid, tid, uid, gid, comm, syscall, args, ret, duration_ns).
  Manual serialisation — no serde dependency.  3 unit tests.

*Record & replay (snoop record / snoop view)*
- Binary `.snoop` format: 16-byte header (magic + version) + length-prefixed
  `SyscallEvent` frames.  Version field guards against struct layout changes.
- `TraceWriter` / `TraceReader` with round-trip and bad-magic tests.
- `snoop record -p PID -o trace.snoop` and spawn mode.
- `snoop view trace.snoop [filters]` — no root needed, all output modes work
  including TUI (events replayed over mpsc channel).
- CLI restructured to use clap `Subcommand` for `record` and `view`; default
  (no subcommand) preserves the existing `snoop -p PID` / `snoop <cmd>` syntax.

**Decisions:**
- sockaddr capped at 28 bytes (IPv6 sockaddr_in6 size); enough for all common
  address families without bloating SyscallEvent further.
- JSON serialised manually to avoid pulling serde into a binary that has no
  other use for it; the format is simple enough.
- Trace file uses raw SyscallEvent bytes (no compression); acceptable for
  analysis traces — 1 M events ≈ 280 MiB.  Compression is a v0.3 item.
- `snoop view` in TUI mode feeds events through an mpsc channel so TuiApp is
  reused unchanged; a `done` signal fires immediately after all events are queued.

**State:** `cargo build` ✓  `cargo test` ✓  (26 tests pass, 0 warnings)

---

## 2026-04-08 — Follow mode and complete syscall decoder coverage

**What changed:**

*snoop-ebpf*
- Added `FOLLOW_MODE: Array<u8>` — single-element flag set by userspace when `--follow` is active.
- Added `EXTRA_PIDS: HashMap<u32, u8>` — runtime set of child PIDs to trace.
- `sys_enter` now allows a process if `pid == TARGET_PID` OR `pid ∈ EXTRA_PIDS`.
- `sys_exit` inserts the return value of fork/vfork/clone/clone3 into `EXTRA_PIDS`
  when `FOLLOW_MODE == 1` and `ret > 0` (parent side of the fork).

*snoop userspace*
- `loader::load()` gains a `follow: bool` parameter; sets `FOLLOW_MODE[0] = 1` before
  attaching tracepoints.
- Spawn mode always enables follow (the entire command tree is the trace target).
- Attach mode honours the `--follow` CLI flag.

*syscall decoder*
- Added decoders for all remaining ROADMAP syscalls: fork/vfork (no args),
  getpid family (no args), ftruncate, truncate, fsync/fdatasync, madvise,
  sendmsg/recvmsg/sendmmsg/recvmmsg, socketpair, sendfile, splice, memfd_create,
  getdents64, readv/writev, mremap, msync, prlimit64, nanosleep.
- Fixed `fchdir`: was incorrectly using the path decoder (takes an fd, not a pointer).
- Added 17 new `SyscallNr` constants.

**Decisions:**
- `EXTRA_PIDS` is a `HashMap<u32, u8>` used as a hash set (value always 1).
  Max 1 024 entries — sufficient for typical process trees; expand in v0.2 if needed.
- Spawn mode unconditionally enables follow mode. A spawned command's children
  are logically part of the trace and excluding them would surprise users.
- `maybe_follow_child()` is `#[inline(always)]` and has an early return when
  `FOLLOW_MODE == 0`, so the cost in the common case is one map lookup and branch.

**State:** `cargo build` ✓  `cargo test` ✓  (10 tests pass, 0 warnings)
