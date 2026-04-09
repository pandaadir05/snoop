# DEVLOG

## 2026-04-09 — Polish pass: correctness fixes and new features

**What changed:**
- Fixed spawn-mode race condition (`snoop <cmd>`) via `ptrace(PTRACE_TRACEME)` in a pre-exec hook. The child now stops at exec entry; the parent loads eBPF while the child is frozen, then detaches ptrace. Every syscall from the very first `execve` is now captured.
- Increased `PATH_MAX_LEN` from 128 → 256 bytes. Paths in deep directory hierarchies or with long filenames were previously silently truncated.
- Added `--count` mode (like `strace -c`). Accumulates per-syscall count, error count, and timing stats across the whole trace; prints a sorted table on exit. Works for live traces and `snoop view`.
- CI fix: `cargo fmt` reformatting across 24 files; removed unneeded `return` and useless `Into` conversion in `cli.rs`; replaced explicit copy closures with `.copied()` in `diff.rs`.

**Decisions:**
- ptrace detach (`PTRACE_DETACH`) is used rather than `PTRACE_CONT` so no ptrace overhead remains after eBPF is loaded.
- `--count` does not show per-call output while running, matching `strace -c` behaviour; combine with filters (`--files`, `--slow`) to narrow the table.

## 2026-04-09 — Uprobe / TLS tracing + CLI wiring

**What changed:**
- Added `snoop-common/src/lib_event.rs`: `LibCallEvent` wire type (`#[repr(C)]`, 364 bytes) and `LibFunc` enum for identifying which library function fired.
- Added `snoop-ebpf/src/programs/uprobes.rs`: eight uprobe/uretprobe eBPF programs — `ssl_write_enter/exit`, `ssl_read_enter/exit` (TLS plaintext capture) and `ltrace_malloc/free/calloc/realloc` entry/return pairs. SSL data is read via a per-CPU scratch buffer (`TLS_BUF`) to stay within the 512-byte eBPF stack limit. ltrace programs encode the function discriminant in the high byte of the `LTRACE_ENTER` key to allow multiple functions on the same thread simultaneously.
- Extended `snoop-ebpf/src/maps.rs` with `LIB_EVENTS` ring buffer (2 MiB), `SSL_ENTER`/`LTRACE_ENTER` hash maps (scratch storage across enter/exit boundary), and `TLS_BUF` per-CPU array.
- Added `snoop/src/uprobe.rs`: `UprobeConfig` struct, `attach_uprobes()` which locates libssl/libc via `/proc/<pid>/maps` and attaches programs with aya, plus `find_library()` helper.
- Added `snoop/src/output/lib_call.rs`: `format_raw()` / `write_raw()` / `write_json()` for `LibCallEvent`; `tui_name()` returns bracketed names like `[SSL_write]` for TUI display.
- Extended `snoop/src/tracer.rs`: `take_lib_channel()` uses `ebpf.take_map("LIB_EVENTS")` (aya 0.13 owned `MapData`) to extract the ring buffer without lifetime ties to the `Ebpf` handle; `consume_lib_ring_buf()` forwards events over mpsc; `opt_recv()` helper parks forever via `std::future::pending()` when no lib channel exists, enabling clean optional `tokio::select!` branches; all `run_*` functions accept and drain the optional `lib_rx`.
- Extended `snoop/src/output/tui.rs`: added `TuiEvent` enum (Syscall/LibCall variants); TUI now drains `lib_rx` each tick and displays library calls inline in the stream with cyan coloring and `[func]` bracket notation; `--tls`/`--ltrace` entries appear in the top-syscalls panel.
- Added `--tls` and `--ltrace` flags to `snoop/src/cli.rs`; both build a `UprobeConfig` passed to `tracer::attach` / `tracer::spawn`.

**Decisions:**
- Separate `LIB_EVENTS` ring buffer (not merged with `EVENTS`) so high-frequency TLS or malloc traffic cannot starve syscall events.
- `Ebpf::take_map()` is the correct aya 0.13 API for extracting an owned ring buffer — avoids the borrow-tie problem that would prevent moving `ebpf` to `consume_ring_buf` while also having a `&mut` ring buffer.
- ltrace programs are separate eBPF programs per function (not a single generic program) because `bpf_get_attach_cookie` requires kernel 5.15+ and we target 5.8+.
- Detail popup in TUI is intentionally skipped for lib-call entries (they have no decoded args tree to display).

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

## 2026-04-08 — Explain mode

Added `--explain` / `snoop view --explain` flag that replaces per-syscall lines with
higher-level activity summaries.

**New files:**
- `snoop/src/explain.rs` — `Explainer` state machine:  tracks `(pid, fd)` → `OpenFile`
  and `(pid, fd)` → `Socket` maps.  On `close`, emits a one-line activity.  On `execve`/
  `fork`/`clone`, emits immediately.  `flush()` surfaces unclosed fds at end-of-trace.
  Open+close with zero bytes is silently suppressed to avoid noise.
- `snoop/src/output/explain.rs` — `ExplainOutput` wraps `Explainer`, applies the normal
  `Filter`, and writes formatted lines to stdout.

**Changed files:**
- `output/mod.rs` — new `OutputMode::Explain` variant.
- `cli.rs` — `--explain` flag on both trace mode and `snoop view`.  Conflicts with
  `--json` and `--raw`.
- `tracer.rs` — `run_explain` async function; dispatched from `run_output`.
- `viewer.rs` — synchronous explain path for recorded files.
- `main.rs` — registers the `explain` module.

**Decisions:**
- Explain mode is a *streaming post-processor*, not a separate pass; it works live and
  on recorded files identically.
- `dup`/`dup2`/`dup3` propagate state so bytes tracked on a duped fd are attributed to
  the original path / peer.
- Fds that had zero I/O are silently dropped (no "opened /proc/stat and closed it"
  noise).
- `flush()` at end-of-trace surfaces anything not explicitly closed (long-lived
  connections, piped fds, etc.).

**State:** `cargo build` ✓  `cargo test` ✓  (34 tests pass, 0 warnings)

## 2026-04-08 — Container / Kubernetes awareness

Added `--docker` and `--pod` target selectors so snoop can attach to containers
without manually looking up host PIDs.

**New file:**
- `snoop/src/container.rs` — two public functions:
  - `resolve_docker(name) -> Result<u32>` — runs `docker inspect --format={{.State.Pid}}`
    to get the container's root PID; falls back to a `/proc/<pid>/cgroup` scan when
    the Docker CLI is absent (containerd-only hosts, etc.).
  - `resolve_pod(pod, namespace) -> Result<u32>` — runs `kubectl get pod … -o jsonpath`
    to obtain the container ID, strips the runtime prefix (`docker://`, `containerd://`,
    `cri-o://`), then scans `/proc/*/cgroup` for the lowest-numbered matching PID.
    No `crictl` or runtime-specific CLI required.
  - `find_pid_by_cgroup(short_id)` — shared scanner; returns the root (lowest PID)
    process whose cgroup path contains the container ID.

**Changed files:**
- `cli.rs` — new `--docker <NAME|ID>`, `--pod <POD>`, `--namespace/-n <NS>` flags on
  both the default trace mode and the `Record` subcommand.  All three targets
  auto-enable `--follow`.  Conflicts enforced via clap `conflicts_with_all`.
  `Record`'s `ArgGroup` expanded to include `docker` and `pod`.
- `main.rs` — registers the `container` module.

**Decisions:**
- Both `--docker` and `--pod` hardcode `follow = true`: users targeting a container
  almost always want the entire process tree traced.
- The `/proc` cgroup scan uses the first 12 chars of the container ID (standard
  short-form) — unambiguous in practice and consistent with how runtimes write cgroup paths.
- `--namespace` defaults to `"default"` (the Kubernetes default) and is a no-op when
  `--pod` is not given (enforced by `requires = "pod"`).
- No runtime version detection: the cgroup scan works uniformly across Docker,
  containerd, and CRI-O without snoop needing to know which is in use.

**State:** `cargo build` ✓  `cargo test` ✓  (40 tests pass, 0 warnings)
