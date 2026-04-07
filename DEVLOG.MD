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
