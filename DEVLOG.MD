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
