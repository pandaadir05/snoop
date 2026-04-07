# snoop

A modern syscall tracer for Linux. Think strace, but built on eBPF, with a
real TUI, smart filters, and argument decoding that humans actually want to read.

## Stack
- Language: Rust (stable, latest)
- eBPF: aya (pure Rust, no C toolchain)
- TUI: ratatui + crossterm
- CLI parsing: clap (derive)
- Async: tokio
- Target: Linux only (kernel 5.8+), x86_64 and aarch64

## Layout
Cargo workspace:
- `snoop`           — userspace binary (CLI + TUI)
- `snoop-ebpf`      — eBPF programs (no_std)
- `snoop-common`    — types shared between userspace and eBPF

## Engineering standards
- Rust 2021 edition. `#![deny(warnings)]` in CI, not in source.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass before every commit.
- No `unwrap()` or `expect()` in non-test code unless justified in a comment.
- Every public item in the userspace crate has a doc comment.
- Errors use `thiserror` for libraries, `anyhow` only at the binary boundary.
- Tests live next to the code (`#[cfg(test)] mod tests`) for unit tests,
  and in `tests/` for integration tests.
- No TODOs left in committed code. If something is deferred, it goes in
  `ROADMAP.md` as a tracked item.

## Git discipline
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
  `chore:`, `perf:`, `build:`, `ci:`. Scopes where useful, e.g. `feat(ebpf):`.
- Small, atomic commits. One logical change per commit.
- Commit messages: imperative mood, under 72 chars for the subject,
  body explains *why* not *what* when the diff isn't self-explanatory.
- Never commit broken code to main. Every commit must compile and pass tests.
- Never commit secrets, binaries, or editor cruft.

## Workflow expectations
- Before starting any task, read PLAN.md and the relevant section of ROADMAP.md.
- After finishing a task, append a short entry to DEVLOG.md with date, what
  changed, and any decisions made.
- Never make architectural changes without proposing them first.
- Never touch files outside the current task's scope without saying so.