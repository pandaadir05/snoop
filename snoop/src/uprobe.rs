//! Uprobe configuration and library-path resolution.
//!
//! This module:
//! 1. Defines [`UprobeConfig`] — which sets of probes the user requested.
//! 2. Provides [`find_library`] — scans `/proc/<pid>/maps` to locate a shared
//!    library on disk so aya can attach the uprobe to the right ELF object.
//! 3. Provides [`attach_uprobes`] — attaches all requested probes to the loaded
//!    eBPF object.
//!
//! # Library detection
//!
//! `/proc/<pid>/maps` lines look like:
//! ```text
//! 7f1a2b3c4000-7f1a2b3d0000 r-xp 00000000 fd:01 123456  /usr/lib/libssl.so.3
//! ```
//! We match on the last field (pathname) using a case-insensitive substring
//! match so `"libssl"` finds both `libssl.so.3` and `libssl.so.1.1`.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aya::{programs::UProbe, Ebpf};

// ── public config type ────────────────────────────────────────────────────────

/// Which uprobe feature sets to enable.
#[derive(Debug, Clone, Default)]
pub struct UprobeConfig {
    /// Attach to `SSL_write` / `SSL_read` in libssl (TLS plaintext capture).
    pub tls: bool,
    /// Attach to `malloc` / `free` / `calloc` / `realloc` in libc (ltrace mode).
    pub ltrace: bool,
}

impl UprobeConfig {
    /// Returns `true` if at least one feature is enabled.
    pub fn any_enabled(&self) -> bool {
        self.tls || self.ltrace
    }
}

// ── attachment ────────────────────────────────────────────────────────────────

/// Attach all uprobes requested by `config` to the already-loaded `ebpf` object.
///
/// `pid` is used only to locate the correct shared library via `/proc/<pid>/maps`.
/// The eBPF programs themselves use `TARGET_PID` / `EXTRA_PIDS` for event
/// filtering, so passing `pid = None` here attaches system-wide (all processes
/// calling the function trigger the probe; only the target's events reach
/// userspace).  Passing `Some(pid)` restricts the kernel-side hook to that
/// one process, which is more efficient but misses children added by follow mode.
///
/// We always pass `None` here so that follow-mode container children are traced.
pub fn attach_uprobes(ebpf: &mut Ebpf, config: &UprobeConfig, pid: u32) -> Result<()> {
    if config.tls {
        let libssl = find_library(pid, "libssl")
            .or_else(|_| find_library(pid, "libcrypto"))
            .context(
                "could not find libssl or libcrypto in the target process.\n\
                 Make sure the process uses OpenSSL (check with: ldd /proc/<pid>/exe)",
            )?;

        attach_uprobe(ebpf, "ssl_write_enter", &libssl, "SSL_write")?;
        attach_uretprobe(ebpf, "ssl_write_exit", &libssl, "SSL_write")?;
        attach_uprobe(ebpf, "ssl_read_enter", &libssl, "SSL_read")?;
        attach_uretprobe(ebpf, "ssl_read_exit", &libssl, "SSL_read")?;
    }

    if config.ltrace {
        let libc = find_library(pid, "libc").context(
            "could not find libc in the target process.\n\
                 Statically linked binaries do not support ltrace mode.",
        )?;

        for func in &["malloc", "free", "calloc", "realloc"] {
            let enter_prog = format!("ltrace_{func}");
            let exit_prog = format!("ltrace_{func}_ret");
            attach_uprobe(ebpf, &enter_prog, &libc, func)?;
            attach_uretprobe(ebpf, &exit_prog, &libc, func)?;
        }
    }

    Ok(())
}

// ── library path resolution ───────────────────────────────────────────────────

/// Find the on-disk path of a shared library loaded by process `pid`.
///
/// `name_pattern` is matched as a case-insensitive substring of the
/// library's path in `/proc/<pid>/maps`.  The first match is returned.
///
/// Example: `find_library(1234, "libssl")` might return
/// `/usr/lib/x86_64-linux-gnu/libssl.so.3`.
pub fn find_library(pid: u32, name_pattern: &str) -> Result<PathBuf> {
    let maps_path = format!("/proc/{pid}/maps");
    let contents = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("could not read {maps_path}"))?;

    let pattern_lower = name_pattern.to_lowercase();

    for line in contents.lines() {
        // maps format: addr-addr perms offset dev inode pathname
        let Some(path_part) = line.split_whitespace().next_back() else {
            continue;
        };

        if !path_part.starts_with('/') {
            // Skip anonymous, stack, heap, vdso, etc.
            continue;
        }

        if path_part.to_lowercase().contains(&pattern_lower) {
            let path = PathBuf::from(path_part);
            // Return the first real file found.
            if path.exists() {
                return Ok(path);
            }
        }
    }

    bail!("library matching {name_pattern:?} not found in /proc/{pid}/maps")
}

// ── aya helpers ───────────────────────────────────────────────────────────────

/// Load and attach a `UProbe` (function entry) program.
fn attach_uprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    lib_path: &PathBuf,
    fn_name: &str,
) -> Result<()> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("uprobe program `{prog_name}` not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{prog_name}` is not a UProbe"))?;

    prog.load()
        .with_context(|| format!("failed to load uprobe `{prog_name}`"))?;

    prog.attach(Some(fn_name), 0, lib_path, None)
        .with_context(|| {
            format!(
                "failed to attach uprobe `{prog_name}` to `{fn_name}` in {}",
                lib_path.display()
            )
        })?;

    Ok(())
}

/// Load and attach a `URetProbe` (function return) program.
///
/// In aya, uretprobes use the same `UProbe` type with `offset = 0`; the
/// distinction is made via the `#[uretprobe]` attribute in the eBPF program.
fn attach_uretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    lib_path: &PathBuf,
    fn_name: &str,
) -> Result<()> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("uretprobe program `{prog_name}` not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{prog_name}` is not a UProbe"))?;

    prog.load()
        .with_context(|| format!("failed to load uretprobe `{prog_name}`"))?;

    // Offset of 0 combined with a function name tells aya to attach at the
    // function's return sites (uretprobe semantics).
    prog.attach(Some(fn_name), 0, lib_path, None)
        .with_context(|| {
            format!(
                "failed to attach uretprobe `{prog_name}` to `{fn_name}` in {}",
                lib_path.display()
            )
        })?;

    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uprobe_config_any_enabled() {
        assert!(!UprobeConfig::default().any_enabled());
        assert!(UprobeConfig {
            tls: true,
            ltrace: false
        }
        .any_enabled());
        assert!(UprobeConfig {
            tls: false,
            ltrace: true
        }
        .any_enabled());
    }

    /// Smoke-test the maps parser against a synthetic /proc/pid/maps snippet.
    #[test]
    fn find_library_parses_maps() {
        // We can't call find_library() for a real PID in unit tests, but we can
        // test the line-parsing logic by verifying the pattern matching would work
        // on a representative line.
        let line = "7f1a2b3c4000-7f1a2b3d0000 r-xp 00000000 fd:01 123456  /usr/lib/libssl.so.3";
        let path_part = line.split_whitespace().next_back().unwrap();
        assert!(path_part.to_lowercase().contains("libssl"));
    }
}
