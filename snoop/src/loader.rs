//! eBPF object loader (Linux only).
//!
//! Loads the compiled `snoop-ebpf` object, sets the PID filter, attaches the
//! tracepoints, and returns a handle to the loaded `Ebpf` instance along with
//! the ring-buffer `AsyncFd`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{TracePoint, ProgramError},
    Ebpf,
};

/// The eBPF object compiled at build time (embedded in the binary on Linux).
///
/// On Linux, `aya-build` compiles `snoop-ebpf` during `cargo build` and
/// places the object in `$OUT_DIR/snoop-ebpf`.  This static ensures the
/// object is always available without an external file dependency.
#[cfg(target_os = "linux")]
static SNOOP_EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoop-ebpf"));

/// Load the eBPF object and attach the tracepoints.
///
/// If `ebpf_obj` is `Some`, the object is read from that path instead of
/// using the embedded bytes (useful during development with `cargo xtask run`
/// before the embedded object has been rebuilt).
///
/// Sets `TARGET_PID[0] = pid_filter` before attaching so the eBPF programs
/// only forward events for the target process.  Pass `0` to trace all PIDs.
///
/// When `follow` is `true`, sets `FOLLOW_MODE[0] = 1` so that fork/clone
/// child PIDs are automatically added to `EXTRA_PIDS` at runtime.
pub fn load(pid_filter: u32, follow: bool, ebpf_obj: Option<PathBuf>) -> Result<Ebpf> {
    let mut ebpf = match ebpf_obj {
        Some(ref path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read eBPF object from `{}`", path.display()))?;
            Ebpf::load(&bytes).context("failed to load eBPF object from file")?
        }
        None => Ebpf::load(SNOOP_EBPF_BYTES).context("failed to load embedded eBPF object")?,
    };

    // Set the PID filter before attaching programs so there is no window
    // where unfiltered events could flood the ring buffer.
    if pid_filter != 0 {
        let mut target: Array<_, u32> = Array::try_from(
            ebpf.map_mut("TARGET_PID")
                .context("TARGET_PID map not found in eBPF object")?,
        )?;
        target.set(0, pid_filter, 0)?;
    }

    // Enable follow mode (child-process tracking via fork/clone).
    if follow {
        let mut follow_map: Array<_, u8> = Array::try_from(
            ebpf.map_mut("FOLLOW_MODE")
                .context("FOLLOW_MODE map not found in eBPF object")?,
        )?;
        follow_map.set(0, 1u8, 0)?;
    }

    // Attach sys_enter.
    attach_tracepoint(&mut ebpf, "sys_enter", "raw_syscalls", "sys_enter")?;

    // Attach sys_exit.
    attach_tracepoint(&mut ebpf, "sys_exit", "raw_syscalls", "sys_exit")?;

    Ok(ebpf)
}

/// Helper that loads a `TracePoint` program by name and attaches it.
fn attach_tracepoint(
    ebpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    tp_name: &str,
) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("program `{prog_name}` not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{prog_name}` is not a TracePoint"))?;

    prog.load().with_context(|| format!("failed to load `{prog_name}`"))?;

    prog.attach(category, tp_name)
        .map(|_link| ())
        .or_else(|e| match e {
            ProgramError::AlreadyAttached => Ok(()),
            other => Err(other),
        })
        .with_context(|| format!("failed to attach `{prog_name}` to {category}/{tp_name}"))?;

    Ok(())
}
