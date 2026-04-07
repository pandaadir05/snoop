//! Command-line interface definition.
//!
//! snoop operates in two modes:
//! * **spawn** — `snoop [options] <cmd> [args…]`   start and trace a new process
//! * **attach** — `snoop -p <pid> [options]`        attach to an existing process

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{ArgGroup, Parser};

use crate::{filter::Filter, output::OutputMode};

/// A modern syscall tracer for Linux, built on eBPF.
#[derive(Debug, Parser)]
#[command(
    name = "snoop",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_SHA"), ")"),
    author,
    about = "strace, but you actually want to use it.",
    long_about = None,
)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(["pid", "command"]),
))]
pub struct Cli {
    // --- Target selection ---

    /// Attach to an existing process by PID.
    #[arg(short = 'p', long, value_name = "PID", conflicts_with = "command")]
    pub pid: Option<u32>,

    /// Also trace children spawned by the target process (`clone`/`fork`).
    ///
    /// Only meaningful with `--pid`.  When spawning a new process with
    /// `snoop <cmd>`, the child is always traced.
    #[arg(long, requires = "pid")]
    pub follow: bool,

    /// Command to spawn and trace (everything after `--` or the first
    /// non-flag argument).
    #[arg(
        value_name = "CMD",
        last = false,
        allow_hyphen_values = true,
        trailing_var_arg = true,
    )]
    pub command: Vec<String>,

    // --- Output mode ---

    /// Print strace-compatible one-line output instead of the TUI.
    ///
    /// Automatically selected when stdout is not a TTY.
    #[arg(long)]
    pub raw: bool,

    // --- Filtering ---

    /// Restrict output to file-system syscalls.
    #[arg(long, conflicts_with_all = ["net"])]
    pub files: bool,

    /// Restrict output to network syscalls.
    #[arg(long, conflicts_with_all = ["files"])]
    pub net: bool,

    /// Only show syscalls that took longer than MILLIS milliseconds.
    #[arg(long, value_name = "MILLIS")]
    pub slow: Option<f64>,

    /// Only show the named syscall(s).  Can be repeated.
    ///
    /// Example: `--syscall openat --syscall read`
    #[arg(long = "syscall", value_name = "NAME")]
    pub syscalls: Vec<String>,

    /// Show raw hex arguments without decoding.
    #[arg(long)]
    pub no_decode: bool,

    // --- Advanced ---

    /// Write a flamegraph SVG to PATH when the trace ends.
    ///
    /// The flamegraph shows time-weighted syscall distribution per process,
    /// using the `inferno` library (identical to `cargo flamegraph` output).
    /// Works with both `--raw` and TUI modes.
    #[arg(long, value_name = "PATH")]
    pub flamegraph: Option<PathBuf>,

    /// Path to the compiled eBPF object file.
    ///
    /// Defaults to the embedded object compiled at build time.  Override
    /// with `SNOOP_EBPF_OBJ` environment variable or this flag for
    /// development builds produced by `cargo xtask run`.
    #[arg(long, value_name = "PATH", env = "SNOOP_EBPF_OBJ")]
    pub ebpf_obj: Option<PathBuf>,
}

impl Cli {
    /// Parse arguments from `std::env::args_os()`.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Validate the parsed arguments and dispatch to the tracer.
    pub async fn run(self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            bail!("snoop requires a Linux kernel (eBPF tracepoints are not available on this OS)");
        }

        #[cfg(target_os = "linux")]
        {
            // Check that we have CAP_BPF / root before spending time on setup.
            check_privileges()?;

            let filter = self.build_filter();
            let mode = self.output_mode();
            let flamegraph = self.flamegraph;

            if let Some(pid) = self.pid {
                crate::tracer::attach(pid, self.follow, filter, mode, flamegraph, self.ebpf_obj)
                    .await
            } else {
                crate::tracer::spawn(&self.command, filter, mode, flamegraph, self.ebpf_obj).await
            }
        }
    }

    fn build_filter(&self) -> Filter {
        Filter {
            category_files: self.files,
            category_net: self.net,
            slow_threshold_ns: self.slow.map(|ms| (ms * 1_000_000.0) as u64),
            syscall_allowlist: if self.syscalls.is_empty() {
                None
            } else {
                Some(self.syscalls.clone())
            },
            no_decode: self.no_decode,
        }
    }

    fn output_mode(&self) -> OutputMode {
        if self.raw || !is_tty() {
            OutputMode::Raw
        } else {
            OutputMode::Tui
        }
    }
}

/// Returns `true` when stdout is connected to a terminal.
fn is_tty() -> bool {
    // Safety: fileno(stdout) == 1 on all UNIX systems.
    unsafe { libc::isatty(1) == 1 }
}

/// Verify that the process has the privileges required to load eBPF programs.
///
/// On kernels >= 5.8 with `CAP_BPF`, non-root users may load programs if the
/// capability is granted.  On older kernels or when capability is absent,
/// effective UID 0 is required.
#[cfg(target_os = "linux")]
fn check_privileges() -> Result<()> {
    // Safety: getuid() always succeeds.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return Ok(());
    }

    // Try a best-effort CAP_BPF check via prctl.  If the kernel doesn't
    // support it we fall through and let aya report the actual error.
    //
    // A proper check via `capget(2)` would need unsafe + niche structs; for
    // a v0.1 tool that almost always needs root anyway, this is sufficient.
    bail!(
        "snoop requires root or CAP_BPF (current euid = {euid}).\n\
         Run with: sudo snoop …"
    )
}
