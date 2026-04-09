//! Command-line interface definition.
//!
//! snoop has three modes:
//! * **trace (default)** — `snoop [options] <-p PID | CMD [ARGS]>`
//! * **record** — `snoop record [options] -o trace.snoop <-p PID | CMD [ARGS]>`
//! * **view** — `snoop view [options] trace.snoop`

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{ArgGroup, Parser, Subcommand};

#[cfg(target_os = "linux")]
use crate::uprobe::UprobeConfig;
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
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    // ── trace mode (default when no subcommand given) ──────────────────────
    /// Attach to an existing process by PID.
    #[arg(short = 'p', long, value_name = "PID", global = false,
          conflicts_with_all = ["docker", "pod"])]
    pub pid: Option<u32>,

    /// Also trace children spawned by the target process (`clone`/`fork`).
    ///
    /// Only meaningful with `--pid`.  When spawning a new process with
    /// `snoop <cmd>`, the child is always traced.
    #[arg(long, requires = "pid")]
    pub follow: bool,

    /// Attach to all processes inside a Docker container (name or ID).
    ///
    /// Automatically enables `--follow` so every process in the container
    /// is traced.  Requires `docker` in `$PATH` (falls back to a
    /// `/proc` cgroup scan when the Docker CLI is absent).
    ///
    /// Example: `sudo snoop --docker nginx`
    #[arg(long, value_name = "NAME|ID", conflicts_with_all = ["pid", "pod"])]
    pub docker: Option<String>,

    /// Attach to all processes inside a Kubernetes pod.
    ///
    /// Automatically enables `--follow`.  Requires `kubectl` configured
    /// to reach the target cluster.  Use `--namespace` to select a
    /// non-default namespace.
    ///
    /// Example: `sudo snoop --pod my-app-pod --namespace production`
    #[arg(long, value_name = "POD", conflicts_with_all = ["pid", "docker"])]
    pub pod: Option<String>,

    /// Kubernetes namespace for `--pod` (default: `"default"`).
    #[arg(
        long,
        short = 'n',
        value_name = "NS",
        default_value = "default",
        requires = "pod"
    )]
    pub namespace: String,

    /// Command to spawn and trace (everything after `--` or the first
    /// non-flag argument).
    #[arg(
        value_name = "CMD",
        last = false,
        allow_hyphen_values = true,
        trailing_var_arg = true
    )]
    pub cmd: Vec<String>,

    // ── output mode ────────────────────────────────────────────────────────
    /// Print strace-compatible one-line output instead of the TUI.
    ///
    /// Automatically selected when stdout is not a TTY.
    #[arg(long, conflicts_with = "json")]
    pub raw: bool,

    /// Emit one JSON object per syscall (JSON Lines / NDJSON).
    ///
    /// Ideal for piping to `jq`.  Implies `--raw` mode.
    #[arg(long)]
    pub json: bool,

    /// Show high-level activity summaries instead of raw syscall lines.
    ///
    /// Groups related syscalls (open/read/close, connect/send/recv) into
    /// single human-readable lines.  Example:
    ///
    /// ```text
    /// READ  /etc/passwd  ↓1.2 KB  (2 calls, 0.80ms)
    /// NET   127.0.0.1:8080  ↑512 B ↓4.0 KB  (18.20ms)
    /// ```
    #[arg(long, conflicts_with_all = ["json", "raw", "count"])]
    pub explain: bool,

    /// Print a per-syscall count and timing summary on exit (like `strace -c`).
    ///
    /// No per-call output is shown while the trace runs.  On exit a table is
    /// printed sorted by total time:
    ///
    /// ```text
    /// % time     seconds  usecs/call     calls    errors  syscall
    /// ------ ----------- ----------- --------- --------- ----------------
    ///  72.14    0.001234         411         3              read
    ///  22.10    0.000378         378         1              openat
    ///   5.76    0.000098          98         1         1   connect
    /// ```
    #[arg(long, conflicts_with_all = ["json", "raw", "explain"])]
    pub count: bool,

    // ── filtering ──────────────────────────────────────────────────────────
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

    // ── advanced ───────────────────────────────────────────────────────────
    /// Capture TLS plaintext via uprobes on `SSL_write` / `SSL_read`.
    ///
    /// Requires OpenSSL in the target process.  Shows decrypted payloads
    /// inline in the event stream.
    #[arg(long)]
    pub tls: bool,

    /// Trace `malloc` / `free` / `calloc` / `realloc` (ltrace mode).
    ///
    /// Attaches uprobes to libc allocation functions so heap activity
    /// appears alongside syscalls.
    #[arg(long)]
    pub ltrace: bool,

    /// Write a flamegraph SVG to PATH when the trace ends.
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

/// Optional subcommand.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Record a trace to a file for later replay.
    ///
    /// Example: `sudo snoop record -p 1234 -o trace.snoop`
    #[command(group(
        ArgGroup::new("target")
            .required(true)
            .args(["pid", "command", "docker", "pod"]),
    ))]
    Record {
        /// Attach to an existing process by PID.
        #[arg(short = 'p', long, value_name = "PID",
              conflicts_with_all = ["docker", "pod"])]
        pid: Option<u32>,

        /// Also trace children (`clone`/`fork`).
        #[arg(long, requires = "pid")]
        follow: bool,

        /// Attach to all processes inside a Docker container (name or ID).
        ///
        /// Automatically enables `--follow`.
        #[arg(long, value_name = "NAME|ID", conflicts_with_all = ["pid", "pod"])]
        docker: Option<String>,

        /// Attach to all processes inside a Kubernetes pod.
        ///
        /// Automatically enables `--follow`.
        #[arg(long, value_name = "POD", conflicts_with_all = ["pid", "docker"])]
        pod: Option<String>,

        /// Kubernetes namespace for `--pod` (default: `"default"`).
        #[arg(
            long,
            short = 'n',
            value_name = "NS",
            default_value = "default",
            requires = "pod"
        )]
        namespace: String,

        /// Command to spawn and trace.
        #[arg(
            value_name = "CMD",
            last = false,
            allow_hyphen_values = true,
            trailing_var_arg = true
        )]
        command: Vec<String>,

        /// Write trace to this file (default: `trace.snoop`).
        #[arg(short = 'o', long, value_name = "FILE", default_value = "trace.snoop")]
        output: PathBuf,

        /// Path to compiled eBPF object (overrides embedded).
        #[arg(long, value_name = "PATH", env = "SNOOP_EBPF_OBJ")]
        ebpf_obj: Option<PathBuf>,
    },

    /// Compare two recorded trace files.
    ///
    /// Shows syscall count changes, median-duration regressions, and
    /// syscalls that appear in one trace but not the other.
    ///
    /// Example: `snoop diff before.snoop after.snoop`
    Diff {
        /// First (baseline) trace file.
        #[arg(value_name = "A")]
        a: PathBuf,
        /// Second (comparison) trace file.
        #[arg(value_name = "B")]
        b: PathBuf,
    },

    /// View a previously recorded trace file.
    ///
    /// No root required.  All display filters apply.
    ///
    /// Example: `snoop view trace.snoop --files --slow 5`
    View {
        /// Trace file to view.
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Print strace-compatible one-line output instead of the TUI.
        #[arg(long, conflicts_with_all = ["json", "explain", "count"])]
        raw: bool,

        /// Emit one JSON object per syscall.
        #[arg(long, conflicts_with_all = ["raw", "explain", "count"])]
        json: bool,

        /// Show high-level activity summaries (explain mode).
        #[arg(long, conflicts_with_all = ["json", "raw", "count"])]
        explain: bool,

        /// Print a per-syscall count and timing summary (like `strace -c`).
        #[arg(long, conflicts_with_all = ["json", "raw", "explain"])]
        count: bool,

        /// Restrict output to file-system syscalls.
        #[arg(long, conflicts_with_all = ["net"])]
        files: bool,

        /// Restrict output to network syscalls.
        #[arg(long, conflicts_with_all = ["files"])]
        net: bool,

        /// Only show syscalls longer than MILLIS milliseconds.
        #[arg(long, value_name = "MILLIS")]
        slow: Option<f64>,

        /// Only show the named syscall(s).
        #[arg(long = "syscall", value_name = "NAME")]
        syscalls: Vec<String>,

        /// Show raw hex arguments without decoding.
        #[arg(long)]
        no_decode: bool,
    },
}

impl Cli {
    /// Parse arguments from `std::env::args_os()`.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Validate the parsed arguments and dispatch to the tracer or viewer.
    pub async fn run(self) -> Result<()> {
        match self.command {
            Some(Command::Diff { a, b }) => crate::diff::run(&a, &b),

            Some(Command::View {
                file,
                raw,
                json,
                explain,
                count,
                files,
                net,
                slow,
                syscalls,
                no_decode,
            }) => {
                let filter = Filter {
                    category_files: files,
                    category_net: net,
                    slow_threshold_ns: slow.map(|ms| (ms * 1_000_000.0) as u64),
                    syscall_allowlist: if syscalls.is_empty() {
                        None
                    } else {
                        Some(syscalls)
                    },
                    no_decode,
                };
                let mode = if json {
                    OutputMode::Json
                } else if count {
                    OutputMode::Count
                } else if explain {
                    OutputMode::Explain
                } else if raw || !is_tty() {
                    OutputMode::Raw
                } else {
                    OutputMode::Tui
                };
                return crate::viewer::run(&file, filter, mode).await;
            }

            #[allow(unused_variables)]
            Some(Command::Record {
                pid,
                follow,
                docker,
                pod,
                namespace,
                command,
                output,
                ebpf_obj,
            }) => {
                #[cfg(not(target_os = "linux"))]
                bail!("snoop requires Linux");

                #[cfg(target_os = "linux")]
                {
                    check_privileges()?;
                    if let Some(name) = docker {
                        let resolved = crate::container::resolve_docker(&name)?;
                        return crate::tracer::record_attach(resolved, true, output, ebpf_obj)
                            .await;
                    } else if let Some(pod_name) = pod {
                        let resolved = crate::container::resolve_pod(&pod_name, &namespace)?;
                        return crate::tracer::record_attach(resolved, true, output, ebpf_obj)
                            .await;
                    } else if let Some(pid) = pid {
                        return crate::tracer::record_attach(pid, follow, output, ebpf_obj).await;
                    } else {
                        return crate::tracer::record_spawn(&command, output, ebpf_obj).await;
                    }
                }
            }

            None => {
                // Default trace mode — require one of: --pid, --docker, --pod, or CMD.
                #[cfg(not(target_os = "linux"))]
                bail!(
                    "snoop requires a Linux kernel (eBPF tracepoints are not available on this OS)"
                );

                #[cfg(target_os = "linux")]
                {
                    if self.pid.is_none()
                        && self.docker.is_none()
                        && self.pod.is_none()
                        && self.cmd.is_empty()
                    {
                        bail!(
                            "specify a target: --pid <PID>, --docker <NAME>, \
                             --pod <POD>, or a command to run"
                        );
                    }

                    check_privileges()?;

                    let filter = self.build_filter();
                    let mode = self.output_mode();
                    let flamegraph = self.flamegraph;
                    let uprobes = UprobeConfig {
                        tls: self.tls,
                        ltrace: self.ltrace,
                    };

                    if let Some(name) = self.docker {
                        let pid = crate::container::resolve_docker(&name)?;
                        crate::tracer::attach(
                            pid,
                            true,
                            filter,
                            mode,
                            flamegraph,
                            self.ebpf_obj,
                            uprobes,
                        )
                        .await
                    } else if let Some(pod_name) = self.pod {
                        let pid = crate::container::resolve_pod(&pod_name, &self.namespace)?;
                        crate::tracer::attach(
                            pid,
                            true,
                            filter,
                            mode,
                            flamegraph,
                            self.ebpf_obj,
                            uprobes,
                        )
                        .await
                    } else if let Some(pid) = self.pid {
                        crate::tracer::attach(
                            pid,
                            self.follow,
                            filter,
                            mode,
                            flamegraph,
                            self.ebpf_obj,
                            uprobes,
                        )
                        .await
                    } else {
                        crate::tracer::spawn(
                            &self.cmd,
                            filter,
                            mode,
                            flamegraph,
                            self.ebpf_obj,
                            uprobes,
                        )
                        .await
                    }
                }
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
        if self.json {
            OutputMode::Json
        } else if self.count {
            OutputMode::Count
        } else if self.explain {
            OutputMode::Explain
        } else if self.raw || !is_tty() {
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
#[cfg(target_os = "linux")]
fn check_privileges() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return Ok(());
    }
    bail!(
        "snoop requires root or CAP_BPF (current euid = {euid}).\n\
         Run with: sudo snoop …"
    )
}
