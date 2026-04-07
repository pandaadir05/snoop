//! High-level tracer that orchestrates loading, consuming, and outputting.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use aya::maps::RingBuf;
use snoop_common::SyscallEvent;
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, watch},
};

use crate::{
    filter::Filter,
    flamegraph::FlamegraphCollector,
    loader,
    output::{json::JsonOutput, raw::RawOutput, tui::TuiApp, OutputMode},
    record::TraceWriter,
};

/// Spawn a new process and trace it.
///
/// Always enables follow mode so any children spawned by the target are
/// also traced; the user opted in by choosing spawn mode.
pub async fn spawn(
    cmd: &[String],
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    ebpf_obj: Option<PathBuf>,
) -> Result<()> {
    if cmd.is_empty() {
        bail!("no command specified");
    }

    // Fork the child.  We use `tokio::process::Command` so we get an async
    // child handle, but we spawn it *before* loading eBPF to minimise the
    // window between exec and the tracepoints being attached.
    //
    // Known limitation: there is a race between exec completing and the
    // tracepoints attaching.  The very first few syscalls of the child may
    // be missed.  See ROADMAP.md for the ptrace-based fix.
    let mut child = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", cmd[0]))?;

    let pid = child
        .id()
        .context("child process has already exited")?;

    // Always follow children when spawning — the user chose to trace this
    // command so tracing its children is the expected behaviour.
    let ebpf = loader::load(pid, true, ebpf_obj)?;
    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    // Drive the ring-buffer consumer and the child watcher concurrently.
    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = run_output(rx, done_rx, filter, mode, flamegraph, Some(pid)) => res?,
        status = child.wait() => {
            let _ = done_tx.send(true);
            let code = status?.code().unwrap_or(-1);
            log::info!("child process exited with status {code}");
        }
    }

    Ok(())
}

/// Attach to an existing process by PID.
pub async fn attach(
    pid: u32,
    follow: bool,
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    ebpf_obj: Option<PathBuf>,
) -> Result<()> {
    // Verify the process exists before we try to load eBPF.
    if !process_exists(pid) {
        bail!("process {pid} does not exist");
    }

    let ebpf = loader::load(pid, follow, ebpf_obj)?;
    let (tx, rx) = mpsc::channel(4096);
    let (_done_tx, done_rx) = watch::channel(false);

    // Watch for the target process to disappear.
    let pid_for_watcher = pid;
    let done_tx_clone = _done_tx.clone();

    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = run_output(rx, done_rx, filter, mode, flamegraph, Some(pid)) => res?,
        _ = watch_pid(pid_for_watcher, done_tx_clone) => {}
    }

    Ok(())
}

/// Poll until `pid` disappears from `/proc`, then signal done.
async fn watch_pid(pid: u32, done: watch::Sender<bool>) {
    loop {
        if !process_exists(pid) {
            let _ = done.send(true);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Read events from the ring buffer and forward them over `tx`.
async fn consume_ring_buf(
    mut ebpf: aya::Ebpf,
    tx: mpsc::Sender<SyscallEvent>,
    mut done: watch::Receiver<bool>,
) -> Result<()> {
    let ring_buf = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .context("EVENTS ring buffer not found in eBPF object")?,
    )?;

    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        // Wait until the ring buffer has data or the tracer signals done.
        tokio::select! {
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    // Safety: the eBPF program always writes a complete
                    // `SyscallEvent`; the sizes are asserted in snoop-ebpf.
                    if item.len() < std::mem::size_of::<SyscallEvent>() {
                        log::warn!("short ring-buffer item ({} bytes), skipping", item.len());
                        continue;
                    }
                    let event = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const SyscallEvent)
                    };
                    if tx.send(event).await.is_err() {
                        // Receiver closed — output layer has exited.
                        return Ok(());
                    }
                }
                guard.clear_ready();
            }
            _ = done.changed() => {
                if *done.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Drive the output layer (raw, JSON, or TUI) until the user quits or the trace ends.
async fn run_output(
    rx: mpsc::Receiver<SyscallEvent>,
    done: watch::Receiver<bool>,
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    match mode {
        OutputMode::Raw  => run_raw(rx, done, filter, flamegraph).await,
        OutputMode::Json => run_json(rx, done, filter, flamegraph).await,
        OutputMode::Tui  => run_tui(rx, done, filter, flamegraph, target_pid).await,
    }
}

async fn run_raw(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let out = RawOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut collector) = fg {
                    collector.record(&event);
                }
                out.handle(&event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    // Drain remaining events.
                    while let Ok(event) = rx.try_recv() {
                        if let Some(ref mut collector) = fg {
                            collector.record(&event);
                        }
                        out.handle(&event).context("write error")?;
                    }
                    break;
                }
            }
        }
    }

    if let (Some(collector), Some(path)) = (fg, flamegraph) {
        collector.write_svg(&path)?;
    }
    Ok(())
}

async fn run_json(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let out = JsonOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut collector) = fg {
                    collector.record(&event);
                }
                out.handle(&event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(event) = rx.try_recv() {
                        if let Some(ref mut collector) = fg {
                            collector.record(&event);
                        }
                        out.handle(&event).context("write error")?;
                    }
                    break;
                }
            }
        }
    }

    if let (Some(collector), Some(path)) = (fg, flamegraph) {
        collector.write_svg(&path)?;
    }
    Ok(())
}

async fn run_tui(
    rx: mpsc::Receiver<SyscallEvent>,
    done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    let collect = flamegraph.is_some();
    let app = TuiApp::with_flamegraph(filter, target_pid, collect);
    let fg = app.run(rx, done).await?;
    if let (Some(collector), Some(path)) = (fg, flamegraph) {
        collector.write_svg(&path)?;
    }
    Ok(())
}

// ── record mode ───────────────────────────────────────────────────────────────

/// Spawn a command, trace it, and write all events to `output_path`.
pub async fn record_spawn(
    cmd: &[String],
    output_path: PathBuf,
    ebpf_obj: Option<PathBuf>,
) -> Result<()> {
    if cmd.is_empty() {
        bail!("no command specified");
    }

    let mut child = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", cmd[0]))?;

    let pid = child.id().context("child process has already exited")?;
    let ebpf = loader::load(pid, true, ebpf_obj)?;
    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = record_events(rx, done_rx, output_path.clone()) => res?,
        status = child.wait() => {
            let _ = done_tx.send(true);
            let code = status?.code().unwrap_or(-1);
            log::info!("child exited with status {code}");
        }
    }

    log::info!("trace written to {}", output_path.display());
    Ok(())
}

/// Attach to a running process and record events to `output_path`.
pub async fn record_attach(
    pid: u32,
    follow: bool,
    output_path: PathBuf,
    ebpf_obj: Option<PathBuf>,
) -> Result<()> {
    if !process_exists(pid) {
        bail!("process {pid} does not exist");
    }

    let ebpf = loader::load(pid, follow, ebpf_obj)?;
    let (tx, rx) = mpsc::channel(4096);
    let (_done_tx, done_rx) = watch::channel(false);
    let done_tx_clone = _done_tx.clone();

    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = record_events(rx, done_rx, output_path.clone()) => res?,
        _ = watch_pid(pid, done_tx_clone) => {}
    }

    log::info!("trace written to {}", output_path.display());
    Ok(())
}

/// Consume events from `rx` and write them to a `.snoop` file.
async fn record_events(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut done: watch::Receiver<bool>,
    path: PathBuf,
) -> Result<()> {
    let mut writer = TraceWriter::create(&path)?;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                writer.write_event(&event).context("failed to write event")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(event) = rx.try_recv() {
                        writer.write_event(&event).context("failed to write event")?;
                    }
                    break;
                }
            }
        }
    }

    let count = writer.finish().context("failed to flush trace file")?;
    eprintln!("recorded {count} events to {}", path.display());
    Ok(())
}
