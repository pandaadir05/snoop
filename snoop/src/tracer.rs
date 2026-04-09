//! High-level tracer that orchestrates loading, consuming, and outputting.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use aya::maps::{MapData, RingBuf};
use snoop_common::{LibCallEvent, SyscallEvent};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, watch},
};

use crate::{
    filter::Filter,
    flamegraph::FlamegraphCollector,
    loader,
    output::{
        explain::ExplainOutput, json::JsonOutput, lib_call, raw::RawOutput, tui::TuiApp,
        OutputMode,
    },
    record::TraceWriter,
    uprobe::UprobeConfig,
};

// ── public trace entry points ─────────────────────────────────────────────────

/// Spawn a new process and trace it.
///
/// Always enables follow mode so children are also traced.
pub async fn spawn(
    cmd: &[String],
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    ebpf_obj: Option<PathBuf>,
    uprobes: UprobeConfig,
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

    let mut ebpf = loader::load(pid, true, ebpf_obj)?;
    if uprobes.any_enabled() {
        crate::uprobe::attach_uprobes(&mut ebpf, &uprobes, pid)?;
    }

    // Extract LIB_EVENTS *before* moving ebpf — take_map gives us owned MapData
    // so there are no lifetime ties to the Ebpf object afterwards.
    let lib_rx = take_lib_channel(&mut ebpf, &uprobes);

    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = run_output(rx, lib_rx, done_rx, filter, mode, flamegraph, Some(pid)) => res?,
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
    uprobes: UprobeConfig,
) -> Result<()> {
    if !process_exists(pid) {
        bail!("process {pid} does not exist");
    }

    let mut ebpf = loader::load(pid, follow, ebpf_obj)?;
    if uprobes.any_enabled() {
        crate::uprobe::attach_uprobes(&mut ebpf, &uprobes, pid)?;
    }

    let lib_rx = take_lib_channel(&mut ebpf, &uprobes);

    let (tx, rx) = mpsc::channel(4096);
    let (_done_tx, done_rx) = watch::channel(false);
    let done_tx_clone = _done_tx.clone();

    tokio::select! {
        res = consume_ring_buf(ebpf, tx, done_rx.clone()) => res?,
        res = run_output(rx, lib_rx, done_rx, filter, mode, flamegraph, Some(pid)) => res?,
        _ = watch_pid(pid, done_tx_clone) => {}
    }

    Ok(())
}

// ── LIB_EVENTS extraction ─────────────────────────────────────────────────────

/// Extract `LIB_EVENTS` from `ebpf` as an *owned* `RingBuf<MapData>` and spin
/// up a background consumer task.  Returns the receive end of its output channel.
///
/// Using `Ebpf::take_map` (aya ≥ 0.13) gives us a `Map` with owned `MapData`;
/// there is no lifetime tie to the `Ebpf` struct, so the ring buffer can be
/// sent to a separate tokio task without lifetime gymnastics.
fn take_lib_channel(
    ebpf: &mut aya::Ebpf,
    uprobes: &UprobeConfig,
) -> Option<mpsc::Receiver<LibCallEvent>> {
    if !uprobes.any_enabled() {
        return None;
    }

    let map = ebpf.take_map("LIB_EVENTS")?;

    // Downcast the generic Map enum to the concrete RingBuf<MapData> type.
    let ring_buf: RingBuf<MapData> = match RingBuf::try_from(map) {
        Ok(rb) => rb,
        Err(e) => {
            log::warn!("LIB_EVENTS is not a ring buffer, uprobe output disabled: {e}");
            return None;
        }
    };

    let (tx, rx) = mpsc::channel::<LibCallEvent>(4096);
    tokio::spawn(consume_lib_ring_buf(ring_buf, tx));
    Some(rx)
}

/// Consume `LIB_EVENTS` until the channel receiver is dropped.
///
/// Owns `RingBuf<MapData>` (no borrowed lifetime — `MapData` was extracted via
/// `Ebpf::take_map`), so this task can run independently of the Ebpf handle.
async fn consume_lib_ring_buf(
    ring_buf: RingBuf<MapData>,
    tx: mpsc::Sender<LibCallEvent>,
) -> Result<()> {
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if item.len() < std::mem::size_of::<LibCallEvent>() {
                log::warn!("short LIB_EVENTS item ({} bytes), skipping", item.len());
                continue;
            }
            let event = unsafe {
                std::ptr::read_unaligned(item.as_ptr() as *const LibCallEvent)
            };
            // When the receiver is gone the output layer has exited — stop.
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        guard.clear_ready();
    }
}

// ── syscall ring buffer consumer ──────────────────────────────────────────────

/// Read events from the `EVENTS` ring buffer and forward them over `tx`.
///
/// Takes ownership of `ebpf` so the eBPF programs remain loaded for the life
/// of this function.
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
        tokio::select! {
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    if item.len() < std::mem::size_of::<SyscallEvent>() {
                        log::warn!("short ring-buffer item ({} bytes), skipping", item.len());
                        continue;
                    }
                    let event = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const SyscallEvent)
                    };
                    if tx.send(event).await.is_err() {
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

// ── output dispatch ───────────────────────────────────────────────────────────

/// Drive the output layer until the user quits or the trace ends.
async fn run_output(
    rx: mpsc::Receiver<SyscallEvent>,
    lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    done: watch::Receiver<bool>,
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    match mode {
        OutputMode::Raw     => run_raw(rx, lib_rx, done, filter, flamegraph).await,
        OutputMode::Json    => run_json(rx, lib_rx, done, filter, flamegraph).await,
        OutputMode::Explain => run_explain(rx, lib_rx, done, filter, flamegraph).await,
        OutputMode::Tui     => run_tui(rx, lib_rx, done, filter, flamegraph, target_pid).await,
    }
}

// ── helper: optional receiver ─────────────────────────────────────────────────

/// Await the next item from `rx`, or park forever when `rx` is `None`.
///
/// Using `std::future::pending()` as the `None` arm means the `tokio::select!`
/// branch that calls this will never fire when no lib-event channel exists, so
/// we get a single unified select loop without conditional compilation.
async fn opt_recv(rx: &mut Option<mpsc::Receiver<LibCallEvent>>) -> Option<LibCallEvent> {
    match rx {
        Some(r) => r.recv().await,
        None    => std::future::pending().await,
    }
}

// ── raw output ────────────────────────────────────────────────────────────────

async fn run_raw(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let out = RawOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event).context("write error")?;
            }
            Some(lib_event) = opt_recv(&mut lib_rx) => {
                lib_call::write_raw(&lib_event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev).context("write error")?;
                    }
                    if let Some(ref mut lrx) = lib_rx {
                        while let Ok(ev) = lrx.try_recv() {
                            lib_call::write_raw(&ev).context("write error")?;
                        }
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

// ── JSON output ───────────────────────────────────────────────────────────────

async fn run_json(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let out = JsonOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event).context("write error")?;
            }
            Some(lib_event) = opt_recv(&mut lib_rx) => {
                lib_call::write_json(&lib_event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev).context("write error")?;
                    }
                    if let Some(ref mut lrx) = lib_rx {
                        while let Ok(ev) = lrx.try_recv() {
                            lib_call::write_json(&ev).context("write error")?;
                        }
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

// ── explain output ────────────────────────────────────────────────────────────

async fn run_explain(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let mut out = ExplainOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event).context("write error")?;
            }
            Some(lib_event) = opt_recv(&mut lib_rx) => {
                // Lib calls are shown verbatim in explain mode alongside activities.
                lib_call::write_raw(&lib_event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev).context("write error")?;
                    }
                    if let Some(ref mut lrx) = lib_rx {
                        while let Ok(ev) = lrx.try_recv() {
                            lib_call::write_raw(&ev).context("write error")?;
                        }
                    }
                    break;
                }
            }
        }
    }

    out.flush().context("write error")?;

    if let (Some(collector), Some(path)) = (fg, flamegraph) {
        collector.write_svg(&path)?;
    }
    Ok(())
}

// ── TUI output ────────────────────────────────────────────────────────────────

async fn run_tui(
    rx: mpsc::Receiver<SyscallEvent>,
    lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    let collect = flamegraph.is_some();
    let app = TuiApp::with_flamegraph(filter, target_pid, collect);
    let fg = app.run(rx, lib_rx, done).await?;
    if let (Some(collector), Some(path)) = (fg, flamegraph) {
        collector.write_svg(&path)?;
    }
    Ok(())
}

// ── utilities ─────────────────────────────────────────────────────────────────

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
