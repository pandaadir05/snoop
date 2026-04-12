//! High-level tracer that orchestrates loading, consuming, and outputting.

use std::fs::File;
use std::io::BufWriter;
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
        count::CountOutput, explain::ExplainOutput, json::JsonOutput, lib_call, raw::RawOutput,
        tui::TuiApp, OutputMode,
    },
    record::TraceWriter,
    uprobe::UprobeConfig,
};

// ── public trace entry points ─────────────────────────────────────────────────

/// Spawn a new process and trace it from its very first syscall.
///
/// Uses `ptrace(PTRACE_TRACEME)` in the child's pre-exec hook so the child
/// stops at exec entry before executing any syscalls.  eBPF is loaded while
/// the child is stopped, then `ptrace(PTRACE_DETACH)` resumes it.  This
/// eliminates the race window that exists when eBPF is attached after the
/// child has already started running.
pub async fn spawn(
    cmd: &[String],
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    output_file: Option<PathBuf>,
    ebpf_obj: Option<PathBuf>,
    uprobes: UprobeConfig,
) -> Result<()> {
    if cmd.is_empty() {
        bail!("no command specified");
    }

    // In TUI mode the child's output would corrupt the alternate-screen
    // terminal, so redirect to /dev/null.  Other modes (raw, json, etc.)
    // let the child's output through like strace does.
    let mut command = tokio::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]).stdin(Stdio::inherit());
    if mode == OutputMode::Tui {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    // Safety: ptrace(PTRACE_TRACEME, ...) is async-signal-safe and may be
    // called between fork() and exec() without restriction.  On success the
    // child will receive a SIGTRAP at exec entry and stop, allowing the parent
    // to load eBPF before any user code runs.
    unsafe {
        command.pre_exec(|| {
            let rc = libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", cmd[0]))?;

    let pid = child.id().context("child process has already exited")?;

    // Block until the child stops at exec entry (SIGTRAP).  This is a brief
    // synchronous wait — the child stops almost immediately.
    wait_for_stop(pid)?;

    // Load eBPF while the child is stopped — no syscalls are missed.
    let mut ebpf = loader::load(pid, true, ebpf_obj)?;
    if uprobes.any_enabled() {
        crate::uprobe::attach_uprobes(&mut ebpf, &uprobes, pid)?;
    }

    // Detach ptrace and let the child run; eBPF takes over from here.
    detach_ptrace(pid)?;

    // Extract LIB_EVENTS *before* moving ebpf — take_map gives us owned MapData
    // so there are no lifetime ties to the Ebpf object afterwards.
    let lib_rx = take_lib_channel(&mut ebpf, &uprobes);

    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    // Extract the EVENTS ring buffer as an owned handle (like LIB_EVENTS).
    // This severs the lifetime tie to `ebpf` while the kernel keeps its own
    // reference to the map so BPF programs continue writing to it.
    let events_rb = take_events_ring_buf(&mut ebpf)?;

    // Spawn the ring buffer consumer as a separate tokio task so it
    // runs independently of the TUI event loop.  The TUI's
    // `event::poll()` is a synchronous blocking call that would starve
    // `consume_ring_buf` if they shared the same task via `select!`.
    let rb_done_rx = done_rx.clone();
    let rb_handle = tokio::spawn(consume_ring_buf(events_rb, tx, rb_done_rx));

    // `ebpf` must stay alive so the attached programs aren't detached.
    // Move it into the select so it's dropped only when the trace ends.
    tokio::select! {
        res = rb_handle => res??,
        res = run_output(rx, lib_rx, done_rx, filter, mode, flamegraph, output_file, Some(pid)) => res?,
        status = child.wait() => {
            let _ = done_tx.send(true);
            let code = status?.code().unwrap_or(-1);
            log::info!("child process exited with status {code}");
            drop(ebpf);
        }
    }

    Ok(())
}

/// Attach to an existing process by PID.
#[allow(clippy::too_many_arguments)]
pub async fn attach(
    pid: u32,
    follow: bool,
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    output_file: Option<PathBuf>,
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
    let (done_tx, done_rx) = watch::channel(false);

    let events_rb = take_events_ring_buf(&mut ebpf)?;

    let rb_done_rx = done_rx.clone();
    let rb_handle = tokio::spawn(consume_ring_buf(events_rb, tx, rb_done_rx));

    tokio::select! {
        res = rb_handle => res??,
        res = run_output(rx, lib_rx, done_rx, filter, mode, flamegraph, output_file, Some(pid)) => res?,
        _ = watch_pid(pid, done_tx.clone()) => { drop(ebpf); }
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
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const LibCallEvent) };
            // When the receiver is gone the output layer has exited — stop.
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        guard.clear_ready();
    }
}

// ── EVENTS ring buffer extraction ─────────────────────────────────────────────

/// Extract `EVENTS` from `ebpf` as an *owned* `RingBuf<MapData>`.
///
/// Uses `Ebpf::take_map` (same pattern as LIB_EVENTS) so the ring buffer
/// has no lifetime tie to the `Ebpf` handle.  The kernel keeps its own
/// reference to the underlying map, so BPF programs continue pushing events.
fn take_events_ring_buf(ebpf: &mut aya::Ebpf) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map("EVENTS")
        .context("EVENTS ring buffer not found in eBPF object")?;
    RingBuf::try_from(map).context("EVENTS is not a ring buffer")
}

// ── syscall ring buffer consumer ──────────────────────────────────────────────

/// Read events from the `EVENTS` ring buffer and forward them over `tx`.
///
/// Polls the ring buffer in a tight loop: drain all pending items, then
/// `tokio::time::sleep` for a short interval before trying again.  This is
/// simpler and more reliable than `AsyncFd`-based notifications, which can
/// be unreliable on certain kernels (e.g. WSL2 5.15) where BPF ring buffer
/// epoll wakeups are not always delivered.
///
/// 10 ms polling gives ~100 Hz update rate, which is well above the TUI's
/// 60 Hz refresh.  CPU cost is negligible (one syscall every 10 ms when idle).
async fn consume_ring_buf(
    mut ring_buf: RingBuf<MapData>,
    tx: mpsc::Sender<SyscallEvent>,
    done: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        // Drain all available events.
        while let Some(item) = ring_buf.next() {
            if item.len() < std::mem::size_of::<SyscallEvent>() {
                log::warn!("short ring-buffer item ({} bytes), skipping", item.len());
                continue;
            }
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const SyscallEvent) };
            if tx.send(event).await.is_err() {
                return Ok(()); // receiver dropped — output layer exited
            }
        }

        // Check if the tracer has finished.
        if done.has_changed().unwrap_or(false) && *done.borrow() {
            // Final drain — pick up any stragglers.
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<SyscallEvent>() {
                    let event =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const SyscallEvent) };
                    let _ = tx.send(event).await;
                }
            }
            return Ok(());
        }

        // Brief sleep to avoid busy-spinning when no events are pending.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

// ── output dispatch ───────────────────────────────────────────────────────────

/// Drive the output layer until the user quits or the trace ends.
#[allow(clippy::too_many_arguments)]
async fn run_output(
    rx: mpsc::Receiver<SyscallEvent>,
    lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    done: watch::Receiver<bool>,
    filter: Filter,
    mode: OutputMode,
    flamegraph: Option<PathBuf>,
    output_file: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    match mode {
        OutputMode::Raw => run_raw(rx, lib_rx, done, filter, flamegraph, output_file).await,
        OutputMode::Json => run_json(rx, lib_rx, done, filter, flamegraph, output_file).await,
        OutputMode::Explain => run_explain(rx, lib_rx, done, filter, flamegraph, output_file).await,
        OutputMode::Count => run_count(rx, done, filter, flamegraph).await,
        OutputMode::Tui => {
            run_tui(
                rx,
                lib_rx,
                done,
                filter,
                flamegraph,
                output_file,
                target_pid,
            )
            .await
        }
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
        None => std::future::pending().await,
    }
}

// ── raw output ────────────────────────────────────────────────────────────────

async fn run_raw(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let out = RawOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());
    let mut tee = open_tee_file(output_file.as_deref())?;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event).context("write error")?;
                if let Some(ref mut w) = tee {
                    out.handle_to(w, &event).context("output-file write error")?;
                }
            }
            Some(lib_event) = opt_recv(&mut lib_rx) => {
                lib_call::write_raw(&lib_event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev).context("write error")?;
                        if let Some(ref mut w) = tee {
                            out.handle_to(w, &ev).context("output-file write error")?;
                        }
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
    output_file: Option<PathBuf>,
) -> Result<()> {
    let out = JsonOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());
    let mut tee = open_tee_file(output_file.as_deref())?;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event).context("write error")?;
                if let Some(ref mut w) = tee {
                    out.handle_to(w, &event).context("output-file write error")?;
                }
            }
            Some(lib_event) = opt_recv(&mut lib_rx) => {
                lib_call::write_json(&lib_event).context("write error")?;
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev).context("write error")?;
                        if let Some(ref mut w) = tee {
                            out.handle_to(w, &ev).context("output-file write error")?;
                        }
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
    output_file: Option<PathBuf>,
) -> Result<()> {
    let mut out = ExplainOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());
    // explain output is flushed as grouped activities; tee is written on flush.
    let tee = open_tee_file(output_file.as_deref())?;
    out.set_tee(tee);

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

// ── count output ─────────────────────────────────────────────────────────────

async fn run_count(
    mut rx: mpsc::Receiver<SyscallEvent>,
    mut done: watch::Receiver<bool>,
    filter: Filter,
    flamegraph: Option<PathBuf>,
) -> Result<()> {
    let mut out = CountOutput::new(filter);
    let mut fg = flamegraph.as_ref().map(|_| FlamegraphCollector::new());

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Some(ref mut c) = fg { c.record(&event); }
                out.handle(&event);
            }
            _ = done.changed() => {
                if *done.borrow() {
                    while let Ok(ev) = rx.try_recv() {
                        if let Some(ref mut c) = fg { c.record(&ev); }
                        out.handle(&ev);
                    }
                    break;
                }
            }
        }
    }

    out.finish().context("write error")?;

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
    output_file: Option<PathBuf>,
    target_pid: Option<u32>,
) -> Result<()> {
    let collect = flamegraph.is_some();
    let tee = open_tee_file(output_file.as_deref())?;
    let app = TuiApp::with_flamegraph(filter, target_pid, collect);
    let fg = app.run(rx, lib_rx, done, tee).await?;
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

/// Open (or create/truncate) the optional tee output file.
///
/// Returns `Ok(None)` when `path` is `None`.
fn open_tee_file(path: Option<&std::path::Path>) -> Result<Option<BufWriter<File>>> {
    match path {
        None => Ok(None),
        Some(p) => {
            let file = File::create(p)
                .with_context(|| format!("cannot create output file: {}", p.display()))?;
            Ok(Some(BufWriter::new(file)))
        }
    }
}

/// Block until `pid` stops (WIFSTOPPED).
///
/// Called after spawning with `PTRACE_TRACEME`; the child stops at exec entry
/// with a SIGTRAP.  The call returns almost immediately in practice.
fn wait_for_stop(pid: u32) -> Result<()> {
    let mut status: libc::c_int = 0;
    let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        bail!("waitpid({pid}) failed: {err}");
    }
    if libc::WIFSTOPPED(status) {
        return Ok(());
    }
    // Unexpected: child exited before we could attach.
    bail!(
        "child process (pid {pid}) exited before eBPF could be attached \
         (waitpid status={status:#x})"
    );
}

/// Detach ptrace from `pid`, resuming normal execution.
///
/// After this call the process runs freely; all further observation is through
/// eBPF rather than ptrace.
fn detach_ptrace(pid: u32) -> Result<()> {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        bail!("ptrace(PTRACE_DETACH, {pid}) failed: {err}");
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
    let mut ebpf = loader::load(pid, true, ebpf_obj)?;
    let events_rb = take_events_ring_buf(&mut ebpf)?;
    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    let rb_done_rx = done_rx.clone();
    let rb_handle = tokio::spawn(consume_ring_buf(events_rb, tx, rb_done_rx));

    tokio::select! {
        res = rb_handle => res??,
        res = record_events(rx, done_rx, output_path.clone()) => res?,
        status = child.wait() => {
            let _ = done_tx.send(true);
            let code = status?.code().unwrap_or(-1);
            log::info!("child exited with status {code}");
            drop(ebpf);
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

    let mut ebpf = loader::load(pid, follow, ebpf_obj)?;
    let events_rb = take_events_ring_buf(&mut ebpf)?;
    let (tx, rx) = mpsc::channel(4096);
    let (done_tx, done_rx) = watch::channel(false);

    let rb_done_rx = done_rx.clone();
    let rb_handle = tokio::spawn(consume_ring_buf(events_rb, tx, rb_done_rx));

    tokio::select! {
        res = rb_handle => res??,
        res = record_events(rx, done_rx, output_path.clone()) => res?,
        _ = watch_pid(pid, done_tx.clone()) => { drop(ebpf); }
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
