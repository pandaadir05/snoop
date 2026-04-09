//! Full-screen TUI built with ratatui + crossterm.
//!
//! Layout:
//! ```text
//! ┌─ snoop ── pid:1234  comm:nginx  events:42,891  elapsed:3.4s ─────────────┐
//! │                                                                           │
//! │  SYSCALL STREAM (scrollable)         TOP SYSCALLS                        │
//! │  ──────────────────────────          ─────────────────────               │
//! │  [  3.421234] read(3, …) = 8192      openat        2,341  28.1%          │
//! │  [  3.421301] write(1, …) = 8192     read          1,893  22.8%          │
//! │  …                                   …                                   │
//! │                                                                           │
//! ├───────────────────────────────────────────────────────────────────────────┤
//! │ [q]uit  [Space]pause  [/]search  [f]iles  [n]et  [c]lear  [?]help        │
//! └───────────────────────────────────────────────────────────────────────────┘
//! ```

use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    },
    Frame, Terminal,
};
use snoop_common::{LibCallEvent, SyscallEvent, SyscallNr};
use tokio::sync::mpsc;

use crate::{
    decode::{comm_to_string, DecodedEvent},
    filter::Filter,
    flamegraph::FlamegraphCollector,
    output::lib_call,
};

/// Maximum number of events kept in the scrollback buffer.
const MAX_EVENTS: usize = 10_000;

/// A single display entry in the TUI event stream.
///
/// Either a decoded syscall or a library-call captured via uprobe.
enum TuiEvent {
    Syscall(DecodedEvent),
    LibCall {
        timestamp_ns: u64,
        duration_ns: u64,
        comm: String,
        name: &'static str,
        args_str: String,
        ret_str: String,
    },
}

/// Tick rate for the render loop.
const TICK_MS: u64 = 16; // ~60 fps

/// Application state managed by the TUI.
pub struct TuiApp {
    filter: Filter,
    /// All events received since start (ring buffer, newest last).
    events: Vec<TuiEvent>,
    /// Per-syscall call counts.
    counts: HashMap<&'static str, u64>,
    /// Total events received (including filtered-out ones).
    total_events: u64,
    /// Whether the stream is paused.
    paused: bool,
    /// Search string currently typed in the search bar.
    search: String,
    /// Whether the search bar is active.
    searching: bool,
    /// Scroll offset for the event stream.
    stream_state: ListState,
    /// Scroll offset for the top-syscalls table.
    table_state: TableState,
    /// Monotonic start time.
    started_at: Instant,
    /// Target PID being traced.
    target_pid: Option<u32>,
    /// Comm of the target process (best effort from first event).
    target_comm: String,
    /// Set to `true` when the target process has exited.
    target_exited: bool,
    /// Optional flamegraph accumulator; `None` when `--flamegraph` was not set.
    fg_collector: Option<FlamegraphCollector>,
    /// When `Some`, a detail popup is shown for the event at this index.
    detail_idx: Option<usize>,
}

impl TuiApp {
    /// Create a new TUI application.
    ///
    /// Pass `collect_flamegraph = true` to enable flamegraph data collection;
    /// the collector is returned from `run` so the caller can write the SVG.
    pub fn new(filter: Filter, target_pid: Option<u32>) -> Self {
        Self::with_flamegraph(filter, target_pid, false)
    }

    /// Create a TUI application, optionally enabling flamegraph collection.
    pub fn with_flamegraph(
        filter: Filter,
        target_pid: Option<u32>,
        collect_flamegraph: bool,
    ) -> Self {
        Self {
            filter,
            events: Vec::with_capacity(1024),
            counts: HashMap::new(),
            total_events: 0,
            paused: false,
            search: String::new(),
            searching: false,
            stream_state: ListState::default(),
            table_state: TableState::default(),
            started_at: Instant::now(),
            target_pid,
            target_comm: String::new(),
            target_exited: false,
            fg_collector: if collect_flamegraph {
                Some(FlamegraphCollector::new())
            } else {
                None
            },
            detail_idx: None,
        }
    }

    /// Push a new event into the application state.
    fn push(&mut self, event: &SyscallEvent) {
        self.total_events += 1;

        if self.target_comm.is_empty() {
            self.target_comm = comm_to_string(&event.comm);
        }

        // Always record for flamegraph regardless of display filter or pause state.
        if let Some(ref mut fg) = self.fg_collector {
            fg.record(event);
        }

        // When paused, skip updating the display buffer and counts so the
        // user sees a frozen snapshot.  Flamegraph data is still collected above.
        if self.paused {
            return;
        }

        if !self.filter.accepts(event) {
            return;
        }

        let decoded = DecodedEvent::from_event(event, !self.filter.no_decode);
        *self.counts.entry(decoded.name).or_insert(0) += 1;

        if self.events.len() >= MAX_EVENTS {
            self.events.remove(0);
        }
        self.events.push(TuiEvent::Syscall(decoded));

        // Auto-scroll to bottom.
        let len = self.events.len();
        if len > 0 {
            self.stream_state.select(Some(len - 1));
        }
    }

    /// Push a library-call event (from uprobes) into the stream.
    fn push_lib(&mut self, event: &LibCallEvent) {
        if self.paused {
            return;
        }

        let Some(func) = event.lib_func() else { return };
        let name = lib_call::tui_name(func);
        let args_str = lib_call::format_args(event);
        let ret_str = lib_call::format_ret(event);
        let comm = comm_to_string(&event.comm);

        *self.counts.entry(name).or_insert(0) += 1;

        if self.events.len() >= MAX_EVENTS {
            self.events.remove(0);
        }
        self.events.push(TuiEvent::LibCall {
            timestamp_ns: event.enter_ns,
            duration_ns: event.duration_ns(),
            comm,
            name,
            args_str,
            ret_str,
        });

        let len = self.events.len();
        if len > 0 {
            self.stream_state.select(Some(len - 1));
        }
    }

    /// Run the TUI event loop, consuming events from `rx` until `done` fires.
    ///
    /// This function takes ownership of the terminal, restores it on exit,
    /// and only returns once the user quits or the trace is complete.
    ///
    /// Returns the flamegraph collector if one was configured so the caller
    /// can write the SVG after the terminal is restored.
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<SyscallEvent>,
        mut lib_rx: Option<mpsc::Receiver<LibCallEvent>>,
        mut done: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<Option<FlamegraphCollector>> {
        // Set up the terminal.
        enable_raw_mode()?;
        let mut stderr = io::stderr();
        execute!(stderr, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(io::stderr());
        let mut terminal = Terminal::new(backend)?;

        let result = self
            .event_loop(&mut terminal, &mut rx, &mut lib_rx, &mut done)
            .await;

        // Always restore the terminal, even on error.
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result.map(|()| self.fg_collector)
    }

    async fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
        rx: &mut mpsc::Receiver<SyscallEvent>,
        lib_rx: &mut Option<mpsc::Receiver<LibCallEvent>>,
        done: &mut tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let tick = Duration::from_millis(TICK_MS);

        loop {
            // Drain all pending syscall events.
            loop {
                match rx.try_recv() {
                    Ok(ev) => {
                        self.push(&ev);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.target_exited = true;
                        break;
                    }
                }
            }

            // Drain all pending lib-call events (uprobes).
            if let Some(ref mut lrx) = lib_rx {
                loop {
                    match lrx.try_recv() {
                        Ok(ev) => self.push_lib(&ev),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            }

            terminal.draw(|f| self.render(f))?;

            // Check for keyboard input (non-blocking with tick timeout).
            if event::poll(tick)? {
                if let Event::Key(key) = event::read()? {
                    if self.handle_key(key) {
                        break; // quit requested
                    }
                }
            }

            // Check if the tracer has finished.
            if *done.borrow() && rx.is_empty() {
                // Allow the user to keep reading the output before we exit.
                // They can quit with 'q'.
                self.target_exited = true;
            }
        }

        Ok(())
    }

    /// Handle a key event.  Returns `true` if the user wants to quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // If the detail popup is open, Esc or Enter closes it.
        if self.detail_idx.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.detail_idx = None;
                }
                _ => {}
            }
            return false;
        }

        if self.searching {
            return self.handle_search_key(key);
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,

            KeyCode::Char(' ') => {
                self.paused = !self.paused;
            }

            KeyCode::Char('/') => {
                self.searching = true;
                self.search.clear();
            }

            KeyCode::Char('f') => {
                self.filter.category_files = !self.filter.category_files;
                self.filter.category_net = false;
            }

            KeyCode::Char('n') => {
                self.filter.category_net = !self.filter.category_net;
                self.filter.category_files = false;
            }

            KeyCode::Char('c') => {
                self.events.clear();
                self.counts.clear();
            }

            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_stream(1);
            }

            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_stream(-1);
            }

            KeyCode::PageDown => {
                self.scroll_stream(20);
            }

            KeyCode::PageUp => {
                self.scroll_stream(-20);
            }

            KeyCode::End | KeyCode::Char('G') => {
                let len = self.events.len();
                if len > 0 {
                    self.stream_state.select(Some(len - 1));
                }
            }

            KeyCode::Home | KeyCode::Char('g') => {
                if !self.events.is_empty() {
                    self.stream_state.select(Some(0));
                }
            }

            // Open detail popup for the currently selected syscall event.
            // Lib-call events do not have a detail popup.
            KeyCode::Enter => {
                if let Some(idx) = self.stream_state.selected() {
                    if matches!(self.events.get(idx), Some(TuiEvent::Syscall(_))) {
                        self.detail_idx = Some(idx);
                    }
                }
            }

            _ => {}
        }

        false
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.searching = false;
                self.search.clear();
                // Clear the allowlist set by a previous search.
                self.filter.syscall_allowlist = None;
            }
            KeyCode::Enter => {
                self.searching = false;
                if self.search.is_empty() {
                    self.filter.syscall_allowlist = None;
                } else {
                    self.filter.syscall_allowlist = Some(vec![self.search.clone()]);
                }
            }
            KeyCode::Backspace => {
                self.search.pop();
            }
            KeyCode::Char(c) => {
                self.search.push(c);
            }
            _ => {}
        }
        false
    }

    fn scroll_stream(&mut self, delta: i64) {
        let len = self.events.len();
        if len == 0 {
            return;
        }
        let current = self
            .stream_state
            .selected()
            .unwrap_or(len.saturating_sub(1)) as i64;
        let next = (current + delta).clamp(0, len as i64 - 1) as usize;
        self.stream_state.select(Some(next));
        // If user scrolled up, pause auto-scroll.
        if delta < 0 {
            self.paused = true;
        }
    }

    // ── rendering ────────────────────────────────────────────────────────────

    fn render(&mut self, f: &mut Frame) {
        let area = f.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // header
                Constraint::Min(3),    // main content
                Constraint::Length(1), // footer
            ])
            .split(area);

        self.render_header(f, chunks[0]);
        self.render_main(f, chunks[1]);
        self.render_footer(f, chunks[2]);

        // Detail popup overlays everything else.
        if let Some(idx) = self.detail_idx {
            if let Some(TuiEvent::Syscall(ev)) = self.events.get(idx) {
                render_detail_popup(f, area, ev);
            }
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let elapsed = self.started_at.elapsed();
        let secs = elapsed.as_secs();
        let millis = elapsed.subsec_millis();

        let pid_str = self
            .target_pid
            .map(|p| format!("pid:{p}"))
            .unwrap_or_default();
        let comm_str = if self.target_comm.is_empty() {
            String::new()
        } else {
            format!("  comm:{}", self.target_comm)
        };
        let exited_str = if self.target_exited { "  [exited]" } else { "" };
        let paused_str = if self.paused { "  [PAUSED]" } else { "" };
        let filter_str = self.active_filter_label();

        let text = format!(
            " snoop  {pid_str}{comm_str}  events:{total}  elapsed:{secs}.{millis:03}s{exited_str}{paused_str}{filter_str}",
            total = self.total_events,
        );

        let para = Paragraph::new(text).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        f.render_widget(para, area);
    }

    fn active_filter_label(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.filter.category_files {
            parts.push("files");
        }
        if self.filter.category_net {
            parts.push("net");
        }
        if self.filter.slow_threshold_ns.is_some() {
            parts.push("slow");
        }
        if self.filter.syscall_allowlist.is_some() {
            parts.push("search");
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("  [{}]", parts.join("+"))
        }
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);

        self.render_stream(f, chunks[0]);
        self.render_top_syscalls(f, chunks[1]);
    }

    fn render_stream(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .events
            .iter()
            .map(|entry| match entry {
                TuiEvent::Syscall(e) => {
                    let duration_ms = e.duration_ns as f64 / 1_000_000.0;
                    let elapsed_s = e.timestamp_ns as f64 / 1_000_000_000.0;
                    let color = syscall_color(SyscallNr(name_to_nr(e.name)));
                    let line = Line::from(vec![
                        Span::styled(
                            format!("[{elapsed_s:>8.3}] "),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{:<12} ", e.comm),
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(e.name, Style::default().fg(color)),
                        Span::raw(format!("({}) = {} ", e.args_str, e.ret_str)),
                        Span::styled(
                            format!("<{duration_ms:.3}ms>"),
                            if duration_ms > 10.0 {
                                Style::default().fg(Color::Red)
                            } else {
                                Style::default().fg(Color::DarkGray)
                            },
                        ),
                    ]);
                    ListItem::new(line)
                }
                TuiEvent::LibCall {
                    timestamp_ns,
                    duration_ns,
                    comm,
                    name,
                    args_str,
                    ret_str,
                    ..
                } => {
                    let duration_ms = *duration_ns as f64 / 1_000_000.0;
                    let elapsed_s = *timestamp_ns as f64 / 1_000_000_000.0;
                    let line = Line::from(vec![
                        Span::styled(
                            format!("[{elapsed_s:>8.3}] "),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(format!("{:<12} ", comm), Style::default().fg(Color::Yellow)),
                        Span::styled(*name, Style::default().fg(Color::Cyan)),
                        Span::raw(format!("({args_str}) = {ret_str} ")),
                        Span::styled(
                            format!("<{duration_ms:.3}ms>"),
                            if duration_ms > 10.0 {
                                Style::default().fg(Color::Red)
                            } else {
                                Style::default().fg(Color::DarkGray)
                            },
                        ),
                    ]);
                    ListItem::new(line)
                }
            })
            .collect();

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" syscall stream ");

        let list = List::new(items)
            .block(block)
            .highlight_style(Style::default().bg(Color::DarkGray));

        f.render_stateful_widget(list, area, &mut self.stream_state);
    }

    fn render_top_syscalls(&mut self, f: &mut Frame, area: Rect) {
        let total: u64 = self.counts.values().sum();

        let mut sorted: Vec<(&str, u64)> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        sorted.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let rows: Vec<Row> = sorted
            .iter()
            .take(area.height.saturating_sub(3) as usize)
            .map(|(name, count)| {
                let pct = if total > 0 {
                    (*count as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                // Lib call names are bracketed (e.g. "[SSL_write]"); show them in cyan.
                let color = if name.starts_with('[') {
                    Color::Cyan
                } else {
                    syscall_color(SyscallNr(name_to_nr(name)))
                };
                Row::new(vec![
                    Cell::from(Span::styled(*name, Style::default().fg(color))),
                    Cell::from(format!("{count:>8}")),
                    Cell::from(format!("{pct:>5.1}%")),
                ])
            })
            .collect();

        let widths = [
            Constraint::Min(12),
            Constraint::Length(9),
            Constraint::Length(7),
        ];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["syscall", "   count", "   pct"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" top syscalls "),
            );

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let text = if self.detail_idx.is_some() {
            " [Esc/Enter] close detail".to_owned()
        } else if self.searching {
            format!(" search: {}█", self.search)
        } else {
            " [q]uit  [Space]pause  [Enter]detail  [/]search  [f]iles  [n]et  [c]lear  [↑↓]scroll"
                .to_owned()
        };

        let style = if self.searching {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let para = Paragraph::new(text).style(style);
        f.render_widget(para, area);
    }
}

/// Render a detail popup over the full terminal area for the given event.
fn render_detail_popup(f: &mut Frame, area: Rect, ev: &DecodedEvent) {
    // Centre a box that is 70% wide and 12 rows tall.
    let popup_w = (area.width * 70 / 100)
        .max(50)
        .min(area.width.saturating_sub(4));
    let popup_h = 14u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(x, y, popup_w, popup_h);

    let elapsed_s = ev.timestamp_ns as f64 / 1_000_000_000.0;
    let dur_ms = ev.duration_ns as f64 / 1_000_000.0;

    let lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("syscall:   ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(ev.name, Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("process:   ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{} (pid {}, tid {})", ev.comm, ev.pid, ev.tid)),
        ]),
        Line::from(vec![
            Span::styled("timestamp: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{:.6}s since boot", elapsed_s)),
        ]),
        Line::from(vec![
            Span::styled("duration:  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{:.3}ms", dur_ms),
                if dur_ms > 10.0 {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::White)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("args:      ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(ev.args_str.clone()),
        ]),
        Line::from(vec![
            Span::styled("return:    ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(ev.ret_str.clone()),
        ]),
    ];

    // Clear the background area first so the popup renders cleanly.
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(format!(" {} ", ev.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(para, popup_area);
}

/// Pick a display color for a syscall category.
fn syscall_color(nr: SyscallNr) -> Color {
    // File-system operations.
    const FS: &[SyscallNr] = &[
        SyscallNr::OPEN,
        SyscallNr::OPENAT,
        SyscallNr::READ,
        SyscallNr::WRITE,
        SyscallNr::CLOSE,
        SyscallNr::STAT,
        SyscallNr::FSTAT,
        SyscallNr::LSTAT,
        SyscallNr::PREAD64,
        SyscallNr::PWRITE64,
        SyscallNr::LSEEK,
        SyscallNr::FSTATAT,
        SyscallNr::STATX,
        SyscallNr::GETDENTS64,
        SyscallNr::TRUNCATE,
        SyscallNr::FTRUNCATE,
        SyscallNr::FALLOCATE,
        SyscallNr::RENAME,
        SyscallNr::RENAMEAT,
        SyscallNr::MKDIR,
        SyscallNr::MKDIRAT,
        SyscallNr::RMDIR,
        SyscallNr::UNLINK,
        SyscallNr::UNLINKAT,
        SyscallNr::FSYNC,
        SyscallNr::FDATASYNC,
    ];
    // Network operations.
    const NET: &[SyscallNr] = &[
        SyscallNr::SOCKET,
        SyscallNr::CONNECT,
        SyscallNr::BIND,
        SyscallNr::LISTEN,
        SyscallNr::ACCEPT,
        SyscallNr::ACCEPT4,
        SyscallNr::SENDTO,
        SyscallNr::RECVFROM,
        SyscallNr::SENDMSG,
        SyscallNr::RECVMSG,
        SyscallNr::GETSOCKNAME,
        SyscallNr::GETPEERNAME,
    ];
    // Process lifecycle.
    const PROC: &[SyscallNr] = &[
        SyscallNr::CLONE,
        SyscallNr::CLONE3,
        SyscallNr::FORK,
        SyscallNr::VFORK,
        SyscallNr::EXECVE,
        SyscallNr::EXECVEAT,
        SyscallNr::EXIT,
        SyscallNr::EXIT_GROUP,
        SyscallNr::WAIT4,
        SyscallNr::WAITID,
        SyscallNr::KILL,
    ];
    // Memory management.
    const MEM: &[SyscallNr] = &[
        SyscallNr::MMAP,
        SyscallNr::MPROTECT,
        SyscallNr::MUNMAP,
        SyscallNr::BRK,
        SyscallNr::MADVISE,
    ];

    if FS.contains(&nr) {
        Color::Green
    } else if NET.contains(&nr) {
        Color::Blue
    } else if PROC.contains(&nr) {
        Color::Magenta
    } else if MEM.contains(&nr) {
        Color::Yellow
    } else {
        Color::White
    }
}

/// Reverse lookup: syscall name → raw number.  Used for coloring in the TUI.
/// Returns -1 (unknown) when the name is not recognised.
fn name_to_nr(name: &str) -> i64 {
    // This is a linear scan but only called during rendering of the visible
    // area, so performance is not a concern.
    use snoop_common::SyscallNr as N;
    const TABLE: &[(&str, SyscallNr)] = &[
        ("read", N::READ),
        ("write", N::WRITE),
        ("open", N::OPEN),
        ("close", N::CLOSE),
        ("stat", N::STAT),
        ("fstat", N::FSTAT),
        ("lstat", N::LSTAT),
        ("lseek", N::LSEEK),
        ("mmap", N::MMAP),
        ("mprotect", N::MPROTECT),
        ("munmap", N::MUNMAP),
        ("brk", N::BRK),
        ("ioctl", N::IOCTL),
        ("pread64", N::PREAD64),
        ("pwrite64", N::PWRITE64),
        ("pipe", N::PIPE),
        ("dup", N::DUP),
        ("dup2", N::DUP2),
        ("socket", N::SOCKET),
        ("connect", N::CONNECT),
        ("accept", N::ACCEPT),
        ("sendto", N::SENDTO),
        ("recvfrom", N::RECVFROM),
        ("sendmsg", N::SENDMSG),
        ("recvmsg", N::RECVMSG),
        ("bind", N::BIND),
        ("listen", N::LISTEN),
        ("clone", N::CLONE),
        ("fork", N::FORK),
        ("vfork", N::VFORK),
        ("execve", N::EXECVE),
        ("exit", N::EXIT),
        ("wait4", N::WAIT4),
        ("kill", N::KILL),
        ("fcntl", N::FCNTL),
        ("getcwd", N::GETCWD),
        ("chdir", N::CHDIR),
        ("fchdir", N::FCHDIR),
        ("rename", N::RENAME),
        ("mkdir", N::MKDIR),
        ("rmdir", N::RMDIR),
        ("unlink", N::UNLINK),
        ("futex", N::FUTEX),
        ("accept4", N::ACCEPT4),
        ("dup3", N::DUP3),
        ("pipe2", N::PIPE2),
        ("openat", N::OPENAT),
        ("mkdirat", N::MKDIRAT),
        ("unlinkat", N::UNLINKAT),
        ("renameat", N::RENAMEAT),
        ("fstatat", N::FSTATAT),
        ("execveat", N::EXECVEAT),
        ("clone3", N::CLONE3),
        ("exit_group", N::EXIT_GROUP),
        ("statx", N::STATX),
        ("getdents64", N::GETDENTS64),
        ("getrandom", N::GETRANDOM),
        ("memfd_create", N::MEMFD_CREATE),
        ("ftruncate", N::FTRUNCATE),
        ("truncate", N::TRUNCATE),
        ("fallocate", N::FALLOCATE),
        ("fsync", N::FSYNC),
        ("fdatasync", N::FDATASYNC),
        ("madvise", N::MADVISE),
        ("sendfile", N::SENDFILE),
        ("splice", N::SPLICE),
        ("getsockname", N::GETSOCKNAME),
        ("getpeername", N::GETPEERNAME),
        ("setsockopt", N::SETSOCKOPT),
        ("getsockopt", N::GETSOCKOPT),
        ("prctl", N::PRCTL),
        ("waitid", N::WAITID),
    ];

    TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| nr.0)
        .unwrap_or(-1)
}
