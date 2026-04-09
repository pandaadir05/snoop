//! Output modes.

pub mod explain;
pub mod json;
pub mod raw;
pub mod tui;

/// Which output mode to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// One line per syscall, strace-compatible, suitable for piping.
    Raw,
    /// Full-screen ratatui TUI.
    Tui,
    /// JSON objects, one per line (NDJSON / JSON Lines).
    Json,
    /// High-level activity summaries (explain mode).
    Explain,
}
