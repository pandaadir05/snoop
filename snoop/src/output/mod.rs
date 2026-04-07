//! Output modes.

pub mod raw;
pub mod tui;

/// Which output mode to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// One line per syscall, strace-compatible, suitable for piping.
    Raw,
    /// Full-screen ratatui TUI.
    Tui,
}
