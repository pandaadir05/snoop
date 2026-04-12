//! Strace-compatible raw output mode.
//!
//! Each line looks like:
//! ```text
//! [14:23:01.234567] nginx(1234/1234) openat(AT_FDCWD, 0x7fff…, O_RDONLY) = 5 <0.043ms>
//! ```

use std::io::{self, Write};

use snoop_common::SyscallEvent;

use crate::decode::DecodedEvent;
use crate::filter::Filter;

/// Writes decoded syscall events to stdout in strace-like format.
pub struct RawOutput {
    filter: Filter,
}

impl RawOutput {
    /// Create a new `RawOutput` instance.
    pub fn new(filter: Filter) -> Self {
        Self { filter }
    }

    /// Write a single event to stdout.
    ///
    /// Returns `Ok(false)` when the event was filtered out, `Ok(true)` when it
    /// was written.
    pub fn handle(&self, event: &SyscallEvent) -> io::Result<bool> {
        if !self.filter.accepts(event) {
            return Ok(false);
        }

        let decoded = DecodedEvent::from_event(event, !self.filter.no_decode);
        let line = self.format_line(&decoded);

        let stdout = io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{line}")?;
        Ok(true)
    }

    /// Write a single event to an arbitrary writer (used for `--output-file`).
    ///
    /// Applies the same filter and formatting as [`handle`].
    /// Returns `Ok(false)` when filtered out, `Ok(true)` when written.
    pub fn handle_to<W: Write>(&self, writer: &mut W, event: &SyscallEvent) -> io::Result<bool> {
        if !self.filter.accepts(event) {
            return Ok(false);
        }
        let decoded = DecodedEvent::from_event(event, !self.filter.no_decode);
        let line = self.format_line(&decoded);
        writeln!(writer, "{line}")?;
        Ok(true)
    }

    fn format_line(&self, e: &DecodedEvent) -> String {
        // Produce a wall-clock-anchored timestamp.
        // `enter_ns` is CLOCK_MONOTONIC since boot; we can't convert it to
        // wall clock without a reference point.  Instead we show the offset
        // from when snoop started.
        let elapsed_us = e.timestamp_ns / 1000;
        let secs = elapsed_us / 1_000_000;
        let micros = elapsed_us % 1_000_000;

        let duration_ms = e.duration_ns as f64 / 1_000_000.0;

        // Determine the syscall name (fall back to numeric for unknowns).
        let name = if e.name == "unknown" {
            format!("syscall_{}", e.pid) // placeholder; real nr in DecodedEvent
        } else {
            e.name.to_owned()
        };

        format!(
            "[{secs:>6}.{micros:06}] {comm}({pid}/{tid}) {name}({args}) = {ret} <{duration_ms:.3}ms>",
            secs = secs,
            micros = micros,
            comm = e.comm,
            pid = e.pid,
            tid = e.tid,
            name = name,
            args = e.args_str,
            ret = e.ret_str,
            duration_ms = duration_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::{SyscallEvent, SyscallNr};

    fn make_filter() -> Filter {
        Filter {
            category_files: false,
            category_net: false,
            slow_threshold_ns: None,
            syscall_allowlist: None,
            no_decode: false,
        }
    }

    #[test]
    fn format_does_not_panic() {
        let out = RawOutput::new(make_filter());
        let event = SyscallEvent {
            pid: 42,
            tid: 42,
            uid: 0,
            gid: 0,
            syscall_nr: SyscallNr::OPENAT.0,
            args: [18446744073709551516, 0x7fff_0000, 0, 0, 0, 0], // AT_FDCWD
            ret: 5,
            enter_ns: 1_000_000_000,
            exit_ns: 1_000_043_000,
            comm: *b"nginx\0\0\0\0\0\0\0\0\0\0\0",
            path: [0; snoop_common::PATH_MAX_LEN],
            path_len: 0,
            sockaddr: [0; 28],
            sockaddr_len: 0,
            argv_extra: [0; snoop_common::ARGV_EXTRA_MAX],
            argv_extra_len: 0,
            _pad: [0; 3],
        };
        let decoded = DecodedEvent::from_event(&event, true);
        let line = out.format_line(&decoded);
        assert!(line.contains("openat"));
        assert!(line.contains("nginx"));
    }
}
