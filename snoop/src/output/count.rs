//! Count mode — accumulate per-syscall statistics and print a summary table.
//!
//! Produces output similar to `strace -c`:
//!
//! ```text
//! % time     seconds  usecs/call     calls    errors  syscall
//! ------ ----------- ----------- --------- --------- ----------------
//!  72.14    0.001234         411         3         0  read
//!  22.10    0.000378         378         1         0  openat
//!   5.76    0.000098          98         1         1  connect
//! ------ ----------- ----------- --------- --------- ----------------
//! 100.00    0.001710                     5         1  total
//! ```
//!
//! The table is written to stdout when [`CountOutput::finish`] is called,
//! typically at the end of the trace.

use std::collections::HashMap;
use std::io::{self, Write};

use snoop_common::SyscallEvent;

use crate::{decode::syscall_name, filter::Filter};

// ── per-syscall stats ─────────────────────────────────────────────────────────

struct Stat {
    count: u64,
    errors: u64,
    total_ns: u64,
    min_ns: u64,
    max_ns: u64,
}

impl Stat {
    fn new(duration_ns: u64, is_error: bool) -> Self {
        Self {
            count: 1,
            errors: u64::from(is_error),
            total_ns: duration_ns,
            min_ns: duration_ns,
            max_ns: duration_ns,
        }
    }

    fn record(&mut self, duration_ns: u64, is_error: bool) {
        self.count += 1;
        if is_error {
            self.errors += 1;
        }
        self.total_ns += duration_ns;
        if duration_ns < self.min_ns {
            self.min_ns = duration_ns;
        }
        if duration_ns > self.max_ns {
            self.max_ns = duration_ns;
        }
    }

    fn usecs_per_call(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        self.total_ns / self.count / 1000
    }
}

// ── CountOutput ───────────────────────────────────────────────────────────────

/// Accumulates per-syscall statistics for a running trace.
///
/// Feed events via [`CountOutput::handle`]; call [`CountOutput::finish`] when
/// the trace ends to print the summary table.
pub struct CountOutput {
    filter: Filter,
    stats: HashMap<&'static str, Stat>,
}

impl CountOutput {
    /// Create a new, empty `CountOutput`.
    pub fn new(filter: Filter) -> Self {
        Self {
            filter,
            stats: HashMap::new(),
        }
    }

    /// Record one event.
    pub fn handle(&mut self, event: &SyscallEvent) {
        if !self.filter.accepts(event) {
            return;
        }

        let snoop_common::SyscallNr(nr) = snoop_common::SyscallNr(event.syscall_nr);
        let name = syscall_name(snoop_common::SyscallNr(nr));
        let duration_ns = event.exit_ns.saturating_sub(event.enter_ns);
        let is_error = event.ret < 0;

        self.stats
            .entry(name)
            .and_modify(|s| s.record(duration_ns, is_error))
            .or_insert_with(|| Stat::new(duration_ns, is_error));
    }

    /// Print the summary table to stdout.
    ///
    /// Rows are sorted by total time descending.
    pub fn finish(&self) -> io::Result<()> {
        if self.stats.is_empty() {
            eprintln!("(no syscalls recorded)");
            return Ok(());
        }

        let total_ns: u64 = self.stats.values().map(|s| s.total_ns).sum();
        let total_calls: u64 = self.stats.values().map(|s| s.count).sum();
        let total_errors: u64 = self.stats.values().map(|s| s.errors).sum();

        // Sort by total time descending; tie-break alphabetically.
        let mut rows: Vec<(&str, &Stat)> = self.stats.iter().map(|(&n, s)| (n, s)).collect();
        rows.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns).then(a.0.cmp(b.0)));

        let stdout = io::stdout();
        let mut out = stdout.lock();

        let sep = format!(
            "{:-<6} {:-<11} {:-<11} {:-<9} {:-<9} {:-<16}",
            "", "", "", "", "", ""
        );

        writeln!(
            out,
            "{:>6} {:>11} {:>11} {:>9} {:>9}  {:<16}",
            "% time", "seconds", "usecs/call", "calls", "errors", "syscall"
        )?;
        writeln!(out, "{sep}")?;

        for (name, stat) in &rows {
            let pct = if total_ns > 0 {
                stat.total_ns as f64 / total_ns as f64 * 100.0
            } else {
                0.0
            };
            let secs = stat.total_ns as f64 / 1_000_000_000.0;
            let upc = stat.usecs_per_call();
            let errors = if stat.errors > 0 {
                format!("{:>9}", stat.errors)
            } else {
                format!("{:>9}", "")
            };

            writeln!(
                out,
                "{:>6.2} {:>11.6} {:>11} {:>9} {errors}  {:<16}",
                pct, secs, upc, stat.count, name,
            )?;
        }

        writeln!(out, "{sep}")?;

        let total_secs = total_ns as f64 / 1_000_000_000.0;
        let total_errors_str = if total_errors > 0 {
            format!("{total_errors:>9}")
        } else {
            format!("{:>9}", "")
        };
        writeln!(
            out,
            "{:>6.2} {:>11.6} {:>11} {:>9} {total_errors_str}  {:<16}",
            100.0f64, total_secs, "", total_calls, "total",
        )?;

        Ok(())
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::{SyscallNr, ARGV_EXTRA_MAX, PATH_MAX_LEN, SOCKADDR_MAX_LEN};

    fn make_filter() -> Filter {
        Filter {
            category_files: false,
            category_net: false,
            slow_threshold_ns: None,
            syscall_allowlist: None,
            no_decode: false,
        }
    }

    fn make_event(nr: SyscallNr, ret: i64, duration_ns: u64) -> SyscallEvent {
        SyscallEvent {
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_nr: nr.0,
            args: [0; 6],
            ret,
            enter_ns: 1_000_000_000,
            exit_ns: 1_000_000_000 + duration_ns,
            comm: [0; 16],
            path: [0; PATH_MAX_LEN],
            path_len: 0,
            sockaddr: [0; SOCKADDR_MAX_LEN],
            sockaddr_len: 0,
            argv_extra: [0; ARGV_EXTRA_MAX],
            argv_extra_len: 0,
            _pad: [0; 3],
        }
    }

    #[test]
    fn counts_accumulate() {
        let mut out = CountOutput::new(make_filter());
        out.handle(&make_event(SyscallNr::READ, 100, 1_000));
        out.handle(&make_event(SyscallNr::READ, 200, 2_000));
        out.handle(&make_event(SyscallNr::OPENAT, -2, 500));

        let read_stat = &out.stats["read"];
        assert_eq!(read_stat.count, 2);
        assert_eq!(read_stat.errors, 0);
        assert_eq!(read_stat.total_ns, 3_000);

        let open_stat = &out.stats["openat"];
        assert_eq!(open_stat.errors, 1);
    }

    #[test]
    fn finish_does_not_panic_on_empty() {
        let out = CountOutput::new(make_filter());
        // Should not panic; writes to stderr.
        out.finish().unwrap();
    }
}
