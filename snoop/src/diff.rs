//! Trace diff — compare two `.snoop` files and summarise differences.
//!
//! `snoop diff a.snoop b.snoop` produces a human-readable report showing:
//!
//! * Syscalls that appear in one trace but not the other
//! * Per-syscall call-count changes
//! * Per-syscall median-duration changes (regression detection)
//! * Top slowest individual events unique to each trace
//!
//! The diff is at the *population* level, not line-by-line — it answers
//! "what changed about the behaviour of this program?" rather than
//! "which exact events differ?".

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;

use crate::{decode::syscall_name, record::TraceReader};
use snoop_common::{SyscallEvent, SyscallNr};

// ── data collection ───────────────────────────────────────────────────────────

#[derive(Default)]
struct Profile {
    /// Per-syscall list of durations (nanoseconds).
    durations: HashMap<&'static str, Vec<u64>>,
    /// Total events seen.
    total: u64,
}

impl Profile {
    fn ingest(&mut self, event: &SyscallEvent) {
        self.total += 1;
        let name = syscall_name(SyscallNr(event.syscall_nr));
        self.durations
            .entry(name)
            .or_default()
            .push(event.duration_ns());
    }

    fn count(&self, name: &str) -> u64 {
        self.durations
            .get(name)
            .map(|v| v.len() as u64)
            .unwrap_or(0)
    }

    fn median_ns(&self, name: &str) -> u64 {
        let v = match self.durations.get(name) {
            Some(v) if !v.is_empty() => v,
            _ => return 0,
        };
        let mut sorted = v.clone();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    fn syscall_names(&self) -> impl Iterator<Item = &&'static str> {
        self.durations.keys()
    }
}

fn load_profile(path: &Path) -> Result<Profile> {
    let mut reader = TraceReader::open(path)?;
    let mut profile = Profile::default();
    while let Some(event) = reader.next_event()? {
        profile.ingest(&event);
    }
    Ok(profile)
}

// ── diff output ───────────────────────────────────────────────────────────────

/// Run a diff between `a` and `b` and print the report to stdout.
pub fn run(path_a: &Path, path_b: &Path) -> Result<()> {
    let pa = load_profile(path_a)?;
    let pb = load_profile(path_b)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "snoop diff")?;
    writeln!(out, "  a: {} ({} events)", path_a.display(), pa.total)?;
    writeln!(out, "  b: {} ({} events)", path_b.display(), pb.total)?;
    writeln!(out)?;

    // Collect all syscall names seen in either trace.
    let mut all_names: Vec<&'static str> = {
        let mut s: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for n in pa.syscall_names() {
            s.insert(n);
        }
        for n in pb.syscall_names() {
            s.insert(n);
        }
        let mut v: Vec<_> = s.into_iter().collect();
        v.sort_unstable();
        v
    };

    // ── count changes ──────────────────────────────────────────────────────
    writeln!(out, "CALL COUNTS")?;
    writeln!(
        out,
        "{:<20} {:>10} {:>10} {:>10}",
        "syscall", "a", "b", "delta"
    )?;
    writeln!(out, "{}", "─".repeat(54))?;

    // Sort by absolute delta descending for relevance.
    all_names.sort_by_key(|n| {
        let ca = pa.count(n) as i64;
        let cb = pb.count(n) as i64;
        -(cb - ca).abs()
    });

    let mut printed_counts = 0;
    for name in &all_names {
        let ca = pa.count(name);
        let cb = pb.count(name);
        if ca == cb && ca > 0 {
            continue; // skip unchanged
        }
        let delta = cb as i64 - ca as i64;
        writeln!(out, "{:<20} {:>10} {:>10} {:>+10}", name, ca, cb, delta,)?;
        printed_counts += 1;
    }
    if printed_counts == 0 {
        writeln!(out, "  (no count changes)")?;
    }
    writeln!(out)?;

    // ── duration regressions ───────────────────────────────────────────────
    writeln!(out, "MEDIAN DURATION (ms)")?;
    writeln!(
        out,
        "{:<20} {:>12} {:>12} {:>12}",
        "syscall", "a", "b", "delta"
    )?;
    writeln!(out, "{}", "─".repeat(60))?;

    let mut dur_rows: Vec<(&'static str, f64, f64, f64)> = all_names
        .iter()
        .filter_map(|&name| {
            let ma = pa.median_ns(name) as f64 / 1_000_000.0;
            let mb = pb.median_ns(name) as f64 / 1_000_000.0;
            let delta = mb - ma;
            // Only show if both traces have the syscall and delta is meaningful.
            if pa.count(name) > 0 && pb.count(name) > 0 && delta.abs() > 0.01 {
                Some((name, ma, mb, delta))
            } else {
                None
            }
        })
        .collect();

    // Sort by absolute delta descending.
    dur_rows.sort_by(|a, b| {
        b.3.abs()
            .partial_cmp(&a.3.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if dur_rows.is_empty() {
        writeln!(out, "  (no significant duration changes)")?;
    } else {
        for (name, ma, mb, delta) in &dur_rows {
            writeln!(
                out,
                "{:<20} {:>11.3}ms {:>11.3}ms {:>+11.3}ms",
                name, ma, mb, delta,
            )?;
        }
    }
    writeln!(out)?;

    // ── syscalls only in a ─────────────────────────────────────────────────
    let only_a: Vec<&str> = all_names
        .iter()
        .filter(|&&n| pa.count(n) > 0 && pb.count(n) == 0)
        .copied()
        .collect();
    if !only_a.is_empty() {
        writeln!(out, "ONLY IN a")?;
        for name in &only_a {
            writeln!(out, "  {} ({}x)", name, pa.count(name))?;
        }
        writeln!(out)?;
    }

    // ── syscalls only in b ─────────────────────────────────────────────────
    let only_b: Vec<&str> = all_names
        .iter()
        .filter(|&&n| pb.count(n) > 0 && pa.count(n) == 0)
        .copied()
        .collect();
    if !only_b.is_empty() {
        writeln!(out, "ONLY IN b")?;
        for name in &only_b {
            writeln!(out, "  {} ({}x)", name, pb.count(name))?;
        }
        writeln!(out)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::SyscallNr;

    fn make_event(syscall_nr: i64, duration_ns: u64) -> SyscallEvent {
        SyscallEvent {
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_nr,
            args: [0; 6],
            ret: 0,
            enter_ns: 1000,
            exit_ns: 1000 + duration_ns,
            comm: [0; 16],
            path: [0; snoop_common::PATH_MAX_LEN],
            path_len: 0,
            sockaddr: [0; 28],
            sockaddr_len: 0,
            argv_extra: [0; snoop_common::ARGV_EXTRA_MAX],
            argv_extra_len: 0,
            _pad: [0; 3],
        }
    }

    #[test]
    fn profile_counts_and_median() {
        let mut p = Profile::default();
        p.ingest(&make_event(SyscallNr::READ.0, 1_000));
        p.ingest(&make_event(SyscallNr::READ.0, 3_000));
        p.ingest(&make_event(SyscallNr::READ.0, 5_000));
        p.ingest(&make_event(SyscallNr::WRITE.0, 2_000));

        assert_eq!(p.count("read"), 3);
        assert_eq!(p.count("write"), 1);
        assert_eq!(p.count("openat"), 0);
        assert_eq!(p.median_ns("read"), 3_000);
        assert_eq!(p.total, 4);
    }

    #[test]
    fn diff_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let pa = dir.path().join("a.snoop");
        let pb = dir.path().join("b.snoop");

        let mut wa = crate::record::TraceWriter::create(&pa).unwrap();
        wa.write_event(&make_event(SyscallNr::READ.0, 1_000))
            .unwrap();
        wa.write_event(&make_event(SyscallNr::OPENAT.0, 2_000))
            .unwrap();
        wa.finish().unwrap();

        let mut wb = crate::record::TraceWriter::create(&pb).unwrap();
        wb.write_event(&make_event(SyscallNr::READ.0, 5_000))
            .unwrap();
        wb.write_event(&make_event(SyscallNr::WRITE.0, 1_000))
            .unwrap();
        wb.finish().unwrap();

        // Should not panic and should produce output.
        run(&pa, &pb).unwrap();
    }
}
