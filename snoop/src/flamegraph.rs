//! Flamegraph export using the `inferno` library.
//!
//! Accumulates syscall events as folded stack entries in the format that
//! `inferno-flamegraph` expects:
//!
//! ```text
//! comm;syscall_name <duration_ns>
//! ```
//!
//! Call [`FlamegraphCollector::record`] for each event, then
//! [`FlamegraphCollector::write_svg`] at the end to produce the SVG file.

use std::io::BufWriter;
use std::path::Path;

use anyhow::{Context, Result};
use inferno::flamegraph::{self, Options};
use snoop_common::SyscallEvent;

use crate::decode::{comm_to_string, syscall_name};
use snoop_common::SyscallNr;

/// Collects folded-stack entries from syscall events and renders an SVG.
pub struct FlamegraphCollector {
    /// Each entry is `"comm;syscall_name duration_ns\n"`.
    lines: Vec<String>,
}

impl FlamegraphCollector {
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Record one syscall event.  The duration is used as the sample count so
    /// that wide frames indicate slow syscalls.
    pub fn record(&mut self, event: &SyscallEvent) {
        let duration = event.duration_ns();
        if duration == 0 {
            return;
        }
        let comm = comm_to_string(&event.comm);
        let name = syscall_name(SyscallNr(event.syscall_nr));
        self.lines
            .push(format!("{comm};{name} {duration}\n"));
    }

    /// Render the accumulated entries to an SVG flamegraph at `path`.
    ///
    /// Returns `Ok(())` without writing if no events were recorded.
    pub fn write_svg(&self, path: &Path) -> Result<()> {
        if self.lines.is_empty() {
            log::warn!("flamegraph: no events recorded, skipping SVG write");
            return Ok(());
        }

        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to create flamegraph file: {}", path.display()))?;
        let writer = BufWriter::new(file);

        let mut opts = Options::default();
        opts.title = "snoop syscall flamegraph".to_owned();
        opts.count_name = "ns".to_owned();
        opts.colors = flamegraph::color::Palette::Basic(flamegraph::color::BasicPalette::Hot);

        // `inferno` reads the folded lines from an iterator of `&str`.
        let input: Vec<&str> = self.lines.iter().map(|s| s.trim_end()).collect();
        flamegraph::from_lines(&mut opts, input.into_iter(), writer)
            .context("inferno failed to render flamegraph")?;

        log::info!("flamegraph written to {}", path.display());
        Ok(())
    }
}
