//! Explain-mode output — prints high-level [`Activity`] summaries to stdout.
//!
//! Each line looks like:
//! ```text
//! [  12.345678]  nginx(1234)  READ   /etc/nginx/nginx.conf  ↓4.2 KB  (3 calls, 1.30ms)
//! [  12.346000]  nginx(1234)  NET    127.0.0.1:8080  ↑512 B ↓4.0 KB  (18.20ms)
//! [  12.350000]  nginx(1234)  EXEC   /usr/sbin/nginx
//! ```

use std::fs::File;
use std::io::{self, BufWriter, Write};

use crate::{
    explain::{Activity, ActivityKind},
    filter::Filter,
};
use snoop_common::SyscallEvent;

use crate::explain::Explainer;

/// Drives the explain output pipeline.
pub struct ExplainOutput {
    filter: Filter,
    explainer: Explainer,
    /// Optional tee writer for `--output-file`.
    tee: Option<BufWriter<File>>,
}

impl ExplainOutput {
    /// Create a new `ExplainOutput`.
    pub fn new(filter: Filter) -> Self {
        Self {
            filter,
            explainer: Explainer::new(),
            tee: None,
        }
    }

    /// Attach a tee writer so activities are also written to `--output-file`.
    pub fn set_tee(&mut self, tee: Option<BufWriter<File>>) {
        self.tee = tee;
    }

    /// Feed a raw event.  Returns `true` if an activity was printed.
    pub fn handle(&mut self, event: &SyscallEvent) -> io::Result<bool> {
        if !self.filter.accepts(event) {
            return Ok(false);
        }
        let activities = self.explainer.push(event);
        let wrote = !activities.is_empty();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for act in &activities {
            let line = format_activity(act);
            writeln!(out, "{line}")?;
            if let Some(ref mut w) = self.tee {
                writeln!(w, "{line}")?;
            }
        }
        Ok(wrote)
    }

    /// Flush pending (unclosed) activities at end-of-trace.
    pub fn flush(&mut self) -> io::Result<()> {
        let activities = self.explainer.flush();
        if activities.is_empty() {
            return Ok(());
        }
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for act in &activities {
            let line = format_activity(act);
            writeln!(out, "{line}")?;
            if let Some(ref mut w) = self.tee {
                writeln!(w, "{line}")?;
            }
        }
        Ok(())
    }
}

/// Format one [`Activity`] as a display line.
fn format_activity(act: &Activity) -> String {
    let elapsed_us = act.timestamp_ns / 1000;
    let secs = elapsed_us / 1_000_000;
    let micros = elapsed_us % 1_000_000;

    let kind_tag = kind_label(act.kind);

    format!(
        "[{secs:>6}.{micros:06}]  {comm}({pid})  {kind_tag}  {summary}",
        secs = secs,
        micros = micros,
        comm = act.comm,
        pid = act.pid,
        kind_tag = kind_tag,
        summary = act.summary,
    )
}

fn kind_label(kind: ActivityKind) -> &'static str {
    match kind {
        ActivityKind::FileRead => "FILE ",
        ActivityKind::FileWrite => "FILE ",
        ActivityKind::FileReadWrite => "FILE ",
        ActivityKind::Network => "NET  ",
        ActivityKind::Exec => "EXEC ",
        ActivityKind::Fork => "FORK ",
    }
}
