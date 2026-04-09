//! Trace file viewer — replays a `.snoop` file through the normal output pipeline.
//!
//! No eBPF or root required.  The viewer reads events from disk and passes
//! them through exactly the same filter → decode → output path as live tracing.

use std::path::Path;

use anyhow::Result;
use tokio::sync::{mpsc, watch};

use crate::{
    filter::Filter,
    output::{explain::ExplainOutput, json::JsonOutput, raw::RawOutput, tui::TuiApp, OutputMode},
    record::TraceReader,
};

/// Replay a trace file through the chosen output mode.
///
/// Applies `filter` so the user can slice the trace post-hoc without root.
pub async fn run(path: &Path, filter: Filter, mode: OutputMode) -> Result<()> {
    // Read all events into an in-memory channel so the TUI async event loop
    // works without modification.  For very large traces this is fine — a
    // 1 M event trace is about 280 MiB; acceptable for an analysis tool.
    let mut reader = TraceReader::open(path)?;

    match mode {
        OutputMode::Raw => {
            let out = RawOutput::new(filter);
            while let Some(event) = reader.next_event()? {
                out.handle(&event)?;
            }
        }
        OutputMode::Json => {
            let out = JsonOutput::new(filter);
            while let Some(event) = reader.next_event()? {
                out.handle(&event)?;
            }
        }
        OutputMode::Explain => {
            let mut out = ExplainOutput::new(filter);
            while let Some(event) = reader.next_event()? {
                out.handle(&event)?;
            }
            out.flush()?;
        }
        OutputMode::Tui => {
            // Feed events through a channel so the existing TuiApp code is
            // reused unchanged.  The done signal fires immediately after all
            // events are queued.
            let (tx, rx) = mpsc::channel(4096);
            let (done_tx, done_rx) = watch::channel(false);

            // Spawn a task that feeds all events into the channel.
            tokio::spawn(async move {
                while let Ok(Some(event)) = reader.next_event().map_err(|_| ()) {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                // Signal that all events have been sent.
                let _ = done_tx.send(true);
            });

            let app = TuiApp::new(filter, None);
            app.run(rx, done_rx).await?;
        }
    }

    Ok(())
}
