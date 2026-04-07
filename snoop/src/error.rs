//! Error types for the snoop library layer.
//!
//! The binary entry point (`main`) uses `anyhow` for the top-level error
//! chain.  Internal library code uses `SnoopError` via `thiserror` so
//! callers can pattern-match on specific failure modes.

use thiserror::Error;

/// Errors that can occur during eBPF loading and event processing.
#[derive(Debug, Error)]
pub enum SnoopError {
    /// The compiled eBPF object file could not be found or read.
    #[error("eBPF object not found at `{path}`: {source}")]
    EbpfObjectNotFound {
        path: String,
        source: std::io::Error,
    },

    /// aya failed to parse or load the eBPF object.
    #[cfg(target_os = "linux")]
    #[error("eBPF load failed: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    /// A required eBPF map was not present in the loaded object.
    #[error("required eBPF map `{name}` not found in object")]
    MapNotFound { name: &'static str },

    /// A required eBPF program was not present in the loaded object.
    #[error("required eBPF program `{name}` not found in object")]
    ProgramNotFound { name: &'static str },

    /// Attaching a tracepoint failed.
    #[cfg(target_os = "linux")]
    #[error("failed to attach tracepoint `{name}`: {source}")]
    AttachFailed {
        name: &'static str,
        source: aya::programs::ProgramError,
    },

    /// The ring buffer could not be opened.
    #[cfg(target_os = "linux")]
    #[error("ring buffer error: {0}")]
    RingBuf(#[from] aya::maps::MapError),

    /// The target process exited before tracing started.
    #[error("target process (pid {pid}) no longer exists")]
    ProcessGone { pid: u32 },

    /// I/O error (spawning child process, writing output, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
