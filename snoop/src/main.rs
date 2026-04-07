//! snoop — a modern syscall tracer for Linux, built on eBPF.
//!
//! Entry point: parse CLI, check privileges, hand off to the tracer.

// On non-Linux hosts the eBPF-dependent modules (tracer, loader) are
// excluded.  The modules that feed them (filter, decode, output) still compile
// for IDE support and type-checking but nothing calls them, so silence the
// resulting dead_code / unused_imports lints.  All code here is intentionally
// Linux-only at runtime.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod cli;
mod decode;
mod error;
mod filter;
mod output;

#[cfg(target_os = "linux")]
mod loader;
#[cfg(target_os = "linux")]
mod tracer;

use anyhow::Result;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .init();

    let cli = Cli::parse_args();
    cli.run().await
}
