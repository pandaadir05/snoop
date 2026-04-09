//! Raw-text and JSON formatting for [`LibCallEvent`]s.
//!
//! Lines in raw mode look like:
//! ```text
//! [  12.345678] nginx(1234/1234) [SSL_write](512 B) = 512 <0.020ms>
//! [  12.346000] nginx(1234/1234) [malloc](4096) = 0x7f8bca001ab0 <0.001ms>
//! ```

use std::io::{self, Write};

use snoop_common::{LibCallEvent, LibFunc};

use crate::decode::comm_to_string;

// ── raw output ────────────────────────────────────────────────────────────────

/// Write a `LibCallEvent` to stdout in strace-style format.
pub fn write_raw(event: &LibCallEvent) -> io::Result<()> {
    let line = format_raw(event);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{line}")
}

/// Format a `LibCallEvent` as a single display line.
pub fn format_raw(event: &LibCallEvent) -> String {
    let elapsed_us = event.enter_ns / 1000;
    let secs    = elapsed_us / 1_000_000;
    let micros  = elapsed_us % 1_000_000;
    let dur_ms  = event.duration_ns() as f64 / 1_000_000.0;
    let comm    = comm_to_string(&event.comm);

    let func_name = event.lib_func().map(|f| f.name()).unwrap_or("?");
    let args_str  = format_args(event);
    let ret_str   = format_ret(event);

    format!(
        "[{secs:>6}.{micros:06}] {comm}({pid}/{tid}) [{func_name}]({args_str}) = {ret_str} <{dur_ms:.3}ms>",
        pid = event.pid,
        tid = event.tid,
    )
}

/// Produce a short arg summary for the function.
pub fn format_args(event: &LibCallEvent) -> String {
    let args = &event.args;
    match event.lib_func() {
        Some(LibFunc::SslWrite) => {
            let len = args[2];
            if event.data_len > 0 {
                format!("{len} B, data=[{}…]", hex_preview(&event.data, event.data_len))
            } else {
                format!("{len} B")
            }
        }
        Some(LibFunc::SslRead) => {
            if event.data_len > 0 {
                format!("data=[{}…]", hex_preview(&event.data, event.data_len))
            } else {
                String::new()
            }
        }
        Some(LibFunc::Malloc) => format!("{}", args[0]),
        Some(LibFunc::Free)   => format!("{:#x}", args[0]),
        Some(LibFunc::Calloc) => format!("{} × {}", args[0], args[1]),
        Some(LibFunc::Realloc) => format!("{:#x}, {}", args[0], args[1]),
        None => format!("{:#x}", args[0]),
    }
}

/// Format the return value for the function.
pub fn format_ret(event: &LibCallEvent) -> String {
    let ret = event.ret;
    match event.lib_func() {
        Some(LibFunc::SslWrite) | Some(LibFunc::SslRead) => {
            if ret < 0 {
                format!("{ret} (SSL error)")
            } else {
                format!("{ret} B")
            }
        }
        Some(LibFunc::Free) => "void".to_owned(),
        _ => {
            if ret == 0 {
                "NULL".to_owned()
            } else {
                format!("{ret:#x}")
            }
        }
    }
}

/// Show up to 8 bytes of data as hex.
fn hex_preview(data: &[u8; 256], data_len: u16) -> String {
    let n = (data_len as usize).min(8);
    data[..n]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── JSON output ───────────────────────────────────────────────────────────────

/// Write a `LibCallEvent` as a JSON Lines object to stdout.
pub fn write_json(event: &LibCallEvent) -> io::Result<()> {
    let func_name = event.lib_func().map(|f| f.name()).unwrap_or("unknown");
    let comm      = comm_to_string(&event.comm);
    let dur_ns    = event.duration_ns();
    let ret       = event.ret;

    // Inline the data as a hex string when present.
    let data_hex = if event.data_len > 0 {
        let n = event.data_len as usize;
        event.data[..n]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    } else {
        String::new()
    };

    let line = format!(
        r#"{{"kind":"lib","pid":{pid},"tid":{tid},"comm":"{comm}","func":"{func_name}","ret":{ret},"duration_ns":{dur_ns},"data":"{data_hex}"}}"#,
        pid = event.pid,
        tid = event.tid,
    );

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{line}")
}

// ── TUI display helper ────────────────────────────────────────────────────────

/// The `&'static str` name shown in the TUI syscall-stream list.
///
/// Wraps the function name in brackets so lib calls are visually distinct
/// from syscalls (e.g. `[SSL_write]` vs `openat`).
pub fn tui_name(func: LibFunc) -> &'static str {
    match func {
        LibFunc::SslWrite  => "[SSL_write]",
        LibFunc::SslRead   => "[SSL_read]",
        LibFunc::Malloc    => "[malloc]",
        LibFunc::Free      => "[free]",
        LibFunc::Calloc    => "[calloc]",
        LibFunc::Realloc   => "[realloc]",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::TLS_DATA_MAX;

    fn make_ssl_event(func: LibFunc, ret: i64, data: &[u8]) -> LibCallEvent {
        let mut ev = LibCallEvent {
            pid: 1,
            tid: 1,
            func: func as u8,
            _pad: [0; 3],
            enter_ns: 1_000_000_000,
            exit_ns:  1_000_020_000,
            comm: *b"nginx\0\0\0\0\0\0\0\0\0\0\0",
            args: [0, 0, data.len() as u64, 0, 0, 0],
            ret,
            data: [0; TLS_DATA_MAX],
            data_len: data.len() as u16,
            _pad2: [0; 6],
        };
        let n = data.len().min(TLS_DATA_MAX);
        ev.data[..n].copy_from_slice(&data[..n]);
        ev
    }

    #[test]
    fn format_ssl_write() {
        let ev = make_ssl_event(LibFunc::SslWrite, 16, b"GET / HTTP/1.1\r\n");
        let line = format_raw(&ev);
        assert!(line.contains("[SSL_write]"));
        assert!(line.contains("16 B"));
    }

    #[test]
    fn format_malloc() {
        let mut ev = make_ssl_event(LibFunc::Malloc, 0x7fff0000_i64, &[]);
        ev.args[0] = 4096;
        let line = format_raw(&ev);
        assert!(line.contains("[malloc]"));
        assert!(line.contains("4096"));
    }
}
