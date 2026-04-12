//! JSON output mode — one JSON object per syscall, newline-delimited.
//!
//! Each object looks like:
//! ```json
//! {"ts_ns":1234567,"pid":1234,"tid":1234,"comm":"nginx","syscall":"openat",
//!  "args":"AT_FDCWD, \"/etc/passwd\", O_RDONLY","ret":5,"ret_raw":5,
//!  "duration_ns":12345,"uid":1000,"gid":1000}
//! ```
//!
//! The output is [JSON Lines](https://jsonlines.org/) — one object per line,
//! no trailing comma, no surrounding array.  Pipe to `jq` for filtering.

use std::io::{self, Write}; // BufWriter used via Write trait in handle_to

use snoop_common::SyscallEvent;

use crate::decode::DecodedEvent;
use crate::filter::Filter;

/// Writes decoded syscall events to stdout as JSON Lines.
pub struct JsonOutput {
    filter: Filter,
}

impl JsonOutput {
    /// Create a new `JsonOutput` instance.
    pub fn new(filter: Filter) -> Self {
        Self { filter }
    }

    /// Write a single event as a JSON object followed by `\n`.
    ///
    /// Returns `Ok(false)` when the event was filtered out, `Ok(true)` when
    /// it was written.
    pub fn handle(&self, event: &SyscallEvent) -> io::Result<bool> {
        if !self.filter.accepts(event) {
            return Ok(false);
        }

        let decoded = DecodedEvent::from_event(event, !self.filter.no_decode);
        let line = Self::format(&decoded, event);

        let stdout = io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{line}")?;
        Ok(true)
    }

    /// Write a single event to an arbitrary writer (used for `--output-file`).
    ///
    /// Returns `Ok(false)` when filtered out, `Ok(true)` when written.
    pub fn handle_to<W: Write>(&self, writer: &mut W, event: &SyscallEvent) -> io::Result<bool> {
        if !self.filter.accepts(event) {
            return Ok(false);
        }
        let decoded = DecodedEvent::from_event(event, !self.filter.no_decode);
        let line = Self::format(&decoded, event);
        writeln!(writer, "{line}")?;
        Ok(true)
    }

    fn format(e: &DecodedEvent, raw: &SyscallEvent) -> String {
        // Manual JSON serialisation — avoids pulling in serde just for this.
        // All string values are JSON-escaped with `json_escape`.
        format!(
            r#"{{"ts_ns":{ts},"pid":{pid},"tid":{tid},"uid":{uid},"gid":{gid},"comm":{comm},"syscall":{name},"args":{args},"ret":{ret_str},"ret_raw":{ret_raw},"duration_ns":{dur}}}"#,
            ts = e.timestamp_ns,
            pid = e.pid,
            tid = e.tid,
            uid = raw.uid,
            gid = raw.gid,
            comm = json_str(&e.comm),
            name = json_str(e.name),
            args = json_str(&e.args_str),
            ret_str = json_str(&e.ret_str),
            ret_raw = raw.ret,
            dur = e.duration_ns,
        )
    }
}

/// Wrap a string in JSON double-quotes and escape special characters.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_str_plain() {
        assert_eq!(json_str("openat"), "\"openat\"");
    }

    #[test]
    fn json_str_escapes_quotes_and_backslash() {
        assert_eq!(json_str(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(json_str(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn json_str_escapes_control() {
        assert_eq!(json_str("a\nb"), r#""a\nb""#);
        assert_eq!(json_str("a\tb"), r#""a\tb""#);
    }
}
