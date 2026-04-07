//! Binary trace recording and replay.
//!
//! # Format
//!
//! A `.snoop` file is a sequence of length-prefixed frames:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  magic: [u8; 8]  = b"SNOOP\x00\x01\x00"                           │  file header
//! │  version: u16    = 1                                                │
//! │  _reserved: [u8; 6]                                                 │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  len: u32 (little-endian)  — byte length of the following payload  │  repeated
//! │  payload: [u8; len]        — raw bytes of one SyscallEvent         │  per event
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The `SyscallEvent` struct is `#[repr(C)]` and stable; the version field in
//! the header guards against layout changes in future releases.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::mem;
use std::path::Path;

use anyhow::{bail, Context, Result};
use snoop_common::SyscallEvent;

const MAGIC: &[u8; 8] = b"SNOOP\x00\x01\x00";
const VERSION: u16 = 1;
const EVENT_SIZE: u32 = mem::size_of::<SyscallEvent>() as u32;

// ── writing ───────────────────────────────────────────────────────────────────

/// Writes `SyscallEvent`s to a `.snoop` file.
pub struct TraceWriter {
    inner: BufWriter<File>,
    count: u64,
}

impl TraceWriter {
    /// Create (or truncate) a trace file at `path` and write the file header.
    pub fn create(path: &Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("cannot create trace file: {}", path.display()))?;
        let mut inner = BufWriter::new(file);
        write_header(&mut inner)?;
        Ok(Self { inner, count: 0 })
    }

    /// Append one event to the trace.
    pub fn write_event(&mut self, event: &SyscallEvent) -> io::Result<()> {
        // Write the 4-byte length prefix followed by the raw event bytes.
        self.inner.write_all(&EVENT_SIZE.to_le_bytes())?;
        // Safety: SyscallEvent is repr(C) + Copy; we transmute it to bytes.
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (event as *const SyscallEvent) as *const u8,
                mem::size_of::<SyscallEvent>(),
            )
        };
        self.inner.write_all(bytes)?;
        self.count += 1;
        Ok(())
    }

    /// Flush and close the trace file.  Returns the number of events written.
    pub fn finish(mut self) -> io::Result<u64> {
        self.inner.flush()?;
        Ok(self.count)
    }
}

fn write_header(w: &mut impl Write) -> io::Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    w.write_all(&[0u8; 6])?; // reserved
    Ok(())
}

// ── reading ───────────────────────────────────────────────────────────────────

/// Reads `SyscallEvent`s from a `.snoop` file.
pub struct TraceReader {
    inner: BufReader<File>,
}

impl TraceReader {
    /// Open a trace file and validate the header.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("cannot open trace file: {}", path.display()))?;
        let mut inner = BufReader::new(file);
        read_header(&mut inner)?;
        Ok(Self { inner })
    }

    /// Read the next event from the trace.  Returns `Ok(None)` at EOF.
    pub fn next_event(&mut self) -> Result<Option<SyscallEvent>> {
        let mut len_buf = [0u8; 4];
        match self.inner.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_le_bytes(len_buf);
        if len != EVENT_SIZE {
            bail!(
                "trace format error: expected event size {EVENT_SIZE}, got {len}. \
                 The trace was recorded with a different version of snoop."
            );
        }

        let mut event = mem::MaybeUninit::<SyscallEvent>::uninit();
        let bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                event.as_mut_ptr() as *mut u8,
                mem::size_of::<SyscallEvent>(),
            )
        };
        self.inner
            .read_exact(bytes)
            .context("unexpected EOF while reading event")?;

        // Safety: we just filled all bytes from a valid file; SyscallEvent is
        // repr(C) + Copy with no padding that requires initialisation.
        Ok(Some(unsafe { event.assume_init() }))
    }
}

fn read_header(r: &mut impl Read) -> Result<()> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).context("failed to read trace header")?;
    if &magic != MAGIC {
        bail!("not a snoop trace file (bad magic bytes)");
    }
    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf).context("failed to read trace version")?;
    let version = u16::from_le_bytes(ver_buf);
    if version != VERSION {
        bail!("unsupported trace version {version} (this snoop understands version {VERSION})");
    }
    let mut reserved = [0u8; 6];
    r.read_exact(&mut reserved).context("failed to read trace header reserved bytes")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::SyscallNr;

    fn make_event(pid: u32, syscall_nr: i64) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            uid: 1000,
            gid: 1000,
            syscall_nr,
            args: [0; 6],
            ret: 0,
            enter_ns: 1_000_000_000,
            exit_ns: 1_000_043_000,
            comm: *b"test\0\0\0\0\0\0\0\0\0\0\0\0",
            path: [0; 128],
            path_len: 0,
            sockaddr: [0; 28],
            sockaddr_len: 0,
            _pad: [0; 5],
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.snoop");

        let ev1 = make_event(100, SyscallNr::OPENAT.0);
        let ev2 = make_event(200, SyscallNr::READ.0);

        // Write
        let mut writer = TraceWriter::create(&path).unwrap();
        writer.write_event(&ev1).unwrap();
        writer.write_event(&ev2).unwrap();
        let count = writer.finish().unwrap();
        assert_eq!(count, 2);

        // Read back
        let mut reader = TraceReader::open(&path).unwrap();
        let r1 = reader.next_event().unwrap().unwrap();
        let r2 = reader.next_event().unwrap().unwrap();
        let eof = reader.next_event().unwrap();

        assert_eq!(r1.pid, 100);
        assert_eq!(r1.syscall_nr, SyscallNr::OPENAT.0);
        assert_eq!(r2.pid, 200);
        assert_eq!(r2.syscall_nr, SyscallNr::READ.0);
        assert!(eof.is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.snoop");
        std::fs::write(&path, b"NOTSNOOP\x01\x00\x00\x00\x00\x00\x00\x00").unwrap();
        assert!(TraceReader::open(&path).is_err());
    }
}
