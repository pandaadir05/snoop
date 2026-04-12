//! "Explain" mode — semantic grouping of raw syscall events.
//!
//! Instead of one line per syscall, explain mode tracks fd lifetimes and
//! emits higher-level activity summaries:
//!
//! * `openat + read* + close`   →  `READ  /etc/passwd  (4.2 KB, 2 calls, 1.3ms)`
//! * `socket + connect + send* + recv* + close` → `TCP 127.0.0.1:8080  ↑512 B ↓4.0 KB`
//! * `execve`  →  `EXEC /usr/bin/python3 arg1 arg2`
//! * `fork`    →  `FORK → child PID 4321`
//!
//! The [`Explainer`] is a pure state machine: call [`Explainer::push`] for
//! every incoming [`SyscallEvent`]; it returns zero or more [`Activity`]
//! values that are ready to display.  Call [`Explainer::flush`] at end-of-
//! trace to emit anything that was never explicitly closed.

use std::collections::HashMap;

use snoop_common::{SyscallEvent, SyscallNr};

use crate::decode::comm_to_string;

// ── public types ─────────────────────────────────────────────────────────────

/// A high-level activity derived from one or more syscalls.
#[derive(Debug)]
pub struct Activity {
    /// Monotonic nanoseconds of the first syscall in this activity.
    pub timestamp_ns: u64,
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub comm: String,
    /// Human-readable one-line summary.
    pub summary: String,
    /// Visual category for colour coding.
    pub kind: ActivityKind,
}

/// Visual category of an [`Activity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityKind {
    /// File read (no writes).
    FileRead,
    /// File write (no reads, or truncate/create).
    FileWrite,
    /// Mixed file read + write.
    FileReadWrite,
    /// Network send/receive.
    Network,
    /// execve / execveat.
    Exec,
    /// fork / vfork / clone.
    Fork,
}

// ── internal state ────────────────────────────────────────────────────────────

/// Key identifying a file descriptor within a process.
type FdKey = (u32 /* pid */, i32 /* fd */);

/// State tracked for an open file descriptor.
struct OpenFile {
    path: String,
    first_ns: u64,
    last_ns: u64,
    bytes_read: u64,
    bytes_written: u64,
    read_calls: u32,
    write_calls: u32,
    comm: [u8; 16],
}

/// State tracked for an active socket.
struct Socket {
    peer: Option<String>,
    first_ns: u64,
    last_ns: u64,
    bytes_sent: u64,
    bytes_received: u64,
    comm: [u8; 16],
}

// ── Explainer ─────────────────────────────────────────────────────────────────

/// Stateful converter from raw [`SyscallEvent`]s to [`Activity`] summaries.
pub struct Explainer {
    open_files: HashMap<FdKey, OpenFile>,
    sockets: HashMap<FdKey, Socket>,
}

impl Explainer {
    /// Create a new, empty `Explainer`.
    pub fn new() -> Self {
        Self {
            open_files: HashMap::new(),
            sockets: HashMap::new(),
        }
    }

    /// Feed a raw syscall event.  Returns any activities that are now complete.
    pub fn push(&mut self, event: &SyscallEvent) -> Vec<Activity> {
        let nr = SyscallNr(event.syscall_nr);
        let pid = event.pid;
        let ts = event.enter_ns;
        let ret = event.ret;
        let args = &event.args;

        match nr {
            // ── file open ─────────────────────────────────────────────────
            SyscallNr::OPEN | SyscallNr::OPENAT => {
                if ret >= 0 {
                    let path = event
                        .path_str()
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|| format!("fd:{ret}"));
                    self.open_files.insert(
                        (pid, ret as i32),
                        OpenFile {
                            path,
                            first_ns: ts,
                            last_ns: ts,
                            bytes_read: 0,
                            bytes_written: 0,
                            read_calls: 0,
                            write_calls: 0,
                            comm: event.comm,
                        },
                    );
                }
                vec![]
            }

            // ── reads on known file fds ───────────────────────────────────
            SyscallNr::READ | SyscallNr::PREAD64 | SyscallNr::READV => {
                let fd = args[0] as i32;
                if ret > 0 {
                    if let Some(f) = self.open_files.get_mut(&(pid, fd)) {
                        f.bytes_read += ret as u64;
                        f.read_calls += 1;
                        f.last_ns = event.exit_ns;
                    }
                    // Also count on sockets.
                    if let Some(s) = self.sockets.get_mut(&(pid, fd)) {
                        s.bytes_received += ret as u64;
                        s.last_ns = event.exit_ns;
                    }
                }
                vec![]
            }

            // ── writes on known file fds ──────────────────────────────────
            SyscallNr::WRITE | SyscallNr::PWRITE64 | SyscallNr::WRITEV => {
                let fd = args[0] as i32;
                if ret > 0 {
                    if let Some(f) = self.open_files.get_mut(&(pid, fd)) {
                        f.bytes_written += ret as u64;
                        f.write_calls += 1;
                        f.last_ns = event.exit_ns;
                    }
                    if let Some(s) = self.sockets.get_mut(&(pid, fd)) {
                        s.bytes_sent += ret as u64;
                        s.last_ns = event.exit_ns;
                    }
                }
                vec![]
            }

            // ── socket creation ───────────────────────────────────────────
            SyscallNr::SOCKET => {
                if ret >= 0 {
                    self.sockets.insert(
                        (pid, ret as i32),
                        Socket {
                            peer: None,
                            first_ns: ts,
                            last_ns: ts,
                            bytes_sent: 0,
                            bytes_received: 0,
                            comm: event.comm,
                        },
                    );
                }
                vec![]
            }

            // ── connect ───────────────────────────────────────────────────
            SyscallNr::CONNECT => {
                let fd = args[0] as i32;
                let peer = decode_sockaddr(event.sockaddr_bytes(), args[1]);
                if let Some(s) = self.sockets.get_mut(&(pid, fd)) {
                    if peer != "?" {
                        s.peer = Some(peer);
                    }
                    s.last_ns = event.exit_ns;
                } else if ret >= 0 {
                    // Socket opened before we started tracing.
                    self.sockets.insert(
                        (pid, fd),
                        Socket {
                            peer: if peer != "?" { Some(peer) } else { None },
                            first_ns: ts,
                            last_ns: event.exit_ns,
                            bytes_sent: 0,
                            bytes_received: 0,
                            comm: event.comm,
                        },
                    );
                }
                vec![]
            }

            // ── accept / accept4 — new inbound socket ─────────────────────
            SyscallNr::ACCEPT | SyscallNr::ACCEPT4 => {
                if ret >= 0 {
                    let peer = decode_sockaddr(event.sockaddr_bytes(), args[1]);
                    self.sockets.insert(
                        (pid, ret as i32),
                        Socket {
                            peer: if peer != "?" { Some(peer) } else { None },
                            first_ns: ts,
                            last_ns: ts,
                            bytes_sent: 0,
                            bytes_received: 0,
                            comm: event.comm,
                        },
                    );
                }
                vec![]
            }

            // ── network send ──────────────────────────────────────────────
            SyscallNr::SENDTO | SyscallNr::SENDMSG | SyscallNr::SENDMMSG => {
                let fd = args[0] as i32;
                if ret > 0 {
                    if let Some(s) = self.sockets.get_mut(&(pid, fd)) {
                        s.bytes_sent += ret as u64;
                        s.last_ns = event.exit_ns;
                    }
                }
                vec![]
            }

            // ── network receive ───────────────────────────────────────────
            SyscallNr::RECVFROM | SyscallNr::RECVMSG | SyscallNr::RECVMMSG => {
                let fd = args[0] as i32;
                if ret > 0 {
                    if let Some(s) = self.sockets.get_mut(&(pid, fd)) {
                        s.bytes_received += ret as u64;
                        s.last_ns = event.exit_ns;
                    }
                }
                vec![]
            }

            // ── dup: alias fd ─────────────────────────────────────────────
            SyscallNr::DUP => {
                if ret >= 0 {
                    let old_fd = args[0] as i32;
                    let new_fd = ret as i32;
                    self.dup_fd(pid, old_fd, new_fd);
                }
                vec![]
            }
            SyscallNr::DUP2 | SyscallNr::DUP3 => {
                if ret >= 0 {
                    let old_fd = args[0] as i32;
                    let new_fd = args[1] as i32;
                    // Close any existing fd at the target slot first.
                    let _ = self.close_fd(pid, new_fd);
                    self.dup_fd(pid, old_fd, new_fd);
                }
                vec![]
            }

            // ── close ─────────────────────────────────────────────────────
            SyscallNr::CLOSE => {
                let fd = args[0] as i32;
                if let Some(act) = self.close_fd(pid, fd) {
                    vec![act]
                } else {
                    vec![]
                }
            }

            // ── execve ────────────────────────────────────────────────────
            SyscallNr::EXECVE | SyscallNr::EXECVEAT => {
                if ret == 0 {
                    let path = event
                        .path_str()
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|| "?".to_owned());
                    vec![Activity {
                        timestamp_ns: ts,
                        pid,
                        comm: comm_to_string(&event.comm),
                        summary: format!("EXEC {path}"),
                        kind: ActivityKind::Exec,
                    }]
                } else {
                    vec![]
                }
            }

            // ── fork / clone ──────────────────────────────────────────────
            SyscallNr::FORK | SyscallNr::VFORK => {
                if ret > 0 {
                    vec![Activity {
                        timestamp_ns: ts,
                        pid,
                        comm: comm_to_string(&event.comm),
                        summary: format!("FORK → child PID {ret}"),
                        kind: ActivityKind::Fork,
                    }]
                } else {
                    vec![]
                }
            }
            SyscallNr::CLONE | SyscallNr::CLONE3 => {
                if ret > 0 {
                    vec![Activity {
                        timestamp_ns: ts,
                        pid,
                        comm: comm_to_string(&event.comm),
                        summary: format!("CLONE → child PID {ret}"),
                        kind: ActivityKind::Fork,
                    }]
                } else {
                    vec![]
                }
            }

            _ => vec![],
        }
    }

    /// Flush all pending (unclosed) file and socket activities.
    ///
    /// Call this at end-of-trace to ensure incomplete transactions are emitted.
    pub fn flush(&mut self) -> Vec<Activity> {
        let mut out = Vec::new();

        let file_keys: Vec<FdKey> = self.open_files.keys().copied().collect();
        for key in file_keys {
            if let Some(act) = self.close_fd(key.0, key.1) {
                out.push(act);
            }
        }

        let sock_keys: Vec<FdKey> = self.sockets.keys().copied().collect();
        for key in sock_keys {
            if let Some(act) = self.close_fd(key.0, key.1) {
                out.push(act);
            }
        }

        out
    }

    // ── helpers ───────────────────────────────────────────────────────────

    /// Materialise and remove an fd, returning an `Activity` if it had I/O.
    fn close_fd(&mut self, pid: u32, fd: i32) -> Option<Activity> {
        let key = (pid, fd);

        if let Some(f) = self.open_files.remove(&key) {
            // Only surface fds that had actual I/O (suppress open+close with 0 bytes).
            if f.bytes_read == 0 && f.bytes_written == 0 {
                return None;
            }
            let summary = file_summary(&f);
            let kind = match (f.bytes_read > 0, f.bytes_written > 0) {
                (true, false) => ActivityKind::FileRead,
                (false, true) => ActivityKind::FileWrite,
                _ => ActivityKind::FileReadWrite,
            };
            return Some(Activity {
                timestamp_ns: f.first_ns,
                pid,
                comm: comm_to_string(&f.comm),
                summary,
                kind,
            });
        }

        if let Some(s) = self.sockets.remove(&key) {
            if s.bytes_sent == 0 && s.bytes_received == 0 {
                return None;
            }
            let summary = socket_summary(&s);
            return Some(Activity {
                timestamp_ns: s.first_ns,
                pid,
                comm: comm_to_string(&s.comm),
                summary,
                kind: ActivityKind::Network,
            });
        }

        None
    }

    /// Copy fd state from `old_fd` to `new_fd` (dup semantics).
    fn dup_fd(&mut self, pid: u32, old_fd: i32, new_fd: i32) {
        if let Some(f) = self.open_files.get(&(pid, old_fd)).cloned() {
            self.open_files.insert(
                (pid, new_fd),
                OpenFile {
                    path: f.path.clone(),
                    ..f
                },
            );
        } else if let Some(s) = self.sockets.get(&(pid, old_fd)).cloned() {
            self.sockets.insert(
                (pid, new_fd),
                Socket {
                    peer: s.peer.clone(),
                    ..s
                },
            );
        }
    }
}

impl Default for Explainer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Clone impls so dup_fd can copy the structs ────────────────────────────────

impl Clone for OpenFile {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            first_ns: self.first_ns,
            last_ns: self.last_ns,
            bytes_read: self.bytes_read,
            bytes_written: self.bytes_written,
            read_calls: self.read_calls,
            write_calls: self.write_calls,
            comm: self.comm,
        }
    }
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Self {
            peer: self.peer.clone(),
            first_ns: self.first_ns,
            last_ns: self.last_ns,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            comm: self.comm,
        }
    }
}

// ── formatters ────────────────────────────────────────────────────────────────

/// Build the one-line summary for a file activity.
fn file_summary(f: &OpenFile) -> String {
    let verb = match (f.bytes_read > 0, f.bytes_written > 0) {
        (true, false) => "READ ",
        (false, true) => "WRITE",
        _ => "R/W  ",
    };
    let mut parts = Vec::new();
    if f.bytes_read > 0 {
        parts.push(format!("↓{}", human_bytes(f.bytes_read)));
    }
    if f.bytes_written > 0 {
        parts.push(format!("↑{}", human_bytes(f.bytes_written)));
    }
    let io = parts.join(" ");
    let calls = f.read_calls + f.write_calls;
    let dur_ms = f.last_ns.saturating_sub(f.first_ns) as f64 / 1_000_000.0;
    format!("{verb}  {}  {io}  ({calls} calls, {dur_ms:.2}ms)", f.path)
}

/// Build the one-line summary for a socket/network activity.
fn socket_summary(s: &Socket) -> String {
    let peer = s.peer.as_deref().unwrap_or("?");
    let mut parts = Vec::new();
    if s.bytes_sent > 0 {
        parts.push(format!("↑{}", human_bytes(s.bytes_sent)));
    }
    if s.bytes_received > 0 {
        parts.push(format!("↓{}", human_bytes(s.bytes_received)));
    }
    let io = if parts.is_empty() {
        String::new()
    } else {
        format!("  {}", parts.join(" "))
    };
    let dur_ms = s.last_ns.saturating_sub(s.first_ns) as f64 / 1_000_000.0;
    format!("NET   {peer}{io}  ({dur_ms:.2}ms)")
}

/// Decode a sockaddr byte slice to a human-readable `"ip:port"` or `"path"`.
/// Returns `"?"` when the bytes are absent or the family is unknown.
pub(crate) fn decode_sockaddr(bytes: &[u8], _fallback_ptr: u64) -> String {
    if bytes.len() < 2 {
        return "?".to_owned();
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        2 if bytes.len() >= 8 => {
            // AF_INET
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let a = bytes[4];
            let b = bytes[5];
            let c = bytes[6];
            let d = bytes[7];
            format!("{a}.{b}.{c}.{d}:{port}")
        }
        10 if bytes.len() >= 20 => {
            // AF_INET6
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let groups: [u16; 8] = core::array::from_fn(|i| {
                u16::from_be_bytes([bytes[8 + i * 2], bytes[8 + i * 2 + 1]])
            });
            let addr = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                groups[0],
                groups[1],
                groups[2],
                groups[3],
                groups[4],
                groups[5],
                groups[6],
                groups[7],
            );
            format!("[{addr}]:{port}")
        }
        1 if bytes.len() >= 3 => {
            // AF_UNIX
            let end = bytes[2..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| p + 2)
                .unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[2..end]).into_owned()
        }
        _ => "?".to_owned(),
    }
}

/// Format a byte count as a human-readable string (B / KB / MB).
fn human_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use snoop_common::PATH_MAX_LEN;

    fn make_event(nr: SyscallNr, args: [u64; 6], ret: i64, path: &str) -> SyscallEvent {
        let mut path_buf = [0u8; PATH_MAX_LEN];
        let len = path.len().min(PATH_MAX_LEN);
        path_buf[..len].copy_from_slice(&path.as_bytes()[..len]);
        SyscallEvent {
            pid: 1,
            tid: 1,
            uid: 0,
            gid: 0,
            syscall_nr: nr.0,
            args,
            ret,
            enter_ns: 1_000_000_000,
            exit_ns: 1_001_000_000,
            comm: *b"test\0\0\0\0\0\0\0\0\0\0\0\0",
            path: path_buf,
            path_len: len as u16,
            sockaddr: [0; snoop_common::SOCKADDR_MAX_LEN],
            sockaddr_len: 0,
            argv_extra: [0; snoop_common::ARGV_EXTRA_MAX],
            argv_extra_len: 0,
            _pad: [0; 3],
        }
    }

    #[test]
    fn file_read_lifecycle() {
        let mut ex = Explainer::new();
        // open → fd 5
        let acts = ex.push(&make_event(
            SyscallNr::OPENAT,
            [0, 0, 0, 0, 0, 0],
            5,
            "/etc/hosts",
        ));
        assert!(acts.is_empty());
        // read 512 bytes
        let acts = ex.push(&make_event(SyscallNr::READ, [5, 0, 512, 0, 0, 0], 512, ""));
        assert!(acts.is_empty());
        // close → should emit activity
        let acts = ex.push(&make_event(SyscallNr::CLOSE, [5, 0, 0, 0, 0, 0], 0, ""));
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].kind, ActivityKind::FileRead);
        assert!(acts[0].summary.contains("/etc/hosts"));
        assert!(acts[0].summary.contains("512 B"));
    }

    #[test]
    fn open_close_no_io_suppressed() {
        let mut ex = Explainer::new();
        ex.push(&make_event(SyscallNr::OPENAT, [0; 6], 3, "/dev/null"));
        let acts = ex.push(&make_event(SyscallNr::CLOSE, [3, 0, 0, 0, 0, 0], 0, ""));
        assert!(acts.is_empty(), "should suppress fds with no I/O");
    }

    #[test]
    fn execve_emits_immediately() {
        let mut ex = Explainer::new();
        let acts = ex.push(&make_event(SyscallNr::EXECVE, [0; 6], 0, "/usr/bin/ls"));
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].kind, ActivityKind::Exec);
        assert!(acts[0].summary.contains("/usr/bin/ls"));
    }

    #[test]
    fn fork_emits_immediately() {
        let mut ex = Explainer::new();
        let acts = ex.push(&make_event(SyscallNr::FORK, [0; 6], 1234, ""));
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].kind, ActivityKind::Fork);
        assert!(acts[0].summary.contains("1234"));
    }

    #[test]
    fn human_bytes_formatting() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn flush_emits_unclosed_fds() {
        let mut ex = Explainer::new();
        ex.push(&make_event(SyscallNr::OPENAT, [0; 6], 7, "/tmp/foo"));
        ex.push(&make_event(SyscallNr::WRITE, [7, 0, 100, 0, 0, 0], 100, ""));
        let acts = ex.flush();
        assert_eq!(acts.len(), 1);
        assert!(acts[0].summary.contains("/tmp/foo"));
    }
}
