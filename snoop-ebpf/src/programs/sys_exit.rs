//! `raw_syscalls/sys_exit` tracepoint.
//!
//! Kernel tracepoint format (raw_syscalls/sys_exit):
//! ```c
//! struct {
//!     u16  common_type;           // offset  0
//!     u8   common_flags;          // offset  2
//!     u8   common_preempt_count;  // offset  3
//!     s32  common_pid;            // offset  4
//!     s64  id;                    // offset  8  — syscall number
//!     s64  ret;                   // offset 16  — return value
//! };
//! ```

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use snoop_common::{
    SyscallEnterData, SyscallEvent, ARGV_EXTRA_MAX, PATH_MAX_LEN, SOCKADDR_MAX_LEN,
};

use crate::maps::{EVENTS, EXTRA_PIDS, FOLLOW_MODE, SYSCALL_ENTER};

/// Tracepoint attached to `raw_syscalls/sys_exit`.
///
/// Looks up the entry data stored by `sys_enter`, combines it with the
/// return value and exit timestamp, captures any path string argument, and
/// submits a complete `SyscallEvent` to the ring buffer.
#[tracepoint(name = "sys_exit", category = "raw_syscalls")]
pub fn sys_exit(ctx: TracePointContext) -> i64 {
    match try_sys_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_sys_exit(ctx: &TracePointContext) -> Result<(), i64> {
    use aya_ebpf::helpers::bpf_get_current_pid_tgid;

    let id = bpf_get_current_pid_tgid();

    // Copy the entry record from the scratch map (≤ 96 bytes, stack-safe).
    let enter = match unsafe { SYSCALL_ENTER.get(&id) } {
        Some(d) => *d,
        None => return Ok(()), // missed the entry — skip this event
    };

    // Remove the scratch entry now to free the slot for future syscalls.
    let _ = SYSCALL_ENTER.remove(&id);

    let ret: i64 = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;
    let exit_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve ring buffer memory for the event.  The SyscallEvent (~280 bytes)
    // lives in ring buffer memory, NOT on the BPF stack, so it doesn't count
    // against the 512-byte stack limit.
    let mut rb_entry = match EVENTS.reserve::<SyscallEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    // Write fixed fields directly into ring buffer memory.
    // Using addr_of_mut! for field-by-field writes avoids constructing a full
    // SyscallEvent on the stack.
    let ev: *mut SyscallEvent = rb_entry.as_mut_ptr();
    unsafe {
        core::ptr::addr_of_mut!((*ev).pid).write(enter.pid);
        core::ptr::addr_of_mut!((*ev).tid).write(enter.tid);
        core::ptr::addr_of_mut!((*ev).uid).write(enter.uid);
        core::ptr::addr_of_mut!((*ev).gid).write(enter.gid);
        core::ptr::addr_of_mut!((*ev).syscall_nr).write(enter.syscall_nr);
        core::ptr::addr_of_mut!((*ev).args).write(enter.args);
        core::ptr::addr_of_mut!((*ev).ret).write(ret);
        core::ptr::addr_of_mut!((*ev).enter_ns).write(enter.enter_ns);
        core::ptr::addr_of_mut!((*ev).exit_ns).write(exit_ns);
        core::ptr::addr_of_mut!((*ev).comm).write(enter.comm);
        core::ptr::addr_of_mut!((*ev)._pad).write([0u8; 3]);
    }

    // Attempt to capture the first string argument for path-bearing syscalls.
    let path_len = capture_path_arg(&enter, ev);
    unsafe {
        core::ptr::addr_of_mut!((*ev).path_len).write(path_len);
        if path_len == 0 {
            core::ptr::addr_of_mut!((*ev).path).write_bytes(0, 1);
        }
    }

    // Attempt to capture the sockaddr argument for socket syscalls.
    let sa_len = capture_sockaddr_arg(&enter, ev, ret);
    unsafe {
        core::ptr::addr_of_mut!((*ev).sockaddr_len).write(sa_len);
        if sa_len == 0 {
            core::ptr::addr_of_mut!((*ev).sockaddr).write_bytes(0, 1);
        }
    }

    // For execve/execveat, attempt to capture extra argv strings (argv[1..]).
    let argv_extra_len = capture_argv_extra(&enter, ev);
    unsafe {
        core::ptr::addr_of_mut!((*ev).argv_extra_len).write(argv_extra_len);
        if argv_extra_len == 0 {
            core::ptr::addr_of_mut!((*ev).argv_extra).write_bytes(0, 1);
        }
    }

    rb_entry.submit(0);

    // If follow mode is active and this was a fork/clone that succeeded in
    // the parent (ret > 0), add the child PID to EXTRA_PIDS so it is traced.
    maybe_follow_child(enter.syscall_nr, ret);

    Ok(())
}

/// When `--follow` is active, insert the child PID returned by fork/clone
/// into `EXTRA_PIDS` so subsequent syscalls from that process are captured.
#[inline(always)]
fn maybe_follow_child(syscall_nr: i64, ret: i64) {
    let follow = match FOLLOW_MODE.get(0) {
        Some(f) => *f,
        None => return,
    };
    if follow == 0 {
        return;
    }

    // fork=57, vfork=58, clone=56, clone3=435
    match syscall_nr {
        56 | 57 | 58 | 435 => {}
        _ => return,
    }

    // ret > 0 in the parent = child PID.  ret == 0 = child side.  ret < 0 = error.
    if ret <= 0 {
        return;
    }

    let child_pid = ret as u32;
    let _ = EXTRA_PIDS.insert(&child_pid, &1u8, 0);
}

/// Determine the path argument for this syscall and read it from user memory
/// directly into the ring buffer entry's `path` field.
///
/// Reads straight from userspace into ring buffer memory via
/// `bpf_probe_read_user_str_bytes` — no per-CPU scratch buffer or copy loop.
/// This eliminates the O(PATH_MAX_LEN²) verifier state explosion that occurred
/// when a scratch buffer was copied to a dynamic ring-buffer offset.
///
/// Returns the number of bytes written (including the null terminator), or 0.
#[inline(always)]
fn capture_path_arg(enter: &SyscallEnterData, ev: *mut SyscallEvent) -> u16 {
    let path_ptr: *const u8 = match enter.syscall_nr {
        // open, creat, execve, stat, lstat, symlink, readlink, access,
        // truncate, mkdir, rmdir, unlink, rename (old path)
        2 | 59 | 85 | 4 | 6 | 88 | 89 | 21 | 76 | 83 | 84 | 87 | 82 => enter.args[0] as *const u8,
        // openat, mkdirat, unlinkat, renameat, execveat, fstatat, readlinkat,
        // faccessat, utimensat (path in args[1])
        257 | 258 | 263 | 264 | 322 | 262 | 267 | 269 | 280 => enter.args[1] as *const u8,
        _ => return 0,
    };

    if path_ptr.is_null() {
        return 0;
    }

    // Read directly from user memory into the ring buffer's `path` field.
    // The destination is a fixed-offset slice (no dynamic accumulation),
    // so the verifier can verify bounds in O(1).
    let dest = unsafe {
        let path_field = core::ptr::addr_of_mut!((*ev).path) as *mut u8;
        core::slice::from_raw_parts_mut(path_field, PATH_MAX_LEN)
    };

    match unsafe { bpf_probe_read_user_str_bytes(path_ptr, dest) } {
        Ok(s) => s.len() as u16,
        Err(_) => 0,
    }
}

/// Capture the sockaddr argument for socket syscalls by reading the struct
/// from user memory into the ring buffer's `sockaddr` field.
///
/// Returns the number of bytes written, or 0 if not applicable or the read
/// fails.  We cap at `SOCKADDR_MAX_LEN` (28 bytes — enough for IPv6).
///
/// Syscall coverage:
/// * connect / bind   — args[1]=ptr, args[2]=addrlen (known at entry)
/// * accept / accept4 — args[1]=ptr, args[2]=ptr-to-addrlen (written by kernel)
/// * getpeername / getsockname — same layout as accept
///
/// For accept-family the kernel writes the actual length into *args[2]; we
/// use that as the read length (clamped to SOCKADDR_MAX_LEN).  On failure
/// we fall back to reading SOCKADDR_MAX_LEN bytes which is safe.
#[inline(always)]
fn capture_sockaddr_arg(enter: &SyscallEnterData, ev: *mut SyscallEvent, ret: i64) -> u8 {
    // Determine the sockaddr pointer and length source.
    let sa_ptr = enter.args[1] as *const u8;
    if sa_ptr.is_null() {
        return 0;
    }

    let read_len: usize = match enter.syscall_nr {
        // connect(fd, sa*, addrlen) / bind(fd, sa*, addrlen)
        // args[2] is the length directly.
        42 | 49 => (enter.args[2] as usize).min(SOCKADDR_MAX_LEN),
        // accept(fd, sa*, len*) / accept4(fd, sa*, len*, flags)
        // getpeername(fd, sa*, len*) / getsockname(fd, sa*, len*)
        // args[2] is a pointer to the length; read it from user memory.
        // syscall numbers: accept=43, accept4=288, getpeername=52, getsockname=51
        43 | 51 | 52 | 288 => {
            // Only valid after the call succeeds (ret >= 0).
            if ret < 0 {
                return 0;
            }
            let len_ptr = enter.args[2] as *const u32;
            if len_ptr.is_null() {
                return 0;
            }
            let mut len_val = 0u32;
            let len_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut len_val) as *mut u32 as *mut u8,
                    core::mem::size_of::<u32>(),
                )
            };
            if unsafe { bpf_probe_read_user_buf(len_ptr as *const u8, len_bytes) }.is_err() {
                SOCKADDR_MAX_LEN
            } else {
                (len_val as usize).min(SOCKADDR_MAX_LEN)
            }
        }
        _ => return 0,
    };

    if read_len == 0 {
        return 0;
    }

    // Read directly from user memory into the ring buffer's `sockaddr` field.
    let dest = unsafe {
        let sa_field = core::ptr::addr_of_mut!((*ev).sockaddr) as *mut u8;
        core::slice::from_raw_parts_mut(sa_field, read_len)
    };

    if unsafe { bpf_probe_read_user_buf(sa_ptr, dest) }.is_err() {
        return 0;
    }

    read_len as u8
}

/// Capture extra argv strings (argv[1], argv[2], argv[3]) for execve/execveat.
///
/// The captured bytes are written into the ring buffer entry's `argv_extra`
/// field as null-separated strings: `"arg1\x00arg2\x00arg3\x00"`.  Userspace
/// splits on `\x00` to reconstruct the individual arguments.
///
/// Returns the total number of bytes written (including all null terminators),
/// or 0 if the syscall is not execve/execveat or no args could be read.
///
/// # Verifier complexity
///
/// The previous implementation used a per-CPU scratch buffer and
/// `copy_nonoverlapping` to move bytes from scratch to ring buffer at a
/// *dynamically-accumulated* destination offset (`dst.add(total)`).  The
/// verifier had to enumerate O(ARGV_EXTRA_MAX²) states for the inner copy loop
/// because both the destination offset AND the copy length were unknown at
/// compile time, overflowing the 1 000 000-instruction limit.
///
/// The fix: read each argument string directly from userspace into the ring
/// buffer via `bpf_probe_read_user_str_bytes`.  This is a single BPF helper
/// call; the verifier analyses it in O(1) regardless of string length,
/// completely eliminating the copy loop.
#[inline(always)]
fn capture_argv_extra(enter: &SyscallEnterData, ev: *mut SyscallEvent) -> u16 {
    use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;

    // Only for execve (59) and execveat (322).
    let argv_ptr: u64 = match enter.syscall_nr {
        59 => enter.args[1],  // execve:    args[1] = char *const argv[]
        322 => enter.args[2], // execveat:  args[2] = char *const argv[]
        _ => return 0,
    };

    if argv_ptr == 0 {
        return 0;
    }

    let base: *mut u8 = unsafe { core::ptr::addr_of_mut!((*ev).argv_extra) as *mut u8 };
    let mut total: usize = 0;

    // Manually unrolled: capture argv[1], argv[2], argv[3].
    macro_rules! read_arg {
        ($idx:expr) => {{
            // Read the pointer value at argv[$idx] (8 bytes on 64-bit).
            let ptr_addr = argv_ptr + ($idx as u64) * 8;
            let mut arg_ptr: u64 = 0;
            let ptr_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut arg_ptr as *mut u64 as *mut u8,
                    core::mem::size_of::<u64>(),
                )
            };
            if unsafe { bpf_probe_read_user_buf(ptr_addr as *const u8, ptr_bytes) }.is_err() {
                return total as u16;
            }
            if arg_ptr == 0 {
                return total as u16; // end of argv[]
            }

            let remaining = ARGV_EXTRA_MAX.saturating_sub(total);
            if remaining == 0 {
                return total as u16;
            }

            // Read the argument string DIRECTLY from userspace into ring buffer
            // memory at the current write position.  No scratch buffer, no copy
            // loop — a single BPF helper call the verifier checks in O(1).
            let dest =
                unsafe { core::slice::from_raw_parts_mut(base.add(total), remaining) };
            let written =
                match unsafe { bpf_probe_read_user_str_bytes(arg_ptr as *const u8, dest) } {
                    Ok(s) => s.len(),
                    Err(_) => return total as u16,
                };
            if written == 0 {
                return total as u16;
            }
            // bpf_probe_read_user_str_bytes appends a null terminator that acts
            // as the field separator for userspace.
            total += written;
        }};
    }

    read_arg!(1);
    read_arg!(2);
    read_arg!(3);

    total as u16
}
