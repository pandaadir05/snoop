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
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_bytes, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use snoop_common::{SyscallEnterData, SyscallEvent, PATH_MAX_LEN, SOCKADDR_MAX_LEN};

use crate::maps::{EVENTS, EXTRA_PIDS, FOLLOW_MODE, PATH_BUF, SOCKADDR_BUF, SYSCALL_ENTER};

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

    let id = unsafe { bpf_get_current_pid_tgid() };

    // Copy the entry record from the scratch map (≤ 96 bytes, stack-safe).
    let enter = match unsafe { SYSCALL_ENTER.get(&id) } {
        Some(d) => *d,
        None => return Ok(()), // missed the entry — skip this event
    };

    // Remove the scratch entry now to free the slot for future syscalls.
    let _ = unsafe { SYSCALL_ENTER.remove(&id) };

    let ret: i64 = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;
    let exit_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve ring buffer memory for the event.  The SyscallEvent (~280 bytes)
    // lives in ring buffer memory, NOT on the BPF stack, so it doesn't count
    // against the 512-byte stack limit.
    let mut rb_entry = match unsafe { EVENTS.reserve::<SyscallEvent>(0) } {
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
        core::ptr::addr_of_mut!((*ev)._pad).write([0u8; 5]);
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
    let sa_len = capture_sockaddr_arg(&enter, ev);
    unsafe {
        core::ptr::addr_of_mut!((*ev).sockaddr_len).write(sa_len);
        if sa_len == 0 {
            core::ptr::addr_of_mut!((*ev).sockaddr).write_bytes(0, 1);
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
    let follow = match unsafe { FOLLOW_MODE.get(0) } {
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
    let _ = unsafe { EXTRA_PIDS.insert(&child_pid, &1u8, 0) };
}

/// Determine the path argument for this syscall and read it from user memory
/// into the ring buffer entry's `path` field via the per-CPU scratch buffer.
///
/// Returns the number of bytes written (including the null terminator that
/// `bpf_probe_read_user_str` appends), or 0 if no path applies or the read
/// fails.
#[inline(always)]
fn capture_path_arg(enter: &SyscallEnterData, ev: *mut SyscallEvent) -> u16 {
    let path_ptr: *const u8 = match enter.syscall_nr {
        // open, creat, execve, stat, lstat, symlink, readlink, access,
        // truncate, mkdir, rmdir, unlink, rename (old path)
        2 | 59 | 85 | 4 | 6 | 88 | 89 | 21 | 76 | 83 | 84 | 87 | 82 => {
            enter.args[0] as *const u8
        }
        // openat, mkdirat, unlinkat, renameat, execveat, fstatat, readlinkat,
        // faccessat, utimensat (path in args[1])
        257 | 258 | 263 | 264 | 322 | 262 | 267 | 269 | 280 => {
            enter.args[1] as *const u8
        }
        _ => return 0,
    };

    if path_ptr.is_null() {
        return 0;
    }

    let scratch: *mut [u8; PATH_MAX_LEN] = match unsafe { PATH_BUF.get_ptr_mut(0) } {
        Some(p) => p,
        None => return 0,
    };

    let dest: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(scratch as *mut u8, PATH_MAX_LEN) };

    let written = match unsafe { bpf_probe_read_user_str_bytes(path_ptr, dest) } {
        Ok(s) => s.len(),
        Err(_) => return 0,
    };

    if written == 0 {
        return 0;
    }

    let copy_len = written.min(PATH_MAX_LEN);

    unsafe {
        let path_dst = core::ptr::addr_of_mut!((*ev).path) as *mut u8;
        core::ptr::copy_nonoverlapping(scratch as *const u8, path_dst, copy_len);
    }

    copy_len as u16
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
fn capture_sockaddr_arg(enter: &SyscallEnterData, ev: *mut SyscallEvent) -> u8 {
    // Determine the sockaddr pointer and length source.
    let sa_ptr = enter.args[1] as *const u8;
    if sa_ptr.is_null() {
        return 0;
    }

    let read_len: usize = match enter.syscall_nr {
        // connect(fd, sa*, addrlen) / bind(fd, sa*, addrlen)
        // args[2] is the length directly.
        42 | 49 => {
            (enter.args[2] as usize).min(SOCKADDR_MAX_LEN)
        }
        // accept(fd, sa*, len*) / accept4(fd, sa*, len*, flags)
        // getpeername(fd, sa*, len*) / getsockname(fd, sa*, len*)
        // args[2] is a pointer to the length; read it from user memory.
        // syscall numbers: accept=43, accept4=288, getpeername=52, getsockname=51
        43 | 51 | 52 | 288 => {
            // Only valid after the call succeeds (ret >= 0).
            if enter.ret < 0 {
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
            if unsafe { bpf_probe_read_user_bytes(len_ptr as *const u8, len_bytes) }.is_err() {
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

    let scratch: *mut [u8; SOCKADDR_MAX_LEN] = match unsafe { SOCKADDR_BUF.get_ptr_mut(0) } {
        Some(p) => p,
        None => return 0,
    };

    let dest: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(scratch as *mut u8, read_len) };

    if unsafe { bpf_probe_read_user_bytes(sa_ptr, dest) }.is_err() {
        return 0;
    }

    unsafe {
        let sa_dst = core::ptr::addr_of_mut!((*ev).sockaddr) as *mut u8;
        core::ptr::copy_nonoverlapping(scratch as *const u8, sa_dst, read_len);
    }

    read_len as u8
}
