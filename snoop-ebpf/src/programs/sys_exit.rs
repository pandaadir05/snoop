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
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use snoop_common::{SyscallEnterData, SyscallEvent, PATH_MAX_LEN};

use crate::maps::{EVENTS, PATH_BUF, SYSCALL_ENTER};

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

    // Reserve ring buffer memory for the event.  The SyscallEvent (~248 bytes)
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
        core::ptr::addr_of_mut!((*ev)._pad).write([0u8; 6]);
    }

    // Attempt to capture the first string argument for path-bearing syscalls.
    let path_len = capture_path_arg(&enter, ev);
    unsafe {
        core::ptr::addr_of_mut!((*ev).path_len).write(path_len);
        if path_len == 0 {
            // Zero the path field so userspace sees a clean buffer.
            core::ptr::addr_of_mut!((*ev).path)
                .write_bytes(0, 1); // write_bytes zeros size_of::<[u8;128]>() bytes
        }
    }

    rb_entry.submit(0);
    Ok(())
}

/// Determine the path argument for this syscall and read it from user memory
/// into the ring buffer entry's `path` field via the per-CPU scratch buffer.
///
/// Returns the number of bytes written (including the null terminator that
/// `bpf_probe_read_user_str` appends), or 0 if no path applies or the read
/// fails.
#[inline(always)]
fn capture_path_arg(enter: &SyscallEnterData, ev: *mut SyscallEvent) -> u16 {
    // Which argument holds the pathname pointer for this syscall?
    // For openat-family syscalls args[0] is dirfd and args[1] is the pointer;
    // for open/execve-family args[0] is the pointer directly.
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

    // Use the per-CPU scratch buffer to read the string — avoids using the
    // BPF stack for the 128-byte path buffer.
    let scratch: *mut [u8; PATH_MAX_LEN] = match unsafe { PATH_BUF.get_ptr_mut(0) } {
        Some(p) => p,
        None => return 0,
    };

    // Safety: scratch points to valid per-CPU map memory; PATH_MAX_LEN is its
    // declared size.
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

    // Copy from the per-CPU scratch buffer directly into the ring buffer
    // `path` field.  Both are valid BPF-accessible memory regions.
    unsafe {
        let path_dst = core::ptr::addr_of_mut!((*ev).path) as *mut u8;
        core::ptr::copy_nonoverlapping(scratch as *const u8, path_dst, copy_len);
    }

    copy_len as u16
}
