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
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};
use snoop_common::SyscallEvent;

use crate::maps::{EVENTS, SYSCALL_ENTER};

/// Tracepoint attached to `raw_syscalls/sys_exit`.
///
/// Looks up the entry data stored by `sys_enter`, combines it with the
/// return value and exit timestamp, and submits a complete `SyscallEvent`
/// to the ring buffer.
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

    // Retrieve the entry data written by sys_enter.
    let enter = match unsafe { SYSCALL_ENTER.get(&id) } {
        Some(d) => *d,
        None => return Ok(()), // missed the entry — skip
    };

    // Remove the scratch entry regardless of what happens next so we don't
    // leak map slots on processes that call execve and change identity.
    let _ = unsafe { SYSCALL_ENTER.remove(&id) };

    let ret: i64 = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;
    let exit_ns = unsafe { bpf_ktime_get_ns() };

    // Emit the full event to the ring buffer.
    let event = SyscallEvent {
        pid: enter.pid,
        tid: enter.tid,
        uid: enter.uid,
        gid: enter.gid,
        syscall_nr: enter.syscall_nr,
        args: enter.args,
        ret,
        enter_ns: enter.enter_ns,
        exit_ns,
        comm: enter.comm,
    };

    // Safety: EVENTS is a valid ring buffer map; output is best-effort.
    unsafe { EVENTS.output(&event, 0) }.map_err(|e| e as i64)?;

    Ok(())
}
