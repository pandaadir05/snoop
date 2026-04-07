//! `raw_syscalls/sys_enter` tracepoint.
//!
//! Kernel tracepoint format (raw_syscalls/sys_enter):
//! ```c
//! struct {
//!     u16  common_type;           // offset  0
//!     u8   common_flags;          // offset  2
//!     u8   common_preempt_count;  // offset  3
//!     s32  common_pid;            // offset  4
//!     s64  id;                    // offset  8  — syscall number
//!     u64  args[6];               // offset 16  — register arguments
//! };
//! ```

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use snoop_common::SyscallEnterData;

use crate::maps::{SYSCALL_ENTER, TARGET_PID};

/// Tracepoint attached to `raw_syscalls/sys_enter`.
///
/// Reads the syscall number, arguments, and thread identity, then stores
/// everything in `SYSCALL_ENTER` keyed by the combined pid/tid value so
/// `sys_exit` can retrieve it later.
#[tracepoint(name = "sys_enter", category = "raw_syscalls")]
pub fn sys_enter(ctx: TracePointContext) -> i64 {
    match try_sys_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 0, // never fail loudly — best-effort tracing
    }
}

#[inline(always)]
fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let id = unsafe { bpf_get_current_pid_tgid() };
    let pid = (id >> 32) as u32;
    let tid = id as u32;

    // Apply PID filter (TARGET_PID[0] == 0 → trace everything).
    if let Some(&target) = unsafe { TARGET_PID.get(0) } {
        if target != 0 && pid != target {
            return Ok(());
        }
    }

    // Read syscall number and arguments from the tracepoint context.
    // Safety: offsets are defined by the kernel ABI and will not change.
    let syscall_nr: i64 = unsafe { ctx.read_at(8) }.map_err(|e| e as i64)?;
    let args: [u64; 6] = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;

    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut comm = [0u8; 16];
    let _ = unsafe { bpf_get_current_comm(&mut comm) };

    let data = SyscallEnterData {
        pid,
        tid,
        uid,
        gid,
        syscall_nr,
        args,
        enter_ns: unsafe { bpf_ktime_get_ns() },
        comm,
    };

    // Store entry data; overwrite any stale entry for the same tid (can
    // happen if sys_exit was missed for a previous call).
    unsafe { SYSCALL_ENTER.insert(&id, &data, 0) }.map_err(|e| e as i64)?;

    Ok(())
}
