//! Uprobe / uretprobe programs for library-call tracing.
//!
//! Two feature sets are implemented here:
//!
//! **TLS decryption** (`--tls`):
//! Intercepts `SSL_write` and `SSL_read` in libssl/libcrypto to capture the
//! plaintext buffer before encryption (write) or after decryption (read).
//! Programs: `ssl_write_enter`, `ssl_write_exit`, `ssl_read_enter`, `ssl_read_exit`.
//!
//! **ltrace / memory tracing** (`--ltrace`):
//! Intercepts `malloc`, `free`, `calloc`, `realloc` in libc to record
//! allocation call sites, sizes, and return pointers.
//! Programs: `ltrace_malloc`, `ltrace_malloc_ret`,
//!           `ltrace_free`, `ltrace_free_ret`,
//!           `ltrace_calloc`, `ltrace_calloc_ret`,
//!           `ltrace_realloc`, `ltrace_realloc_ret`.
//!
//! All programs respect the TARGET_PID / EXTRA_PIDS filter so they only
//! emit events for the traced process tree.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_bytes},
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use snoop_common::{LibCallEvent, LibFunc, TLS_DATA_MAX};

use crate::maps::{
    EXTRA_PIDS, LIB_EVENTS, LTRACE_ENTER, SSL_ENTER, TARGET_PID, TLS_BUF,
    LtraceEnterData, SslEnterData,
};

// ── PID filter helper ─────────────────────────────────────────────────────────

/// Returns `false` when the current PID is NOT in the trace scope.
#[inline(always)]
fn pid_allowed(pid: u32) -> bool {
    if let Some(&target) = unsafe { TARGET_PID.get(0) } {
        if target != 0 && pid != target {
            return unsafe { EXTRA_PIDS.get(&pid) }.is_some();
        }
    }
    true
}

// ── TLS probes: SSL_write ─────────────────────────────────────────────────────

/// Uprobe on `SSL_write(SSL *ssl, const void *buf, int num)`.
///
/// Saves `buf` and `num` in `SSL_ENTER` for the exit probe to read.
#[uprobe(name = "ssl_write_enter")]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_enter(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

/// Uretprobe on `SSL_write` — reads the plaintext buffer and emits a `LibCallEvent`.
#[uretprobe(name = "ssl_write_exit")]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_exit(&ctx, LibFunc::SslWrite as u8) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

// ── TLS probes: SSL_read ──────────────────────────────────────────────────────

/// Uprobe on `SSL_read(SSL *ssl, void *buf, int num)`.
#[uprobe(name = "ssl_read_enter")]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_enter(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

/// Uretprobe on `SSL_read` — reads the decrypted buffer and emits a `LibCallEvent`.
#[uretprobe(name = "ssl_read_exit")]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_exit(&ctx, LibFunc::SslRead as u8) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

// ── ltrace probes: malloc ─────────────────────────────────────────────────────

#[uprobe(name = "ltrace_malloc")]
pub fn ltrace_malloc(ctx: ProbeContext) -> u32 {
    ltrace_enter_impl(&ctx, LibFunc::Malloc as u8)
}

#[uretprobe(name = "ltrace_malloc_ret")]
pub fn ltrace_malloc_ret(ctx: RetProbeContext) -> u32 {
    ltrace_exit_impl(&ctx, LibFunc::Malloc as u8)
}

// ── ltrace probes: free ───────────────────────────────────────────────────────

#[uprobe(name = "ltrace_free")]
pub fn ltrace_free(ctx: ProbeContext) -> u32 {
    ltrace_enter_impl(&ctx, LibFunc::Free as u8)
}

#[uretprobe(name = "ltrace_free_ret")]
pub fn ltrace_free_ret(ctx: RetProbeContext) -> u32 {
    ltrace_exit_impl(&ctx, LibFunc::Free as u8)
}

// ── ltrace probes: calloc ─────────────────────────────────────────────────────

#[uprobe(name = "ltrace_calloc")]
pub fn ltrace_calloc(ctx: ProbeContext) -> u32 {
    ltrace_enter_impl(&ctx, LibFunc::Calloc as u8)
}

#[uretprobe(name = "ltrace_calloc_ret")]
pub fn ltrace_calloc_ret(ctx: RetProbeContext) -> u32 {
    ltrace_exit_impl(&ctx, LibFunc::Calloc as u8)
}

// ── ltrace probes: realloc ────────────────────────────────────────────────────

#[uprobe(name = "ltrace_realloc")]
pub fn ltrace_realloc(ctx: ProbeContext) -> u32 {
    ltrace_enter_impl(&ctx, LibFunc::Realloc as u8)
}

#[uretprobe(name = "ltrace_realloc_ret")]
pub fn ltrace_realloc_ret(ctx: RetProbeContext) -> u32 {
    ltrace_exit_impl(&ctx, LibFunc::Realloc as u8)
}

// ── shared SSL implementation ─────────────────────────────────────────────────

/// Common entry logic for `SSL_write` and `SSL_read`.
///
/// Saves the data buffer pointer and declared length in `SSL_ENTER`.
/// `_is_write` is currently unused but retained for future differentiation.
#[inline(always)]
fn try_ssl_enter(ctx: &ProbeContext, _is_write: bool) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;

    if !pid_allowed(pid) {
        return Ok(());
    }

    // SSL_write(ssl*, buf*, num) / SSL_read(ssl*, buf*, num)
    // arg(0) = SSL*  arg(1) = buf*  arg(2) = num
    let buf_ptr: u64 = unsafe { ctx.arg(1) }.unwrap_or(0);
    let num: u64 = unsafe { ctx.arg::<u64>(2) }.unwrap_or(0);

    let mut comm = [0u8; 16];
    let _ = unsafe { bpf_get_current_comm(&mut comm) };

    let data = SslEnterData {
        buf_ptr,
        num,
        enter_ns: unsafe { bpf_ktime_get_ns() },
        comm,
    };

    unsafe { SSL_ENTER.insert(&pid_tgid, &data, 0) }.map_err(|e| e as i64)?;
    Ok(())
}

/// Common exit logic for `SSL_write` and `SSL_read`.
///
/// Reads `SslEnterData`, captures up to `TLS_DATA_MAX` bytes of plaintext,
/// and emits a `LibCallEvent` to `LIB_EVENTS`.
#[inline(always)]
fn try_ssl_exit(ctx: &RetProbeContext, func: u8) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let enter = match unsafe { SSL_ENTER.get(&pid_tgid) } {
        Some(d) => *d,
        None => return Ok(()),
    };
    let _ = unsafe { SSL_ENTER.remove(&pid_tgid) };

    let ret: i64 = unsafe { ctx.ret_val() }.unwrap_or(-1);
    let exit_ns = unsafe { bpf_ktime_get_ns() };

    let mut rb_entry = match unsafe { LIB_EVENTS.reserve::<LibCallEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };

    let ev: *mut LibCallEvent = rb_entry.as_mut_ptr();

    // Write fixed fields into ring-buffer memory (avoids a 364-byte stack alloc).
    unsafe {
        core::ptr::addr_of_mut!((*ev).pid).write(pid);
        core::ptr::addr_of_mut!((*ev).tid).write(tid);
        core::ptr::addr_of_mut!((*ev).func).write(func);
        core::ptr::addr_of_mut!((*ev)._pad).write([0u8; 3]);
        core::ptr::addr_of_mut!((*ev).enter_ns).write(enter.enter_ns);
        core::ptr::addr_of_mut!((*ev).exit_ns).write(exit_ns);
        core::ptr::addr_of_mut!((*ev).comm).write(enter.comm);
        // args[0] = ssl*, args[1] = buf*, args[2] = num — reconstruct from enter
        core::ptr::addr_of_mut!((*ev).args).write([0, enter.buf_ptr, enter.num, 0, 0, 0]);
        core::ptr::addr_of_mut!((*ev).ret).write(ret);
        core::ptr::addr_of_mut!((*ev)._pad2).write([0u8; 6]);
    }

    // Capture plaintext — only when the call succeeded (ret > 0).
    let data_len = if ret > 0 && enter.buf_ptr != 0 {
        // How many bytes to capture:
        // For SSL_write, `enter.num` is the length we passed in.
        // For SSL_read,  `ret` is the number of bytes actually read.
        // We cap both at TLS_DATA_MAX.
        let want = if func == LibFunc::SslWrite as u8 {
            (enter.num as usize).min(TLS_DATA_MAX)
        } else {
            (ret as usize).min(TLS_DATA_MAX)
        };

        if want > 0 {
            let scratch: *mut [u8; TLS_DATA_MAX] = match unsafe { TLS_BUF.get_ptr_mut(0) } {
                Some(p) => p,
                None => {
                    unsafe { core::ptr::addr_of_mut!((*ev).data_len).write(0) };
                    rb_entry.submit(0);
                    return Ok(());
                }
            };

            let dest = unsafe {
                core::slice::from_raw_parts_mut(scratch as *mut u8, want)
            };

            let written = if unsafe {
                bpf_probe_read_user_bytes(enter.buf_ptr as *const u8, dest)
            }.is_ok() {
                unsafe {
                    let data_dst = core::ptr::addr_of_mut!((*ev).data) as *mut u8;
                    core::ptr::copy_nonoverlapping(scratch as *const u8, data_dst, want);
                }
                want as u16
            } else {
                0u16
            };
            written
        } else {
            0u16
        }
    } else {
        0u16
    };

    unsafe { core::ptr::addr_of_mut!((*ev).data_len).write(data_len) };

    rb_entry.submit(0);
    Ok(())
}

// ── shared ltrace implementation ──────────────────────────────────────────────

/// Common entry logic for all ltrace uprobes.
///
/// Saves args and entry timestamp in `LTRACE_ENTER` keyed by pid_tgid.
#[inline(always)]
fn ltrace_enter_impl(ctx: &ProbeContext, func: u8) -> u32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;

    if !pid_allowed(pid) {
        return 0;
    }

    let args: [u64; 6] = [
        unsafe { ctx.arg(0) }.unwrap_or(0),
        unsafe { ctx.arg(1) }.unwrap_or(0),
        unsafe { ctx.arg(2) }.unwrap_or(0),
        unsafe { ctx.arg(3) }.unwrap_or(0),
        unsafe { ctx.arg(4) }.unwrap_or(0),
        unsafe { ctx.arg(5) }.unwrap_or(0),
    ];

    let mut comm = [0u8; 16];
    let _ = unsafe { bpf_get_current_comm(&mut comm) };

    // Encode the func ID in the high byte of the key so different functions
    // on the same thread don't overwrite each other's entry data.
    let key = (pid_tgid & 0x0000_ffff_ffff_ffff) | ((func as u64) << 56);

    let data = LtraceEnterData {
        args,
        enter_ns: unsafe { bpf_ktime_get_ns() },
        comm,
    };

    let _ = unsafe { LTRACE_ENTER.insert(&key, &data, 0) };
    0
}

/// Common exit logic for all ltrace uretprobes.
///
/// Reads `LtraceEnterData`, combines with the return value, and emits a
/// `LibCallEvent` to `LIB_EVENTS`.
#[inline(always)]
fn ltrace_exit_impl(ctx: &RetProbeContext, func: u8) -> u32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let key = (pid_tgid & 0x0000_ffff_ffff_ffff) | ((func as u64) << 56);

    let enter = match unsafe { LTRACE_ENTER.get(&key) } {
        Some(d) => *d,
        None => return 0,
    };
    let _ = unsafe { LTRACE_ENTER.remove(&key) };

    let ret: i64 = unsafe { ctx.ret_val() }.unwrap_or(0);
    let exit_ns = unsafe { bpf_ktime_get_ns() };

    let mut rb_entry = match unsafe { LIB_EVENTS.reserve::<LibCallEvent>(0) } {
        Some(e) => e,
        None => return 0,
    };

    let ev: *mut LibCallEvent = rb_entry.as_mut_ptr();

    unsafe {
        core::ptr::addr_of_mut!((*ev).pid).write(pid);
        core::ptr::addr_of_mut!((*ev).tid).write(tid);
        core::ptr::addr_of_mut!((*ev).func).write(func);
        core::ptr::addr_of_mut!((*ev)._pad).write([0u8; 3]);
        core::ptr::addr_of_mut!((*ev).enter_ns).write(enter.enter_ns);
        core::ptr::addr_of_mut!((*ev).exit_ns).write(exit_ns);
        core::ptr::addr_of_mut!((*ev).comm).write(enter.comm);
        core::ptr::addr_of_mut!((*ev).args).write(enter.args);
        core::ptr::addr_of_mut!((*ev).ret).write(ret);
        // No data payload for ltrace functions.
        core::ptr::addr_of_mut!((*ev).data_len).write(0);
        core::ptr::addr_of_mut!((*ev)._pad2).write([0u8; 6]);
        // Zero the unused data field.
        core::ptr::addr_of_mut!((*ev).data).write_bytes(0, 1);
    }

    rb_entry.submit(0);
    0
}
