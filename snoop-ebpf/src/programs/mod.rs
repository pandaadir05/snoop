//! Tracepoint and uprobe programs.

mod sys_enter;
mod sys_exit;
mod uprobes;

pub use sys_enter::sys_enter;
pub use sys_exit::sys_exit;
pub use uprobes::{
    ltrace_calloc,
    ltrace_calloc_ret,
    ltrace_free,
    ltrace_free_ret,
    // ltrace
    ltrace_malloc,
    ltrace_malloc_ret,
    ltrace_realloc,
    ltrace_realloc_ret,
    ssl_read_enter,
    ssl_read_exit,
    // SSL/TLS
    ssl_write_enter,
    ssl_write_exit,
};
