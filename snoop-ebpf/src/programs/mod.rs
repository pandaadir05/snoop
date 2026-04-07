//! Tracepoint programs.

mod sys_enter;
mod sys_exit;

pub use sys_enter::sys_enter;
pub use sys_exit::sys_exit;
