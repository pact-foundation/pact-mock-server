//! Sets up a log sink to view logs from the FFI.

mod ffi;
mod level_filter;
mod logger;
mod sink;
mod status;
mod target;
mod inmem_buffer;

pub use crate::log::ffi::{
    logger_apply,
    logger_attach_sink,
    logger_init,
    fetch_log_buffer,
    log_to_stdout,
    log_to_stderr,
    log_to_file,
    log_to_buffer,
    init,
    init_with_log_level,
    log_message
};
pub(crate) use crate::log::target::TARGET;
