//! The public FFI functions for initializing, adding sinks to, and applying a logger.

use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::ptr;
use std::str::from_utf8;

use fern::Dispatch;
use libc::{c_char, c_int};
use log::{error, LevelFilter as LogLevelFilter};

use pact_matching::logging::fetch_buffer_contents;

use crate::error::set_error_msg;
use crate::log::level_filter::LevelFilter;
use crate::log::logger::{add_sink, apply_logger, set_logger};
use crate::log::sink::Sink;
use crate::log::status::Status;
use crate::util::string::to_c;
use log::*;
use std::str::FromStr;
use env_logger::Builder;

/// Convenience function to direct all logging to stdout.
#[no_mangle]
pub extern "C" fn log_to_stdout(level_filter: LevelFilter) -> c_int {
    logger_init();

    let spec = match CString::new("stdout") {
        Ok(spec) => spec,
        Err(e) => {
            set_error_msg(e.to_string());
            return Status::CantConstructSink as c_int;
        }
    };

    let status = logger_attach_sink(spec.as_ptr(), level_filter);
    if status != 0 {
        return status;
    }

    let status = logger_apply();
    if status != 0 {
        return status;
    }

    Status::Success as c_int
}

/// Convenience function to direct all logging to stderr.
#[no_mangle]
pub extern "C" fn log_to_stderr(level_filter: LevelFilter) -> c_int {
    logger_init();

    let spec = match CString::new("stderr") {
        Ok(spec) => spec,
        Err(e) => {
            set_error_msg(e.to_string());
            return Status::CantConstructSink as c_int;
        }
    };

    let status = logger_attach_sink(spec.as_ptr(), level_filter);
    if status != 0 {
        return status;
    }

    let status = logger_apply();
    if status != 0 {
        return status;
    }

    Status::Success as c_int
}

/// Convenience function to direct all logging to a file.
#[no_mangle]
pub unsafe extern "C" fn log_to_file(
    file_name: *const c_char,
    level_filter: LevelFilter,
) -> c_int {
    logger_init();

    let spec = {
        if file_name.is_null() {
            return Status::CantConstructSink as c_int;
        }

        let file_name =
            match CStr::from_ptr(file_name).to_str() {
                Ok(file_name) => file_name,
                Err(e) => {
                    set_error_msg(e.to_string());
                    return Status::CantConstructSink as c_int;
                }
            };

        let spec = format!("file {}", file_name);

        match CString::new(spec) {
            Ok(spec) => spec,
            Err(e) => {
                set_error_msg(e.to_string());
                return Status::CantConstructSink as c_int;
            }
        }
    };

    let status = logger_attach_sink(spec.as_ptr(), level_filter);
    if status != 0 {
        return status;
    }

    let status = logger_apply();
    if status != 0 {
        return status;
    }

    Status::Success as c_int
}


/// Convenience function to direct all logging to a thread local memory buffer.
#[no_mangle]
pub extern "C" fn log_to_buffer(level_filter: LevelFilter) -> c_int {
  logger_init();

  let spec = match CString::new("buffer") {
    Ok(spec) => spec,
    Err(e) => {
      set_error_msg(e.to_string());
      return Status::CantConstructSink as c_int;
    }
  };

  let status = logger_attach_sink(spec.as_ptr(), level_filter);
  if status != 0 {
    return status;
  }

  let status = logger_apply();
  if status != 0 {
    return status;
  }

  Status::Success as c_int
}

// C API uses something like the pledge API to select write locations, including:
//
// * stdout (`logger_attach_sink("stdout", LevelFilter_Info)`)
// * stderr (`logger_attach_sink("stderr", LevelFilter_Debug)`)
// * file w/ file path (`logger_attach_sink("file /some/file/path", LevelFilter_Trace)`)
//
// The general flow is:
//
// 1. Call `logger_init` to create a `Dispatch` struct.
// 2. Call `logger_attach_sink` to add an additional sink, using bitflags to set the metadata.
// 3. Call `logger_apply` to finalize the logger and enable logging to the configured sinks.
//
// Once `logger_apply` has been called, any additional calls to `logger_attach_sink` will fail
// with an error indicating the logger has been applied already.
//
// ```
// logger_init();
//
// int result = logger_attach_sink("stderr", FilterLevel_Debug);
// /* handle the error */
//
// int result = logger_attach_sink("file /some/file/path", FilterLevel_Info);
// /* handle the error */
//
// int result = logger_apply();
// /* handle the error */
// ```

/// Initialize the thread-local logger with no sinks.
///
/// This initialized logger does nothing until `logger_apply` has been called.
///
/// # Usage
///
/// ```c
/// logger_init();
/// ```
///
/// # Safety
///
/// This function is always safe to call.
#[no_mangle]
pub extern "C" fn logger_init() {
    set_logger(Dispatch::new());
}

/// Attach an additional sink to the thread-local logger.
///
/// This logger does nothing until `logger_apply` has been called.
///
/// Three types of sinks can be specified:
///
/// - stdout (`logger_attach_sink("stdout", LevelFilter_Info)`)
/// - stderr (`logger_attach_sink("stderr", LevelFilter_Debug)`)
/// - file w/ file path (`logger_attach_sink("file /some/file/path", LevelFilter_Trace)`)
/// - buffer (`logger_attach_sink("buffer", LevelFilter_Debug)`)
///
/// # Usage
///
/// ```c
/// int result = logger_attach_sink("file /some/file/path", LogLevel_Filter);
/// ```
///
/// # Error Handling
///
/// The return error codes are as follows:
///
/// - `-1`: Can't set logger (applying the logger failed, perhaps because one is applied already).
/// - `-2`: No logger has been initialized (call `logger_init` before any other log function).
/// - `-3`: The sink specifier was not UTF-8 encoded.
/// - `-4`: The sink type specified is not a known type (known types: "stdout", "stderr", or "file /some/path").
/// - `-5`: No file path was specified in a file-type sink specification.
/// - `-6`: Opening a sink to the specified file path failed (check permissions).
///
/// # Safety
///
/// This function checks the validity of the passed-in sink specifier, and errors
/// out if the specifier isn't valid UTF-8.
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn logger_attach_sink(
    sink_specifier: *const c_char,
    level_filter: LevelFilter,
) -> c_int {
    // Get the specifier from the raw C string.
    let sink_specifier = unsafe { CStr::from_ptr(sink_specifier) };
    let sink_specifier = match sink_specifier.to_str() {
        Ok(sink_specifier) => sink_specifier,
        // TODO: Permit non-UTF8 strings, as some filesystems may have non-UTF8
        //       paths to which the user wants to direct the logging output.
        Err(_) => return Status::SpecifierNotUtf8 as c_int,
    };

    // Attempt to construct a sink from the specifier.
    let sink = match Sink::try_from(sink_specifier) {
        Ok(sink) => sink,
        Err(err) => return Status::from(err) as c_int,
    };

    // Convert from our `#[repr(C)]` LevelFilter to the one from the `log` crate.
    let level_filter: LogLevelFilter = level_filter.into();

    // Construct a dispatcher from the sink and level filter.
    let dispatch = Into::<Dispatch>::into(sink)
        .level(level_filter)
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                record.level(),
                record.target(),
                message
            ))
        });

    // Take the existing logger, if there is one, add a new sink to it, and put it back.
    let status = match add_sink(dispatch) {
        Ok(_) => Status::Success,
        Err(err) => Status::from(err),
    };

    status as c_int
}

/// Apply the thread-local logger to the program.
///
/// Any attempts to modify the logger after the call to `logger_apply` will fail.
#[no_mangle]
pub extern "C" fn logger_apply() -> c_int {
    let status = match apply_logger() {
        Ok(_) => Status::Success,
        Err(err) => Status::from(err),
    };

    status as c_int
}


/// Fetch the in-memory logger buffer contents. This will only have any contents if the `buffer`
/// sink has been configured to log to. The contents will be allocated on the heap and will need
/// to be freed with `string_delete`.
///
/// Fetches the logs associated with the provided identifier, or uses the "global" one if the
/// identifier is not specified (i.e. NULL).
///
/// Returns a NULL pointer if the buffer can't be fetched. This can occur is there is not
/// sufficient memory to make a copy of the contents or the buffer contains non-UTF-8 characters.
#[no_mangle]
pub unsafe extern "C" fn fetch_log_buffer(log_id: *const c_char,) -> *const c_char {
  let id = if log_id.is_null() {
    "global"
  } else {
    CStr::from_ptr(log_id).to_str().unwrap_or("global")
  };
  match from_utf8(&fetch_buffer_contents(&id.to_string())) {
    Ok(contents) => match to_c(contents) {
      Ok(c_str) => c_str,
      Err(err) => {
        error!("Failed to copy in-memory log buffer - {}", err);
        ptr::null()
      }
    }
    Err(err) => {
      error!("Failed to convert in-memory log buffer to UTF-8 = {}", err);
      ptr::null()
    }
  }
}

/// Initialise the mock server library, can provide an environment variable name to use to
/// set the log levels.
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern fn init(log_env_var: *const c_char) {
  let log_env_var = if !log_env_var.is_null() {
    let c_str = CStr::from_ptr(log_env_var);
    match c_str.to_str() {
      Ok(str) => str,
      Err(err) => {
        warn!("Failed to parse the environment variable name as a UTF-8 string: {}", err);
        "LOG_LEVEL"
      }
    }
  } else {
    "LOG_LEVEL"
  };

  let env = env_logger::Env::new().filter(log_env_var);
  let mut builder = Builder::from_env(env);
  builder.try_init().unwrap_or(());
}

/// Initialises the log and sets the level explicitly.
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern "C" fn init_with_log_level(level: *const c_char) {
  let mut builder = Builder::from_default_env();
  let log_level = log_level_from_c_char(level);

  builder.filter_level(log_level.to_level_filter());
  builder.try_init().unwrap_or(());
}

/// Log using the shared core logging facility.
///
/// * `source` - String. The source of the log, such as the class or caller framework to
///                      disambiguate log lines from the rust logging (e.g. pact_go)
/// * `log_level` - String. One of TRACE, DEBUG, INFO, WARN, ERROR
/// * `message` - Message to log
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern "C" fn log_message(source: *const c_char, log_level: *const c_char, message: *const c_char) {
  let target = convert_cstr("target", source).unwrap_or("client");

  if !message.is_null() {
    match convert_cstr("message", message) {
      Some(message) => log!(
        target: target,
        log_level_from_c_char(log_level),
        "{}",
        message
      ),
      None => (),
    }
  }
}

unsafe fn log_level_from_c_char(log_level: *const c_char) -> log::Level {
  if !log_level.is_null() {
    let level = convert_cstr("log_level", log_level).unwrap_or("INFO");

    log::Level::from_str(level).unwrap_or(log::Level::Info)
  } else {
    log::Level::Info
  }
}


  fn convert_cstr(name: &str, value: *const c_char) -> Option<&str> {
    unsafe {
      if value.is_null() {
        warn!("{} is NULL!", name);
        None
      } else {
        let c_str = CStr::from_ptr(value);
        match c_str.to_str() {
          Ok(str) => Some(str),
          Err(err) => {
            warn!(
              "Failed to parse {} name as a UTF-8 string: {}",
              name, err
            );
            None
          }
        }
      }
    }}