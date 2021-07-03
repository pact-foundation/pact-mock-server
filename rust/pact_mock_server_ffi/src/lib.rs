//! The `pact_mock_server` crate provides a number of exported functions using C bindings for
//! controlling the mock server. These can be used in any language that supports C bindings.
//!
//! ## [create_mock_server](fn.create_mock_server_ffi.html)
//!
//! External interface to create a mock server. A pointer to the pact JSON as a C string is passed in,
//! as well as the port for the mock server to run on. A value of 0 for the port will result in a
//! port being allocated by the operating system. The port of the mock server is returned.
//!
//! ## [mock_server_matched](fn.mock_server_matched_ffi.html)
//!
//! Simple function that returns a boolean value given the port number of the mock service. This value will be true if all
//! the expectations of the pact that the mock server was created with have been met. It will return false if any request did
//! not match, an un-recognised request was received or an expected request was not received.
//!
//! ## [mock_server_mismatches](fn.mock_server_mismatches_ffi.html)
//!
//! This returns all the mismatches, un-expected requests and missing requests in JSON format, given the port number of the
//! mock server.
//!
//! **IMPORTANT NOTE:** The JSON string for the result is allocated on the rust heap, and will have to be freed once the
//! code using the mock server is complete. The [`cleanup_mock_server`](fn.cleanup_mock_server.html) function is provided for this purpose. If the mock
//! server is not cleaned up properly, this will result in memory leaks as the rust heap will not be reclaimed.
//!
//! ## [cleanup_mock_server](fn.cleanup_mock_server.html)
//!
//! This function will try terminate the mock server with the given port number and cleanup any memory allocated for it by
//! the [`mock_server_mismatches`](fn.mock_server_mismatches.html) function. Returns `true`, unless a mock server with the given port number does not exist,
//! or the function fails in some way.
//!
//! **NOTE:** Although `close()` on the listerner for the mock server is called, this does not currently work and the
//! listerner will continue handling requests. In this case, it will always return a 501 once the mock server has been
//! cleaned up.
//!
//! ## [write_pact_file](fn.write_pact_file.html)
//!
//! External interface to trigger a mock server to write out its pact file. This function should
//! be called if all the consumer tests have passed. The directory to write the file to is passed
//! as the second parameter. If a NULL pointer is passed, the current working directory is used.
//!
//! Returns 0 if the pact file was successfully written. Returns a positive code if the file can
//! not be written, or there is no mock server running on that port or the function panics.

#![warn(missing_docs)]

use std::{ptr, str};
use std::any::Any;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::str::from_utf8;

use bytes::Bytes;
use chrono::Local;
use env_logger::Builder;
use itertools::Itertools;
use libc::{c_char, c_ushort, size_t};
use log::*;
use maplit::*;
use onig::Regex;
use rand::prelude::*;
use serde_json::json;
use uuid::Uuid;

use pact_matching::logging::fetch_buffer_contents;
use pact_matching::models::{HttpPart, Pact, RequestResponseInteraction};
use pact_matching::models::generators::Generators;
use pact_matching::models::matchingrules::{MatchingRule, RuleLogic};
use pact_matching::models::matchingrules::MatchingRules;
use pact_matching::models::message::Message;
use pact_mock_server::{MANAGER, MockServerError, tls::TlsConfigBuilder, WritePactFileErr};
use pact_mock_server::server_manager::ServerManager;
use pact_models::bodies::OptionalBody::{Null, Present};
use pact_models::bodies::OptionalBody;
use pact_models::content_types::ContentType;
use pact_models::PactSpecification;
use pact_models::provider_states::ProviderState;
use pact_models::time_utils::{parse_pattern, to_chrono_pattern};

use crate::bodies::{empty_multipart_body, file_as_multipart_body, MultipartBody, process_json, request_multipart, response_multipart};
use crate::bodies::process_object;
use crate::handles::InteractionPart;

// Export all the FFI logging functions from pact_matching_ffi
pub use pact_matching_ffi::log::{
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

pub mod handles;
pub mod bodies;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Get the current library version
#[no_mangle]
pub extern "C" fn version() -> *const c_char {
  VERSION.as_ptr() as *const c_char
}

/// External interface to create a mock server. A pointer to the pact JSON as a C string is passed in,
/// as well as the port for the mock server to run on. A value of 0 for the port will result in a
/// port being allocated by the operating system. The port of the mock server is returned.
///
/// * `pact_str` - Pact JSON
/// * `addr_str` - Address to bind to in the form name:port (i.e. 127.0.0.1:0)
/// * `tls` - boolean flag to indicate of the mock server should use TLS (using a self-signed certificate)
///
/// # Errors
///
/// Errors are returned as negative values.
///
/// | Error | Description |
/// |-------|-------------|
/// | -1 | A null pointer was received |
/// | -2 | The pact JSON could not be parsed |
/// | -3 | The mock server could not be started |
/// | -4 | The method panicked |
/// | -5 | The address is not valid |
/// | -6 | Could not create the TLS configuration with the self-signed certificate |
///
#[no_mangle]
pub extern fn create_mock_server(pact_str: *const c_char, addr_str: *const c_char, tls: bool) -> i32 {
  let result = catch_unwind(|| {
    let c_str = unsafe {
      if pact_str.is_null() {
        log::error!("Got a null pointer instead of pact json");
        return -1;
      }
      CStr::from_ptr(pact_str)
    };

    let addr_c_str = unsafe {
      if addr_str.is_null() {
        log::error!("Got a null pointer instead of listener address");
        return -1;
      }
      CStr::from_ptr(addr_str)
    };

    let tls_config = if tls {
      let key = include_str!("self-signed.key");
      let cert = include_str!("self-signed.crt");
      match TlsConfigBuilder::new()
        .key(key.as_bytes())
        .cert(cert.as_bytes())
        .build() {
        Ok(tls_config) => Some(tls_config),
        Err(err) => {
          error!("Failed to build TLS configuration - {}", err);
          return -6;
        }
      }
    } else {
      None
    };

    if let Ok(Ok(addr)) = str::from_utf8(addr_c_str.to_bytes()).map(|s| s.parse::<std::net::SocketAddr>()) {
      let server_result = match tls_config {
        Some(tls_config) => pact_mock_server::create_tls_mock_server(str::from_utf8(c_str.to_bytes()).unwrap(), addr, &tls_config),
        None => pact_mock_server::create_mock_server(str::from_utf8(c_str.to_bytes()).unwrap(), addr)
      };
      match server_result {
        Ok(ms_port) => ms_port,
        Err(err) => match err.downcast_ref::<MockServerError>() {
          Some(err) => match err {
            MockServerError::InvalidPactJson => -2,
            MockServerError::MockServerFailedToStart => -3
          },
          None => -3
        }
      }
    }
    else {
      -5
    }
  });

  match result {
    Ok(val) => val,
    Err(cause) => {
      log::error!("Caught a general panic: {:?}", cause);
      -4
    }
  }
}

/// Fetch the CA Certificate used to generate the self-signed certificate for the TLS mock server.
///
/// **NOTE:** The string for the result is allocated on the heap, and will have to be freed
/// by the caller using free_string
///
/// # Errors
///
/// An empty string indicates an error reading the pem file
#[no_mangle]
pub extern fn get_tls_ca_certificate() -> *mut c_char  {
  let cert_file = include_str!("ca.pem");
  let cert_str = CString::new(cert_file).unwrap_or_default();

  cert_str.into_raw()
}

/// External interface to create a mock server. A Pact handle is passed in,
/// as well as the port for the mock server to run on. A value of 0 for the port will result in a
/// port being allocated by the operating system. The port of the mock server is returned.
///
/// * `pact` - Handle to a Pact model
/// * `addr_str` - Address to bind to in the form name:port (i.e. 127.0.0.1:0)
/// * `tls` - boolean flag to indicate of the mock server should use TLS (using a self-signed certificate)
///
/// # Errors
///
/// Errors are returned as negative values.
///
/// | Error | Description |
/// |-------|-------------|
/// | -1 | An invalid handle was received |
/// | -3 | The mock server could not be started |
/// | -4 | The method panicked |
/// | -5 | The address is not valid |
/// | -6 | Could not create the TLS configuration with the self-signed certificate |
///
#[no_mangle]
pub extern fn create_mock_server_for_pact(pact: handles::PactHandle, addr_str: *const c_char, tls: bool) -> i32 {
  let result = catch_unwind(|| {
    let addr_c_str = unsafe {
      if addr_str.is_null() {
        log::error!("Got a null pointer instead of listener address");
        return -1;
      }
      CStr::from_ptr(addr_str)
    };

    let tls_config = if tls {
      let key = include_str!("self-signed.key");
      let cert = include_str!("self-signed.crt");
      match TlsConfigBuilder::new()
        .key(key.as_bytes())
        .cert(cert.as_bytes())
        .build() {
        Ok(tls_config) => Some(tls_config),
        Err(err) => {
          error!("Failed to build TLS configuration - {}", err);
          return -6;
        }
      }
    } else {
      None
    };

    if let Ok(Ok(addr)) = str::from_utf8(addr_c_str.to_bytes()).map(|s| s.parse::<std::net::SocketAddr>()) {
      pact.with_pact(&move |_, inner| {
        let server_result = match &tls_config {
          Some(tls_config) => pact_mock_server::start_tls_mock_server(
            Uuid::new_v4().to_string(), inner.pact.boxed(), addr, tls_config),
          None => pact_mock_server::start_mock_server(Uuid::new_v4().to_string(), inner.pact.boxed(), addr)
        };
        match server_result {
          Ok(ms_port) => {
            inner.mock_server_started = true;
            ms_port
          },
          Err(err) => {
            error!("Failed to start mock server - {}", err);
            -3
          }
        }
      }).unwrap_or(-1)
    }
    else {
      -5
    }
  });

  match result {
    Ok(val) => val,
    Err(cause) => {
      log::error!("Caught a general panic: {:?}", cause);
      -4
    }
  }
}

/// External interface to check if a mock server has matched all its requests. The port number is
/// passed in, and if all requests have been matched, true is returned. False is returned if there
/// is no mock server on the given port, or if any request has not been successfully matched, or
/// the method panics.
#[no_mangle]
pub extern fn mock_server_matched(mock_server_port: i32) -> bool {
  let result = catch_unwind(|| {
    pact_mock_server::mock_server_matched(mock_server_port)
  });

  match result {
    Ok(val) => val,
    Err(cause) => {
      error!("Caught a general panic: {:?}", cause);
      false
    }
  }
}

/// External interface to get all the mismatches from a mock server. The port number of the mock
/// server is passed in, and a pointer to a C string with the mismatches in JSON format is
/// returned.
///
/// **NOTE:** The JSON string for the result is allocated on the heap, and will have to be freed
/// once the code using the mock server is complete. The [`cleanup_mock_server`](fn.cleanup_mock_server.html) function is
/// provided for this purpose.
///
/// # Errors
///
/// If there is no mock server with the provided port number, or the function panics, a NULL
/// pointer will be returned. Don't try to dereference it, it will not end well for you.
///
#[no_mangle]
pub extern fn mock_server_mismatches(mock_server_port: i32) -> *mut c_char {
  let result = catch_unwind(|| {
    let result = MANAGER.lock().unwrap()
      .get_or_insert_with(ServerManager::new)
      .find_mock_server_by_port_mut(mock_server_port as u16, &|ref mut mock_server| {
        let mismatches = mock_server.mismatches().iter()
          .map(|mismatch| mismatch.to_json() )
          .collect::<Vec<serde_json::Value>>();
        let json = json!(mismatches);
        let s = CString::new(json.to_string()).unwrap();
        let p = s.as_ptr();
        mock_server.resources.push(s);
        p
      });
    match result {
      Some(p) => p as *mut _,
      None => std::ptr::null_mut()
    }
  });

  match result {
    Ok(val) => val,
    Err(cause) => {
      error!("{}", error_message(cause, "mock_server_mismatches"));
      std::ptr::null_mut()
    }
  }
}

/// External interface to cleanup a mock server. This function will try terminate the mock server
/// with the given port number and cleanup any memory allocated for it. Returns true, unless a
/// mock server with the given port number does not exist, or the function panics.
#[no_mangle]
pub extern fn cleanup_mock_server(mock_server_port: i32) -> bool {
  let result = catch_unwind(|| {
    pact_mock_server::shutdown_mock_server(mock_server_port)
  });

  match result {
    Ok(val) => val,
    Err(cause) => {
      log::error!("Caught a general panic: {:?}", cause);
      false
    }
  }
}

/// External interface to trigger a mock server to write out its pact file. This function should
/// be called if all the consumer tests have passed. The directory to write the file to is passed
/// as the second parameter. If a NULL pointer is passed, the current working directory is used.
///
/// If overwrite is true, the file will be overwritten with the contents of the current pact.
/// Otherwise, it will be merged with any existing pact file.
///
/// Returns 0 if the pact file was successfully written. Returns a positive code if the file can
/// not be written, or there is no mock server running on that port or the function panics.
///
/// # Errors
///
/// Errors are returned as positive values.
///
/// | Error | Description |
/// |-------|-------------|
/// | 1 | A general panic was caught |
/// | 2 | The pact file was not able to be written |
/// | 3 | A mock server with the provided port was not found |
#[no_mangle]
pub extern fn write_pact_file(mock_server_port: i32, directory: *const c_char, overwrite: bool) -> i32 {
  let result = catch_unwind(|| {
    let dir = path_from_dir(directory, None);
    let path = dir.map(|path| path.into_os_string().into_string().unwrap_or_default());

    pact_mock_server::write_pact_file(mock_server_port, path, overwrite)
  });

  match result {
    Ok(val) => match val {
      Ok(_) => 0,
      Err(err) => match err {
        WritePactFileErr::IOError => 2,
        WritePactFileErr::NoMockServer => 3
      }
    },
    Err(cause) => {
      log::error!("Caught a general panic: {:?}", cause);
      1
    }
  }
}


/// Fetch the logs for the mock server. This needs the memory buffer log sink to be setup before
/// the mock server is started. Returned string will be freed with the `cleanup_mock_server`
/// function call.
///
/// Will return a NULL pointer if the logs for the mock server can not be retrieved.
#[no_mangle]
pub extern fn mock_server_logs(mock_server_port: i32) -> *const c_char {
  let result = catch_unwind(|| {
    MANAGER.lock().unwrap()
      .get_or_insert_with(ServerManager::new)
      .find_mock_server_by_port_mut(mock_server_port as u16, &|mock_server| {
        match from_utf8(&fetch_buffer_contents(&mock_server.id)) {
          Ok(contents) => match CString::new(contents.to_string()) {
            Ok(c_str) => {
              let p = c_str.as_ptr();
              mock_server.resources.push(c_str);
              p
            },
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
      })
  });

  match result {
    Ok(val) => val.unwrap_or_else(|| ptr::null()),
    Err(cause) => {
      error!("Caught a general panic: {:?}", cause);
      ptr::null()
    }
  }
}

/// Creates a new Pact model and returns a handle to it.
///
/// * `consumer_name` - The name of the consumer for the pact.
/// * `provider_name` - The name of the provider for the pact.
///
/// Returns a new `PactHandle`.
#[no_mangle]
pub extern fn new_pact(consumer_name: *const c_char, provider_name: *const c_char) -> handles::PactHandle {
  let consumer = convert_cstr("consumer_name", consumer_name).unwrap_or_else(|| "Consumer");
  let provider = convert_cstr("provider_name", provider_name).unwrap_or_else(|| "Provider");
  handles::PactHandle::new(consumer, provider)
}

/// Creates a new Interaction and returns a handle to it.
///
/// * `description` - The interaction description. It needs to be unique for each interaction.
///
/// Returns a new `InteractionHandle`.
#[no_mangle]
pub extern fn new_interaction(pact: handles::PactHandle, description: *const c_char) -> handles::InteractionHandle {
  if let Some(description) = convert_cstr("description", description) {
    pact.with_pact(&|_, inner| {
      let interaction = RequestResponseInteraction {
        description: description.to_string(),
        ..RequestResponseInteraction::default()
      };
      inner.pact.interactions.push(interaction);
      handles::InteractionHandle::new(pact.clone(), inner.pact.interactions.len())
    }).unwrap_or_else(|| handles::InteractionHandle::new(pact.clone(), 0))
  } else {
    handles::InteractionHandle::new(pact.clone(), 0)
  }
}

/// Sets the description for the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `description` - The interaction description. It needs to be unique for each interaction.
#[no_mangle]
pub extern fn upon_receiving(interaction: handles::InteractionHandle, description: *const c_char) -> bool {
  if let Some(description) = convert_cstr("description", description) {
    interaction.with_interaction(&|_, mock_server_started, inner| {
      inner.description = description.to_string();
      !mock_server_started
    }).unwrap_or(false)
  } else {
    false
  }
}

/// Adds a provider state to the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `description` - The provider state description. It needs to be unique.
#[no_mangle]
pub extern fn given(interaction: handles::InteractionHandle, description: *const c_char) -> bool {
  if let Some(description) = convert_cstr("description", description) {
    interaction.with_interaction(&|_, mock_server_started, inner| {
      inner.provider_states.push(ProviderState::default(&description.to_string()));
      !mock_server_started
    }).unwrap_or(false)
  } else {
    false
  }
}

/// Adds a provider state to the Interaction with a parameter key and value. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `description` - The provider state description. It needs to be unique.
/// * `name` - Parameter name.
/// * `value` - Parameter value.
#[no_mangle]
pub extern fn given_with_param(interaction: handles::InteractionHandle, description: *const c_char,
                               name: *const c_char, value: *const c_char) -> bool {
  if let Some(description) = convert_cstr("description", description) {
    if let Some(name) = convert_cstr("name", name) {
      let value = convert_cstr("value", value).unwrap_or_default();
      interaction.with_interaction(&|_, mock_server_started, inner| {
        let value = match serde_json::from_str(value) {
          Ok(json) => json,
          Err(_) => json!(value)
        };
        match inner.provider_states.iter().find_position(|state| state.name == description) {
          Some((index, _)) => {
            inner.provider_states.get_mut(index).unwrap().params.insert(name.to_string(), value);
          },
          None => inner.provider_states.push(ProviderState {
            name: description.to_string(),
            params: hashmap!{ name.to_string() => value }
          })
        };
        !mock_server_started
      }).unwrap_or(false)
    } else {
      false
    }
  } else {
    false
  }
}

/// Configures the request for the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `method` - The request method. Defaults to GET.
/// * `path` - The request path. Defaults to `/`.
#[no_mangle]
pub extern fn with_request(
  interaction: handles::InteractionHandle,
  method: *const c_char,
  path: *const c_char
) -> bool {
  let method = convert_cstr("method", method).unwrap_or_else(|| "GET");
  let path = convert_cstr("path", path).unwrap_or_else(|| "/");

  interaction.with_interaction(&|_, mock_server_started, inner| {
    let path = from_integration_json(&mut inner.request.matching_rules, &mut inner.request.generators, &path.to_string(), &"".to_string(), "path");
    inner.request.method = method.to_string();
    inner.request.path = path.to_string();
    !mock_server_started
  }).unwrap_or(false)
}

/// Configures a query parameter for the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `name` - the query parameter name.
/// * `value` - the query parameter value.
/// * `index` - the index of the value (starts at 0). You can use this to create a query parameter with multiple values
#[no_mangle]
pub extern fn with_query_parameter(
  interaction: handles::InteractionHandle,
  name: *const c_char,
  index: size_t,
  value: *const c_char
) -> bool {
  if let Some(name) = convert_cstr("name", name) {
    let value = convert_cstr("value", value).unwrap_or_default();
    interaction.with_interaction(&|_, mock_server_started, inner| {
      inner.request.query = inner.request.query.clone().map(|mut q| {
        let value = from_integration_json(&mut inner.request.matching_rules, &mut inner.request.generators, &value.to_string(), &format!("{}[{}]", &name, index).to_string(), "query");
        if q.contains_key(name) {
          let values = q.get_mut(name).unwrap();
          if index >= values.len() {
            values.resize_with(index + 1, Default::default);
          }
          values[index] = value.to_string();
        } else {
          let mut values: Vec<String> = Vec::new();
          values.resize_with(index + 1, Default::default);
          values[index] = value.to_string();
          q.insert(name.to_string(), values);
        };
        q
      }).or_else(|| {
        let value = from_integration_json(&mut inner.request.matching_rules, &mut inner.request.generators, &value.to_string(), &format!("{}[{}]", &name, index).to_string(), "query");
        let mut values: Vec<String> = Vec::new();
        values.resize_with(index + 1, Default::default);
        values[index] = value.to_string();
        Some(hashmap!{ name.to_string() => values })
      });
      !mock_server_started
    }).unwrap_or(false)
  } else {
    warn!("Ignoring query parameter with empty or null name");
    false
  }
}

/// Convert JSON matching rule structures into their internal representation (excl. bodies)
///
/// For non-body values (headers, query, path etc.) extract out the value from any matchers
/// and apply the matchers/generators to the model
fn from_integration_json(rules: &mut MatchingRules, generators: &mut Generators, value: &str, path: &str, category: &str) -> String {
  let category = rules.add_category(category);

  match serde_json::from_str(&value) {
    Ok(json) => match json {
      serde_json::Value::Object(ref map) => {
        let json: serde_json::Value = process_object(map, category, generators, path, false, false);
        // These are simple JSON primitives (strings), so we must unescape them
        json.as_str().unwrap_or_default().to_string()
      },
      _ => value.to_string()
    },
    Err(_) => value.to_string()
  }
}

/// Sets the specification version for a given Pact model. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `pact` - Handle to a Pact model
/// * `version` - the spec version to use
#[no_mangle]
pub extern fn with_specification(pact: handles::PactHandle, version: PactSpecification) -> bool {
  pact.with_pact(&|_, inner| {
    inner.pact.specification_version = version.clone();
    !inner.mock_server_started
  }).unwrap_or(false)
}

/// Sets the additional metadata on the Pact file. Common uses are to add the client library details such as the name and version
/// Returns false if the interaction or Pact can't be modified (i.e. the mock server for it has already started)
///
/// * `pact` - Handle to a Pact model
/// * `namespace` - the top level metadat key to set any key values on
/// * `name` - the key to set
/// * `value` - the value to set
#[no_mangle]
pub extern fn with_pact_metadata(
  pact: handles::PactHandle,
  namespace: *const c_char,
  name: *const c_char,
  value: *const c_char
) -> bool {
  pact.with_pact(&|_, inner| {
    let namespace = convert_cstr("namespace", namespace).unwrap_or_default();
    let name = convert_cstr("name", name).unwrap_or_default();
    let value = convert_cstr("value", value).unwrap_or_default();

    if !namespace.is_empty() {
      let mut child = BTreeMap::new();
      child.insert(name.to_string(), value.to_string());
      inner.pact.metadata.insert(namespace.to_string(), child);
    } else {
      log::warn!("no namespace provided for metadata {:?} => {:?}. Ignoring", name, value);
    }
    !inner.mock_server_started
  }).unwrap_or(false)
}

/// Configures a header for the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `part` - The part of the interaction to add the header to (Request or Response).
/// * `name` - the header name.
/// * `value` - the header value.
/// * `index` - the index of the value (starts at 0). You can use this to create a header with multiple values
#[no_mangle]
pub extern fn with_header(
  interaction: handles::InteractionHandle,
  part: InteractionPart,
  name: *const c_char,
  index: size_t,
  value: *const c_char
) -> bool {
  if let Some(name) = convert_cstr("name", name) {
    let value = convert_cstr("value", value).unwrap_or_default();
    interaction.with_interaction(&|_, mock_server_started, inner| {
      let headers = match part {
        InteractionPart::Request => inner.request.headers.clone(),
        InteractionPart::Response => inner.response.headers.clone()
      };

      let value = match part {
        InteractionPart::Request => from_integration_json(&mut inner.request.matching_rules,
                                                          &mut inner.request.generators,
                                                          &value.to_string(),
                                                          &name.to_string(),
                                                          "header"),
        InteractionPart::Response => from_integration_json(&mut inner.response.matching_rules,
                                                           &mut inner.response.generators,
                                                           &value.to_string(),
                                                           &name.to_string(),
                                                           "header")
      };

      let updated_headers = headers.map(|mut h| {
        if h.contains_key(name) {
          let values = h.get_mut(name).unwrap();
          if index >= values.len() {
            values.resize_with(index + 1, Default::default);
          }
          values[index] = value.to_string();
        } else {
          let mut values: Vec<String> = Vec::new();
          values.resize_with(index + 1, Default::default);
          values[index] = value.to_string();
          h.insert(name.to_string(), values);
        };
        h
      }).or_else(|| {
        let mut values: Vec<String> = Vec::new();
        values.resize_with(index + 1, Default::default);
        values[index] = value.to_string();
        Some(hashmap!{ name.to_string() => values })
      });
      match part {
        InteractionPart::Request => inner.request.headers = updated_headers,
        InteractionPart::Response => inner.response.headers = updated_headers
      };
      !mock_server_started
    }).unwrap_or(false)
  } else {
    warn!("Ignoring header with empty or null name");
    false
  }
}

/// Configures the response for the Interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `status` - the response status. Defaults to 200.
#[no_mangle]
pub extern fn response_status(interaction: handles::InteractionHandle, status: c_ushort) -> bool {
  interaction.with_interaction(&|_, mock_server_started, inner| {
    inner.response.status = status;
    !mock_server_started
  }).unwrap_or(false)
}

/// Adds the body for the interaction. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `part` - The part of the interaction to add the body to (Request or Response).
/// * `content_type` - The content type of the body. Defaults to `text/plain`. Will be ignored if a content type
///   header is already set.
/// * `body` - The body contents. For JSON payloads, matching rules can be embedded in the body.
#[no_mangle]
pub extern fn with_body(
  interaction: handles::InteractionHandle,
  part: InteractionPart,
  content_type: *const c_char,
  body: *const c_char
) -> bool {
  let content_type = convert_cstr("content_type", content_type).unwrap_or("text/plain");
  let body = convert_cstr("body", body).unwrap_or_default();
  let content_type_header = "Content-Type".to_string();
  interaction.with_interaction(&|_, mock_server_started, inner| {
    match part {
      InteractionPart::Request => {
        if !inner.request.has_header(&content_type_header) {
          match inner.request.headers {
            Some(ref mut headers) => {
              headers.insert(content_type_header.clone(), vec![ content_type.to_string() ]);
            },
            None => {
              inner.request.headers = Some(hashmap! { content_type_header.clone() => vec![ content_type.to_string() ]});
            }
          }
        }
        let body = if inner.request.content_type().unwrap_or_default().is_json() {
          let category = inner.request.matching_rules.add_category("body");
          OptionalBody::from(process_json(body.to_string(), category, &mut inner.request.generators))
        } else {
          OptionalBody::from(body)
        };
        inner.request.body = body;
      },
      InteractionPart::Response => {
        if !inner.response.has_header(&content_type_header) {
          match inner.response.headers {
            Some(ref mut headers) => {
              headers.insert(content_type_header.clone(), vec![ content_type.to_string() ]);
            },
            None => {
              inner.response.headers = Some(hashmap! { content_type_header.clone() => vec![ content_type.to_string() ]});
            }
          }
        }
        let body = if inner.response.content_type().unwrap_or_default().is_json() {
          let category = inner.response.matching_rules.add_category("body");
          OptionalBody::from(process_json(body.to_string(), category, &mut inner.response.generators))
        } else {
          OptionalBody::from(body)
        };
        inner.response.body = body;
      }
    };
    !mock_server_started
  }).unwrap_or(false)
}

fn error_message(err: Box<dyn Any>, method: &str) -> String {
  if let Some(err) = err.downcast_ref::<&str>() {
    format!("{} failed with an error - {}", method, err)
  } else if let Some(err) = err.downcast_ref::<String>() {
    format!("{} failed with an error - {}", method, err)
  } else {
    format!("{} failed with an unknown error", method)
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
          warn!("Failed to parse {} name as a UTF-8 string: {}", name, err);
          None
        }
      }
    }
  }
}

#[repr(C)]
#[derive(Debug, Clone)]
/// Result of wrapping a string value
pub enum StringResult {
  /// Was generated OK
  Ok(*mut c_char),
  /// There was an error generating the string
  Failed(*mut c_char)
}

/// Generates a datetime value from the provided format string, using the current system date and time
/// NOTE: The memory for the returned string needs to be freed with the free_string function
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern fn generate_datetime_string(format: *const c_char) -> StringResult {
  if format.is_null() {
    let error = CString::new("generate_datetime_string: format is NULL").unwrap();
    StringResult::Failed(error.into_raw())
  } else {
    let c_str = CStr::from_ptr(format);
    match c_str.to_str() {
      Ok(s) => match parse_pattern(s) {
        Ok(pattern_tokens) => {
          let result = Local::now().format(to_chrono_pattern(&pattern_tokens).as_str()).to_string();
          let result_str = CString::new(result.as_str()).unwrap();
          StringResult::Ok(result_str.into_raw())
        },
        Err(err) => {
          let error = format!("Error parsing '{}': {:?}", s, err);
          let error_str = CString::new(error.as_str()).unwrap();
          StringResult::Failed(error_str.into_raw())
        }
      },
      Err(err) => {
        let error = format!("generate_datetime_string: format is not a valid UTF-8 string: {:?}", err);
        let error_str = CString::new(error.as_str()).unwrap();
        StringResult::Failed(error_str.into_raw())
      }
    }
  }
}

/// Checks that the example string matches the given regex
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern fn check_regex(regex: *const c_char, example: *const c_char) -> bool {
  if regex.is_null() {
    false
  } else {
    let c_str = CStr::from_ptr(regex);
    match c_str.to_str() {
      Ok(regex) => {
        let example = convert_cstr("example", example).unwrap_or_default();
        match Regex::new(regex) {
          Ok(re) => re.is_match(example),
          Err(err) => {
            error!("check_regex: '{}' is not a valid regular expression - {}", regex, err);
            false
          }
        }
      },
      Err(err) => {
        error!("check_regex: regex is not a valid UTF-8 string: {:?}", err);
        false
      }
    }
  }
}

/// Generates an example string based on the provided regex.
pub fn generate_regex_value_internal(regex: &str) -> Result<String, String> {
  let mut parser = regex_syntax::ParserBuilder::new().unicode(false).build();
  match parser.parse(regex) {
    Ok(hir) => {
      let mut rnd = rand::thread_rng();
      let gen = rand_regex::Regex::with_hir(hir, 20).unwrap();
      let result: String = rnd.sample(gen);
      Ok(result)
    },
    Err(err) => {
      let error = format!("generate_regex_value: '{}' is not a valid regular expression - {}", regex, err);
      Err(error)
    }
  }
}

/// Generates an example string based on the provided regex.
/// NOTE: The memory for the returned string needs to be freed with the free_string function
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern fn generate_regex_value(regex: *const c_char) -> StringResult {
  if regex.is_null() {
    let error = CString::new("generate_regex_value: regex is NULL").unwrap();
    StringResult::Failed(error.into_raw())
  } else {
    let c_str = CStr::from_ptr(regex);
    match c_str.to_str() {
      Ok(regex) => match generate_regex_value_internal(regex) {
        Ok(val) => {
          let result_str = CString::new(val.as_str()).unwrap();
          StringResult::Ok(result_str.into_raw())
        },
        Err(err) => {
          let error = CString::new(err).unwrap();
          StringResult::Failed(error.into_raw())
        }
      },
      Err(err) => {
        let error = CString::new(format!("generate_regex_value: regex is not a valid UTF-8 string: {:?}", err)).unwrap();
        StringResult::Failed(error.into_raw())
      }
    }
  }
}

/// Frees the memory allocated to a string by another function
///
/// # Safety
///
/// Exported functions are inherently unsafe.
#[no_mangle]
pub unsafe extern fn free_string(s: *mut c_char) {
  if s.is_null() {
    return;
  }
  CString::from_raw(s);
}

/// Adds a binary file as the body with the expected content type and example contents. Will use
/// a mime type matcher to match the body. Returns false if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `interaction` - Interaction handle to set the body for.
/// * `part` - Request or response part.
/// * `content_type` - Expected content type.
/// * `body` - example body contents in bytes
/// * `size` - number of bytes in the body
#[no_mangle]
pub extern fn with_binary_file(
  interaction: handles::InteractionHandle,
  part: InteractionPart,
  content_type: *const c_char,
  body: *const u8 ,
  size: size_t
) -> bool {
  let content_type_header = "Content-Type".to_string();
  match convert_cstr("content_type", content_type) {
    Some(content_type) => {
      interaction.with_interaction(&|_, mock_server_started, inner| {
        match part {
          InteractionPart::Request => {
            inner.request.body = convert_ptr_to_body(body, size);
            if !inner.request.has_header(&content_type_header) {
              match inner.request.headers {
                Some(ref mut headers) => {
                  headers.insert(content_type_header.clone(), vec!["application/octet-stream".to_string()]);
                },
                None => {
                  inner.request.headers = Some(hashmap! { content_type_header.clone() => vec!["application/octet-stream".to_string()]});
                }
              }
            };
            inner.request.matching_rules.add_category("body").add_rule("$", MatchingRule::ContentType(content_type.into()), &RuleLogic::And);
          },
          InteractionPart::Response => {
            inner.response.body = convert_ptr_to_body(body, size);
            if !inner.response.has_header(&content_type_header) {
              match inner.response.headers {
                Some(ref mut headers) => {
                  headers.insert(content_type_header.clone(), vec!["application/octet-stream".to_string()]);
                },
                None => {
                  inner.response.headers = Some(hashmap! { content_type_header.clone() => vec!["application/octet-stream".to_string()]});
                }
              }
            }
            inner.response.matching_rules.add_category("body").add_rule("$", MatchingRule::ContentType(content_type.into()), &RuleLogic::And);
          }
        };
        !mock_server_started
      }).unwrap_or(false)
    },
    None => {
      warn!("with_binary_file: Content type value is not valid (NULL or non-UTF-8)");
      false
    }
  }
}

/// Adds a binary file as the body as a MIME multipart with the expected content type and example contents. Will use
/// a mime type matcher to match the body. Returns an error if the interaction or Pact can't be
/// modified (i.e. the mock server for it has already started)
///
/// * `interaction` - Interaction handle to set the body for.
/// * `part` - Request or response part.
/// * `content_type` - Expected content type of the file.
/// * `file` - path to the example file
/// * `part_name` - name for the mime part
#[no_mangle]
pub extern fn with_multipart_file(
  interaction: handles::InteractionHandle,
  part: InteractionPart,
  content_type: *const c_char,
  file: *const c_char,
  part_name: *const c_char
) -> StringResult {
  let part_name = convert_cstr("part_name", part_name).unwrap_or("file");
  match convert_cstr("content_type", content_type) {
    Some(content_type) => {
      match interaction.with_interaction(&|_, mock_server_started, inner| {
        match convert_ptr_to_mime_part_body(file, part_name) {
          Ok(body) => {
            match part {
              InteractionPart::Request => request_multipart(&mut inner.request, &body.boundary, body.body, &content_type, part_name),
              InteractionPart::Response => response_multipart(&mut inner.response, &body.boundary, body.body, &content_type, part_name)
            };
            if mock_server_started {
              Err("with_multipart_file: This Pact can not be modified, as the mock server has already started".to_string())
            } else {
              Ok(())
            }
          },
          Err(err) => Err(format!("with_multipart_file: failed to generate multipart body - {}", err))
        }
      }) {
        Some(result) => match result {
          Ok(_) => StringResult::Ok(null_mut()),
          Err(err) => {
            let error = CString::new(err).unwrap();
            StringResult::Failed(error.into_raw())
          }
        },
        None => {
          let error = CString::new("with_multipart_file: Interaction handle is invalid").unwrap();
          StringResult::Failed(error.into_raw())
        }
      }
    },
    None => {
      warn!("with_multipart_file: Content type value is not valid (NULL or non-UTF-8)");
      let error = CString::new("with_multipart_file: Content type value is not valid (NULL or non-UTF-8)").unwrap();
      StringResult::Failed(error.into_raw())
    }
  }
}

fn convert_ptr_to_body(body: *const u8, size: size_t) -> OptionalBody {
  if body.is_null() {
    OptionalBody::Null
  } else if size == 0 {
    OptionalBody::Empty
  } else {
    OptionalBody::Present(Bytes::from(unsafe { std::slice::from_raw_parts(body, size) }), None)
  }
}

fn convert_ptr_to_mime_part_body(file: *const c_char, part_name: &str) -> Result<MultipartBody, String> {
  if file.is_null() {
    empty_multipart_body()
  } else {
    let c_str = unsafe { CStr::from_ptr(file) };
    let file = match c_str.to_str() {
      Ok(str) => Ok(str),
      Err(err) => {
        warn!("convert_ptr_to_mime_part_body: Failed to parse file name as a UTF-8 string: {}", err);
        Err(format!("convert_ptr_to_mime_part_body: Failed to parse file name as a UTF-8 string: {}", err))
      }
    }?;
    file_as_multipart_body(file, part_name)
  }
}

/// Creates a new Pact Message model and returns a handle to it.
///
/// * `consumer_name` - The name of the consumer for the pact.
/// * `provider_name` - The name of the provider for the pact.
///
/// Returns a new `MessagePactHandle`.
#[no_mangle]
pub extern fn new_message_pact(consumer_name: *const c_char, provider_name: *const c_char) -> handles::MessagePactHandle {
  let consumer = convert_cstr("consumer_name", consumer_name).unwrap_or("Consumer");
  let provider = convert_cstr("provider_name", provider_name).unwrap_or("Provider");
  handles::MessagePactHandle::new(consumer, provider)
}

/// Creates a new Message and returns a handle to it.
///
/// * `description` - The message description. It needs to be unique for each Message.
///
/// Returns a new `MessageHandle`.
#[no_mangle]
pub extern fn new_message(pact: handles::MessagePactHandle, description: *const c_char) -> handles::MessageHandle {
  if let Some(description) = convert_cstr("description", description) {
    pact.with_pact(&|_, inner| {
      let message = Message {
        description: description.to_string(),
        ..Message::default()
      };
      inner.messages.push(message);
      handles::MessageHandle::new(pact.clone(), inner.messages.len())
    }).unwrap_or_else(|| handles::MessageHandle::new(pact.clone(), 0))
  } else {
    handles::MessageHandle::new(pact, 0)
  }
}

/// Sets the description for the Message.
///
/// * `description` - The message description. It needs to be unique for each message.
#[no_mangle]
pub extern fn message_expects_to_receive(message: handles::MessageHandle, description: *const c_char) {
  if let Some(description) = convert_cstr("description", description) {
    message.with_message(&|_, inner| {
      inner.description = description.to_string();
    });
  }
}

/// Adds a provider state to the Interaction.
///
/// * `description` - The provider state description. It needs to be unique for each message
#[no_mangle]
pub extern fn message_given(message: handles::MessageHandle, description: *const c_char) {
  if let Some(description) = convert_cstr("description", description) {
    message.with_message(&|_, inner| {
      inner.provider_states.push(ProviderState::default(&description.to_string()));
    });
  }
}

/// Adds a provider state to the Message with a parameter key and value.
///
/// * `description` - The provider state description. It needs to be unique.
/// * `name` - Parameter name.
/// * `value` - Parameter value.
#[no_mangle]
pub extern fn message_given_with_param(message: handles::MessageHandle, description: *const c_char,
                               name: *const c_char, value: *const c_char) {
  if let Some(description) = convert_cstr("description", description) {
    if let Some(name) = convert_cstr("name", name) {
      let value = convert_cstr("value", value).unwrap_or_default();
      message.with_message(&|_, inner| {
        let value = match serde_json::from_str(value) {
          Ok(json) => json,
          Err(_) => json!(value)
        };
        match inner.provider_states.iter().find_position(|state| state.name == description) {
          Some((index, _)) => {
            inner.provider_states.get_mut(index).unwrap().params.insert(name.to_string(), value);
          },
          None => inner.provider_states.push(ProviderState {
            name: description.to_string(),
            params: hashmap!{ name.to_string() => value }
          })
        };
      });
    }
  }
}

/// Adds the contents of the Message.
///
/// Accepts JSON, binary and other payload types. Binary data will be base64 encoded when serialised.
///
/// Note: For text bodies (plain text, JSON or XML), you can pass in a C string (NULL terminated)
/// and the size of the body is not required (it will be ignored). For binary bodies, you need to
/// specify the number of bytes in the body.
///
/// * `content_type` - The content type of the body. Defaults to `text/plain`, supports JSON structures with matchers and binary data.
/// * `body` - The body contents as bytes. For text payloads (JSON, XML, etc.), a C string can be used and matching rules can be embedded in the body.
/// * `content_type` - Expected content type (e.g. application/json, application/octet-stream)
/// * `size` - number of bytes in the message body to read. This is not required for text bodies (JSON, XML, etc.).
#[no_mangle]
pub extern fn message_with_contents(message: handles::MessageHandle, content_type: *const c_char, body: *const u8, size: size_t) {
  let content_type = convert_cstr("content_type", content_type).unwrap_or("text/plain");

  message.with_message(&|_, inner| {
    let content_type = ContentType::parse(content_type).ok();

    let body = if let Some(content_type) = content_type {
      if content_type.is_text() {
        let body = convert_cstr("body", body as *const c_char).unwrap_or_default();
        let category = inner.matching_rules.add_category("body");
        OptionalBody::Present(Bytes::from(process_json(body.to_string(), category, &mut inner.generators)), Some(content_type))
      } else {
        OptionalBody::Present(Bytes::from(unsafe { std::slice::from_raw_parts(body, size) }), Some(content_type))
      }
    } else {
      OptionalBody::Present(Bytes::from(unsafe { std::slice::from_raw_parts(body, size) }), None)
    };

    inner.contents = body;
  });
}

/// Adds expected metadata to the Message
///
/// * `key` - metadata key
/// * `value` - metadata value.
#[no_mangle]
pub extern fn message_with_metadata(message: handles::MessageHandle, key: *const c_char, value: *const c_char) {
  if let Some(key) = convert_cstr("key", key) {
    let value = convert_cstr("value", value).unwrap_or_default();
    message.with_message(&|_, inner| inner.metadata.insert(key.to_string(), value.to_string()));
  }
}

/// Reifies the given message
///
/// Reification is the process of stripping away any matchers, and returning the original contents.
/// NOTE: the returned string needs to be deallocated with the `free_string` function
#[no_mangle]
pub extern fn message_reify(message: handles::MessageHandle) -> *const c_char {
  let res = message.with_message(&|_, inner| {
    match inner.body() {
      Null => "null".to_string(),
      Present(_, _) => inner.to_json(&PactSpecification::V3).to_string(),
      _ => "".to_string()
    }
  });

  match res {
    Some(res) => {
      let string = CString::new(res).unwrap();
      string.into_raw() as *const c_char
    },
    None => CString::default().into_raw() as *const c_char
  }
}

/// External interface to write out the message pact file. This function should
/// be called if all the consumer tests have passed. The directory to write the file to is passed
/// as the second parameter. If a NULL pointer is passed, the current working directory is used.
///
/// If overwrite is true, the file will be overwritten with the contents of the current pact.
/// Otherwise, it will be merged with any existing pact file.
///
/// Returns 0 if the pact file was successfully written. Returns a positive code if the file can
/// not be written, or there is no mock server running on that port or the function panics.
///
/// # Errors
///
/// Errors are returned as positive values.
///
/// | Error | Description |
/// |-------|-------------|
/// | 1 | The pact file was not able to be written |
/// | 2 | The message pact for the given handle was not found |
#[no_mangle]
pub extern fn write_message_pact_file(pact: handles::MessagePactHandle, directory: *const c_char, overwrite: bool) -> i32 {
  let result = pact.with_pact(&|_, inner| {
    let filename = path_from_dir(directory, Some(inner.default_file_name().as_str()));
    pact_matching::models::write_pact(inner.boxed(), &filename.unwrap(), inner.specification_version(), overwrite)
  });

  match result {
    Some(write_result) => match write_result {
      Ok(_) => 0,
      Err(e) => {
        log::error!("unable to write the pact file: {:}", e);
        1
      }
    },
    None => {
      log::error!("unable to write the pact file, message pact for handle {:?} not found", &pact);
      2
    }
  }
}

/// Sets the additional metadata on the Pact file. Common uses are to add the client library details such as the name and version
///
/// * `pact` - Handle to a Pact model
/// * `namespace` - the top level metadat key to set any key values on
/// * `name` - the key to set
/// * `value` - the value to set
#[no_mangle]
pub extern fn with_message_pact_metadata(pact: handles::MessagePactHandle, namespace: *const c_char, name: *const c_char, value: *const c_char) {
  pact.with_pact(&|_, inner| {
    let namespace = convert_cstr("namespace", namespace).unwrap_or_default();
    let name = convert_cstr("name", name).unwrap_or_default();
    let value = convert_cstr("value", value).unwrap_or_default();

    if !namespace.is_empty() {
      let mut child = BTreeMap::new();
      child.insert(name.to_string(), value.to_string());
      inner.metadata.insert(namespace.to_string(), child);
    } else {
      log::warn!("no namespace provided for metadata {:?} => {:?}. Ignoring", name, value);
    }
  });
}

/// Given a c string for the output directory, and an optional filename
/// return a fully qualified directory or file path name for the output pact file
fn path_from_dir(directory: *const c_char, file_name: Option<&str>) -> Option<PathBuf> {
  let dir = unsafe {
    if directory.is_null() {
      log::warn!("Directory to write to is NULL, defaulting to the current working directory");
      None
    } else {
      let c_str = CStr::from_ptr(directory);
      let dir_str = str::from_utf8(c_str.to_bytes()).unwrap();
      if dir_str.is_empty() {
        None
      } else {
        Some(dir_str.to_string())
      }
    }
  };

  dir.map(|path| {
    let mut full_path = PathBuf::from(path);
    if let Some(pact_file_name) = file_name {
      full_path.push(pact_file_name);
    }
    full_path
  })
}
