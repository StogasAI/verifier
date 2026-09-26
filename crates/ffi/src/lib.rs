//! Narrow stateful C ABI for the deterministic Stogas verifier.
//!
//! The ABI deliberately exchanges only bounded UTF-8 JSON and bundle byte slices. It does not
//! expose keys, signatures, hashes, certificate helpers, or any other cryptographic primitive.

#![deny(unsafe_op_in_unsafe_fn)]

use serde::Serialize;
use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};

mod evidence;
pub use evidence::*;

#[cfg(feature = "transport")]
mod transport;
#[cfg(feature = "transport")]
pub use transport::*;

/// ABI version implemented by this library and its public header.
pub const STOGAS_VERIFIER_ABI_VERSION: u32 = 1;

#[derive(Serialize)]
struct AbiResponse<T> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

struct AbiError {
    message: String,
    code: Option<&'static str>,
}

impl From<String> for AbiError {
    fn from(message: String) -> Self {
        Self {
            message,
            code: Some("invalid_operation"),
        }
    }
}

impl From<&str> for AbiError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl From<stogas_verifier::evidence::Error> for AbiError {
    fn from(error: stogas_verifier::evidence::Error) -> Self {
        Self {
            message: error.to_string(),
            code: Some(error.code()),
        }
    }
}

impl From<stogas_verifier::receipt::Error> for AbiError {
    fn from(error: stogas_verifier::receipt::Error) -> Self {
        Self {
            message: error.to_string(),
            code: Some("invalid_receipt"),
        }
    }
}

/// Return the ABI version before constructing a session.
#[unsafe(no_mangle)]
pub const extern "C" fn stogas_verifier_abi_version() -> u32 {
    STOGAS_VERIFIER_ABI_VERSION
}

/// Release a JSON response returned by this ABI.
///
/// # Safety
///
/// `value` must be null or a live pointer returned by this ABI. A live pointer must be released
/// exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_verifier_string_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: the pointer was returned by `CString::into_raw` in `response` and is reclaimed
        // exactly once by the caller.
        drop(unsafe { CString::from_raw(value) });
    }
}

#[cfg(feature = "transport")]
fn response<T, F>(operation: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> Result<T, String>,
{
    response_coded(|| operation().map_err(AbiError::from))
}

fn response_coded<T: Serialize>(operation: impl FnOnce() -> Result<T, AbiError>) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(operation));
    let bytes = match result {
        Ok(Ok(value)) => serde_json::to_vec(&AbiResponse {
            ok: true,
            value: Some(value),
            error: None,
            code: None,
        }),
        Ok(Err(error)) => serde_json::to_vec(&AbiResponse::<()> {
            ok: false,
            value: None,
            error: Some(error.message),
            code: error.code,
        }),
        Err(_) => serde_json::to_vec(&AbiResponse::<()> {
            ok: false,
            value: None,
            error: Some("verifier aborted an invalid operation".into()),
            code: Some("invalid_operation"),
        }),
    }
    .unwrap_or_else(|_| {
        br#"{"ok":false,"error":"verifier response serialization failed"}"#.to_vec()
    });
    // Serialized JSON cannot contain an unescaped NUL byte. Keep the ABI fail-closed if that
    // invariant changes in a future serializer.
    CString::new(bytes)
        .unwrap_or_else(|_| {
            CString::new("{\"ok\":false,\"error\":\"invalid verifier response\"}")
                .unwrap_or_default()
        })
        .into_raw()
}

unsafe fn input_slice<'a>(
    pointer: *const u8,
    length: usize,
    maximum: usize,
    label: &str,
) -> Result<&'a [u8], String> {
    if length > maximum {
        return Err(format!("{label} exceeds {maximum} bytes"));
    }
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(format!("{label} pointer is null"));
    }
    // SAFETY: the ABI requires a readable allocation of `length` bytes for this synchronous call.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::ffi::CStr;

    pub unsafe fn take_json(pointer: *mut c_char) -> Value {
        assert!(!pointer.is_null());
        // SAFETY: the test owns one response pointer until the matching free below.
        let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec();
        // SAFETY: response pointer is released exactly once.
        unsafe { stogas_verifier_string_free(pointer) };
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    #[cfg(feature = "transport")]
    fn managed_transport_rejects_invalid_options_before_network_access() {
        let configuration = br#"{"security":"tls","max_connections":0}"#;
        let mut transport = std::ptr::null_mut();
        // SAFETY: fixture bytes and the writable output pointer live for the synchronous call.
        let result = unsafe {
            take_json(stogas_transport_start(
                configuration.as_ptr(),
                configuration.len(),
                &raw mut transport,
            ))
        };
        assert_eq!(result["ok"], false);
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("must be positive")
        );
        assert!(transport.is_null());
    }
}
