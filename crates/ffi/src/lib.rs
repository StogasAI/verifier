//! Narrow stateful C ABI for the deterministic Stogas verifier.
//!
//! The ABI deliberately exchanges only bounded UTF-8 JSON and bundle byte slices. It does not
//! expose keys, signatures, hashes, certificate helpers, or any other cryptographic primitive.

#![deny(unsafe_op_in_unsafe_fn)]

use serde::Serialize;
use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::Mutex,
};
use stogas_verifier::{
    Environment, MAX_NODE_EVIDENCE_AGE_MS, MIN_NODE_EVIDENCE_AGE_MS, VerificationOutput, Verifier,
};

/// ABI version implemented by this library and its public header.
pub const STOGAS_VERIFIER_ABI_VERSION: u32 = 1;

struct VerifierSession {
    core: Verifier,
    environment: Environment,
}

/// Opaque verifier session. Callers must not inspect or copy it.
pub struct StogasVerifier {
    session: Mutex<VerifierSession>,
}

#[derive(Serialize)]
struct AbiResponse<T> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Return the ABI version before constructing a session.
#[unsafe(no_mangle)]
pub const extern "C" fn stogas_verifier_abi_version() -> u32 {
    STOGAS_VERIFIER_ABI_VERSION
}

/// Construct a verifier session.
///
/// `max_node_age_ms` must be between one and three minutes. A null result means the argument was
/// invalid or allocation failed. The session is safe to call concurrently; each verification is
/// serialized.
#[unsafe(no_mangle)]
pub extern "C" fn stogas_verifier_new(max_node_age_ms: i64) -> *mut StogasVerifier {
    if !(MIN_NODE_EVIDENCE_AGE_MS..=MAX_NODE_EVIDENCE_AGE_MS).contains(&max_node_age_ms) {
        return ptr::null_mut();
    }
    let mut environment = Environment::stogas();
    environment.max_node_evidence_age_ms = max_node_age_ms;
    Box::into_raw(Box::new(StogasVerifier {
        session: Mutex::new(VerifierSession {
            core: Verifier::default(),
            environment,
        }),
    }))
}

/// Destroy a verifier session.
///
/// A null pointer is ignored. The caller must ensure no other call is using the session.
///
/// # Safety
///
/// `verifier` must be null or a live pointer returned by `stogas_verifier_new`. A live
/// pointer must be freed exactly once, after every concurrent operation has finished.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_verifier_free(verifier: *mut StogasVerifier) {
    if !verifier.is_null() {
        // SAFETY: ownership was returned by `stogas_verifier_new`, and the ABI contract
        // requires exactly one free after all concurrent calls finish.
        drop(unsafe { Box::from_raw(verifier) });
    }
}

/// Verify one bundle at a caller-captured Unix wall-clock time in milliseconds.
///
/// Success returns the complete `VerificationOutput` as the response value. The session caches
/// immutable release verification only as a performance optimization.
///
/// # Safety
///
/// `verifier` must point to a live session. `bundle` must point to `bundle_len` readable bytes for
/// the duration of the call, unless `bundle_len` is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_verifier_verify_bundle(
    verifier: *const StogasVerifier,
    bundle: *const u8,
    bundle_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response(|| {
        // SAFETY: pointers are validated before use and live for this synchronous call.
        let verifier = unsafe { verifier_ref(verifier)? };
        // SAFETY: pointer and bound are validated by `input_slice`.
        let bundle = unsafe {
            input_slice(
                bundle,
                bundle_len,
                stogas_verifier::MAX_INPUT_BYTES,
                "bundle",
            )?
        };
        let mut session = verifier
            .session
            .lock()
            .map_err(|_| "verifier session lock is poisoned".to_owned())?;
        let environment = session.environment.clone();
        let output = session
            .core
            .verify_bundle(bundle, now_unix_ms, &environment)
            .map_err(|error| error.to_string())?;
        drop(session);
        Ok::<VerificationOutput, String>(output)
    })
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

fn response<T, F>(operation: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> Result<T, String>,
{
    let result = catch_unwind(AssertUnwindSafe(operation));
    let bytes = match result {
        Ok(Ok(value)) => serde_json::to_vec(&AbiResponse {
            ok: true,
            value: Some(value),
            error: None,
        }),
        Ok(Err(error)) => serde_json::to_vec(&AbiResponse::<()> {
            ok: false,
            value: None,
            error: Some(error),
        }),
        Err(_) => serde_json::to_vec(&AbiResponse::<()> {
            ok: false,
            value: None,
            error: Some("verifier aborted an invalid operation".into()),
        }),
    }
    .unwrap_or_else(|_| {
        br#"{"ok":false,"error":"verifier response serialization failed"}"#.to_vec()
    });
    // Serialized JSON cannot contain an unescaped NUL byte.
    CString::new(bytes)
        .expect("serialized verifier response contains no NUL")
        .into_raw()
}

unsafe fn verifier_ref<'a>(verifier: *const StogasVerifier) -> Result<&'a StogasVerifier, String> {
    // SAFETY: `as_ref` only reads the pointer. Lifetime and concurrent-free requirements are part
    // of the public C ABI contract.
    unsafe { verifier.as_ref() }.ok_or_else(|| "verifier session is null".into())
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

    unsafe fn take_json(pointer: *mut c_char) -> Value {
        assert!(!pointer.is_null());
        // SAFETY: the test owns one response pointer until the matching free below.
        let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec();
        // SAFETY: response pointer is released exactly once.
        unsafe { stogas_verifier_string_free(pointer) };
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn rejects_invalid_constructor_policy() {
        assert!(stogas_verifier_new(0).is_null());
        assert!(stogas_verifier_new(25).is_null());
    }

    #[test]
    fn rejects_null_and_oversized_inputs_without_panicking() {
        let verifier = stogas_verifier_new(3 * 60 * 1000);
        assert!(!verifier.is_null());
        // SAFETY: verifier is live for this synchronous call.
        let null = unsafe { take_json(stogas_verifier_verify_bundle(verifier, ptr::null(), 1, 0)) };
        assert_eq!(null["ok"], false);
        assert_eq!(null["error"], "bundle pointer is null");
        // SAFETY: the length is rejected before the pointer is read.
        let oversized = unsafe {
            take_json(stogas_verifier_verify_bundle(
                verifier,
                ptr::null(),
                stogas_verifier::MAX_INPUT_BYTES + 1,
                0,
            ))
        };
        assert_eq!(oversized["ok"], false);
        assert!(oversized["error"].as_str().unwrap().contains("exceeds"));
        // SAFETY: no call is using this live verifier.
        unsafe { stogas_verifier_free(verifier) };
    }

    #[test]
    fn verifies_the_shared_real_staging_bundle_through_the_c_abi() {
        let bundle =
            include_bytes!("../../verifier/tests/fixtures/staging-bundle-sequence-1927.json");
        let verifier = stogas_verifier_new(3 * 60 * 1000);
        assert!(!verifier.is_null());
        // SAFETY: the session and fixture bytes remain live for this synchronous call.
        let response = unsafe {
            take_json(stogas_verifier_verify_bundle(
                verifier,
                bundle.as_ptr(),
                bundle.len(),
                1_784_414_117_082,
            ))
        };
        assert_eq!(response["ok"], true);
        assert_eq!(response["value"]["bundle"]["sequence"], 1_927);
        assert_eq!(
            response["value"]["bundle"]["nodes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // SAFETY: no call is using this live verifier.
        unsafe { stogas_verifier_free(verifier) };
    }
}
