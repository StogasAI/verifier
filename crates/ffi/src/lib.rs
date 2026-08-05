//! Narrow stateful C ABI for the deterministic Stogas verifier.
//!
//! The ABI deliberately exchanges only bounded UTF-8 JSON and bundle byte slices. It does not
//! expose keys, signatures, hashes, certificate helpers, or any other cryptographic primitive.

#![deny(unsafe_op_in_unsafe_fn)]

use serde::{Deserialize, Serialize};
use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
    sync::Mutex,
};
use stogas_sdk::{SecurityMode, Transport as ManagedTransport, TransportOptions};
use stogas_verifier::{
    Environment, VerificationOutput, Verifier,
    response_proof::{MAX_BODY_BYTES, MAX_PROOF_BYTES},
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

/// Opaque managed HTTP transport.
pub struct StogasTransport {
    transport: Mutex<ManagedTransport>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AbiTransportOptions {
    security: String,
    bundle_refresh_interval_seconds: u64,
    #[serde(alias = "baseURL")]
    base_url: Option<String>,
    #[serde(alias = "bundleURL")]
    bundle_url: Option<String>,
}

impl Default for AbiTransportOptions {
    fn default() -> Self {
        Self {
            security: "tls".into(),
            bundle_refresh_interval_seconds: 300,
            base_url: None,
            bundle_url: None,
        }
    }
}

#[derive(Serialize)]
struct StartedTransport {
    base_url: String,
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
/// A null result means allocation failed. The session is safe to call concurrently; each
/// verification is serialized.
#[unsafe(no_mangle)]
pub extern "C" fn stogas_verifier_new() -> *mut StogasVerifier {
    Box::into_raw(Box::new(StogasVerifier {
        session: Mutex::new(VerifierSession {
            core: Verifier::default(),
            environment: Environment::stogas(),
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

/// Start an in-process managed transport and verify its initial bundle.
///
/// `configuration` is bounded JSON. `transport_out` is set only on success. The returned JSON
/// contains the capability-protected loopback `base_url`.
///
/// # Safety
///
/// `configuration` must point to `configuration_len` readable bytes. `transport_out` must be a
/// writable pointer and the caller must eventually free a successful handle exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_start(
    configuration: *const u8,
    configuration_len: usize,
    transport_out: *mut *mut StogasTransport,
) -> *mut c_char {
    response(|| {
        if transport_out.is_null() {
            return Err("transport output pointer is null".into());
        }
        // SAFETY: caller supplied a writable output pointer for this synchronous call.
        unsafe { transport_out.write(std::ptr::null_mut()) };
        // SAFETY: pointer and bound are validated by `input_slice`.
        let configuration =
            unsafe { input_slice(configuration, configuration_len, 16 * 1024, "configuration")? };
        let configuration: AbiTransportOptions = if configuration.is_empty() {
            AbiTransportOptions::default()
        } else {
            serde_json::from_slice(configuration)
                .map_err(|error| format!("invalid transport configuration: {error}"))?
        };
        let defaults = TransportOptions::default();
        let options = TransportOptions {
            security: match configuration.security.as_str() {
                "tls" => SecurityMode::Tls,
                "e2ee" => SecurityMode::E2ee,
                "both" => SecurityMode::Both,
                _ => return Err("security must be tls, e2ee, or both".into()),
            },
            bundle_refresh_interval: std::time::Duration::from_secs(
                configuration.bundle_refresh_interval_seconds,
            ),
            base_url: configuration.base_url.unwrap_or(defaults.base_url),
            bundle_url: configuration.bundle_url.unwrap_or(defaults.bundle_url),
        };
        let transport = ManagedTransport::start(&options).map_err(|error| error.to_string())?;
        let base_url = transport.base_url().to_owned();
        let transport = Box::into_raw(Box::new(StogasTransport {
            transport: Mutex::new(transport),
        }));
        // SAFETY: output was validated above and is written exactly once on success.
        unsafe { transport_out.write(transport) };
        Ok::<_, String>(StartedTransport { base_url })
    })
}

/// Refresh the managed transport's evidence bundle immediately.
///
/// # Safety
///
/// `transport` must be a live pointer returned by `stogas_transport_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_refresh(
    transport: *const StogasTransport,
) -> *mut c_char {
    response(|| {
        // SAFETY: pointer validity is part of the public C ABI contract.
        let transport =
            unsafe { transport.as_ref() }.ok_or_else(|| "transport is null".to_owned())?;
        let transport = transport
            .transport
            .lock()
            .map_err(|_| "transport lock is poisoned".to_owned())?;
        transport
            .refresh_bundle()
            .map_err(|error| error.to_string())
    })
}

/// Stop and release a managed transport.
///
/// # Safety
///
/// `transport` must be null or a live pointer returned by `stogas_transport_start`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_free(transport: *mut StogasTransport) {
    if !transport.is_null() {
        // SAFETY: ownership and exactly-once release are required by the public ABI.
        drop(unsafe { Box::from_raw(transport) });
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

/// Verify one response receipt against the session's active verified bundle.
///
/// An empty transcript slice means ordinary TLS mode. A non-empty slice must contain the expected
/// lowercase E2EE transcript SHA-256.
///
/// # Safety
///
/// Every pointer must address its declared readable length for this synchronous call. `verifier`
/// must point to a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_verifier_verify_response_proof(
    verifier: *const StogasVerifier,
    proof: *const u8,
    proof_len: usize,
    request_body: *const u8,
    request_body_len: usize,
    response_body: *const u8,
    response_body_len: usize,
    e2ee_transcript_sha256: *const u8,
    e2ee_transcript_sha256_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response(|| {
        // SAFETY: pointers are validated before use and live for this synchronous call.
        let verifier = unsafe { verifier_ref(verifier)? };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let proof = unsafe { input_slice(proof, proof_len, MAX_PROOF_BYTES, "response proof")? };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let request_body = unsafe {
            input_slice(
                request_body,
                request_body_len,
                MAX_BODY_BYTES,
                "request body",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let response_body = unsafe {
            input_slice(
                response_body,
                response_body_len,
                MAX_BODY_BYTES,
                "response body",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let transcript = unsafe {
            input_slice(
                e2ee_transcript_sha256,
                e2ee_transcript_sha256_len,
                64,
                "E2EE transcript SHA-256",
            )?
        };
        let transcript = optional_utf8(transcript, "E2EE transcript SHA-256")?;
        let session = verifier
            .session
            .lock()
            .map_err(|_| "verifier session lock is poisoned".to_owned())?;
        session
            .core
            .verify_response_proof(proof, request_body, response_body, transcript, now_unix_ms)
            .map_err(|error| error.to_string())
    })
}

/// Verify one response receipt and immutable historical node ledger together.
///
/// # Safety
///
/// Every pointer must address its declared readable length for this synchronous call. `verifier`
/// must point to a live session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_verifier_verify_historical_response_proof(
    verifier: *const StogasVerifier,
    proof: *const u8,
    proof_len: usize,
    request_body: *const u8,
    request_body_len: usize,
    response_body: *const u8,
    response_body_len: usize,
    ledger: *const u8,
    ledger_len: usize,
    catalog: *const u8,
    catalog_len: usize,
    e2ee_transcript_sha256: *const u8,
    e2ee_transcript_sha256_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response(|| {
        // SAFETY: pointers are validated before use and live for this synchronous call.
        let verifier = unsafe { verifier_ref(verifier)? };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let proof = unsafe { input_slice(proof, proof_len, MAX_PROOF_BYTES, "response proof")? };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let request_body = unsafe {
            input_slice(
                request_body,
                request_body_len,
                MAX_BODY_BYTES,
                "request body",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let response_body = unsafe {
            input_slice(
                response_body,
                response_body_len,
                MAX_BODY_BYTES,
                "response body",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let ledger = unsafe {
            input_slice(
                ledger,
                ledger_len,
                stogas_verifier::MAX_INPUT_BYTES,
                "ledger",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let catalog = unsafe {
            input_slice(
                catalog,
                catalog_len,
                stogas_verifier::MAX_INPUT_BYTES,
                "catalog approval",
            )?
        };
        // SAFETY: each pointer and bound is validated by `input_slice`.
        let transcript = unsafe {
            input_slice(
                e2ee_transcript_sha256,
                e2ee_transcript_sha256_len,
                64,
                "E2EE transcript SHA-256",
            )?
        };
        let transcript = optional_utf8(transcript, "E2EE transcript SHA-256")?;
        let session = verifier
            .session
            .lock()
            .map_err(|_| "verifier session lock is poisoned".to_owned())?;
        let environment = session.environment.clone();
        session
            .core
            .verify_historical_response_proof(&stogas_verifier::HistoricalResponseProofInput {
                proof_bytes: proof,
                request_body,
                response_body,
                expected_e2ee_transcript_sha256: transcript,
                now_unix_ms,
                ledger_bytes: ledger,
                catalog_approval_bytes: catalog,
                environment: &environment,
            })
            .map_err(|error| error.to_string())
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

fn optional_utf8<'a>(bytes: &'a [u8], label: &str) -> Result<Option<&'a str>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("{label} is not UTF-8"))
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
    fn rejects_null_and_oversized_inputs_without_panicking() {
        let verifier = stogas_verifier_new();
        assert!(!verifier.is_null());
        // SAFETY: verifier is live for this synchronous call.
        let null = unsafe {
            take_json(stogas_verifier_verify_bundle(
                verifier,
                std::ptr::null(),
                1,
                0,
            ))
        };
        assert_eq!(null["ok"], false);
        assert_eq!(null["error"], "bundle pointer is null");
        // SAFETY: the length is rejected before the pointer is read.
        let oversized = unsafe {
            take_json(stogas_verifier_verify_bundle(
                verifier,
                std::ptr::null(),
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
    fn managed_transport_rejects_invalid_options_before_network_access() {
        let configuration = br#"{"security":"tls","bundle_refresh_interval_seconds":0}"#;
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

    #[test]
    fn c_abi_rejects_the_legacy_bundle() {
        let bundle =
            include_bytes!("../../verifier/tests/fixtures/staging-bundle-sequence-1927.json");
        let verifier = stogas_verifier_new();
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
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("catalog_hash"));
        // SAFETY: no call is using this live verifier.
        unsafe { stogas_verifier_free(verifier) };
    }
}
