//! Archive appraisal shares the core's isolated historical authority.

use super::{AbiError, StogasEvidence, input_slice, response_coded};
use std::{ffi::c_char, sync::MutexGuard};
use stogas_verifier::evidence;

unsafe fn verifier<'a>(
    handle: *const StogasEvidence,
) -> Result<MutexGuard<'a, evidence::Verifier>, AbiError> {
    // SAFETY: the public ABI requires a live handle throughout the call.
    unsafe { handle.as_ref() }
        .ok_or_else(|| "evidence handle is null".to_owned())?
        .core
        .lock()
        .map_err(|_| "evidence lock is poisoned".to_owned().into())
}

/// Authenticate archived approvals without changing current trust or revocation state.
///
/// # Safety
/// Handle must be live. Input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_archive(
    handle: *const StogasEvidence,
    bundle: *const u8,
    bundle_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the live handle and input through this operation.
        let (verifier, bundle) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    bundle,
                    bundle_len,
                    stogas_verifier::MAX_INPUT_BYTES,
                    "evidence",
                )?,
            )
        };
        Ok(verifier.verify_evidence_archive(bundle, now_unix_ms)?)
    })
}

/// Appraise archived boot evidence at its authenticated log time. Grants no live permission.
///
/// # Safety
/// Handle must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_boot_archive(
    handle: *const StogasEvidence,
    archive: *const u8,
    archive_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the live handle and inputs through this operation.
        let (verifier, archive, bundle) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    archive,
                    archive_len,
                    evidence::MAX_ARCHIVE_BYTES,
                    "boot archive",
                )?,
                input_slice(
                    bundle,
                    bundle_len,
                    stogas_verifier::MAX_INPUT_BYTES,
                    "evidence",
                )?,
            )
        };
        Ok(verifier
            .verify_boot_archive(archive, bundle, now_unix_ms)?
            .summary())
    })
}

/// Verify a content receipt using historical boot evidence and locally computed hashes.
/// This establishes neither current authorization nor when inference occurred.
///
/// # Safety
/// Handle must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_receipt_archive(
    handle: *const StogasEvidence,
    archive: *const u8,
    archive_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    receipt: *const u8,
    receipt_len: usize,
    request_hash: *const u8,
    request_hash_len: usize,
    response_hash: *const u8,
    response_hash_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the handle and every readable slice through this call.
        let (verifier, archive, bundle, receipt, request, response) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    archive,
                    archive_len,
                    evidence::MAX_ARCHIVE_BYTES,
                    "boot archive",
                )?,
                input_slice(
                    bundle,
                    bundle_len,
                    stogas_verifier::MAX_INPUT_BYTES,
                    "evidence",
                )?,
                input_slice(
                    receipt,
                    receipt_len,
                    stogas_verifier::receipt::MAX_METADATA_BYTES,
                    "receipt",
                )?,
                input_slice(request_hash, request_hash_len, 32, "request SHA-256")?,
                input_slice(response_hash, response_hash_len, 32, "response SHA-256")?,
            )
        };
        let request = request
            .try_into()
            .map_err(|_| "request SHA-256 must be 32 bytes")?;
        let response = response
            .try_into()
            .map_err(|_| "response SHA-256 must be 32 bytes")?;

        let boot = verifier.verify_boot_archive(archive, bundle, now_unix_ms)?;
        Ok(stogas_verifier::receipt::verify_metadata(receipt, &boot, request, response)?.receipt)
    })
}
