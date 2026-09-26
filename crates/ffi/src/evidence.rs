//! Offline evidence ownership for C and Go. Network retrieval belongs to the caller.

use super::{AbiError, input_slice, response_coded};
use serde::Deserialize;
use std::{
    ffi::c_char,
    sync::{Arc, Mutex},
};
use stogas_verifier::{
    approvals::{Environment, RootKey},
    evidence,
};

mod history;
pub use history::*;

/// Offline verifier and learned root/vendor revocations.
pub struct StogasEvidence {
    core: Mutex<evidence::Verifier>,
}

/// Immutable verified evidence, independent of the verifier handle's lifetime.
pub struct StogasEvidenceSnapshot {
    core: Arc<evidence::Snapshot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    environment: Environment,
    /// A caller-owned offline trust seed; never read from downloaded evidence.
    root: Option<RootKey>,
}

/// Construct an offline evidence verifier. Omitting `root` selects the compiled Stogas root.
///
/// # Safety
/// Input must address its declared readable length; output must be writable. A successful
/// handle must be freed once, after concurrent operations finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_new(
    configuration: *const u8,
    configuration_len: usize,
    output: *mut *mut StogasEvidence,
) -> *mut c_char {
    response_coded(|| {
        if output.is_null() {
            return Err("evidence output pointer is null".to_owned().into());
        }
        // SAFETY: the caller provides a writable output pointer.
        unsafe { output.write(std::ptr::null_mut()) };
        // SAFETY: the caller owns these readable bytes for the call.
        let bytes =
            unsafe { input_slice(configuration, configuration_len, 4096, "configuration")? };
        let config: Configuration = serde_json::from_slice(bytes)
            .map_err(|_| "invalid evidence configuration".to_owned())?;
        let core = match config.root {
            Some(root) => evidence::Verifier::new(config.environment, root)?,
            None => evidence::Verifier::stogas(config.environment)?,
        };
        // SAFETY: output was checked above. Ownership passes only after successful construction.
        unsafe {
            output.write(Box::into_raw(Box::new(StogasEvidence {
                core: Mutex::new(core),
            })));
        };
        Ok(())
    })
}

/// # Safety
/// Handle must be null or live, with no concurrent operation, and freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_free(handle: *mut StogasEvidence) {
    if !handle.is_null() {
        // SAFETY: the caller returns exclusive ownership exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Verify a complete candidate and return an owned snapshot plus its public summary.
/// Authenticated revocations remain learned even when the candidate fails.
///
/// # Safety
/// Handle must be live; input must address its readable length; output must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_refresh(
    handle: *const StogasEvidence,
    bundle: *const u8,
    bundle_len: usize,
    now_unix_ms: i64,
    output: *mut *mut StogasEvidenceSnapshot,
) -> *mut c_char {
    response_coded(|| {
        if output.is_null() {
            return Err("snapshot output pointer is null".to_owned().into());
        }
        // SAFETY: the caller provides writable output and a live handle.
        unsafe { output.write(std::ptr::null_mut()) };
        // SAFETY: caller keeps the handle alive for this synchronous operation.
        let handle =
            unsafe { handle.as_ref() }.ok_or_else(|| "evidence handle is null".to_owned())?;
        // SAFETY: the caller owns readable bytes; the bound is checked before constructing a slice.
        let bytes = unsafe {
            input_slice(
                bundle,
                bundle_len,
                stogas_verifier::MAX_INPUT_BYTES,
                "evidence",
            )?
        };
        let mut verifier = handle
            .core
            .lock()
            .map_err(|_| "evidence lock is poisoned".to_owned())?;
        let core = verifier.refresh(bytes, now_unix_ms)?;
        drop(verifier);
        let summary = core.summary();
        // SAFETY: output was validated and takes ownership only on success.
        unsafe { output.write(Box::into_raw(Box::new(StogasEvidenceSnapshot { core }))) };
        Ok(summary)
    })
}

/// # Safety
/// Handle must be null or live, with no concurrent operation, and freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_snapshot_free(handle: *mut StogasEvidenceSnapshot) {
    if !handle.is_null() {
        // SAFETY: the caller returns exclusive ownership exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

unsafe fn snapshot<'a>(
    handle: *const StogasEvidenceSnapshot,
) -> Result<&'a evidence::Snapshot, AbiError> {
    // SAFETY: public ABI requires a live handle throughout the synchronous operation.
    unsafe { handle.as_ref() }
        .map(|handle| handle.core.as_ref())
        .ok_or_else(|| "evidence snapshot is null".to_owned().into())
}

/// Verify a boot report against the caller's one-use challenge; returns authenticated identity.
///
/// # Safety
/// Snapshot must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_registration(
    handle: *const StogasEvidenceSnapshot,
    document: *const u8,
    document_len: usize,
    challenge: *const u8,
    challenge_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: callers own every input and the snapshot through this operation.
        let (snapshot, document, challenge) = unsafe {
            (
                snapshot(handle)?,
                input_slice(
                    document,
                    document_len,
                    stogas_verifier::attestation::evidence::MAX_EVIDENCE_BYTES,
                    "boot",
                )?,
                input_slice(challenge, challenge_len, 32, "challenge")?,
            )
        };
        let challenge = challenge
            .try_into()
            .map_err(|_| "challenge must be 32 bytes".to_owned())?;
        Ok(snapshot
            .verify_registration(document, challenge, now_unix_ms)?
            .summary())
    })
}

/// Verify exact logged boot bytes using current approvals and vendor collateral.
///
/// # Safety
/// Snapshot must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_logged_boot(
    handle: *const StogasEvidenceSnapshot,
    document: *const u8,
    document_len: usize,
    inclusion: *const u8,
    inclusion_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: callers own every input and the snapshot through this operation.
        let (snapshot, document, inclusion) = unsafe {
            (
                snapshot(handle)?,
                input_slice(
                    document,
                    document_len,
                    stogas_verifier::attestation::evidence::MAX_EVIDENCE_BYTES,
                    "boot",
                )?,
                input_slice(
                    inclusion,
                    inclusion_len,
                    stogas_verifier::attestation::evidence::MAX_EVIDENCE_BYTES,
                    "inclusion",
                )?,
            )
        };
        Ok(snapshot
            .verify_logged_boot(document, inclusion, now_unix_ms)?
            .summary())
    })
}

/// Verify a complete Stogas metadata bag against exact locally computed SHA-256 hashes.
///
/// The boot is appraised against this snapshot at the caller's trusted clock.
/// The single signature covers content and canonical metadata, not inference time.
///
/// # Safety
/// Snapshot must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_receipt(
    handle: *const StogasEvidenceSnapshot,
    document: *const u8,
    document_len: usize,
    inclusion: *const u8,
    inclusion_len: usize,
    receipt: *const u8,
    receipt_len: usize,
    request_hash: *const u8,
    request_hash_len: usize,
    response_hash: *const u8,
    response_hash_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    use stogas_verifier::attestation::evidence::MAX_EVIDENCE_BYTES;
    response_coded(|| {
        // SAFETY: callers retain all slices and the snapshot through this synchronous call.
        let (snapshot, document, inclusion, receipt, request, response) = unsafe {
            (
                snapshot(handle)?,
                input_slice(document, document_len, MAX_EVIDENCE_BYTES, "boot")?,
                input_slice(inclusion, inclusion_len, MAX_EVIDENCE_BYTES, "inclusion")?,
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

        let boot = snapshot.verify_logged_boot(document, inclusion, now_unix_ms)?;
        Ok(stogas_verifier::receipt::verify_metadata(receipt, &boot, request, response)?.receipt)
    })
}

#[cfg(test)]
mod tests;
