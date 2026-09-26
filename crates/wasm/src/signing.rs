//! Signing and publication primitives for document publishers; no network or stored keys.

use stogas_verifier::signing;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

/// Sign an exact purpose-separated message using ML-DSA-65 and an RFC 9881 seed key.
/// The mutable DER input is erased, including on failure. The caller owns any other copies.
///
/// # Errors
/// Rejects malformed keys, oversized messages/contexts or unavailable randomness.
#[wasm_bindgen]
pub fn sign_mldsa65(
    private_key_der: &mut [u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    let key = signing::SigningKey::from_pkcs8(private_key_der);
    private_key_der.zeroize();
    if message.len() > stogas_verifier::MAX_INPUT_BYTES {
        return Err(JsError::new("signature message exceeds the input limit"));
    }
    key.map_err(error)?
        .sign(message, context)
        .map(|signature| signature.to_vec())
        .map_err(error)
}

/// Derive the public SPKI from an RFC 9881 seed key, erasing the mutable input DER.
///
/// # Errors
/// Rejects malformed or unsupported private keys.
#[wasm_bindgen]
pub fn mldsa65_public_key(private_key_der: &mut [u8]) -> Result<Vec<u8>, JsError> {
    let key = signing::SigningKey::from_pkcs8(private_key_der);
    private_key_der.zeroize();
    key.map_err(error)?.public_key_spki().map_err(error)
}

/// Verify an exact ML-DSA-65 message/context with a DER public key.
///
/// # Errors
/// Rejects other algorithms, malformed encodings or a signature mismatch.
#[wasm_bindgen]
pub fn verify_mldsa65(
    public_key_spki: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), JsError> {
    if message.len() > stogas_verifier::MAX_INPUT_BYTES {
        return Err(JsError::new("signature message exceeds the input limit"));
    }
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    signing::verify(key, message, context, signature).map_err(error)
}

/// Compute FIPS 204's message representative for a remote ML-DSA-65 signer.
/// Callers must independently verify the returned signature on the original bytes.
///
/// # Errors
/// Rejects malformed public keys, oversized messages and contexts.
#[wasm_bindgen]
pub fn mldsa65_message_representative(
    public_key_spki: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    signing::message_representative(key, message, context)
        .map(|mu| mu.to_vec())
        .map_err(error)
}

/// Derive the stable Rekor submission public key, erasing the mutable input DER.
/// Its authenticated association with the ML-DSA key enables independent log searches.
///
/// # Errors
/// Rejects malformed or unsupported private keys.
#[wasm_bindgen]
pub fn rekor_public_key(private_key_der: &mut [u8]) -> Result<Vec<u8>, JsError> {
    let key = signing::SigningKey::from_pkcs8(private_key_der);
    private_key_der.zeroize();
    key.map_err(error)?.rekor_public_key_spki().map_err(error)
}

/// Prepare a public Rekor submission using the authorized publisher's derived key.
/// Erases the mutable input DER. The caller must persist the exact result before
/// delivery and independently verify the ML-DSA signature on the complete document.
///
/// # Errors
/// Rejects malformed keys, oversized input and signing failures.
#[wasm_bindgen]
pub fn prepare_rekor_submission(
    private_key_der: &mut [u8],
    signed_document: &[u8],
) -> Result<String, JsError> {
    let key = signing::SigningKey::from_pkcs8(private_key_der);
    private_key_der.zeroize();
    key.map_err(error)?
        .prepare_rekor_submission(signed_document)
        .map_err(error)
}

/// Read the public identity of a separate Rekor submission seed. This supports
/// non-exportable document signers without exporting their ML-DSA private key.
/// The input seed is erased on success and failure.
///
/// # Errors
/// Rejects seeds other than 32 bytes or public-key encoding failures.
#[wasm_bindgen]
pub fn rekor_public_key_from_seed(seed: &mut [u8]) -> Result<Vec<u8>, JsError> {
    let key = signing::RekorSubmissionKey::from_seed(seed);
    seed.zeroize();
    key.map_err(error)?.public_key_spki().map_err(error)
}

/// Prepare Rekor v1 inclusion using a separate submission seed, erasing the input.
/// The signed document's ML-DSA signature remains independently mandatory.
///
/// # Errors
/// Rejects malformed seeds, oversized input and signing failures.
#[wasm_bindgen]
pub fn prepare_rekor_submission_with_seed(
    seed: &mut [u8],
    signed_document: &[u8],
) -> Result<String, JsError> {
    let key = signing::RekorSubmissionKey::from_seed(seed);
    seed.zeroize();
    key.map_err(error)?
        .prepare_submission(signed_document)
        .map_err(error)
}

/// Verify inclusion of exact signed bytes; this does not establish document authorship.
///
/// # Errors
/// Rejects malformed proofs, changed documents and invalid log signatures or times.
#[wasm_bindgen]
pub fn verify_rekor_document_inclusion(
    bundle: &[u8],
    signed_document: &[u8],
    submission_key_spki: &[u8],
    now_unix_ms: f64,
) -> Result<f64, JsError> {
    let now = super::parse_unix_ms(now_unix_ms, "now_unix_ms")?;
    let time = stogas_offline_sigstore::verify_rekor_document_inclusion(
        bundle,
        signed_document,
        submission_key_spki,
        now,
    )
    .map_err(|error| JsError::new(&error.to_string()))?;
    // A verified seconds value is bounded by the safe-integer millisecond input above.
    #[allow(clippy::cast_precision_loss)]
    Ok(time as f64)
}

fn error(error: signing::Error) -> JsError {
    JsError::new(&error.to_string())
}
