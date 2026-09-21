//! Browser and Node/Bun adapter. The core remains deterministic and networkless.
mod channel;
mod evidence;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
use stogas_verifier::{inspect_snp_report as inspect_report, secret_release};
use wasm_bindgen::prelude::*;

/// Report whether this artifact contains the private staging provenance policy.
#[wasm_bindgen(js_name = verifierSupportsStagingProvenance)]
#[must_use]
#[expect(
    clippy::missing_const_for_fn,
    reason = "wasm-bindgen rejects const exported functions"
)]
pub fn verifier_supports_staging_provenance() -> bool {
    cfg!(feature = "staging")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSubject {
    name: String,
    sha256: String,
}

#[derive(Serialize)]
struct WasmSealedSecret {
    ciphertext: String,
    encapsulated_key: String,
}

fn wall_clock_ms() -> Result<i64, JsError> {
    parse_unix_ms(js_sys::Date::now(), "platform wall clock")
}

#[allow(clippy::cast_possible_truncation)]
fn parse_unix_ms(value: f64, label: &str) -> Result<i64, JsError> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > MAX_SAFE_INTEGER {
        return Err(JsError::new(&format!("{label} must be a safe integer")));
    }
    Ok(value as i64)
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Seal one Control secret to an attested X-Wing public key.
///
/// # Errors
///
/// Returns a JavaScript error for an invalid key or input, or an encryption failure.
#[wasm_bindgen]
pub fn seal_secret_release(
    public_key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsError> {
    let sealed = secret_release::seal(public_key, aad, plaintext)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&WasmSealedSecret {
        ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext),
        encapsulated_key: URL_SAFE_NO_PAD.encode(sealed.encapsulated_key),
    })
}

/// Verify the networkless Sigstore profile directly. This is also the browser conformance seam.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy, time, or untrusted evidence.
#[wasm_bindgen]
pub fn verify_sigstore_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    let now_unix_ms = parse_unix_ms(now_unix_ms, "now_unix_ms")?;
    let owned: Vec<OwnedSubject> = serde_json::from_str(expected_subjects_json)
        .map_err(|error| JsError::new(&format!("invalid subjects: {error}")))?;
    let subjects = owned
        .iter()
        .map(|subject| Subject {
            name: &subject.name,
            sha256: &subject.sha256,
        })
        .collect::<Vec<_>>();
    let policy: GithubPolicy = serde_json::from_str(policy_json)
        .map_err(|error| JsError::new(&format!("invalid policy: {error}")))?;
    let output = verify_github_attestation(bundle, &subjects, &policy, now_unix_ms)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Read untrusted raw-report selectors for vendor collateral acquisition.
///
/// # Errors
/// Rejects malformed or unsupported report bytes. Full attestation verification remains required.
#[wasm_bindgen]
pub fn inspect_snp_report(report: &[u8]) -> Result<JsValue, JsError> {
    let output = inspect_report(report).map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}
