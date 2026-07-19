//! Small browser, Worker, Node, and Bun adapter for the generic offline Sigstore verifier.

use serde::{Deserialize, Serialize};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation as verify_core};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSubject {
    name: String,
    sha256: String,
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Verify a GitHub/Sigstore attestation using one captured platform wall-clock value.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy, invalid platform time, or untrusted evidence.
#[wasm_bindgen]
pub fn verify_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
) -> Result<JsValue, JsError> {
    verify_github_attestation_at(
        bundle,
        expected_subjects_json,
        policy_json,
        js_sys::Date::now(),
    )
}

/// Verify at an injected time for deterministic tests and audits.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy, invalid time, or untrusted evidence.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_github_attestation_at(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    if !now_unix_ms.is_finite() || now_unix_ms.fract() != 0.0 {
        return Err(JsError::new("now_unix_ms must be an integer"));
    }
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
    let output = verify_core(bundle, &subjects, &policy, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}
