//! Browser and Node/Bun adapter. The core remains deterministic and networkless.

use serde::{Deserialize, Serialize};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
use stogas_verifier::{
    DEFAULT_NODE_EVIDENCE_AGE_MS, Environment, MAX_NODE_EVIDENCE_AGE_MS, MIN_NODE_EVIDENCE_AGE_MS,
    Verifier as CoreVerifier, inspect_snp_quote as inspect_quote,
    verify_amd_collateral_admission as verify_amd_collateral, verify_bundle as verify_core_bundle,
    verify_heartbeat_admission as verify_admission,
    verify_local_heartbeat_admission as verify_local_admission,
    verify_release_approval as verify_release,
    verify_staging_release_approval as verify_staging_release,
};
use wasm_bindgen::prelude::*;

const DEFAULT_NODE_EVIDENCE_AGE_MS_F64: f64 = 120_000.0;
const MIN_NODE_EVIDENCE_AGE_MS_F64: f64 = 60_000.0;
const MAX_NODE_EVIDENCE_AGE_MS_F64: f64 = 900_000.0;
const _: () = assert!(DEFAULT_NODE_EVIDENCE_AGE_MS == 120_000);
const _: () = assert!(MIN_NODE_EVIDENCE_AGE_MS == 60_000);
const _: () = assert!(MAX_NODE_EVIDENCE_AGE_MS == 900_000);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSubject {
    name: String,
    sha256: String,
}

/// Browser verifier which caches immutable release provenance in memory.
#[wasm_bindgen(js_name = Verifier)]
pub struct WasmVerifier {
    core: CoreVerifier,
    environment: Environment,
}

#[wasm_bindgen(js_class = Verifier)]
impl WasmVerifier {
    /// Construct a verifier with an optional node-freshness policy.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error when the freshness policy is invalid.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(max_node_age_ms: Option<f64>, staging: Option<bool>) -> Result<Self, JsError> {
        Ok(Self {
            core: CoreVerifier::default(),
            environment: verifier_environment(
                max_node_age_ms.unwrap_or(DEFAULT_NODE_EVIDENCE_AGE_MS_F64),
                staging.unwrap_or(false),
            )?,
        })
    }

    /// Verify with one captured browser wall-clock value.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for an untrusted bundle.
    #[allow(clippy::cast_possible_truncation)]
    pub fn verify_bundle(&mut self, bundle: &[u8]) -> Result<JsValue, JsError> {
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let output = self
            .core
            .verify_bundle(bundle, now_unix_ms as i64, &self.environment)
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }
}

fn validate_time(now_unix_ms: f64) -> Result<(), JsError> {
    if !now_unix_ms.is_finite() || now_unix_ms.fract() != 0.0 {
        return Err(JsError::new("now_unix_ms must be an integer"));
    }
    Ok(())
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

fn verifier_environment(max_node_age_ms: f64, staging: bool) -> Result<Environment, JsError> {
    if !max_node_age_ms.is_finite()
        || max_node_age_ms.fract() != 0.0
        || !(MIN_NODE_EVIDENCE_AGE_MS_F64..=MAX_NODE_EVIDENCE_AGE_MS_F64).contains(&max_node_age_ms)
    {
        return Err(JsError::new(
            "max_node_age_ms must be an integer between 60000 and 900000",
        ));
    }
    let mut environment = if staging {
        Environment::staging()
    } else {
        Environment::stogas()
    };
    #[allow(clippy::cast_possible_truncation)]
    let milliseconds = max_node_age_ms as i64;
    environment.max_node_evidence_age_ms = milliseconds;
    Ok(environment)
}

/// Verify a bundle using one captured platform wall-clock value.
///
/// # Errors
///
/// Returns a JavaScript error when the platform time or bundle is invalid.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_bundle(bundle: &[u8]) -> Result<JsValue, JsError> {
    let now_unix_ms = js_sys::Date::now();
    validate_time(now_unix_ms)?;
    let output = verify_core_bundle(bundle, now_unix_ms as i64, &Environment::stogas())
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify one release approval with the same Stogas and GitHub policy used for bundle verification.
///
/// # Errors
///
/// Returns a JavaScript error when the captured time or release authorization is invalid.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_release_approval(release: &[u8], now_unix_ms: f64) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_release(release, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify one release approval using the staging-only development provenance policy.
///
/// # Errors
///
/// Returns a JavaScript error when the captured time or release authorization is invalid.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_staging_release_approval(
    release: &[u8],
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_staging_release(release, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify fetched AMD collateral before Control activates it.
///
/// # Errors
///
/// Returns a JavaScript error for invalid time, certificate, CRL, identity, or digest data.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_amd_collateral_admission(
    request: &[u8],
    now_unix_ms: f64,
    required_until_unix_ms: f64,
) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    validate_time(required_until_unix_ms)?;
    let output = verify_amd_collateral(request, now_unix_ms as i64, required_until_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify the networkless Sigstore profile directly. This is also the browser conformance seam.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy, time, or untrusted evidence.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_sigstore_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
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
    let output = verify_github_attestation(bundle, &subjects, &policy, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Extract untrusted SNP identity fields for selecting candidate AMD collateral.
///
/// # Errors
///
/// Returns a JavaScript error for malformed or unsupported quote bytes.
#[wasm_bindgen]
pub fn inspect_snp_quote(quote: &str) -> Result<JsValue, JsError> {
    let output = inspect_quote(quote).map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify one Control heartbeat admission with the same cryptographic core used by clients.
///
/// # Errors
///
/// Returns a JavaScript error when time, input, or any trust check fails.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_heartbeat_admission(request: &[u8], now_unix_ms: f64) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_admission(request, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

/// Verify one explicitly local Control heartbeat without granting production AMD trust.
///
/// # Errors
///
/// Returns a JavaScript error when time, input, binding, replay, or configured local signature
/// verification fails.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_local_heartbeat_admission(
    request: &[u8],
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_local_admission(request, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}
