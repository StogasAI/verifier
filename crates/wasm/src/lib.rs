//! Browser and Node/Bun adapter. The core remains deterministic and networkless.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
#[cfg(feature = "staging")]
use stogas_verifier::verify_staging_catalog_approval as verify_staging_catalog;
#[cfg(feature = "staging")]
use stogas_verifier::verify_staging_release_approval as verify_staging_release;
use stogas_verifier::{
    Environment, HistoricalResponseProofHashInput, HistoricalResponseProofInput,
    Verifier as CoreVerifier,
    e2ee::{
        Request as CoreE2eeRequest, ResponseDecoder, ResponseEvent, bundle_sha256,
        recipients_from_verified_bundle, seal_request,
    },
    inspect_snp_quote as inspect_quote, response_proof, secret_release,
    verify_amd_collateral_admission as verify_amd_collateral, verify_bundle as verify_core_bundle,
    verify_catalog_approval as verify_catalog,
    verify_certificate_csr_submission as verify_csr_submission,
    verify_heartbeat_admission as verify_admission,
    verify_local_heartbeat_admission as verify_local_admission,
    verify_node_ledger_record as verify_ledger_record,
    verify_recognized_heartbeat_signature as verify_recognized_heartbeat,
    verify_release_approval as verify_release,
};
use wasm_bindgen::prelude::*;

/// Report whether this artifact contains the private staging provenance policy.
#[wasm_bindgen(js_name = verifierSupportsStagingProvenance)]
#[must_use]
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

/// Browser verifier which caches immutable release provenance in memory.
#[wasm_bindgen(js_name = Verifier)]
pub struct WasmVerifier {
    core: CoreVerifier,
    environment: Environment,
    #[cfg(feature = "staging")]
    staging: bool,
    active_bundle: Option<ActiveBundle>,
}

struct ActiveBundle {
    expires_at_unix_ms: i64,
    sha256: String,
    recipients: Option<Vec<stogas_verifier::e2ee::Recipient>>,
    verification: stogas_verifier::VerificationOutput,
}

impl Default for WasmVerifier {
    fn default() -> Self {
        Self {
            core: CoreVerifier::default(),
            environment: Environment::stogas(),
            #[cfg(feature = "staging")]
            staging: false,
            active_bundle: None,
        }
    }
}

/// One request encrypted by the Rust core and its stateful authenticated response decoder.
#[wasm_bindgen(js_name = E2eeRequest)]
pub struct WasmE2eeRequest {
    body: Vec<u8>,
    request_id: String,
    transcript_sha256: String,
    response: ResponseDecoder,
}

/// Constant-memory response hash state for one signed streaming exchange.
#[wasm_bindgen(js_name = ResponseProofStream)]
pub struct WasmResponseProofStream {
    request_sha256: String,
    response_hasher: Option<Sha256>,
}

#[wasm_bindgen(js_class = Verifier)]
impl WasmVerifier {
    /// Construct a verifier for public Stogas evidence.
    ///
    /// A staging-enabled build can select the private staging trust environment. Production
    /// builds ignore this argument and contain no staging provenance parser or trust policy.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(staging: Option<bool>) -> Self {
        #[cfg(not(feature = "staging"))]
        let _ = staging;
        #[cfg(not(feature = "staging"))]
        return Self::default();

        #[cfg(feature = "staging")]
        let staging = staging.unwrap_or(false);
        #[cfg(feature = "staging")]
        Self {
            core: CoreVerifier::default(),
            environment: if staging {
                Environment::staging()
            } else {
                Environment::stogas()
            },
            staging,
            active_bundle: None,
        }
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
        let result = to_js_value(&output)?;
        self.active_bundle = Some(ActiveBundle {
            expires_at_unix_ms: output.bundle.expires_at_unix_ms,
            sha256: bundle_sha256(bundle),
            recipients: recipients_from_verified_bundle(&output).ok(),
            verification: output,
        });
        Ok(result)
    }

    /// Verify one compact response receipt against the active bundle.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for body, signature, attested-key, drand, expiry, or E2EE
    /// transcript mismatches.
    #[allow(clippy::cast_possible_truncation)]
    pub fn verify_response_proof(
        &self,
        proof: &[u8],
        request_body: &[u8],
        response_body: &[u8],
        e2ee_transcript_sha256: Option<String>,
    ) -> Result<JsValue, JsError> {
        let e2ee_transcript_sha256 = e2ee_transcript_sha256.map(String::into_boxed_str);
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let active = self
            .active_bundle
            .as_ref()
            .ok_or_else(|| JsError::new("a bundle must be verified before a response proof"))?;
        let output = response_proof::verify_with_bundle(
            proof,
            request_body,
            response_body,
            e2ee_transcript_sha256.as_deref(),
            now_unix_ms as i64,
            &active.verification,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }

    /// Start constant-memory verification for one streaming response.
    ///
    /// Feed every client-visible plaintext SSE frame except the final `stogas` proof comment to
    /// the returned state. The final `[DONE]` frame is part of the hash.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if no bundle has been verified.
    pub fn start_response_proof(
        &self,
        request_body: &[u8],
    ) -> Result<WasmResponseProofStream, JsError> {
        if self.active_bundle.is_none() {
            return Err(JsError::new(
                "a bundle must be verified before a response proof",
            ));
        }
        Ok(WasmResponseProofStream {
            request_sha256: hex::encode(Sha256::digest(request_body)),
            response_hasher: Some(Sha256::new()),
        })
    }

    /// Verify a compact response receipt against an immutable historical node ledger.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if the historical admission chain or receipt is invalid.
    #[allow(clippy::cast_possible_truncation)]
    pub fn verify_historical_response_proof(
        &self,
        proof: &[u8],
        request_body: &[u8],
        response_body: &[u8],
        ledger: &[u8],
        catalog: &[u8],
        e2ee_transcript_sha256: Option<String>,
    ) -> Result<JsValue, JsError> {
        let e2ee_transcript_sha256 = e2ee_transcript_sha256.map(String::into_boxed_str);
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let output = self
            .core
            .verify_historical_response_proof(&HistoricalResponseProofInput {
                proof_bytes: proof,
                request_body,
                response_body,
                expected_e2ee_transcript_sha256: e2ee_transcript_sha256.as_deref(),
                now_unix_ms: now_unix_ms as i64,
                ledger_bytes: ledger,
                catalog_approval_bytes: catalog,
                environment: &self.environment,
            })
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }

    /// Verify one immutable historical node-admission ledger record.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if release provenance, SNP evidence, drand, or the derived
    /// node identity is invalid.
    pub fn verify_node_ledger_record(&self, ledger: &[u8]) -> Result<JsValue, JsError> {
        let output = verify_ledger_record(ledger, &self.environment)
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }

    /// Verify one historical gateway release approval with this verifier's environment.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if either build proof, the launch policy, or the Stogas
    /// signature is invalid.
    #[allow(clippy::cast_possible_truncation)]
    pub fn verify_release_approval(&self, release: &[u8]) -> Result<JsValue, JsError> {
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        #[cfg(feature = "staging")]
        let output = if self.staging {
            verify_staging_release(release, now_unix_ms as i64)
        } else {
            verify_release(release, now_unix_ms as i64)
        };
        #[cfg(not(feature = "staging"))]
        let output = verify_release(release, now_unix_ms as i64);
        to_js_value(&output.map_err(|error| JsError::new(&error.to_string()))?)
    }

    /// Verify one historical catalog approval with independent GitHub and Stogas evidence.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if either proof lane or their artifact hashes differ.
    #[allow(clippy::cast_possible_truncation)]
    pub fn verify_catalog_approval(&self, approval: &[u8]) -> Result<JsValue, JsError> {
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        #[cfg(feature = "staging")]
        let output = if self.staging {
            verify_staging_catalog(approval, now_unix_ms as i64)
        } else {
            verify_catalog(approval, now_unix_ms as i64)
        };
        #[cfg(not(feature = "staging"))]
        let output = verify_catalog(approval, now_unix_ms as i64);
        to_js_value(&output.map_err(|error| JsError::new(&error.to_string()))?)
    }

    /// Encrypt one ordinary OpenAI-compatible inference request to every trusted bundle member.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error unless a current verified bundle contains E2EE recipients.
    #[allow(clippy::cast_possible_truncation)]
    pub fn seal_e2ee_request(
        &self,
        path: &str,
        api_key: &str,
        body: &[u8],
        accept: Option<String>,
        extra_fields: bool,
    ) -> Result<WasmE2eeRequest, JsError> {
        let accept = accept.map(String::into_boxed_str);
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let now_unix_ms = now_unix_ms as i64;
        let active = self
            .active_bundle
            .as_ref()
            .ok_or_else(|| JsError::new("a bundle must be verified before encrypted inference"))?;
        if now_unix_ms >= active.expires_at_unix_ms {
            return Err(JsError::new("the active verified bundle has expired"));
        }
        let recipients = active
            .recipients
            .as_deref()
            .ok_or_else(|| JsError::new("the active verified bundle has no E2EE recipients"))?;
        let sealed = seal_request(&CoreE2eeRequest {
            path,
            request_id: None,
            now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(60_000),
            bundle_sha256: &active.sha256,
            recipients,
            api_key,
            accept: accept.as_deref(),
            extra_fields,
            body,
        })
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(WasmE2eeRequest {
            body: sealed.body,
            request_id: sealed.request_id,
            transcript_sha256: sealed.transcript_sha256,
            response: sealed.response,
        })
    }
}

#[wasm_bindgen(js_class = ResponseProofStream)]
impl WasmResponseProofStream {
    /// Add exact plaintext response bytes to the running SHA-256 state.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error after the state was finished.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        let hasher = self
            .response_hasher
            .as_mut()
            .ok_or_else(|| JsError::new("response proof stream is already finished"))?;
        hasher.update(chunk);
        Ok(())
    }

    /// Finish verification against the verifier's current active bundle.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for a reused state or any proof verification failure.
    #[allow(clippy::cast_possible_truncation)]
    pub fn finish(
        &mut self,
        verifier: &WasmVerifier,
        proof: &[u8],
        e2ee_transcript_sha256: Option<String>,
    ) -> Result<JsValue, JsError> {
        let response_sha256 = self.finish_response_sha256()?;
        let e2ee_transcript_sha256 = e2ee_transcript_sha256.map(String::into_boxed_str);
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let output = verifier
            .core
            .verify_response_proof_hashes(
                proof,
                &self.request_sha256,
                &response_sha256,
                e2ee_transcript_sha256.as_deref(),
                now_unix_ms as i64,
            )
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }

    /// Finish verification against immutable historical node and catalog evidence.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for a reused state or any evidence or proof failure.
    #[allow(clippy::cast_possible_truncation)]
    pub fn finish_historical(
        &mut self,
        verifier: &WasmVerifier,
        proof: &[u8],
        ledger: &[u8],
        catalog: &[u8],
        e2ee_transcript_sha256: Option<String>,
    ) -> Result<JsValue, JsError> {
        let response_sha256 = self.finish_response_sha256()?;
        let e2ee_transcript_sha256 = e2ee_transcript_sha256.map(String::into_boxed_str);
        let now_unix_ms = js_sys::Date::now();
        validate_time(now_unix_ms)?;
        let output = verifier
            .core
            .verify_historical_response_proof_hashes(&HistoricalResponseProofHashInput {
                proof_bytes: proof,
                request_sha256: &self.request_sha256,
                response_sha256: &response_sha256,
                expected_e2ee_transcript_sha256: e2ee_transcript_sha256.as_deref(),
                now_unix_ms: now_unix_ms as i64,
                ledger_bytes: ledger,
                catalog_approval_bytes: catalog,
                environment: &verifier.environment,
            })
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&output)
    }
}

impl WasmResponseProofStream {
    fn finish_response_sha256(&mut self) -> Result<String, JsError> {
        let hasher = self
            .response_hasher
            .take()
            .ok_or_else(|| JsError::new("response proof stream is already finished"))?;
        Ok(hex::encode(hasher.finalize()))
    }
}

#[wasm_bindgen(js_class = E2eeRequest)]
impl WasmE2eeRequest {
    /// JSON envelope sent to the ordinary inference endpoint.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }

    /// Unique single-use request identifier bound into the encrypted transcript.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn request_id(&self) -> String {
        self.request_id.clone()
    }

    /// SHA-256 of the request transcript needed for later response-receipt verification.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn transcript_sha256(&self) -> String {
        self.transcript_sha256.clone()
    }

    /// Authenticate another encrypted response chunk and return zero or more typed events.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for malformed, reordered, or unauthenticated response bytes.
    pub fn push_response(&mut self, bytes: &[u8]) -> Result<js_sys::Array, JsError> {
        let events = self
            .response
            .push(bytes)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let output = js_sys::Array::new();
        for event in events {
            let object = js_sys::Object::new();
            match event {
                ResponseEvent::Metadata(metadata) => {
                    set_property(&object, "type", &JsValue::from_str("metadata"))?;
                    set_property(&object, "metadata", &to_js_value(&metadata)?)?;
                }
                ResponseEvent::Data(bytes) => {
                    set_property(&object, "type", &JsValue::from_str("data"))?;
                    set_property(
                        &object,
                        "data",
                        &js_sys::Uint8Array::from(bytes.as_slice()).into(),
                    )?;
                }
                ResponseEvent::Final => {
                    set_property(&object, "type", &JsValue::from_str("final"))?;
                }
            }
            output.push(&object);
        }
        Ok(output)
    }

    /// Require the authenticated final response frame and no partial trailing data.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error if the encrypted response was truncated.
    pub fn finish(&self) -> Result<(), JsError> {
        self.response
            .finish()
            .map_err(|error| JsError::new(&error.to_string()))
    }
}

fn set_property(object: &js_sys::Object, name: &str, value: &JsValue) -> Result<(), JsError> {
    js_sys::Reflect::set(object, &JsValue::from_str(name), value)
        .map(|_| ())
        .map_err(|_| JsError::new("could not construct an E2EE response event"))
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

/// Verify one catalog approval with independent Stogas and GitHub build evidence.
///
/// # Errors
///
/// Returns a JavaScript error when the captured time or either authorization is invalid.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_catalog_approval(approval: &[u8], now_unix_ms: f64) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_catalog(approval, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

#[cfg(feature = "staging")]
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_staging_catalog_approval(
    approval: &[u8],
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    validate_time(now_unix_ms)?;
    let output = verify_staging_catalog(approval, now_unix_ms as i64)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

#[cfg(not(feature = "staging"))]
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_staging_catalog_approval(
    _approval: &[u8],
    _now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "staging catalog verification is not available in this build",
    ))
}

#[cfg(feature = "staging")]
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

#[cfg(not(feature = "staging"))]
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_staging_release_approval(
    _release: &[u8],
    _now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "staging release verification is not available in this build",
    ))
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

/// Authenticate one intermediate heartbeat with a previously attested generation key.
///
/// # Errors
///
/// Returns a JavaScript error for malformed input or an invalid signature.
#[wasm_bindgen]
pub fn verify_recognized_heartbeat_signature(
    heartbeat: &[u8],
    public_key_b64url: &str,
) -> Result<(), JsError> {
    verify_recognized_heartbeat(heartbeat, public_key_b64url)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Verify an untrusted CSR submission against a separately supplied trusted Control context.
///
/// # Errors
///
/// Returns a JavaScript error for malformed DER, invalid signatures, or identity mismatch.
#[wasm_bindgen]
pub fn verify_certificate_csr_submission(
    submission: &[u8],
    trusted_context: &[u8],
) -> Result<(), JsError> {
    verify_csr_submission(submission, trusted_context)
        .map_err(|error| JsError::new(&error.to_string()))
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
