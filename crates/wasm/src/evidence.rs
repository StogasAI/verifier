use std::sync::Arc;

use serde_json::json;
use stogas_verifier::{
    approvals::RootKey,
    evidence::{self, Snapshot},
};
use wasm_bindgen::prelude::*;

/// Authenticate a renewal with the key from an already verified boot registration.
///
/// # Errors
/// Rejects malformed requests, changed identities, signatures or stale timestamps.
#[wasm_bindgen]
pub fn verify_certificate_renewal(
    request: &[u8],
    node_id: &str,
    public_key: &[u8],
) -> Result<(), JsValue> {
    evidence::boot::verify_certificate_renewal(
        request,
        node_id,
        public_key,
        super::wall_clock_ms()?,
    )
    .map_err(|error| verification_error(&error))
}

/// Environment endpoints compiled into this artifact. Unsupported environments fail closed.
///
/// # Errors
/// Rejects environments absent from this build or failed output conversion.
#[wasm_bindgen]
pub fn transport_configuration(environment: &str) -> Result<JsValue, JsError> {
    let environment: stogas_verifier::approvals::Environment =
        serde_json::from_value(json!(environment))
            .map_err(|_| JsError::new("unsupported verification environment"))?;
    super::to_js_value(&json!({
        "environment": environment,
        "evidence_origins": environment.evidence_origins(),
        "api_origin": environment.api_origin(),
        "e2ee_origin": environment.e2ee_origin()
    }))
}

/// Stateful offline verifier. The trust seed comes from local configuration, never the bundle.
#[wasm_bindgen(js_name = EvidenceVerifier)]
pub struct EvidenceVerifier {
    core: evidence::Verifier,
}

/// Owned immutable evidence for a connection or in-flight request. Free it when no longer used.
#[wasm_bindgen(js_name = EvidenceSnapshot)]
pub struct EvidenceSnapshot {
    pub(crate) core: Arc<Snapshot>,
}

#[wasm_bindgen(js_class = EvidenceVerifier)]
impl EvidenceVerifier {
    /// Inspect immutable approval history without changing current trust.
    ///
    /// # Errors
    /// Rejects incomplete, altered or unauthenticated evidence.
    pub fn verify_evidence_archive(&self, evidence: &[u8]) -> Result<JsValue, JsValue> {
        let summary = self
            .core
            .verify_evidence_archive(evidence, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&summary)?)
    }

    /// Verify immutable boot history without changing current approvals.
    ///
    /// # Errors
    /// Rejects altered history or evidence invalid at the authenticated log-inclusion time.
    pub fn verify_boot_archive(&self, archive: &[u8], evidence: &[u8]) -> Result<JsValue, JsValue> {
        let boot = self
            .core
            .verify_boot_archive(archive, evidence, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&boot.summary())?)
    }

    /// Construct the managed Stogas verifier from its compiled environment authority.
    ///
    /// # Errors
    /// Rejects unsupported environments and unprovisioned authorities.
    pub fn for_stogas(environment: &str) -> Result<Self, JsValue> {
        let environment = serde_json::from_value(json!(environment))
            .map_err(|_| js_sys::Error::new("unsupported verification environment"))?;
        Ok(Self {
            core: evidence::Verifier::stogas(environment)
                .map_err(|error| verification_error(&error))?,
        })
    }

    /// # Errors
    /// Rejects invalid root signatures/inclusion and conflicting or retired key decisions.
    pub fn verify_key_manifest(&self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        let keys = self
            .core
            .verify_key_manifest(bytes, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&keys)?)
    }

    /// # Errors
    /// Rejects unsupported environments and malformed locally configured root keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        environment: &str,
        root_key_id: String,
        root_public_key: String,
    ) -> Result<Self, JsValue> {
        let environment = serde_json::from_value(json!(environment))
            .map_err(|_| js_sys::Error::new("unsupported verification environment"))?;
        let core = evidence::Verifier::new(
            environment,
            RootKey {
                key_id: root_key_id,
                public_key: root_public_key,
            },
        )
        .map_err(|error| verification_error(&error))?;
        Ok(Self { core })
    }

    /// # Errors
    /// Rejects an invalid candidate. Authenticated revocations still constrain retained snapshots.
    pub fn refresh(&mut self, bundle: &[u8]) -> Result<EvidenceSnapshot, JsValue> {
        let now = super::wall_clock_ms()?;
        self.core
            .refresh(bundle, now)
            .map(|core| EvidenceSnapshot { core })
            .map_err(|error| verification_error(&error))
    }
}

#[wasm_bindgen(js_class = EvidenceSnapshot)]
impl EvidenceSnapshot {
    /// Digest of the complete verified bundle, for immutable archive references.
    #[must_use]
    pub fn body_sha256(&self) -> String {
        self.core.body_sha256().to_owned()
    }

    /// # Errors
    /// Returns an error if output conversion fails; this does not re-appraise a live node.
    pub fn summary(&self) -> Result<JsValue, JsError> {
        super::to_js_value(&self.core.summary())
    }

    /// Highest approved catalog this approved gateway can run, or null when none is compatible.
    ///
    /// # Errors
    /// Returns an error if output conversion fails.
    pub fn compatible_catalog(&self, gateway_release_id: &str) -> Result<JsValue, JsError> {
        super::to_js_value(
            &self
                .core
                .compatible_catalog(gateway_release_id)
                .map(|(release_id, release)| json!({"release_id": release_id, "release": release})),
        )
    }

    /// # Errors
    /// Rejects an expired root decision or one superseded by an authenticated refresh.
    pub fn require_current_keys(&self) -> Result<(), JsValue> {
        self.core
            .require_current_keys()
            .map_err(|error| verification_error(&error))?;
        self.core
            .approvals()
            .valid_until(super::wall_clock_ms()?)
            .map_err(|error| verification_error(&evidence::Error::from(error)))?;
        Ok(())
    }

    /// # Errors
    /// Rejects absent, expired or revoked collateral for this exact platform.
    pub fn collateral_validity(
        &self,
        chip_id: &str,
        reported_tcb: &str,
    ) -> Result<JsValue, JsValue> {
        let validity = self
            .core
            .collateral_validity(chip_id, reported_tcb, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&json!({
            "valid_from_unix_ms": validity.not_before_unix_ms,
            "valid_until_unix_ms": validity.not_after_unix_ms
        }))?)
    }

    /// Verify the exact quote and the caller's one-use registration challenge.
    ///
    /// # Errors
    /// Rejects unapproved hardware/software, mismatched bindings and invalid hardware signatures.
    pub fn verify_registration(
        &self,
        document: &[u8],
        challenge: &[u8],
    ) -> Result<JsValue, JsValue> {
        let challenge = challenge
            .try_into()
            .map_err(|_| js_sys::Error::new("registration challenge must be 32 bytes"))?;
        let verified = self
            .core
            .verify_registration(document, challenge, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&verified.summary())?)
    }

    /// Appraise registration and its TLS key's CSR before certificate issuance.
    ///
    /// # Errors
    /// Rejects failed registration, another CSR key/hostname or invalid proof of possession.
    pub fn verify_registration_csr(
        &self,
        document: &[u8],
        challenge: &[u8],
        csr_der: &[u8],
    ) -> Result<JsValue, JsValue> {
        let challenge = challenge
            .try_into()
            .map_err(|_| js_sys::Error::new("registration challenge must be 32 bytes"))?;
        let verified = self
            .core
            .verify_registration(document, challenge, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        verified
            .verify_csr(csr_der)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&verified.summary())?)
    }

    /// Reappraise durable registration bytes and their CSR against current authorization.
    /// The expected digest is supplied by the registration store, not by the guest.
    ///
    /// # Errors
    /// Rejects changed registration, failed current appraisal or a mismatched CSR.
    pub fn verify_registered_boot_csr(
        &self,
        document: &[u8],
        registered_sha256: &[u8],
        csr_der: &[u8],
    ) -> Result<JsValue, JsValue> {
        let digest = registered_sha256
            .try_into()
            .map_err(|_| js_sys::Error::new("registered digest must be 32 bytes"))?;
        let verified = self
            .core
            .verify_registered_boot(document, digest, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        verified
            .verify_csr(csr_der)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&verified.summary())?)
    }

    /// Reappraise the exact boot already retained by the registration authority.
    ///
    /// # Errors
    /// Rejects changed registration bytes or failed current hardware/release appraisal.
    pub fn verify_registered_boot(
        &self,
        document: &[u8],
        registered_sha256: &[u8],
    ) -> Result<JsValue, JsValue> {
        let digest = registered_sha256
            .try_into()
            .map_err(|_| js_sys::Error::new("registered digest must be 32 bytes"))?;
        let verified = self
            .core
            .verify_registered_boot(document, digest, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&verified.summary())?)
    }

    /// # Errors
    /// Rejects unknown log signers, wrong inclusion or failed current hardware appraisal.
    pub fn verify_logged_boot(
        &self,
        document: &[u8],
        inclusion: &[u8],
    ) -> Result<JsValue, JsValue> {
        let verified = self
            .core
            .verify_logged_boot(document, inclusion, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))?;
        Ok(super::to_js_value(&verified.summary())?)
    }
}

pub fn verification_error(error: &evidence::Error) -> JsValue {
    let value = js_sys::Error::new(&error.to_string());
    value.set_name("EvidenceVerificationError");
    // Fixed own properties on a newly constructed Error; no caller-controlled setter is invoked.
    let _ = js_sys::Reflect::set(
        &value,
        &JsValue::from_str("code"),
        &JsValue::from_str(error.code()),
    );
    value.into()
}
