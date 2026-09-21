//! Offline appraisal uses the same owned snapshots as the managed transport.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::sync::Arc;
use stogas_verifier::{
    approvals::{Environment, OnlineKey},
    evidence::{self, boot::VerifiedBoot},
    receipt,
};

pyo3::create_exception!(stogas_verifier, VerificationError, PyValueError);

#[pyclass(name = "EvidenceVerifier")]
struct EvidenceVerifier {
    core: evidence::Verifier,
}

#[pyclass(name = "EvidenceSnapshot", frozen)]
struct EvidenceSnapshot {
    core: Arc<evidence::Snapshot>,
}

#[pyclass(name = "VerifiedBoot", frozen)]
struct Boot {
    core: VerifiedBoot,
}

#[pymethods]
impl EvidenceVerifier {
    #[new]
    #[pyo3(signature = (*, environment = "prod", root_key_id = None, root_public_key = None))]
    fn new(
        py: Python<'_>,
        environment: &str,
        root_key_id: Option<String>,
        root_public_key: Option<String>,
    ) -> PyResult<Self> {
        let environment: Environment = serde_json::from_value(serde_json::json!(environment))
            .map_err(|_| PyValueError::new_err("environment is unsupported by this build"))?;
        let core = match (root_key_id, root_public_key) {
            (None, None) => evidence::Verifier::stogas(environment),
            (Some(key_id), Some(public_key)) => {
                evidence::Verifier::new(environment, OnlineKey { key_id, public_key })
            }
            _ => {
                return Err(PyValueError::new_err(
                    "root key ID and public key are required together",
                ));
            }
        }
        .map_err(|error| evidence_error(py, &error))?;
        Ok(Self { core })
    }

    fn refresh(
        &mut self,
        py: Python<'_>,
        bundle: &Bound<'_, PyBytes>,
    ) -> PyResult<EvidenceSnapshot> {
        let bytes = bundle.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.refresh(bytes, now))
            .map(|core| EvidenceSnapshot { core })
            .map_err(|error| evidence_error(py, &error))
    }

    fn verify_key_manifest<'py>(
        &self,
        py: Python<'py>,
        document: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = document.as_bytes();
        let now = super::wall_clock_ms()?;
        let keys = py
            .detach(|| self.core.verify_key_manifest(bytes, now))
            .map_err(|error| evidence_error(py, &error))?;
        super::json_bytes(py, &keys)
    }

    /// Authenticate archived approvals without installing them as current permission.
    fn verify_evidence_archive<'py>(
        &self,
        py: Python<'py>,
        evidence: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let evidence = evidence.as_bytes();
        let now = super::wall_clock_ms()?;
        let result = py
            .detach(|| self.core.verify_evidence_archive(evidence, now))
            .map_err(|error| evidence_error(py, &error))?;
        super::json_bytes(py, &result)
    }

    /// Appraise a boot at its authenticated log time. This grants no live authorization.
    fn verify_boot_archive(
        &self,
        py: Python<'_>,
        archive: &Bound<'_, PyBytes>,
        evidence: &Bound<'_, PyBytes>,
    ) -> PyResult<Boot> {
        let archive = archive.as_bytes();
        let evidence = evidence.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.verify_boot_archive(archive, evidence, now))
            .map(|core| Boot { core })
            .map_err(|error| evidence_error(py, &error))
    }
}

#[pymethods]
impl EvidenceSnapshot {
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        super::json_bytes(py, &self.core.summary())
    }

    fn require_current_keys(&self, py: Python<'_>) -> PyResult<()> {
        self.core
            .require_current_keys()
            .map_err(|error| evidence_error(py, &error))
    }

    fn collateral_validity<'py>(
        &self,
        py: Python<'py>,
        chip_id: &str,
        reported_tcb: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let validity = self
            .core
            .collateral_validity(chip_id, reported_tcb, super::wall_clock_ms()?)
            .map_err(|error| evidence_error(py, &error))?;
        super::json_bytes(
            py,
            &serde_json::json!({
                "valid_from_unix_ms": validity.not_before_unix_ms,
                "valid_until_unix_ms": validity.not_after_unix_ms
            }),
        )
    }

    fn verify_registration<'py>(
        &self,
        py: Python<'py>,
        document: &Bound<'_, PyBytes>,
        challenge: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let document = document.as_bytes();
        let challenge = digest(challenge.as_bytes(), "registration challenge")?;
        let now = super::wall_clock_ms()?;
        let verified = py
            .detach(|| self.core.verify_registration(document, challenge, now))
            .map_err(|error| evidence_error(py, &error))?;
        super::json_bytes(py, &verified.summary())
    }

    fn verify_logged_boot(
        &self,
        py: Python<'_>,
        document: &Bound<'_, PyBytes>,
        inclusion: &Bound<'_, PyBytes>,
    ) -> PyResult<Boot> {
        let document = document.as_bytes();
        let inclusion = inclusion.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.verify_logged_boot(document, inclusion, now))
            .map(|core| Boot { core })
            .map_err(|error| evidence_error(py, &error))
    }
}

#[pymethods]
impl Boot {
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        super::json_bytes(py, &self.core.summary())
    }

    /// Verify a content receipt using locally computed SHA-256 hashes of the exact bodies.
    fn verify_receipt<'py>(
        &self,
        py: Python<'py>,
        document: &Bound<'_, PyBytes>,
        request_sha256: &Bound<'_, PyBytes>,
        response_sha256: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let document = document.as_bytes();
        let request = digest(request_sha256.as_bytes(), "request digest")?;
        let response = digest(response_sha256.as_bytes(), "response digest")?;
        let result = py
            .detach(|| receipt::Receipt::parse(document)?.verify(&self.core, request, response))
            .map_err(|error| receipt_error(py, &error))?;
        super::json_bytes(py, &result)
    }

    /// Verify a buffered response containing its final Stogas metadata object.
    fn verify_response<'py>(
        &self,
        py: Python<'py>,
        request_sha256: &Bound<'_, PyBytes>,
        response_body: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let request = digest(request_sha256.as_bytes(), "request digest")?;
        let response = response_body.as_bytes();
        let result = py
            .detach(|| receipt::verify_buffered(&self.core, request, response))
            .map_err(|error| receipt_error(py, &error))?;
        super::json_bytes(py, &result)
    }
}

fn digest<'a>(bytes: &'a [u8], name: &str) -> PyResult<&'a [u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be 32 bytes")))
}

fn evidence_error(py: Python<'_>, error: &evidence::Error) -> PyErr {
    coded_error(py, error.code(), error.to_string())
}

fn receipt_error(py: Python<'_>, error: &receipt::Error) -> PyErr {
    let code = match error {
        receipt::Error::Invalid => "invalid_receipt",
        receipt::Error::Content => "receipt_content",
        receipt::Error::Identity => "receipt_identity",
        receipt::Error::Signature => "receipt_signature",
    };
    coded_error(py, code, error.to_string())
}

fn coded_error(py: Python<'_>, code: &str, message: String) -> PyErr {
    let error = VerificationError::new_err(message);
    match error.value(py).setattr("code", code) {
        Ok(()) => error,
        Err(error) => error,
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<EvidenceVerifier>()?;
    module.add_class::<EvidenceSnapshot>()?;
    module.add_class::<Boot>()?;
    module.add(
        "VerificationError",
        module.py().get_type::<VerificationError>(),
    )
}
