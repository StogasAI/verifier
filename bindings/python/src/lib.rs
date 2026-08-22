//! Thin Python adapter for the deterministic verifier core.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::time::{SystemTime, UNIX_EPOCH};
use stogas_sdk::{SecurityMode, Transport as ManagedTransport, TransportOptions};
use stogas_verifier::{
    Environment, HistoricalResponseProofInput, Verifier as CoreVerifier,
    verify_bundle as verify_core_bundle,
    verify_bundle_with_policy as verify_core_bundle_with_policy,
};

#[pyclass(name = "Verifier")]
struct PythonVerifier {
    core: CoreVerifier,
    environment: Environment,
}

#[pyclass(name = "Transport")]
struct PythonTransport {
    inner: Option<ManagedTransport>,
}

#[pymethods]
impl PythonTransport {
    #[new]
    #[pyo3(signature = (
        security = "tls",
        bundle_refresh_interval_seconds = 300,
        base_url = None,
        bundle_url = None,
        hardware_policy = None
    ))]
    fn new(
        security: &str,
        bundle_refresh_interval_seconds: u64,
        base_url: Option<String>,
        bundle_url: Option<String>,
        hardware_policy: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let defaults = TransportOptions::default();
        let options = TransportOptions {
            security: match security {
                "tls" => SecurityMode::Tls,
                "e2ee" => SecurityMode::E2ee,
                "both" => SecurityMode::Both,
                _ => return Err(PyValueError::new_err("security must be tls, e2ee, or both")),
            },
            bundle_refresh_interval: std::time::Duration::from_secs(
                bundle_refresh_interval_seconds,
            ),
            base_url: base_url.unwrap_or(defaults.base_url),
            bundle_url: bundle_url.unwrap_or(defaults.bundle_url),
            hardware_policy,
        };
        let inner = ManagedTransport::start(&options)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self { inner: Some(inner) })
    }

    #[getter]
    fn base_url(&self) -> PyResult<&str> {
        self.inner
            .as_ref()
            .map(ManagedTransport::base_url)
            .ok_or_else(|| PyValueError::new_err("Stogas transport is closed"))
    }

    fn refresh_bundle(&self) -> PyResult<bool> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("Stogas transport is closed"))?
            .refresh_bundle()
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    fn close(&mut self) {
        self.inner.take();
    }
}

#[pymethods]
impl PythonVerifier {
    #[new]
    fn new() -> Self {
        Self {
            core: CoreVerifier::default(),
            environment: Environment::stogas(),
        }
    }

    fn verify_bundle<'py>(
        &mut self,
        py: Python<'py>,
        bundle: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.verify_bundle_with_time(py, bundle, wall_clock_ms()?)
    }

    fn verify_bundle_with_policy<'py>(
        &mut self,
        py: Python<'py>,
        bundle: &[u8],
        policy: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let output = self
            .core
            .verify_bundle_with_policy(bundle, policy, wall_clock_ms()?, &self.environment)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        json_bytes(py, &output)
    }

    #[pyo3(signature = (proof, request_body, response_body, e2ee_transcript_sha256=None))]
    fn verify_response_proof<'py>(
        &self,
        py: Python<'py>,
        proof: &[u8],
        request_body: &[u8],
        response_body: &[u8],
        e2ee_transcript_sha256: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let output = self
            .core
            .verify_response_proof(
                proof,
                request_body,
                response_body,
                e2ee_transcript_sha256,
                wall_clock_ms()?,
            )
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        json_bytes(py, &output)
    }

    #[pyo3(signature = (proof, request_body, response_body, ledger, catalog, e2ee_transcript_sha256=None))]
    #[allow(clippy::too_many_arguments)]
    fn verify_historical_response_proof<'py>(
        &self,
        py: Python<'py>,
        proof: &[u8],
        request_body: &[u8],
        response_body: &[u8],
        ledger: &[u8],
        catalog: &[u8],
        e2ee_transcript_sha256: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let output = self
            .core
            .verify_historical_response_proof(&HistoricalResponseProofInput {
                proof_bytes: proof,
                request_body,
                response_body,
                expected_e2ee_transcript_sha256: e2ee_transcript_sha256,
                now_unix_ms: wall_clock_ms()?,
                ledger_bytes: ledger,
                catalog_approval_bytes: catalog,
                environment: &self.environment,
            })
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        json_bytes(py, &output)
    }
}

impl PythonVerifier {
    fn verify_bundle_with_time<'py>(
        &mut self,
        py: Python<'py>,
        bundle: &[u8],
        now_unix_ms: i64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let output = self
            .core
            .verify_bundle(bundle, now_unix_ms, &self.environment)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        json_bytes(py, &output)
    }
}

#[pyfunction]
fn verify_bundle<'py>(py: Python<'py>, bundle: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    verify_bundle_with_time(py, bundle, wall_clock_ms()?)
}

#[pyfunction]
fn verify_bundle_with_policy<'py>(
    py: Python<'py>,
    bundle: &[u8],
    policy: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let output =
        verify_core_bundle_with_policy(bundle, policy, wall_clock_ms()?, &Environment::stogas())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
    json_bytes(py, &output)
}

fn wall_clock_ms() -> PyResult<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PyValueError::new_err("system clock predates the Unix epoch"))?
            .as_millis(),
    )
    .map_err(|_| PyValueError::new_err("system clock is too large"))
}

fn verify_bundle_with_time<'py>(
    py: Python<'py>,
    bundle: &[u8],
    now_unix_ms: i64,
) -> PyResult<Bound<'py, PyBytes>> {
    let output = verify_core_bundle(bundle, now_unix_ms, &Environment::stogas())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    json_bytes(py, &output)
}

fn json_bytes<'py, T: serde::Serialize>(
    py: Python<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyBytes>> {
    let json =
        serde_json::to_vec(value).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(PyBytes::new(py, &json))
}

#[pymodule]
fn _stogas_verifier(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PythonVerifier>()?;
    module.add_class::<PythonTransport>()?;
    module.add_function(wrap_pyfunction!(verify_bundle, module)?)?;
    module.add_function(wrap_pyfunction!(verify_bundle_with_policy, module)?)
}
