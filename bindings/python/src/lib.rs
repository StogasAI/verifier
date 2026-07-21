//! Thin Python adapter for the deterministic verifier core.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::time::{SystemTime, UNIX_EPOCH};
use stogas_verifier::{Environment, Verifier as CoreVerifier, verify_bundle as verify_core_bundle};

#[pyclass(name = "Verifier")]
struct PythonVerifier {
    core: CoreVerifier,
    environment: Environment,
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
    module.add_function(wrap_pyfunction!(verify_bundle, module)?)
}
