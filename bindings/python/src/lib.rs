//! Thin Python adapter for the deterministic verifier core.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use stogas_verifier::{Environment, verify_bundle};

#[pyfunction]
fn verify_staging_bundle<'py>(
    py: Python<'py>,
    bundle: &[u8],
    now_unix_ms: i64,
) -> PyResult<Bound<'py, PyBytes>> {
    let output = verify_bundle(bundle, now_unix_ms, &Environment::staging_legacy(), None)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let json =
        serde_json::to_vec(&output).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(PyBytes::new(py, &json))
}

#[pymodule]
fn _stogas_verifier(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_staging_bundle, module)?)
}
