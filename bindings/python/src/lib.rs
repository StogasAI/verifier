//! Thin Python adapter for the deterministic verifier core.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::time::{SystemTime, UNIX_EPOCH};
use stogas_sdk::{SecurityMode, Transport as ManagedTransport, TransportOptions};
mod evidence;

#[pyclass(name = "Transport")]
struct PythonTransport {
    inner: Option<ManagedTransport>,
}

#[pymethods]
impl PythonTransport {
    #[new]
    #[pyo3(signature = (*, environment = "prod", security = "tls", max_connections = 4, base_url = None))]
    fn new(
        py: Python<'_>,
        environment: &str,
        security: &str,
        max_connections: usize,
        base_url: Option<String>,
    ) -> PyResult<Self> {
        let options = TransportOptions {
            environment: serde_json::from_value(serde_json::Value::String(environment.to_owned()))
                .map_err(|_| PyValueError::new_err("environment is unsupported by this build"))?,
            security: match security {
                "tls" => SecurityMode::Tls,
                "e2ee" => SecurityMode::E2ee,
                _ => return Err(PyValueError::new_err("security must be tls or e2ee")),
            },
            max_connections,
            base_url,
        };
        let inner = py
            .detach(move || ManagedTransport::start(&options))
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

    fn refresh_bundle(&self, py: Python<'_>) -> PyResult<bool> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("Stogas transport is closed"))?;
        py.detach(|| inner.refresh_bundle())
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    fn close(&mut self, py: Python<'_>) {
        let inner = self.inner.take();
        py.detach(move || {
            if let Some(mut inner) = inner {
                inner.close();
            }
        });
    }
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
    evidence::register(module)?;
    module.add_class::<PythonTransport>()
}
