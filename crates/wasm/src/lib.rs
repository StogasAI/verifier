//! Browser and Node/Bun adapter. The core remains deterministic and networkless.

#[cfg(target_arch = "wasm32")]
compile_error!(
    "browser release blocked: full WASM-compatible Sigstore and AMD SNP cryptographic backends are required"
);

use stogas_verifier::{Environment, verify_bundle};
use wasm_bindgen::prelude::*;

/// Verify a staging bundle using a caller-captured wall-clock value.
///
/// # Errors
///
/// Returns a JavaScript error when the captured time or bundle is invalid.
#[wasm_bindgen]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_staging_bundle(bundle: &[u8], now_unix_ms: f64) -> Result<JsValue, JsError> {
    if !now_unix_ms.is_finite() || now_unix_ms.fract() != 0.0 {
        return Err(JsError::new("now_unix_ms must be an integer"));
    }
    let output = verify_bundle(
        bundle,
        now_unix_ms as i64,
        &Environment::staging_legacy(),
        None,
    )
    .map_err(|error| JsError::new(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&output).map_err(|error| JsError::new(&error.to_string()))
}
