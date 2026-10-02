mod request;
pub use request::EncryptedRequest;
use std::sync::Arc;

use stogas_verifier::{
    channel::{ClientSession, Error, ratchet::ChunkSize, setup::PendingSetup},
    evidence::{Snapshot, VerifiedSession},
};
use wasm_bindgen::prelude::*;

use crate::evidence::{EvidenceSnapshot, verification_error};

/// A fresh setup contains no application credentials or content.
#[wasm_bindgen(js_name = EncryptedSetup)]
pub struct EncryptedSetup {
    core: PendingSetup,
}

#[wasm_bindgen(js_class = EncryptedSetup)]
impl EncryptedSetup {
    /// # Errors
    /// Rejects unsupported environments or unavailable secure randomness.
    #[wasm_bindgen(constructor)]
    pub fn new(environment: &str, ratchet_bytes: Option<u16>) -> Result<Self, JsError> {
        let environment = serde_json::from_value(serde_json::json!(environment))
            .map_err(|_| JsError::new("unsupported verification environment"))?;
        Ok(Self {
            core: PendingSetup::with_chunk_size(
                environment,
                ChunkSize::new(ratchet_bytes.unwrap_or(ChunkSize::FULL.get()))?,
            )?,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn hello(&self) -> Vec<u8> {
        self.core.hello().to_vec()
    }

    /// # Errors
    /// No session is returned before the fixed hardware, boot log, approval and
    /// possession checks pass. An evidence miss preserves the pending setup for
    /// one bounded refresh by the asynchronous transport.
    pub fn complete(
        &mut self,
        response: &[u8],
        snapshot: &EvidenceSnapshot,
    ) -> Result<EncryptedSession, JsValue> {
        let (core, appraisal) = self
            .core
            .complete_verified(response, &snapshot.core, crate::wall_clock_ms()?)
            .map_err(|error| match error {
                stogas_verifier::channel::setup::SetupError::Appraisal(error) => {
                    verification_error(&error)
                }
                error => js_sys::Error::new(&error.to_string()).into(),
            })?;
        Ok(EncryptedSession {
            core,
            appraisal: Arc::new(appraisal),
            snapshot: Arc::clone(&snapshot.core),
        })
    }
}

/// Reusable encrypted state. Individual requests own independent directional keys.
#[wasm_bindgen(js_name = EncryptedSession)]
pub struct EncryptedSession {
    core: ClientSession,
    appraisal: Arc<VerifiedSession>,
    snapshot: Arc<Snapshot>,
}

#[wasm_bindgen(js_class = EncryptedSession)]
impl EncryptedSession {
    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.appraisal.boot().hardware().node_id().to_owned()
    }

    #[wasm_bindgen(getter)]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "wasm-bindgen exports cannot be const"
    )]
    pub fn idle_seconds(&self) -> u32 {
        self.core.idle_seconds()
    }

    /// # Errors
    /// Rejects learned revocations, invalid current evidence and exhausted or
    /// closed sessions before application bytes are encrypted or submitted.
    pub fn request(
        &mut self,
        snapshot: &EvidenceSnapshot,
        receipt: bool,
    ) -> Result<EncryptedRequest, JsValue> {
        let now = crate::wall_clock_ms()?;
        if Arc::ptr_eq(&snapshot.core, &self.snapshot) {
            snapshot
                .core
                .check_session(&self.appraisal, now)
                .map_err(|error| verification_error(&error))?;
        } else {
            let appraisal = snapshot
                .core
                .reappraise_session(&self.appraisal, now)
                .map_err(|error| verification_error(&error))?;
            self.appraisal = Arc::new(appraisal);
            self.snapshot = Arc::clone(&snapshot.core);
        }
        self.core
            .expire(elapsed_ms()?)
            .map_err(|error| channel_error(&error))?;
        let request = self
            .core
            .request_with::<crate::host_cipher::HostCipher>()
            .map_err(|error| channel_error(&error))?;
        Ok(EncryptedRequest::new(
            request,
            Arc::clone(&self.snapshot),
            Arc::clone(&self.appraisal),
            receipt,
        ))
    }

    /// Local disposal. The HTTP transport sends an authenticated close request first
    /// when possible; lost close messages are handled by the server's idle expiry.
    pub fn close(&mut self) {
        self.core.close();
    }
}

#[wasm_bindgen(js_name = ResponseCompletion)]
pub struct ResponseCompletion {
    core: Option<stogas_verifier::receipt::StreamCompletion>,
}

#[wasm_bindgen(js_class = ResponseCompletion)]
impl ResponseCompletion {
    /// # Errors
    /// Rejects malformed SSE or use after completion.
    pub fn push_sse(&mut self, bytes: &[u8]) -> Result<JsValue, JsError> {
        let core = self
            .core
            .as_mut()
            .ok_or_else(|| JsError::new("response is closed"))?;
        let output = js_sys::Array::new();
        for chunk in core.push(bytes)? {
            output.push(&js_sys::Uint8Array::from(chunk.as_slice()));
        }
        Ok(output.into())
    }

    /// Call only after the encrypted response's completion and outer EOF are verified.
    /// # Errors
    /// Rejects a truncated stream or duplicate completion.
    pub fn finish_sse(&mut self) -> Result<(), JsError> {
        self.core
            .take()
            .ok_or_else(|| JsError::new("response is closed"))?
            .finish()?;
        Ok(())
    }
}

/// The response metadata verifier owns the request's original boot, not a newer catalog snapshot.
#[wasm_bindgen(js_name = ResponseReceipt)]
pub struct ResponseReceipt {
    appraisal: Arc<VerifiedSession>,
    request: [u8; 32],
    stream: Option<stogas_verifier::receipt::Stream>,
    finished: bool,
}

#[wasm_bindgen(js_class = ResponseReceipt)]
impl ResponseReceipt {
    /// # Errors
    /// Rejects malformed, excessive or misordered streaming metadata.
    pub fn push_sse(&mut self, bytes: &[u8]) -> Result<JsValue, JsError> {
        if self.finished {
            return Err(JsError::new("receipt verifier is closed"));
        }
        let stream = self
            .stream
            .get_or_insert_with(|| stogas_verifier::receipt::Stream::new(self.request));
        match stream.push(bytes) {
            Ok(chunks) => {
                let output = js_sys::Array::new();
                for chunk in chunks {
                    output.push(&js_sys::Uint8Array::from(chunk.as_slice()));
                }
                Ok(output.into())
            }
            Err(error) => {
                self.finished = true;
                self.stream = None;
                Err(JsError::new(&error.to_string()))
            }
        }
    }

    /// Call at authenticated transport EOF; release the terminal delimiter only on success.
    ///
    /// # Errors
    /// Rejects missing receipts, changed content, truncation and invalid signatures.
    pub fn finish_sse(&mut self) -> Result<JsValue, JsError> {
        if self.finished {
            return Err(JsError::new("receipt verifier is closed"));
        }
        self.finished = true;
        let stream = self
            .stream
            .take()
            .ok_or_else(|| JsError::new("empty receipt stream"))?;
        let result = stream.finish(self.appraisal.boot())?;
        super::to_js_value(&result)
    }

    /// # Errors
    /// Rejects malformed responses or receipts not bound to this request and boot.
    pub fn finish_buffered(&mut self, response: &[u8]) -> Result<JsValue, JsError> {
        if self.finished || self.stream.is_some() {
            return Err(JsError::new("receipt verifier is closed"));
        }
        self.finished = true;
        let result = stogas_verifier::receipt::verify_buffered(
            self.appraisal.boot(),
            &self.request,
            response,
        )?;
        super::to_js_value(&result)
    }
}

fn channel_error(error: &Error) -> JsValue {
    let value = js_sys::Error::new(&error.to_string());
    value.set_name("EncryptedChannelError");
    let code = match error {
        Error::Pending => "pending",
        Error::Closed => "closed",
        Error::Limit => "limit",
        Error::Record => "record",
        Error::Authentication => "authentication",
        Error::Truncated => "truncated",
        Error::Crypto => "crypto",
    };
    let _ = js_sys::Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_str(code));
    value.into()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn monotonic_now() -> f64;
}

fn elapsed_ms() -> Result<u64, JsValue> {
    let now = monotonic_now();
    if !(0.0..=9_007_199_254_740_991.0).contains(&now) {
        return Err(js_sys::Error::new("monotonic clock is unavailable").into());
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "finite nonnegative safe integer range checked above"
    )]
    Ok(now as u64)
}
