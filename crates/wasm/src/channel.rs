use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use stogas_verifier::{
    channel::{ClientRequest, ClientSession, Error, Kind, ResponseDecoder, setup::PendingSetup},
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
    pub fn new(environment: &str) -> Result<Self, JsError> {
        let environment = serde_json::from_value(serde_json::json!(environment))
            .map_err(|_| JsError::new("unsupported verification environment"))?;
        Ok(Self {
            core: PendingSetup::new(environment)?,
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
        let request = self.core.request().map_err(|error| channel_error(&error))?;
        Ok(EncryptedRequest {
            prefix: request.prefix().to_vec(),
            request: Some(request),
            decoder: None,
            snapshot: Arc::clone(&self.snapshot),
            appraisal: Arc::clone(&self.appraisal),
            request_hasher: receipt.then(Sha256::new),
            request_finished: false,
        })
    }

    /// Local disposal. The HTTP transport sends an authenticated close request first
    /// when possible; lost close messages are handled by the server's idle expiry.
    pub fn close(&mut self) {
        self.core.close();
    }
}

/// One HTTP exchange. Its verification snapshot outlives any later evidence refresh.
#[wasm_bindgen(js_name = EncryptedRequest)]
pub struct EncryptedRequest {
    prefix: Vec<u8>,
    request: Option<ClientRequest>,
    decoder: Option<ResponseDecoder>,
    snapshot: Arc<Snapshot>,
    appraisal: Arc<VerifiedSession>,
    request_hasher: Option<Sha256>,
    request_finished: bool,
}

#[wasm_bindgen(js_class = EncryptedRequest)]
impl EncryptedRequest {
    /// Guard SSE completion independently of optional receipt verification.
    /// # Errors
    /// Requires the complete request before creating its response guard.
    pub fn response_completion(&self) -> Result<ResponseCompletion, JsError> {
        if !self.request_finished {
            return Err(JsError::new("request content is incomplete"));
        }
        Ok(ResponseCompletion {
            core: Some(stogas_verifier::receipt::StreamCompletion::default()),
        })
    }
    #[wasm_bindgen(getter)]
    pub fn prefix(&self) -> Vec<u8> {
        self.prefix.clone()
    }

    /// Retain this request's original evidence when checking its terminal receipt.
    pub fn evidence(&self) -> EvidenceSnapshot {
        EvidenceSnapshot {
            core: Arc::clone(&self.snapshot),
        }
    }

    /// Verify terminal content under this request's original appraised boot key.
    /// Current catalog changes do not change the request's signing identity.
    ///
    /// # Errors
    /// Rejects malformed receipts, changed content and signatures from another boot.
    pub fn verify_receipt(
        &self,
        receipt: &[u8],
        request_sha256: &[u8],
        response_sha256: &[u8],
    ) -> Result<JsValue, JsError> {
        let request = request_sha256
            .try_into()
            .map_err(|_| JsError::new("request digest must be 32 bytes"))?;
        let response = response_sha256
            .try_into()
            .map_err(|_| JsError::new("response digest must be 32 bytes"))?;
        let verified = stogas_verifier::receipt::verify_metadata(
            receipt,
            self.appraisal.boot(),
            request,
            response,
        )?
        .receipt;
        super::to_js_value(&verified)
    }

    /// # Errors
    /// Rejects record ordering/usage errors and writes after response decoding starts.
    pub fn seal(&mut self, kind: u8, content: &[u8]) -> Result<Vec<u8>, JsValue> {
        let kind = Kind::try_from(kind).map_err(|error| channel_error(&error))?;
        let record = self
            .request
            .as_mut()
            .ok_or_else(|| channel_error(&Error::Closed))?
            .seal(kind, content)
            .map_err(|error| channel_error(&error))?;
        if kind == Kind::Data
            && let Some(hasher) = &mut self.request_hasher
        {
            hasher.update(content);
        }
        if kind == Kind::Finished {
            self.request_finished = true;
        }
        Ok(record)
    }

    /// Own the original boot appraisal beyond transport completion, without retaining keys.
    ///
    /// # Errors
    /// Requires all request content to have been sealed before taking its exact digest.
    pub fn response_receipt(&self) -> Result<ResponseReceipt, JsError> {
        if !self.request_finished {
            return Err(JsError::new("request content is incomplete"));
        }
        Ok(ResponseReceipt {
            appraisal: Arc::clone(&self.appraisal),
            request: self
                .request_hasher
                .clone()
                .ok_or_else(|| JsError::new("receipt was not requested"))?
                .finalize()
                .into(),
            stream: None,
            finished: false,
        })
    }

    /// Emit authenticated records one at a time without retaining a whole HTTP chunk's
    /// plaintext. The callback receives `(kind, Uint8Array)` and must not re-enter this object.
    ///
    /// # Errors
    /// Invalid framing/authentication or a throwing callback permanently closes decoding.
    pub fn push(&mut self, input: &[u8], emit: &js_sys::Function) -> Result<(), JsValue> {
        if let Some(request) = self.request.take() {
            self.decoder = Some(ResponseDecoder::new(request));
        }
        let decoder = self
            .decoder
            .as_mut()
            .ok_or_else(|| channel_error(&Error::Closed))?;
        let mut callback_error = None;
        let result = decoder.push(input, |kind, content| {
            emit.call2(
                &JsValue::UNDEFINED,
                &JsValue::from(kind as u8),
                &js_sys::Uint8Array::from(content),
            )
            .map(|_| ())
            .map_err(|error| {
                callback_error = Some(error);
                Error::Closed
            })
        });
        if let Some(error) = callback_error {
            return Err(error);
        }
        result.map_err(|error| channel_error(&error))
    }

    /// # Errors
    /// Rejects missing authenticated completion, a partial final record or prior failure.
    pub fn finish(&mut self) -> Result<(), JsValue> {
        self.request = None;
        self.decoder
            .take()
            .ok_or_else(|| channel_error(&Error::Truncated))?
            .finish()
            .map_err(|error| channel_error(&error))
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
