#![allow(
    clippy::future_not_send,
    reason = "JavaScript promises run on their owning event loop"
)]

use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    rc::Rc,
    sync::Arc,
    task::{Poll, Waker},
};

use js_sys::{Function, Promise, Uint8Array, futures::future_to_promise};
use sha2::{Digest as _, Sha256};
use stogas_verifier::{
    channel::{ClientRequest, Error, Kind, ResponseDecoder},
    evidence::{Snapshot, VerifiedSession},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::{ResponseCompletion, ResponseReceipt, channel_error};
use crate::{evidence::EvidenceSnapshot, host_cipher::HostCipher};

/// One HTTP exchange. Its verification snapshot outlives any later evidence refresh.
#[wasm_bindgen(js_name = EncryptedRequest)]
pub struct EncryptedRequest {
    prefix: Vec<u8>,
    state: Rc<RequestState>,
    snapshot: Arc<Snapshot>,
    appraisal: Arc<VerifiedSession>,
}

struct RequestIo {
    request: Option<ClientRequest<HostCipher>>,
    decoder: Option<ResponseDecoder<HostCipher>>,
    request_hasher: Option<Sha256>,
    request_finished: bool,
}

// Move the IO out for each operation. No Wasm or RefCell mutable borrow survives
// an await or callback, so free() can cancel an operation while WebCrypto runs.
struct RequestState {
    io: RefCell<Option<RequestIo>>,
    closed: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl RequestState {
    fn close(&self) {
        self.closed.set(true);
        self.io.borrow_mut().take();
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    fn check_open(&self) -> Result<(), JsValue> {
        if self.closed.get() {
            Err(channel_error(&Error::Closed))
        } else {
            Ok(())
        }
    }

    async fn run<T>(&self, future: impl Future<Output = Result<T, Error>>) -> Result<T, JsValue> {
        let mut future = std::pin::pin!(future);
        let result = poll_fn(|cx| {
            if self.closed.get() {
                return Poll::Ready(Err(Error::Closed));
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            future.as_mut().poll(cx)
        })
        .await;
        self.waker.borrow_mut().take();
        self.check_open()?;
        result.map_err(|error| channel_error(&error))
    }
}

// An error, cancellation, or callback exception consumes the request's keys.
struct Operation {
    owner: Rc<RequestState>,
    completed: bool,
}

impl Operation {
    fn begin(owner: &Rc<RequestState>) -> Result<(Self, RequestIo), JsValue> {
        owner.check_open()?;
        let io = owner
            .io
            .borrow_mut()
            .take()
            .ok_or_else(|| channel_error(&Error::Pending))?;
        Ok((
            Self {
                owner: Rc::clone(owner),
                completed: false,
            },
            io,
        ))
    }

    fn commit(mut self, io: RequestIo) -> Result<(), JsValue> {
        self.owner.check_open()?;
        *self.owner.io.borrow_mut() = Some(io);
        self.completed = true;
        Ok(())
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.close();
        }
    }
}

impl Drop for EncryptedRequest {
    fn drop(&mut self) {
        self.state.close();
    }
}

impl EncryptedRequest {
    pub(super) fn new(
        request: ClientRequest<HostCipher>,
        snapshot: Arc<Snapshot>,
        appraisal: Arc<VerifiedSession>,
        receipt: bool,
    ) -> Self {
        Self {
            prefix: request.prefix().to_vec(),
            state: Rc::new(RequestState {
                io: RefCell::new(Some(RequestIo {
                    request: Some(request),
                    decoder: None,
                    request_hasher: receipt.then(Sha256::new),
                    request_finished: false,
                })),
                closed: Cell::new(false),
                waker: RefCell::new(None),
            }),
            snapshot,
            appraisal,
        }
    }
}

#[wasm_bindgen(js_class = EncryptedRequest)]
impl EncryptedRequest {
    /// Guard SSE completion independently of optional receipt verification.
    /// # Errors
    /// Requires the complete request before creating its response guard.
    pub fn response_completion(&self) -> Result<ResponseCompletion, JsValue> {
        self.state.check_open()?;
        let io = self.state.io.borrow();
        if !io.as_ref().is_some_and(|io| io.request_finished) {
            return Err(js_sys::Error::new("request content is incomplete").into());
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
        crate::to_js_value(&verified)
    }

    /// # Errors
    /// Rejects overlapping operations, record ordering/usage errors and writes after decoding.
    pub fn seal(&self, kind: u8, content: Vec<u8>) -> Result<Promise, JsValue> {
        let content = Zeroizing::new(content);
        let (operation, mut io) = Operation::begin(&self.state)?;
        let kind = Kind::try_from(kind).map_err(|error| channel_error(&error))?;
        Ok(future_to_promise(async move {
            let request = io
                .request
                .as_mut()
                .ok_or_else(|| channel_error(&Error::Closed))?;
            let record = operation
                .owner
                .run(request.seal_async(kind, &content))
                .await?;
            if kind == Kind::Data
                && let Some(hasher) = &mut io.request_hasher
            {
                hasher.update(&content);
            }
            if kind == Kind::Finished {
                io.request_finished = true;
            }
            operation.commit(io)?;
            Ok(Uint8Array::from(record.as_slice()).into())
        }))
    }

    /// Own the original boot appraisal beyond transport completion, without retaining keys.
    ///
    /// # Errors
    /// Requires all request content to have been sealed before taking its exact digest.
    pub fn response_receipt(&self) -> Result<ResponseReceipt, JsValue> {
        self.state.check_open()?;
        let io = self.state.io.borrow();
        let io = io
            .as_ref()
            .filter(|io| io.request_finished)
            .ok_or_else(|| js_sys::Error::new("request content is incomplete"))?;
        Ok(ResponseReceipt {
            appraisal: Arc::clone(&self.appraisal),
            request: io
                .request_hasher
                .clone()
                .ok_or_else(|| js_sys::Error::new("receipt was not requested"))?
                .finalize()
                .into(),
            stream: None,
            finished: false,
        })
    }

    /// Emit authenticated records one at a time. The callback receives `(kind, Uint8Array)`.
    /// Other record operations reject while this operation is pending; `free()` cancels it.
    ///
    /// # Errors
    /// Invalid framing/authentication or a throwing callback permanently closes decoding.
    pub fn push(&self, input: Vec<u8>, emit: &Function) -> Result<Promise, JsValue> {
        let (operation, mut io) = Operation::begin(&self.state)?;
        let emit = emit.clone();
        Ok(future_to_promise(async move {
            if let Some(request) = io.request.take() {
                io.decoder = Some(ResponseDecoder::new(request));
            }
            let decoder = io
                .decoder
                .as_mut()
                .ok_or_else(|| channel_error(&Error::Closed))?;
            let mut callback_error = None;
            let result = operation
                .owner
                .run(
                    decoder.push_async(&input, super::elapsed_ms()?, |kind, content| {
                        if operation.owner.closed.get() {
                            return Err(Error::Closed);
                        }
                        emit.call2(
                            &JsValue::UNDEFINED,
                            &JsValue::from(kind as u8),
                            &Uint8Array::from(content),
                        )
                        .map(|_| ())
                        .map_err(|error| {
                            callback_error = Some(error);
                            Error::Closed
                        })
                    }),
                )
                .await;
            if let Some(error) = callback_error {
                return Err(error);
            }
            result?;
            operation.commit(io)?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// # Errors
    /// Rejects missing authenticated completion, a partial final record or prior failure.
    pub fn finish(&self) -> Result<(), JsValue> {
        let (operation, mut io) = Operation::begin(&self.state)?;
        io.request = None;
        io.decoder
            .take()
            .ok_or_else(|| channel_error(&Error::Truncated))?
            .finish()
            .map_err(|error| channel_error(&error))?;
        operation.commit(io)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests;
