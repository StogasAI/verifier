//! HTTP carriage for an already verified binary session. No inference is retried.
use crate::encrypted_setup::CONTENT_TYPE;
use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, header},
};
use futures_util::stream;
use reqwest::Client;
use serde_json::{Map, Value, json};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use stogas_verifier::channel::{
    self, ClientRequest, Kind, MAX_RECORD_BYTES, MAX_RECORD_PLAINTEXT, ResponseDecoder,
};
use tokio::{
    sync::Notify,
    time::{Instant, timeout_at},
};
use url::Url;

const MAX_METADATA_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid encrypted request metadata; request was not sent")]
    Request,
    #[error("encrypted request deadline expired; request was not sent")]
    NotSentDeadline,
    #[error("encrypted response deadline expired; execution is unknown")]
    Deadline,
    #[error("encrypted HTTP failed; execution is unknown: {0}")]
    Http(#[from] reqwest::Error),
    #[error("origin did not return an encrypted response; execution is unknown")]
    Response,
    #[error("invalid encrypted response metadata; execution is unknown")]
    Metadata,
    #[error("encrypted record failed; execution is unknown: {0}")]
    Record(#[from] channel::Error),
    #[error("encrypted SSE completion failed; delivery is incomplete: {0}")]
    Completion(#[from] stogas_verifier::receipt::Error),
}

/// Encrypt metadata before creating the outer request. The caller must supply a
/// configured HTTP client with redirects disabled and no application credentials.
///
/// # Errors
/// Invalid input fails before submission. Once HTTP begins, errors are execution-unknown;
/// even an outer 503 is not proof that an earlier arrival never ran.
pub async fn send(
    http: &Client,
    endpoint: Url,
    node_id: &str,
    exchange: ClientRequest,
    request: Request<Bytes>,
    deadline: Instant,
    acknowledged: Option<Arc<Notify>>,
) -> Result<Response<Body>, Error> {
    let metadata = request_metadata(&request)?;
    let node_id = HeaderValue::from_str(node_id).map_err(|_| Error::Request)?;
    if Instant::now() >= deadline {
        return Err(Error::NotSentDeadline);
    }
    let (mut encoder, decoder) = exchange.split();
    let prefix = Bytes::copy_from_slice(&encoder.prefix());
    let metadata = Bytes::from(
        encoder
            .seal(Kind::Metadata, &metadata)
            .map_err(|_| Error::Request)?,
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let upload = Upload {
        encoder,
        body: request.into_body(),
        initial: VecDeque::from([prefix, metadata]),
        finished: false,
        cancelled: Arc::clone(&cancelled),
        deadline,
    };
    let guard = CancelUpload(cancelled);
    let body = reqwest::Body::wrap_stream(stream::unfold(Some(upload), |state| async {
        let mut state = state?;
        match state.next() {
            Ok(Some(bytes)) => Some((Ok(bytes), Some(state))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    }));
    let response = timeout_at(
        deadline,
        http.post(endpoint)
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header(header::ACCEPT, CONTENT_TYPE)
            .header("stogas-node-id", node_id)
            .body(body)
            .send(),
    )
    .await
    .map_err(|_| Error::Deadline)??;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(CONTENT_TYPE)
        || response
            .content_length()
            .is_some_and(|length| length > channel::MAX_RESPONSE_WIRE_BYTES)
    {
        return Err(Error::Response);
    }
    let mut state = Incoming {
        source: response,
        decoder: Some(decoder),
        input: Bytes::new(),
        pending: VecDeque::new(),
        metadata: None,
        completion: None,
        body_allowed: false,
        deadline,
        _upload: guard,
        acknowledged,
    };
    while state.metadata.is_none() && state.decoder.is_some() {
        state.advance().await?;
    }
    let (status, headers) = state.metadata.take().ok_or(Error::Metadata)?;
    let body = if state.body_allowed {
        Body::from_stream(stream::unfold(Some(state), |state| async {
            let mut state = state?;
            match state.next().await {
                Ok(Some(bytes)) => Some((Ok::<_, Error>(bytes), Some(state))),
                Ok(None) => None,
                Err(error) => Some((Err(error), None)),
            }
        }))
    } else {
        // Even a 204 must authenticate completion and reject any body or trailing bytes.
        while state.decoder.is_some() {
            state.advance().await?;
        }
        Body::empty()
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn request_metadata(request: &Request<Bytes>) -> Result<Vec<u8>, Error> {
    let path = request.uri().path();
    if request.uri().query().is_some()
        || request.body().len() > MAX_REQUEST_BYTES
        || !((request.method() == "POST"
            && matches!(path, "/v1/chat/completions" | "/v1/responses"))
            || (request.method() == "DELETE" && path == "/v1/session" && request.body().is_empty()))
    {
        return Err(Error::Request);
    }
    let mut headers = Map::new();
    for (name, value) in request.headers() {
        if name == header::CONTENT_LENGTH {
            continue;
        }
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "expect"
                | "stogas-node-id"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
        ) || headers.contains_key(name.as_str())
        {
            return Err(Error::Request);
        }
        headers.insert(
            name.as_str().to_owned(),
            Value::String(value.to_str().map_err(|_| Error::Request)?.to_owned()),
        );
    }
    let bytes = serde_json::to_vec(
        &json!({"method":request.method().as_str(),"path":path,"headers":headers}),
    )
    .map_err(|_| Error::Request)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::Request);
    }
    Ok(bytes)
}

struct Upload {
    encoder: channel::RequestEncoder,
    body: Bytes,
    initial: VecDeque<Bytes>,
    finished: bool,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl Upload {
    fn next(&mut self) -> Result<Option<Bytes>, Error> {
        if self.cancelled.load(Ordering::Acquire) {
            return Ok(None);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        if let Some(bytes) = self.initial.pop_front() {
            return Ok(Some(bytes));
        }
        if !self.body.is_empty() {
            let bytes = self
                .body
                .split_to(self.body.len().min(MAX_RECORD_PLAINTEXT));
            return Ok(Some(Bytes::from(self.encoder.seal(Kind::Data, &bytes)?)));
        }
        if self.finished {
            return Ok(None);
        }
        self.finished = true;
        Ok(Some(Bytes::from(self.encoder.seal(Kind::Finished, &[])?)))
    }
}
struct CancelUpload(Arc<AtomicBool>);
impl Drop for CancelUpload {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Incoming {
    source: reqwest::Response,
    decoder: Option<ResponseDecoder>,
    input: Bytes,
    pending: VecDeque<Bytes>,
    metadata: Option<(StatusCode, HeaderMap)>,
    completion: Option<stogas_verifier::receipt::StreamCompletion>,
    body_allowed: bool,
    deadline: Instant,
    _upload: CancelUpload,
    acknowledged: Option<Arc<Notify>>,
}
impl Incoming {
    async fn advance(&mut self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        if self.input.is_empty() {
            if let Some(bytes) = timeout_at(self.deadline, self.source.chunk())
                .await
                .map_err(|_| Error::Deadline)??
            {
                self.input = bytes;
            } else {
                self.decoder
                    .take()
                    .ok_or(Error::Metadata)?
                    .finish()
                    .map_err(Error::from)?;
                if let Some(completion) = self.completion.take() {
                    completion.finish()?;
                    self.pending.push_back(Bytes::from_static(b"\n\n"));
                }
                return Ok(());
            }
        }
        let bytes = self.input.split_to(self.input.len().min(MAX_RECORD_BYTES));
        let mut metadata_error = false;
        self.decoder
            .as_mut()
            .ok_or(Error::Metadata)?
            .push(&bytes, |kind, bytes| {
                if let Some(acknowledged) = self.acknowledged.take() {
                    acknowledged.notify_waiters();
                }
                match kind {
                    Kind::Metadata => {
                        if let Ok((status, headers)) = response_metadata(bytes) {
                            self.body_allowed = !matches!(status.as_u16(), 204 | 205 | 304);
                            if headers
                                .get(header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .is_some_and(|v| {
                                    v.split(';').next().is_some_and(|v| {
                                        v.trim().eq_ignore_ascii_case("text/event-stream")
                                    })
                                })
                            {
                                self.completion =
                                    Some(stogas_verifier::receipt::StreamCompletion::default());
                            }
                            self.metadata = Some((status, headers));
                        } else {
                            metadata_error = true;
                            return Err(channel::Error::Record);
                        }
                    }
                    Kind::Data if !self.body_allowed => return Err(channel::Error::Record),
                    Kind::Data => {
                        if let Some(completion) = &mut self.completion {
                            self.pending.extend(
                                completion
                                    .push(bytes)
                                    .map_err(|_| channel::Error::Record)?
                                    .into_iter()
                                    .map(Bytes::from),
                            );
                        } else {
                            self.pending.push_back(Bytes::copy_from_slice(bytes));
                        }
                    }
                    Kind::Finished | Kind::Keepalive => {}
                }
                Ok(())
            })
            .map_err(|error| {
                if metadata_error {
                    Error::Metadata
                } else {
                    Error::Record(error)
                }
            })
    }
    async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(Error::Deadline);
            }
            if let Some(bytes) = self.pending.pop_front() {
                return Ok(Some(bytes));
            }
            if self.decoder.is_none() {
                return Ok(None);
            }
            self.advance().await?;
        }
    }
}

fn response_metadata(bytes: &[u8]) -> Result<(StatusCode, HeaderMap), Error> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::Metadata);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Metadata)?;
    let object = value.as_object().ok_or(Error::Metadata)?;
    if object.len() != 2 {
        return Err(Error::Metadata);
    }
    let status = object
        .get("status")
        .and_then(Value::as_u64)
        .filter(|v| (200..=599).contains(v))
        .ok_or(Error::Metadata)?;
    let status = StatusCode::from_u16(u16::try_from(status).map_err(|_| Error::Metadata)?)
        .map_err(|_| Error::Metadata)?;
    let values = object
        .get("headers")
        .and_then(Value::as_object)
        .ok_or(Error::Metadata)?;
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::try_from(name).map_err(|_| Error::Metadata)?;
        if !matches!(
            name.as_str(),
            "content-type" | "cache-control" | "retry-after"
        ) || headers.contains_key(&name)
        {
            return Err(Error::Metadata);
        }
        let value = HeaderValue::from_str(value.as_str().ok_or(Error::Metadata)?)
            .map_err(|_| Error::Metadata)?;
        headers.insert(name, value);
    }
    Ok((status, headers))
}

#[cfg(test)]
pub(crate) mod tests;
