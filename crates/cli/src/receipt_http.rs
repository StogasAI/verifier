//! Verify optional content receipts while retaining the request's original attestation.
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{Response, header::CONTENT_TYPE},
};
use futures_util::{StreamExt as _, stream};
use std::{collections::VecDeque, sync::Arc};
use stogas_verifier::{evidence::VerifiedSession, receipt};
use tokio::time::{Instant, timeout_at};

const MAX_RESPONSE_BYTES: usize = stogas_verifier::receipt::MAX_BUFFERED_BYTES;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("response deadline expired; execution is unknown")]
    Deadline,
    #[error("response body failed; execution is unknown: {0}")]
    Body(#[from] axum::Error),
    #[error("content receipt verification failed; inference was not retried: {0}")]
    Receipt(#[from] receipt::Error),
}

/// This function has no request sender. Evidence refresh cannot replay inference.
pub(crate) async fn verify(
    response: Response<Body>,
    peer: Arc<VerifiedSession>,
    request: [u8; 32],
    deadline: Instant,
) -> Result<Response<Body>, Error> {
    if !response.status().is_success() {
        return Ok(response);
    }
    let streaming = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    let (parts, body) = response.into_parts();
    if !streaming {
        let bytes = timeout_at(deadline, to_bytes(body, MAX_RESPONSE_BYTES))
            .await
            .map_err(|_| Error::Deadline)??;
        receipt::verify_buffered(peer.boot(), &request, &bytes)?;
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    let state = StreamState {
        source: body.into_data_stream(),
        receipt: Some(receipt::Stream::new(request)),
        pending: VecDeque::new(),
        peer,
        deadline,
    };
    Ok(Response::from_parts(
        parts,
        Body::from_stream(stream::unfold(Some(state), |state| async move {
            let mut state = state?;
            match state.next().await {
                Ok(Some(bytes)) => Some((Ok::<_, Error>(bytes), Some(state))),
                Ok(None) => None,
                Err(error) => Some((Err(error), None)),
            }
        })),
    ))
}

struct StreamState {
    source: axum::body::BodyDataStream,
    receipt: Option<receipt::Stream>,
    pending: VecDeque<Bytes>,
    peer: Arc<VerifiedSession>,
    deadline: Instant,
}
impl StreamState {
    async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(Error::Deadline);
            }
            if let Some(bytes) = self.pending.pop_front() {
                return Ok(Some(bytes));
            }
            let Some(receipt) = &mut self.receipt else {
                return Ok(None);
            };
            if let Some(bytes) = timeout_at(self.deadline, self.source.next())
                .await
                .map_err(|_| Error::Deadline)?
            {
                self.pending
                    .extend(receipt.push(&bytes?)?.into_iter().map(Bytes::from));
            } else {
                self.receipt
                    .take()
                    .ok_or(receipt::Error::Invalid)?
                    .finish(self.peer.boot())?;
                // The final SSE event becomes visible only after authenticated EOF.
                return Ok(Some(Bytes::from_static(b"\n\n")));
            }
        }
    }
}

#[cfg(all(test, feature = "staging"))]
mod tests;
