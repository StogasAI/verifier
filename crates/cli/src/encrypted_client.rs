//! Reusable native E2EE sessions. HTTP sockets carry ciphertext and need no affinity.
use crate::{
    encrypted_http, encrypted_setup,
    evidence_client::{self, EvidenceClient, wall_clock_ms},
    native_http::{self, Channel, RequestContext},
    receipt_http,
};
use axum::{
    body::{Body, BodyDataStream, Bytes},
    http::{Request, Response},
};
use futures_util::{StreamExt as _, stream};
use sha2::{Digest as _, Sha256};
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};
use stogas_verifier::{
    approvals::Environment,
    channel::{self, ClientRequest, ClientSession},
};
use tokio::{
    sync::Notify,
    time::{Instant, timeout_at},
};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encrypted transport is closed; request was not sent")]
    Closed,
    #[error("encrypted session state is unavailable; request was not sent")]
    State,
    #[error("encrypted session capacity or setup deadline expired; request was not sent")]
    Deadline,
    #[error("encrypted transport close deadline expired")]
    CloseDeadline,
    #[error("Stogas-Metadata must be v1; request was not sent")]
    Metadata,
    #[error(transparent)]
    Setup(#[from] encrypted_setup::Error),
    #[error(transparent)]
    Evidence(#[from] evidence_client::Error),
    #[error(transparent)]
    Appraisal(#[from] native_http::Error),
    #[error(transparent)]
    Record(#[from] channel::Error),
    #[error(transparent)]
    Http(#[from] encrypted_http::Error),
    #[error(transparent)]
    Receipt(#[from] receipt_http::Error),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Evidence(error) => error.code(),
            Self::Appraisal(error) => error.code(),
            Self::Setup(error) => error.code(),
            Self::Closed => "closed",
            Self::Deadline => "setup_deadline",
            Self::Metadata
            | Self::Http(encrypted_http::Error::Request | encrypted_http::Error::NotSentDeadline) => {
                "invalid_request"
            }
            Self::Receipt(_) => "receipt_failed",
            Self::Record(_) | Self::State => "verification_unavailable",
            Self::CloseDeadline | Self::Http(_) => "transport_failed",
        }
    }
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}
struct Inner {
    evidence: Arc<EvidenceClient>,
    http: reqwest::Client,
    endpoint: Url,
    environment: Environment,
    maximum: NonZeroUsize,
    state: Mutex<State>,
    changed: Arc<Notify>,
    closing: Notify,
    shutdown: tokio::sync::Mutex<()>,
}
struct State {
    owners: Vec<Arc<Owner>>,
    opening: bool,
    closed: bool,
}
struct Owner {
    channel: Channel,
    node_id: String,
    state: Mutex<SessionState>,
    changed: Arc<Notify>,
    force_close: Notify,
}
struct SessionState {
    core: ClientSession,
    active: usize,
    idle_since: Instant,
    retired: bool,
    forced: bool,
}
struct Lease {
    owner: Arc<Owner>,
}
enum Selection {
    Ready(Box<(Lease, ClientRequest)>),
    Opening(Opening),
    Wait,
}

struct Opening {
    inner: Arc<Inner>,
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .opening = false;
        self.inner.changed.notify_waiters();
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active -= 1;
        if state.active == 0 {
            state.idle_since = Instant::now();
        }
        drop(state);
        self.owner.changed.notify_waiters();
    }
}
impl Owner {
    fn new(connection: encrypted_setup::Connection, changed: Arc<Notify>) -> Self {
        Self {
            node_id: connection.appraisal.boot().hardware().node_id().to_owned(),
            channel: Channel::new(connection.snapshot, connection.appraisal),
            state: Mutex::new(SessionState {
                core: connection.session,
                active: 0,
                idle_since: Instant::now(),
                retired: false,
                forced: false,
            }),
            changed,
            force_close: Notify::new(),
        }
    }
    fn retire(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retired = true;
        state.core.close();
        drop(state);
        self.changed.notify_waiters();
    }
    fn force(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retired = true;
        state.forced = true;
        state.core.close();
        drop(state);
        self.force_close.notify_waiters();
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        for owner in &self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owners
        {
            owner.force();
        }
    }
}

impl Client {
    /// Open the first session on demand and grow only when its pending-start window is full.
    /// The fixed evidence client supplies the credential-free outer HTTP configuration.
    pub fn new(
        evidence: Arc<EvidenceClient>,
        endpoint: Url,
        environment: Environment,
        maximum: NonZeroUsize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                http: evidence.carriage(),
                evidence,
                endpoint,
                environment,
                maximum,
                state: Mutex::new(State {
                    owners: Vec::new(),
                    opening: false,
                    closed: false,
                }),
                changed: Arc::new(Notify::new()),
                closing: Notify::new(),
                shutdown: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Send exactly once. The returned body owns request admission and its original evidence.
    ///
    /// # Errors
    /// Setup/appraisal failures occur before submission. HTTP/receipt failures never retry inference.
    pub async fn send(
        &self,
        request: Request<Bytes>,
        deadline: Instant,
    ) -> Result<Response<Body>, Error> {
        let mut metadata = request.headers().get_all("stogas-metadata").iter();
        let requested = match (metadata.next(), metadata.next()) {
            (None, None) => false,
            (Some(value), None) if value == "v1" => true,
            _ => return Err(Error::Metadata),
        };
        let digest: Option<[u8; 32]> = requested.then(|| Sha256::digest(request.body()).into());
        let (lease, exchange, context) = self.acquire(deadline).await?;
        let response = encrypted_http::send(
            &self.inner.http,
            self.inner.endpoint.clone(),
            &lease.owner.node_id,
            exchange,
            request,
            deadline,
            Some(Arc::clone(&lease.owner.changed)),
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                lease.owner.retire();
                return Err(error.into());
            }
        };
        let mut response = response;
        response.extensions_mut().insert(Arc::clone(&context));
        let (parts, body) = response.into_parts();
        let state = OwnedResponse {
            source: body.into_data_stream(),
            lease,
            _context: Arc::clone(&context),
        };
        let response = Response::from_parts(
            parts,
            Body::from_stream(stream::unfold(Some(state), |state| async {
                let mut state = state?;
                match state.next().await {
                    Ok(Some(bytes)) => Some((Ok::<_, std::io::Error>(bytes), Some(state))),
                    Ok(None) => None,
                    Err(error) => Some((Err(error), None)),
                }
            })),
        );
        match digest {
            Some(digest) => {
                Ok(
                    receipt_http::verify(response, Arc::clone(&context.session), digest, deadline)
                        .await?,
                )
            }
            None => Ok(response),
        }
    }

    async fn acquire(
        &self,
        deadline: Instant,
    ) -> Result<(Lease, ClientRequest, Arc<RequestContext>), Error> {
        let setup_deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        timeout_at(setup_deadline, async {
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let closing = self.inner.closing.notified();
                tokio::pin!(closing);
                closing.as_mut().enable();
                match self.select()? {
                    Selection::Ready(selected) => {
                        let (lease, exchange) = *selected;
                        let context = lease.owner.channel.prepare(&self.inner.evidence, setup_deadline, wall_clock_ms).await;
                        let context = match context {
                            Ok(context) => context,
                            Err(error) => { lease.owner.retire(); return Err(error.into()); }
                        };
                        if self.inner.state.lock().map_err(|_| Error::State)?.closed { return Err(Error::Closed); }
                        return Ok((lease, exchange, context));
                    }
                    Selection::Opening(_opening) => {
                        let connection = tokio::select! {
                            biased;
                            () = &mut closing => return Err(Error::Closed),
                            result = encrypted_setup::connect(&self.inner.evidence, &self.inner.http, self.inner.endpoint.clone(), self.inner.environment, setup_deadline) => result?,
                        };
                        let owner = Arc::new(Owner::new(connection, Arc::clone(&self.inner.changed)));
                        let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
                        if state.closed { return Err(Error::Closed); }
                        state.owners.push(owner);
                    }
                    Selection::Wait => changed.await,
                }
            }
        }).await.map_err(|_| Error::Deadline)?
    }

    fn select(&self) -> Result<Selection, Error> {
        let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
        if state.closed {
            return Err(Error::Closed);
        }
        state.owners.retain(|owner| {
            let mut session = owner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if session.active == 0
                && session.idle_since.elapsed()
                    >= Duration::from_secs(u64::from(session.core.idle_seconds()))
            {
                session.retired = true;
            }
            !(session.retired && session.active == 0)
        });
        state.owners.sort_by_key(|owner| {
            owner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active
        });
        for owner in &state.owners {
            let mut session = owner.state.lock().map_err(|_| Error::State)?;
            if session.retired {
                continue;
            }
            match session.core.request() {
                Ok(request) => {
                    session.active += 1;
                    return Ok(Selection::Ready(Box::new((
                        Lease {
                            owner: Arc::clone(owner),
                        },
                        request,
                    ))));
                }
                Err(channel::Error::Pending) => {}
                Err(channel::Error::Limit | channel::Error::Closed) => session.retired = true,
                Err(error) => return Err(error.into()),
            }
        }
        let serving = state
            .owners
            .iter()
            .filter(|owner| {
                !owner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retired
            })
            .count();
        let opening = if !state.opening
            && serving < self.inner.maximum.get()
            && state.owners.len() <= self.inner.maximum.get()
        {
            state.opening = true;
            drop(state);
            Selection::Opening(Opening {
                inner: Arc::clone(&self.inner),
            })
        } else {
            Selection::Wait
        };
        Ok(opening)
    }

    /// Stop new work, finish active responses, then send one authenticated close per session.
    ///
    /// # Errors
    /// A close deadline forces local cleanup. Unreachable servers recover through idle expiry.
    pub async fn close(&self, deadline: Instant) -> Result<(), Error> {
        let _shutdown = timeout_at(deadline, self.inner.shutdown.lock())
            .await
            .map_err(|_| Error::CloseDeadline)?;
        {
            let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
            state.closed = true;
        }
        self.inner.closing.notify_waiters();
        self.inner.changed.notify_waiters();
        let result = timeout_at(deadline, async {
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let idle = {
                    let state = self.inner.state.lock().map_err(|_| Error::State)?;
                    !state.opening
                        && state.owners.iter().all(|owner| {
                            owner.state.lock().is_ok_and(|session| session.active == 0)
                        })
                };
                if idle {
                    break;
                }
                changed.await;
            }
            let owners =
                std::mem::take(&mut self.inner.state.lock().map_err(|_| Error::State)?.owners);
            let operations = owners.into_iter().map(|owner| async move {
                let request = {
                    let mut session = owner.state.lock().map_err(|_| Error::State)?;
                    let request = session.core.request();
                    session.core.close();
                    request
                };
                if let Ok(exchange) = request {
                    let request = Request::delete("/v1/session")
                        .body(Bytes::new())
                        .map_err(|_| Error::State)?;
                    let response = encrypted_http::send(
                        &self.inner.http,
                        self.inner.endpoint.clone(),
                        &owner.node_id,
                        exchange,
                        request,
                        deadline,
                        None,
                    )
                    .await?;
                    axum::body::to_bytes(response.into_body(), 0)
                        .await
                        .map_err(|_| Error::State)?;
                }
                Ok::<_, Error>(())
            });
            for result in futures_util::future::join_all(operations).await {
                result?;
            }
            Ok(())
        })
        .await;
        if let Ok(result) = result {
            result
        } else {
            let state = self.inner.state.lock().map_err(|_| Error::State)?;
            for owner in &state.owners {
                owner.force();
            }
            drop(state);
            Err(Error::CloseDeadline)
        }
    }
}

struct OwnedResponse {
    source: BodyDataStream,
    lease: Lease,
    _context: Arc<RequestContext>,
}
impl OwnedResponse {
    async fn next(&mut self) -> Result<Option<Bytes>, std::io::Error> {
        let closing = self.lease.owner.force_close.notified();
        tokio::pin!(closing);
        closing.as_mut().enable();
        if self
            .lease
            .owner
            .state
            .lock()
            .map_or(true, |state| state.forced)
        {
            return Err(std::io::Error::other("encrypted transport closed"));
        }
        let next = tokio::select! {
            biased;
            () = &mut closing => return Err(std::io::Error::other("encrypted transport closed")),
            next = self.source.next() => next,
        };
        match next {
            Some(Ok(bytes)) => Ok(Some(bytes)),
            None => Ok(None),
            Some(Err(error)) => {
                self.lease.owner.retire();
                Err(std::io::Error::other(error))
            }
        }
    }
}

#[cfg(all(test, feature = "staging"))]
mod tests;
