//! Reusable native HTTP/2 over fresh attested TLS. Evidence changes reappraise live channels;
//! they do not re-execute requests or discard evidence already owned by a response.
use crate::{
    evidence_client::{self, EvidenceClient, wall_clock_ms},
    http2_pool::{self, Pool},
    native_tls, receipt_http,
};
use axum::{
    body::Body,
    http::{Request, Response},
};
use hyper::body::Bytes;
use rustls::pki_types::ServerName;
use sha2::{Digest as _, Sha256};
use std::{future::Future, sync::Arc};
use stogas_verifier::evidence::{Snapshot, VerifiedSession};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    time::{Instant, timeout_at},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pool(#[from] http2_pool::Error),
    #[error(transparent)]
    Evidence(#[from] evidence_client::Error),
    #[error("session evidence recovery failed: {acquisition}; original failure: {verification}")]
    Recovery {
        verification: stogas_verifier::evidence::Error,
        acquisition: evidence_client::Error,
    },
    #[error("request size accounting overflow")]
    Size,
    #[error("Stogas-Metadata must be v1")]
    Metadata,
    #[error(transparent)]
    Receipt(#[from] receipt_http::Error),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Evidence(error) => error.code(),
            Self::Recovery { verification, .. } => verification.code(),
            Self::Pool(http2_pool::Error::Connect(error)) => error
                .downcast_ref::<native_tls::Error>()
                .map_or("connection_failed", native_tls::Error::code),
            Self::Pool(http2_pool::Error::Deadline) => "setup_deadline",
            Self::Pool(http2_pool::Error::Capacity) => "client_capacity",
            Self::Pool(http2_pool::Error::Closed) => "closed",
            Self::Pool(_) => "transport_failed",
            Self::Receipt(_) => "receipt_failed",
            Self::Size | Self::Metadata => "invalid_request",
        }
    }
}

/// Immutable per-request appraisal, also retained by the response body after headers are dropped.
pub struct RequestContext {
    pub snapshot: Arc<Snapshot>,
    pub session: Arc<VerifiedSession>,
}
pub(crate) struct Channel {
    current: Mutex<Arc<RequestContext>>,
}

/// A fixed dialer/server identity, one evidence authority and one shared pool across clones.
#[derive(Clone)]
pub struct Client {
    evidence: Arc<EvidenceClient>,
    pool: Pool<Channel>,
}
impl Client {
    /// Authentication always completes before any HTTP bytes. A dialer opens only a byte stream.
    pub fn new<T, F, Fut>(
        evidence: Arc<EvidenceClient>,
        dial: F,
        server_name: ServerName<'static>,
        limits: http2_pool::Limits,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<T>> + Send + 'static,
    {
        let dial = Arc::new(dial);
        let authority = Arc::clone(&evidence);
        let pool = Pool::new(limits, move |deadline| {
            let evidence = Arc::clone(&authority);
            let dial = Arc::clone(&dial);
            let server_name = server_name.clone();
            async move {
                let connection = native_tls::connect_with_evidence(
                    &evidence,
                    move || dial(),
                    server_name,
                    deadline,
                )
                .await
                .map_err(|error| http2_pool::Error::Connect(Box::new(error)))?;
                if connection.stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(http2_pool::Error::Connect(Box::new(
                        native_tls::Error::Profile,
                    )));
                }
                Ok((
                    connection.stream,
                    Channel::new(connection.snapshot, connection.session),
                ))
            }
        });
        Self { evidence, pool }
    }

    /// Submit once after checking the current appraisal. The response extensions contain
    /// `Arc<RequestContext>`. Requested receipts use that original context and the same deadline;
    /// the consumer owns body deadlines when no receipt is requested.
    ///
    /// # Errors
    /// Pool/verification errors before submission release no application bytes. A transport error
    /// or response-header timeout after dispatch may leave execution unknown; no replay is attempted.
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
        let retained = request.headers().iter().try_fold(
            request
                .body()
                .len()
                .checked_add(request.uri().to_string().len())
                .ok_or(Error::Size)?,
            |size, (name, value)| {
                size.checked_add(name.as_str().len())
                    .and_then(|size| size.checked_add(value.len()))
                    .ok_or(Error::Size)
            },
        )?;
        let mut permit = self.pool.acquire(retained, deadline).await?;
        let context = permit
            .metadata
            .prepare(&self.evidence, deadline, wall_clock_ms)
            .await?;
        permit.retain_context(Arc::clone(&context));
        let mut response = permit.send(request, deadline).await?;
        response.extensions_mut().remove::<Arc<Channel>>();
        response.extensions_mut().insert(Arc::clone(&context));
        let response = response.map(Body::new);
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

    /// Stop new work and finish owned responses before the deadline.
    ///
    /// # Errors
    /// Returns an error if forced closure was needed or pool state is unavailable.
    pub async fn close(&self, deadline: Instant) -> Result<(), Error> {
        self.pool.close(deadline).await.map_err(Error::from)
    }
}
impl Channel {
    pub(crate) fn new(snapshot: Arc<Snapshot>, session: Arc<VerifiedSession>) -> Self {
        Self {
            current: Mutex::new(Arc::new(RequestContext { snapshot, session })),
        }
    }

    pub(crate) async fn prepare(
        &self,
        evidence: &EvidenceClient,
        deadline: Instant,
        now: impl Fn() -> Result<i64, evidence_client::Error> + Copy + Send + Sync + 'static,
    ) -> Result<Arc<RequestContext>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Evidence(evidence_client::Error::Deadline));
        }
        timeout_at(deadline, async {
            let mut retained = self.current.lock().await;
            let latest = evidence.current()?.ok_or(evidence_client::Error::State)?;
            if Arc::ptr_eq(&latest, &retained.snapshot)
                && latest.check_session(&retained.session, now()?).is_ok()
            {
                return Ok(Arc::clone(&retained));
            }
            let appraised = evidence
                .reappraise_session(
                    Arc::clone(&latest),
                    Arc::clone(&retained.session),
                    deadline,
                    now()?,
                )
                .await;
            let (snapshot, session) = match appraised {
                Ok(session) => (latest, session),
                Err(evidence_client::Error::Verification(verification)) => {
                    let session = Arc::clone(&retained.session);
                    let snapshot = evidence
                        .recover(deadline, move |snapshot| {
                            let time = now().map_err(|_| {
                                stogas_verifier::evidence::Error::Invalid("local time".into())
                            })?;
                            snapshot.reappraise_session(&session, time).map(|_| ())
                        })
                        .await
                        .map_err(|acquisition| Error::Recovery {
                            verification,
                            acquisition,
                        })?;
                    let session = evidence
                        .reappraise_session(
                            Arc::clone(&snapshot),
                            Arc::clone(&retained.session),
                            deadline,
                            now()?,
                        )
                        .await?;
                    (snapshot, session)
                }
                Err(error) => return Err(error.into()),
            };
            let context = Arc::new(RequestContext { snapshot, session });
            context
                .snapshot
                .check_session(&context.session, now()?)
                .map_err(evidence_client::Error::from)?;
            *retained = Arc::clone(&context);
            drop(retained);
            Ok(context)
        })
        .await
        .map_err(|_| Error::Evidence(evidence_client::Error::Deadline))?
    }
}
