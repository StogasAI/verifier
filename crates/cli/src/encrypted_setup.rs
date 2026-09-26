//! Fresh encrypted setup over HTTP, independent of application request formats.
use crate::evidence_client::{self, EvidenceClient, wall_clock_ms};
use reqwest::{Client, StatusCode, header};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use stogas_verifier::{
    approvals::Environment,
    channel::{
        ClientSession,
        setup::{MAX_SERVER_SETUP_BYTES, PendingSetup, SetupError},
    },
    evidence::{self, Snapshot, VerifiedSession},
};
use tokio::time::{Instant, timeout_at};
use url::Url;

pub const CONTENT_TYPE: &str = "application/vnd.stogas.session";
const SETUP_BUDGET: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encrypted setup deadline expired")]
    Deadline,
    #[error("encrypted setup HTTP failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("origin did not return a bounded encrypted setup")]
    Response,
    #[error("encrypted setup state is unavailable")]
    State,
    #[error(transparent)]
    Setup(#[from] SetupError),
    #[error(transparent)]
    Evidence(#[from] evidence_client::Error),
    #[error(
        "encrypted setup evidence recovery failed: {acquisition}; original failure: {verification}"
    )]
    Recovery {
        verification: evidence::Error,
        acquisition: evidence_client::Error,
    },
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Deadline => "setup_deadline",
            Self::Evidence(error) => error.code(),
            Self::Setup(SetupError::Appraisal(error))
            | Self::Recovery {
                verification: error,
                ..
            } => error.code(),
            Self::Setup(_) => "invalid_attestation",
            Self::Response | Self::Http(_) => "setup_delivery_failed",
            Self::State => "verification_unavailable",
        }
    }
}

/// No application credentials have been sent. A session becomes available only
/// after hardware appraisal, boot inclusion, transcript binding and possession checks.
pub struct Connection {
    pub session: ClientSession,
    pub snapshot: Arc<Snapshot>,
    pub appraisal: Arc<VerifiedSession>,
}

/// Establish one session and resolve unfamiliar evidence without repeating setup.
/// The caller supplies HTTP carriage; the fixed verifier owns every trust decision.
///
/// # Errors
/// Every failure occurs before application submission. The original deadline
/// bounds evidence acquisition, HTTP, queueing and cryptographic verification.
pub async fn connect(
    evidence: &EvidenceClient,
    http: &Client,
    endpoint: Url,
    environment: Environment,
    deadline: Instant,
) -> Result<Connection, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    let deadline = deadline.min(Instant::now() + SETUP_BUDGET);
    timeout_at(
        deadline,
        connect_inner(evidence, http, endpoint, environment, deadline),
    )
    .await
    .map_err(|_| Error::Deadline)?
}

async fn connect_inner(
    evidence: &EvidenceClient,
    http: &Client,
    endpoint: Url,
    environment: Environment,
    deadline: Instant,
) -> Result<Connection, Error> {
    let snapshot = match evidence.current()? {
        Some(current) => current,
        None => evidence.recover(deadline, |_| Ok(())).await?,
    };
    let pending = evidence
        .compute(deadline, move || PendingSetup::new(environment))
        .await??;
    let mut response = http
        .post(endpoint)
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .header(header::ACCEPT, CONTENT_TYPE)
        .body(pending.hello().to_vec())
        .send()
        .await?;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(CONTENT_TYPE)
        || response
            .content_length()
            .is_some_and(|length| length > MAX_SERVER_SETUP_BYTES as u64)
    {
        return Err(Error::Response);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_SERVER_SETUP_BYTES.saturating_sub(bytes.len()) {
            return Err(Error::Response);
        }
        bytes.extend_from_slice(&chunk);
    }
    let attempt = Arc::new(Attempt {
        pending: Mutex::new(pending),
        bytes,
    });
    match complete(evidence, Arc::clone(&attempt), snapshot, deadline).await {
        Err(Error::Setup(SetupError::Appraisal(verification))) => {
            let retained = Arc::clone(&attempt);
            let snapshot = evidence
                .recover(deadline, move |snapshot| retained.check(snapshot))
                .await
                .map_err(|acquisition| Error::Recovery {
                    verification,
                    acquisition,
                })?;
            complete(evidence, attempt, snapshot, deadline).await
        }
        result => result,
    }
}

struct Attempt {
    pending: Mutex<PendingSetup>,
    bytes: Vec<u8>,
}
impl Attempt {
    fn check(&self, snapshot: &Snapshot) -> Result<(), evidence::Error> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| evidence::Error::Invalid("setup state unavailable".into()))?;
        let now = wall_clock_ms()
            .map_err(|_| evidence::Error::Invalid("local clock unavailable".into()))?;
        pending
            .check_evidence(&self.bytes, snapshot, now)
            .map(|_| ())
            .map_err(|error| match error {
                SetupError::Appraisal(error) => error,
                error => evidence::Error::Attestation(error.to_string()),
            })
    }
}

async fn complete(
    evidence: &EvidenceClient,
    attempt: Arc<Attempt>,
    snapshot: Arc<Snapshot>,
    deadline: Instant,
) -> Result<Connection, Error> {
    evidence
        .compute(deadline, move || {
            let (session, appraisal) = attempt
                .pending
                .lock()
                .map_err(|_| Error::State)?
                .complete_verified(&attempt.bytes, &snapshot, wall_clock_ms()?)?;
            Ok(Connection {
                session,
                snapshot,
                appraisal: Arc::new(appraisal),
            })
        })
        .await?
}
