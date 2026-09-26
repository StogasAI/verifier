//! Demand-driven evidence acquisition. Network I/O and CPU verification have separate owners.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{
    Client, StatusCode,
    header::{ETAG, HeaderValue, IF_NONE_MATCH},
};
use stogas_verifier::{
    MAX_INPUT_BYTES,
    approvals::{Environment, RootKey},
    evidence::{self, Snapshot, VerifiedSession},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore},
    time::{Instant, timeout_at},
};
use url::Url;

const ORIGIN_BUDGET: Duration = Duration::from_secs(5);
const RECOVERY_BUDGET: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("evidence acquisition deadline expired")]
    Deadline,
    #[error("evidence acquisition is cooling down after a failed attempt")]
    Cooldown,
    #[error("evidence delivery failed: {0}")]
    Delivery(#[from] reqwest::Error),
    #[error("could not configure evidence HTTPS: {0}")]
    Configuration(#[from] rustls::Error),
    #[error("evidence origin returned HTTP {0}")]
    Http(StatusCode),
    #[error("evidence exceeds the decoded input limit")]
    TooLarge,
    #[error("evidence origin returned 304 without its own cached representation")]
    MissingRepresentation,
    #[error("evidence verification failed: {0}")]
    Verification(#[from] evidence::Error),
    #[error("evidence verification task failed")]
    Worker,
    #[error("evidence state is unavailable")]
    State,
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Verification(error) => error.code(),
            Self::TooLarge => "evidence_too_large",
            Self::Worker | Self::State | Self::Configuration(_) => "verification_unavailable",
            _ => "evidence_unavailable",
        }
    }
}

struct Representation {
    bytes: Arc<[u8]>,
    etag: Option<HeaderValue>,
}

#[derive(Default)]
struct Acquisition {
    representations: [Option<Representation>; 2],
    retry_after: Option<Instant>,
}

type Check = Arc<dyn Fn(&Snapshot) -> Result<(), evidence::Error> + Send + Sync>;

/// One current snapshot, one acquisition and one bounded representation per configured origin.
/// There are no timer tasks, third-party fetches or per-missing-identifier lookup tables.
pub struct EvidenceClient {
    client: Client,
    origins: [Url; 2],
    verifier: Arc<Mutex<evidence::Verifier>>,
    current: Arc<RwLock<Option<Arc<Snapshot>>>>,
    acquisition: AsyncMutex<Acquisition>,
    cpu: Arc<Semaphore>,
}

impl EvidenceClient {
    /// The root is a locally pinned trust seed. Evidence cannot replace it.
    ///
    /// # Errors
    /// Rejects a malformed root or unavailable maintained HTTPS configuration.
    pub fn new(environment: Environment, root: RootKey) -> Result<Self, Error> {
        let origins = environment.evidence_origins();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(ORIGIN_BUDGET)
            .build()?;
        let origins = [
            Url::parse(origins[0]).map_err(|_| Error::State)?,
            Url::parse(origins[1]).map_err(|_| Error::State)?,
        ];
        Self::from_parts(client, origins, environment, root)
    }

    fn from_parts(
        client: Client,
        origins: [Url; 2],
        environment: Environment,
        root: RootKey,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            origins,
            verifier: Arc::new(Mutex::new(evidence::Verifier::new(environment, root)?)),
            current: Arc::default(),
            acquisition: AsyncMutex::default(),
            cpu: Arc::new(Semaphore::new(1)),
        })
    }

    /// Clone the current evidence without waiting for network or cryptographic work.
    ///
    /// # Errors
    /// Fails closed if an earlier panic poisoned snapshot ownership.
    pub fn current(&self) -> Result<Option<Arc<Snapshot>>, Error> {
        Ok(self.current.read().map_err(|_| Error::State)?.clone())
    }

    // This client carries no application headers, cookies or redirect behavior.
    pub(crate) fn carriage(&self) -> Client {
        self.client.clone()
    }

    pub(crate) async fn compute<T: Send + 'static>(
        &self,
        deadline: Instant,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        timeout_at(deadline, run_cpu(Arc::clone(&self.cpu), move || Ok(work())))
            .await
            .map_err(|_| Error::Deadline)?
    }

    pub(crate) async fn reappraise_session(
        &self,
        snapshot: Arc<Snapshot>,
        session: Arc<VerifiedSession>,
        deadline: Instant,
        now_unix_ms: i64,
    ) -> Result<Arc<VerifiedSession>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        timeout_at(
            deadline,
            run_cpu(Arc::clone(&self.cpu), move || {
                Ok(Arc::new(
                    snapshot.reappraise_session(&session, now_unix_ms)?,
                ))
            }),
        )
        .await
        .map_err(|_| Error::Deadline)?
    }

    /// Initialize or explicitly refresh. Every operation shares the caller's remaining deadline.
    ///
    /// # Errors
    /// Tries the configured replica on delivery or verification failure; preserves accepted state.
    pub async fn refresh(&self, deadline: Instant) -> Result<Arc<Snapshot>, Error> {
        self.acquire(deadline, None).await
    }

    /// Resolve a failed verification once. A successful HTTP response is insufficient unless
    /// the supplied offline check succeeds; otherwise the second origin is tried before redial.
    ///
    /// # Errors
    /// Fails after the two bounded attempts or during the shared failed-recovery cooldown.
    pub async fn recover<F>(&self, deadline: Instant, check: F) -> Result<Arc<Snapshot>, Error>
    where
        F: Fn(&Snapshot) -> Result<(), evidence::Error> + Send + Sync + 'static,
    {
        self.acquire(deadline, Some(Arc::new(check))).await
    }

    async fn acquire(
        &self,
        deadline: Instant,
        check: Option<Check>,
    ) -> Result<Arc<Snapshot>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let deadline = deadline.min(Instant::now() + RECOVERY_BUDGET);
        timeout_at(deadline, self.acquire_inner(deadline, check))
            .await
            .map_err(|_| Error::Deadline)?
    }

    async fn acquire_inner(
        &self,
        deadline: Instant,
        check: Option<Check>,
    ) -> Result<Arc<Snapshot>, Error> {
        let mut acquisition = self.acquisition.lock().await;
        if let Some(check) = &check
            && let Some(current) = self.current()?
        {
            let check = Arc::clone(check);
            let checked = run_cpu(Arc::clone(&self.cpu), move || {
                current.require_current_keys()?;
                current
                    .approvals()
                    .valid_until(wall_clock_ms()?)
                    .map_err(evidence::Error::from)?;
                check(&current)?;
                Ok(current)
            })
            .await;
            if let Ok(current) = checked {
                return Ok(current);
            }
        }
        if acquisition
            .retry_after
            .is_some_and(|until| Instant::now() < until)
        {
            return Err(Error::Cooldown);
        }
        let mut failure = Error::Deadline;
        for (index, origin) in self.origins.iter().enumerate() {
            let attempt_deadline = deadline.min(Instant::now() + ORIGIN_BUDGET);
            let result = timeout_at(attempt_deadline, async {
                let candidate = self
                    .download(origin, acquisition.representations[index].as_ref())
                    .await?;
                let verifier = Arc::clone(&self.verifier);
                let current = Arc::clone(&self.current);
                let bytes = Arc::clone(&candidate.bytes);
                let snapshot = run_cpu(Arc::clone(&self.cpu), move || {
                    let now = wall_clock_ms()?;
                    let snapshot = verifier
                        .lock()
                        .map_err(|_| Error::State)?
                        .refresh(&bytes, now)?;
                    *current.write().map_err(|_| Error::State)? = Some(Arc::clone(&snapshot));
                    Ok(snapshot)
                })
                .await?;
                acquisition.representations[index] = Some(candidate);
                if let Some(check) = &check {
                    let check = Arc::clone(check);
                    let owned = Arc::clone(&snapshot);
                    run_cpu(Arc::clone(&self.cpu), move || {
                        owned.require_current_keys()?;
                        owned
                            .approvals()
                            .valid_until(wall_clock_ms()?)
                            .map_err(evidence::Error::from)?;
                        check(&owned)?;
                        Ok(())
                    })
                    .await?;
                }
                Ok::<_, Error>(snapshot)
            })
            .await
            .unwrap_or(Err(Error::Deadline));
            match result {
                Ok(snapshot) => {
                    acquisition.retry_after = None;
                    return Ok(snapshot);
                }
                Err(error) => failure = error,
            }
        }
        acquisition.retry_after =
            Some(Instant::now() + Duration::from_millis(rand::random_range(4500..=5500)));
        drop(acquisition);
        Err(failure)
    }

    async fn download(
        &self,
        origin: &Url,
        cached: Option<&Representation>,
    ) -> Result<Representation, Error> {
        let mut request = self.client.get(origin.clone());
        if let Some(etag) = cached.and_then(|value| value.etag.as_ref()) {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let mut response = request.send().await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            let cached = cached.ok_or(Error::MissingRepresentation)?;
            return Ok(Representation {
                bytes: Arc::clone(&cached.bytes),
                etag: cached.etag.clone(),
            });
        }
        if response.status() != StatusCode::OK {
            return Err(Error::Http(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|bytes| bytes > MAX_INPUT_BYTES as u64)
        {
            return Err(Error::TooLarge);
        }
        let etag = response.headers().get(ETAG).cloned();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > MAX_INPUT_BYTES.saturating_sub(bytes.len()) {
                return Err(Error::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Representation {
            bytes: bytes.into(),
            etag,
        })
    }
}

async fn run_cpu<T: Send + 'static>(
    cpu: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let permit = cpu.acquire_owned().await.map_err(|_| Error::State)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| Error::Worker)?
}

pub(crate) fn wall_clock_ms() -> Result<i64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .ok_or(Error::State)
}

#[cfg(all(test, feature = "staging"))]
mod tests;
