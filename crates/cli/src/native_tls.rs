//! Fresh attested TLS over a caller-owned byte stream, independent of HTTP request formats.

use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, NamedGroup,
    ProtocolVersion, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use stogas_verifier::evidence::{self, Snapshot, VerifiedSession};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::evidence_client::{self, EvidenceClient};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("attested TLS setup deadline expired")]
    Deadline,
    #[error("could not create an attestation challenge")]
    Entropy,
    #[error("attested TLS verification failed: {0}")]
    Verification(Arc<VerificationFailure>),
    #[error("attested TLS evidence acquisition failed: {0}")]
    Evidence(#[from] evidence_client::Error),
    #[error(
        "attested TLS evidence recovery failed: {acquisition}; original failure: {verification}"
    )]
    Recovery {
        verification: Arc<VerificationFailure>,
        acquisition: evidence_client::Error,
    },
    #[error("attested TLS handshake failed: {0}")]
    Tls(#[from] std::io::Error),
    #[error("could not configure attested TLS: {0}")]
    Configuration(#[from] TlsError),
    #[error("attested TLS did not complete the required handshake profile")]
    Profile,
    #[error("attested TLS verification state is unavailable")]
    State,
}

impl Error {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Verification(error)
            | Self::Recovery {
                verification: error,
                ..
            } => error.reason().code(),
            Self::Evidence(error) => error.code(),
            Self::Profile => "unsupported_profile",
            Self::Deadline => "setup_deadline",
            Self::Tls(_) => "tls_failed",
            _ => "verification_unavailable",
        }
    }
}

/// Retains the rejected public certificate and its challenge only for bounded setup recovery.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct VerificationFailure {
    reason: evidence::Error,
    certificate: Option<(CertificateDer<'static>, [u8; 32])>,
}

impl VerificationFailure {
    #[must_use]
    pub const fn reason(&self) -> &evidence::Error {
        &self.reason
    }

    fn check(&self, snapshot: &Snapshot) -> Result<(), evidence::Error> {
        snapshot.require_current_keys()?;
        if let Some((certificate, challenge)) = &self.certificate {
            let now = i64::try_from(UnixTime::now().as_secs())
                .ok()
                .and_then(|seconds| seconds.checked_mul(1000))
                .ok_or_else(|| evidence::Error::Attestation("invalid local time".into()))?;
            snapshot.verify_native_certificate(certificate, *challenge, now)?;
        }
        Ok(())
    }
}

/// Available only after hardware appraisal, TLS signature verification and handshake completion.
pub struct Connection<T> {
    pub stream: TlsStream<T>,
    pub session: Arc<VerifiedSession>,
    pub snapshot: Arc<Snapshot>,
}

/// Set up a verified channel with at most one evidence recovery and one fresh redial.
/// The dialer opens only a byte stream. Credentials and inference remain the caller's next step.
///
/// # Errors
/// The original deadline covers initial evidence, both dials, handshakes and replica recovery.
pub async fn connect_with_evidence<T, F, Fut>(
    evidence: &EvidenceClient,
    mut dial: F,
    server_name: ServerName<'static>,
    deadline: Instant,
) -> Result<Connection<T>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    let snapshot = match evidence.current()? {
        Some(snapshot) => snapshot,
        None => evidence.recover(deadline, |_| Ok(())).await?,
    };
    let stream = tokio::time::timeout_at(deadline, dial())
        .await
        .map_err(|_| Error::Deadline)??;
    match connect(stream, server_name.clone(), snapshot, deadline).await {
        Ok(connection) => Ok(connection),
        Err(Error::Verification(failure)) => {
            let retained = Arc::clone(&failure);
            let snapshot = evidence
                .recover(deadline, move |candidate| retained.check(candidate))
                .await
                .map_err(|acquisition| Error::Recovery {
                    verification: failure,
                    acquisition,
                })?;
            let stream = tokio::time::timeout_at(deadline, dial())
                .await
                .map_err(|_| Error::Deadline)??;
            connect(stream, server_name, snapshot, deadline).await
        }
        Err(error) => Err(error),
    }
}

/// Establish one fresh TLS 1.3/X25519MLKEM768 connection. No application bytes are sent here.
/// Evidence acquisition and any retry belong to the asynchronous connector outside this function.
///
/// # Errors
/// Returns the original appraisal failure, negotiation/transport error or absolute deadline.
pub async fn connect<T>(
    stream: T,
    server_name: ServerName<'static>,
    snapshot: Arc<Snapshot>,
    deadline: Instant,
) -> Result<Connection<T>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    let handshake = Handshake::new(snapshot)?;
    let result = tokio::time::timeout_at(
        deadline,
        TlsConnector::from(Arc::clone(&handshake.config)).connect(server_name, stream),
    )
    .await
    .map_err(|_| Error::Deadline)?;
    let appraised = handshake
        .verifier
        .result
        .lock()
        .map_err(|_| Error::State)?
        .take();
    if let Some(Err(error)) = appraised.as_ref() {
        return Err(Error::Verification(Arc::clone(error)));
    }
    let stream = result?;
    let tls = &stream.get_ref().1;
    if tls.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || tls
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name)
            != Some(NamedGroup::X25519MLKEM768)
        || !matches!(tls.alpn_protocol(), Some(b"h2" | b"http/1.1"))
    {
        return Err(Error::Profile);
    }
    // The callback result alone never authorizes a stream: the peer must finish TLS first.
    let session = appraised
        .ok_or(Error::State)?
        .map_err(Error::Verification)?;
    handshake
        .verifier
        .snapshot
        .check_session(&session, evidence_client::wall_clock_ms()?)
        .map_err(|reason| {
            Error::Verification(Arc::new(VerificationFailure {
                reason,
                certificate: None,
            }))
        })?;
    Ok(Connection {
        stream,
        session,
        snapshot: Arc::clone(&handshake.verifier.snapshot),
    })
}

struct Handshake {
    config: Arc<ClientConfig>,
    verifier: Arc<CertificateVerifier>,
}

impl Handshake {
    fn new(snapshot: Arc<Snapshot>) -> Result<Self, Error> {
        snapshot.require_current_keys().map_err(|reason| {
            Error::Verification(Arc::new(VerificationFailure {
                reason,
                certificate: None,
            }))
        })?;
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| Error::Entropy)?;
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        let verifier = Arc::new(CertificateVerifier {
            snapshot,
            challenge,
            result: Mutex::new(None),
        });
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        config.alpn_protocols = vec![
            format!("stogas-attest-v1.{}", URL_SAFE_NO_PAD.encode(challenge)).into_bytes(),
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];
        Ok(Self {
            config: Arc::new(config),
            verifier,
        })
    }
}

#[derive(Debug)]
struct CertificateVerifier {
    snapshot: Arc<Snapshot>,
    challenge: [u8; 32],
    result: Mutex<Option<Result<Arc<VerifiedSession>, Arc<VerificationFailure>>>>,
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let rejected =
            || TlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        if !intermediates.is_empty() {
            return Err(rejected());
        }
        let now_ms = i64::try_from(now.as_secs())
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or_else(rejected)?;
        let result = self
            .snapshot
            .verify_native_certificate(end_entity.as_ref(), self.challenge, now_ms)
            .map(Arc::new)
            .map_err(|reason| {
                Arc::new(VerificationFailure {
                    reason,
                    certificate: Some((end_entity.clone().into_owned(), self.challenge)),
                })
            });
        let accepted = result.is_ok();
        *self.result.lock().map_err(|_| rejected())? = Some(result);
        if accepted {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rejected())
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("attested TLS requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SignatureScheme::ML_DSA_65 {
            return Err(TlsError::General("attested TLS requires ML-DSA-65".into()));
        }
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ML_DSA_65]
    }
}

#[cfg(all(test, feature = "staging"))]
mod tests;
