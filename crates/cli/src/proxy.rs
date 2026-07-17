use anyhow::{Context as _, Result, bail};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderName, StatusCode, header},
    response::Response,
    routing::any,
};
use futures_util::StreamExt as _;
use rand::Rng as _;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest as _, Sha256};
use std::{
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use stogas_verifier::{
    Environment, VerificationOutput, VerifiedNode, VerifierState, verify_bundle,
};
use tokio::sync::{Mutex, RwLock};
use url::Url;

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const REFRESH_RETRY: Duration = Duration::from_secs(5);

pub struct ServeConfig {
    bundle_url: Url,
    upstream: Url,
    listen: SocketAddr,
    expected_host: String,
    environment: Environment,
    state_path: PathBuf,
}

impl ServeConfig {
    pub(crate) fn new(
        bundle_url: &str,
        upstream: &str,
        listen: &str,
        environment: Environment,
        state_path: PathBuf,
    ) -> Result<Self> {
        let bundle_url = secure_bundle_url(bundle_url)?;
        let upstream = secure_base_url(upstream, "upstream URL")?;
        let listen: SocketAddr = listen.parse().context("invalid listen address")?;
        if !listen.ip().is_loopback() {
            bail!("serve listener must use a loopback address");
        }
        Ok(Self {
            bundle_url,
            upstream,
            listen,
            expected_host: listen.to_string(),
            environment,
            state_path,
        })
    }
}

fn secure_base_url(value: &str, label: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("invalid {label}"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("{label} must be an HTTPS origin without credentials, query, fragment, or path");
    }
    Ok(url)
}

fn secure_bundle_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid bundle URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("bundle URL must use HTTPS without credentials, query, or fragment");
    }
    Ok(url)
}

struct ActiveBundle {
    output: VerificationOutput,
    client: reqwest::Client,
}

struct ProxyState {
    active: RwLock<Arc<ActiveBundle>>,
    clock: SecureClock,
    config: Arc<ServeConfig>,
    refresh_lock: Mutex<()>,
}

#[derive(Clone)]
struct SecureClock {
    monotonic_start: Instant,
    wall_at_start_ms: i64,
}

impl SecureClock {
    fn capture() -> Self {
        Self {
            monotonic_start: Instant::now(),
            wall_at_start_ms: wall_clock_ms(),
        }
    }

    fn now_ms(&self) -> i64 {
        effective_time_ms(
            wall_clock_ms(),
            self.wall_at_start_ms,
            i64::try_from(self.monotonic_start.elapsed().as_millis()).unwrap_or(i64::MAX),
        )
    }
}

fn effective_time_ms(wall_now_ms: i64, wall_at_start_ms: i64, elapsed_ms: i64) -> i64 {
    wall_now_ms.max(wall_at_start_ms.saturating_add(elapsed_ms))
}

pub async fn serve(config: ServeConfig) -> Result<()> {
    let config = Arc::new(config);
    let clock = SecureClock::capture();
    let prior = read_state(&config.state_path).await?;
    let initial = fetch_active(&config, prior.as_ref(), clock.now_ms()).await?;
    write_state(&config.state_path, &initial.output.next_state).await?;
    let state = Arc::new(ProxyState {
        active: RwLock::new(Arc::new(initial)),
        clock,
        config: Arc::clone(&config),
        refresh_lock: Mutex::new(()),
    });
    tokio::spawn(refresh_loop(Arc::clone(&state)));

    let app = Router::new().fallback(any(proxy_request)).with_state(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn refresh_loop(state: Arc<ProxyState>) {
    loop {
        let expires_at = state.active.read().await.output.bundle.expires_at_unix_ms;
        let lead_seconds = rand::rng().random_range(60_i64..=75_i64);
        let refresh_at = expires_at.saturating_sub(lead_seconds * 1000);
        sleep_until_wall_clock(&state.clock, refresh_at).await;

        loop {
            if refresh_once(&state).await.is_ok() {
                let new_expiry = state.active.read().await.output.bundle.expires_at_unix_ms;
                if new_expiry > expires_at {
                    break;
                }
            }
            tokio::time::sleep(REFRESH_RETRY).await;
        }
    }
}

async fn sleep_until_wall_clock(clock: &SecureClock, deadline_ms: i64) {
    let delay_ms = deadline_ms.saturating_sub(clock.now_ms());
    if let Ok(delay) = u64::try_from(delay_ms) {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

async fn refresh_once(state: &ProxyState) -> Result<()> {
    let _guard = state.refresh_lock.lock().await;
    let prior = state.active.read().await.output.next_state.clone();
    let candidate = fetch_active(&state.config, Some(&prior), state.clock.now_ms()).await?;
    let current_sequence = state.active.read().await.output.bundle.sequence;
    if candidate.output.bundle.sequence < current_sequence {
        bail!("replacement bundle sequence regressed");
    }
    write_state(&state.config.state_path, &candidate.output.next_state).await?;
    *state.active.write().await = Arc::new(candidate);
    Ok(())
}

async fn fetch_active(
    config: &ServeConfig,
    prior: Option<&VerifierState>,
    now_unix_ms: i64,
) -> Result<ActiveBundle> {
    let fetcher = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = fetcher
        .get(config.bundle_url.clone())
        .send()
        .await?
        .error_for_status()?;
    let bytes = bounded_response(response, MAX_BUNDLE_BYTES).await?;
    let output = verify_bundle(&bytes, now_unix_ms, &config.environment, prior)?;
    let client = pinned_client(&output.bundle.nodes)?;
    Ok(ActiveBundle { output, client })
}

async fn bounded_response(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("response exceeds {limit} bytes");
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            bail!("response exceeds {limit} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn proxy_request(State(state): State<Arc<ProxyState>>, request: Request) -> Response<Body> {
    match proxy_request_inner(&state, request).await {
        Ok(response) => response,
        Err((status, message)) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(message))
            .unwrap_or_else(|_| Response::new(Body::empty())),
    }
}

async fn proxy_request_inner(
    state: &ProxyState,
    request: Request,
) -> Result<Response<Body>, (StatusCode, &'static str)> {
    if request.headers().contains_key(header::ORIGIN) {
        return Err((StatusCode::FORBIDDEN, "browser origins are not accepted"));
    }
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(state.config.expected_host.as_str())
    {
        return Err((StatusCode::MISDIRECTED_REQUEST, "invalid Host header"));
    }
    if !request.uri().path().starts_with("/v1/") {
        return Err((StatusCode::NOT_FOUND, "only /v1/* is available"));
    }
    let active = state.active.read().await.clone();
    if state.clock.now_ms() >= active.output.bundle.expires_at_unix_ms {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "verified trust bundle expired",
        ));
    }

    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_REQUEST_BYTES)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"))?;
    match send_upstream(state, &active, &parts, body.clone()).await {
        Ok(response) => Ok(response),
        Err(error) if error.is_connect() => {
            refresh_once(state)
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, "upstream TLS verification failed"))?;
            let refreshed = state.active.read().await.clone();
            if state.clock.now_ms() >= refreshed.output.bundle.expires_at_unix_ms {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "verified trust bundle expired",
                ));
            }
            send_upstream(state, &refreshed, &parts, body)
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, "upstream connection failed"))
        }
        Err(_) => Err((StatusCode::BAD_GATEWAY, "upstream request failed")),
    }
}

async fn send_upstream(
    state: &ProxyState,
    active: &ActiveBundle,
    parts: &axum::http::request::Parts,
    body: Bytes,
) -> reqwest::Result<Response<Body>> {
    let mut url = state.config.upstream.clone();
    url.set_path(parts.uri.path());
    url.set_query(parts.uri.query());
    let mut request = active.client.request(parts.method.clone(), url);
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name) && name != header::HOST && name != header::CONTENT_LENGTH {
            request = request.header(name, value);
        }
    }
    let upstream = request.body(body).send().await?;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let stream = upstream.bytes_stream();
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !is_hop_by_hop(name) {
            response = response.header(name, value);
        }
    }
    Ok(response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[derive(Clone)]
struct NodePins {
    certificate_sha256: Vec<[u8; 32]>,
    spki_sha256: [u8; 32],
}

impl TryFrom<&VerifiedNode> for NodePins {
    type Error = anyhow::Error;

    fn try_from(node: &VerifiedNode) -> Result<Self> {
        let spki_sha256 = decode_sha256(&node.tls_spki_sha256)?;
        let certificate_sha256 = node
            .accepted_cert_sha256
            .iter()
            .map(|value| decode_sha256(value))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            certificate_sha256,
            spki_sha256,
        })
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).context("pin is not hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("pin is not a SHA-256 digest"))
}

struct PinnedServerVerifier {
    webpki: Arc<dyn ServerCertVerifier>,
    nodes: Vec<NodePins>,
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedServerVerifier")
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        validate_leaf_pin(end_entity.as_ref(), &self.nodes)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn validate_leaf_pin(certificate_der: &[u8], nodes: &[NodePins]) -> Result<(), RustlsError> {
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    let cert_hash: [u8; 32] = Sha256::digest(certificate_der).into();
    let spki_hash: [u8; 32] = Sha256::digest(certificate.public_key().raw).into();
    if nodes
        .iter()
        .any(|node| node.spki_sha256 == spki_hash && node.certificate_sha256.contains(&cert_hash))
    {
        Ok(())
    } else {
        Err(RustlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

fn pinned_client(nodes: &[VerifiedNode]) -> Result<reqwest::Client> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    pinned_client_with_roots(nodes, roots)
}

fn pinned_client_with_roots(
    nodes: &[VerifiedNode],
    roots: RootCertStore,
) -> Result<reqwest::Client> {
    if nodes.is_empty() {
        bail!("a proxy trust bundle must contain at least one verified node");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()?;
    let verifier = Arc::new(PinnedServerVerifier {
        webpki,
        nodes: nodes
            .iter()
            .map(NodePins::try_from)
            .collect::<Result<Vec<_>>>()?,
    });
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .build()?)
}

async fn read_state(path: &Path) -> Result<Option<VerifierState>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("invalid verifier state")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn write_state(path: &Path, state: &VerifierState) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    tokio::fs::write(&temporary, serde_json::to_vec(state)?).await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

fn wall_clock_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    struct TestCertificate {
        ca: CertificateDer<'static>,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        node: VerifiedNode,
    }

    fn test_certificate() -> TestCertificate {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
        let leaf_der = leaf.der().clone();
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf_der.as_ref()).unwrap();
        let cert_hash = hex::encode(Sha256::digest(leaf_der.as_ref()));
        let spki_hash = hex::encode(Sha256::digest(parsed.public_key().raw));
        TestCertificate {
            ca: ca.der().clone(),
            chain: vec![leaf_der, ca.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            node: VerifiedNode {
                accepted_cert_sha256: vec![cert_hash],
                node_id: "node".into(),
                region: "test".into(),
                release_measurement: "00".repeat(48),
                tls_spki_sha256: spki_hash,
            },
        }
    }

    async fn tls_server(certificate: TestCertificate, attempts: usize) -> SocketAddr {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificate.chain, certificate.key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..attempts {
                let (stream, _) = listener.accept().await.unwrap();
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = vec![0; 4096];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        address
    }

    fn roots(ca: CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        roots
    }

    #[tokio::test]
    async fn same_connection_requires_webpki_certificate_and_spki_for_one_node() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let node = certificate.node.clone();
        let address = tls_server(certificate, 1).await;
        let client = pinned_client_with_roots(&[node], roots(ca)).unwrap();
        let response = client
            .get(format!("https://localhost:{}/v1/test", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn rejects_valid_webpki_certificate_when_pin_is_not_trusted() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let mut node = certificate.node.clone();
        node.accepted_cert_sha256 = vec!["11".repeat(32)];
        let address = tls_server(certificate, 1).await;
        let client = pinned_client_with_roots(&[node], roots(ca)).unwrap();
        assert!(
            client
                .get(format!("https://localhost:{}/v1/test", address.port()))
                .send()
                .await
                .is_err()
        );
    }

    #[test]
    fn rejects_cross_node_certificate_and_spki_mixing() {
        let certificate = test_certificate();
        let leaf = certificate.chain[0].as_ref();
        let actual = NodePins::try_from(&certificate.node).unwrap();
        let nodes = vec![
            NodePins {
                certificate_sha256: actual.certificate_sha256.clone(),
                spki_sha256: [0x22; 32],
            },
            NodePins {
                certificate_sha256: vec![[0x33; 32]],
                spki_sha256: actual.spki_sha256,
            },
        ];
        assert!(validate_leaf_pin(leaf, &nodes).is_err());
    }

    #[test]
    fn rejects_non_loopback_listener_and_non_https_origins() {
        assert!(
            ServeConfig::new(
                "https://evidence.example",
                "https://api.example",
                "0.0.0.0:8787",
                Environment::staging_legacy(),
                PathBuf::from("state")
            )
            .is_err()
        );
        assert!(secure_base_url("http://api.example", "upstream URL").is_err());
        assert!(secure_base_url("https://user@api.example", "upstream URL").is_err());
        assert!(secure_base_url("https://api.example/path", "upstream URL").is_err());
        assert!(secure_bundle_url("https://evidence.example/bundles/latest.json").is_ok());
        assert!(secure_bundle_url("https://evidence.example/latest.json?redirect=1").is_err());
    }

    #[test]
    fn monotonic_time_prevents_wall_clock_rollback_from_extending_trust() {
        assert_eq!(effective_time_ms(900, 1_000, 250), 1_250);
        assert_eq!(effective_time_ms(1_500, 1_000, 250), 1_500);
        assert_eq!(effective_time_ms(i64::MIN, i64::MAX - 1, 10), i64::MAX);
    }
}
