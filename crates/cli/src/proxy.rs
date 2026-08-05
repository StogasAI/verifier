use anyhow::{Context as _, Result, bail};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
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
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, mpsc::SyncSender},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stogas_verifier::{
    Environment, VerificationOutput, VerifiedNode, Verifier,
    e2ee::{Recipient, recipients_from_verified_bundle},
};
use tokio::sync::{Mutex, RwLock, oneshot};
use url::Url;

use crate::{SecurityMode, e2ee};

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const BUNDLE_ORIGIN_TIMEOUT_SECONDS: u64 = 5;
const MIN_REFRESH_RETRY_SECONDS: u64 = 4;
const MAX_REFRESH_RETRY_SECONDS: u64 = 8;
const MIN_BUNDLE_REFRESH_LEAD_SECONDS: i64 = 40;
const MAX_BUNDLE_REFRESH_LEAD_SECONDS: i64 = 70;
const PRODUCTION_BUNDLE_URL: &str = "https://evidence.stogas.ai/bundles/latest.json";
const PRODUCTION_BUNDLE_FALLBACK_URL: &str = "https://evidence2.stogas.ai/bundles/latest.json";
const STAGING_BUNDLE_URL: &str = "https://evidence-staging.stogas.ai/bundles/latest.json";
const STAGING_BUNDLE_FALLBACK_URL: &str = "https://evidence2-staging.stogas.ai/bundles/latest.json";
const VERIFIED_TLS_CONNECTION_ERROR: &str = "Verified TLS connection failed. TLS mode requires TLS 1.3 with X25519MLKEM768 and a certificate in the active verified bundle. Select E2EE mode if hybrid TLS is unavailable.";

pub struct ServeConfig {
    bundle_urls: Vec<Url>,
    bundle_fetcher: reqwest::Client,
    upstream_client: reqwest::Client,
    upstream: Url,
    listen: SocketAddr,
    expected_host: String,
    control_capability: String,
    environment: Environment,
    bundle_refresh_interval: Duration,
    security: SecurityMode,
    browser: Option<BrowserAccess>,
    client_capability: Option<String>,
}

pub struct ServeConfigInput<'a> {
    pub bundle_url: &'a str,
    pub upstream: &'a str,
    pub listen: &'a str,
    pub environment: Environment,
    pub bundle_refresh_interval: Duration,
    pub security: SecurityMode,
    pub browser_origin: Option<&'a str>,
    pub protect_loopback_path: bool,
}

struct BrowserAccess {
    origin: String,
    capability: String,
}

impl ServeConfig {
    pub fn new(input: ServeConfigInput<'_>) -> Result<Self> {
        let bundle_urls = secure_bundle_urls(input.bundle_url)?;
        let bundle_fetcher = reqwest::Client::builder()
            .use_preconfigured_tls(compatible_webpki_tls_config()?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(BUNDLE_ORIGIN_TIMEOUT_SECONDS))
            .build()?;
        let upstream_client = reqwest::Client::builder()
            .use_preconfigured_tls(compatible_webpki_tls_config()?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let upstream = secure_base_url(input.upstream, "upstream URL")?;
        let listen: SocketAddr = input.listen.parse().context("invalid listen address")?;
        if !listen.ip().is_loopback() {
            bail!("serve listener must use a loopback address");
        }
        let browser = match input.browser_origin {
            Some(origin) => Some(BrowserAccess {
                origin: secure_browser_origin(origin)?,
                capability: random_capability(),
            }),
            None => None,
        };
        Ok(Self {
            bundle_urls,
            bundle_fetcher,
            upstream_client,
            upstream,
            listen,
            expected_host: listen.to_string(),
            control_capability: random_capability(),
            environment: input.environment,
            bundle_refresh_interval: input.bundle_refresh_interval,
            security: input.security,
            browser,
            client_capability: input.protect_loopback_path.then(random_capability),
        })
    }

    fn base_url(&self) -> String {
        let capability = self
            .browser
            .as_ref()
            .map(|browser| browser.capability.as_str())
            .or(self.client_capability.as_deref());
        capability.map_or_else(
            || format!("http://{}/v1", self.expected_host),
            |capability| format!("http://{}/{capability}/v1", self.expected_host),
        )
    }

    fn refresh_url(&self) -> String {
        format!(
            "http://{}/_stogas/{}/refresh",
            self.expected_host, self.control_capability
        )
    }

    fn refresh_path(&self) -> String {
        format!("/_stogas/{}/refresh", self.control_capability)
    }
}

fn secure_browser_origin(value: &str) -> Result<String> {
    let url = Url::parse(value).context("invalid browser origin")?;
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("browser origin must be an HTTPS origin or an HTTP loopback origin");
    }
    Ok(url.origin().ascii_serialization())
}

fn random_capability() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
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

fn secure_bundle_urls(primary: &str) -> Result<Vec<Url>> {
    let primary = secure_bundle_url(primary)?;
    let fallback = match primary.as_str() {
        PRODUCTION_BUNDLE_URL => Some(PRODUCTION_BUNDLE_FALLBACK_URL),
        STAGING_BUNDLE_URL => Some(STAGING_BUNDLE_FALLBACK_URL),
        _ => None,
    };
    let mut urls = vec![primary];
    if let Some(fallback) = fallback {
        urls.push(secure_bundle_url(fallback)?);
    }
    Ok(urls)
}

struct ActiveBundle {
    output: VerificationOutput,
    client: reqwest::Client,
    recipients: Vec<Recipient>,
    bundle_sha256: [u8; 32],
}

#[derive(Clone)]
struct OriginCacheState {
    etag: Option<String>,
    bundle_sha256: [u8; 32],
}

enum BundleFetch {
    Changed(BundleCandidate),
    Unchanged,
}

struct BundleCandidate {
    bytes: Vec<u8>,
    origin_cache: OriginCacheState,
}

struct ProxyState {
    active: RwLock<Arc<ActiveBundle>>,
    origin_caches: Mutex<HashMap<String, OriginCacheState>>,
    config: Arc<ServeConfig>,
    refresh_lock: Mutex<()>,
    verifier: Mutex<Verifier>,
}

pub async fn serve(config: ServeConfig) -> Result<()> {
    let config = Arc::new(config);
    let mut verifier = Verifier::default();
    let (initial, origin_caches) = fetch_initial_bundle(&config, &mut verifier).await?;
    let state = Arc::new(ProxyState {
        active: RwLock::new(Arc::new(initial)),
        origin_caches: Mutex::new(origin_caches),
        config: Arc::clone(&config),
        refresh_lock: Mutex::new(()),
        verifier: Mutex::new(verifier),
    });
    tokio::spawn(refresh_loop(Arc::clone(&state)));

    let app = Router::new().fallback(any(proxy_request)).with_state(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    println!("OpenAI base URL: {}", config.base_url());
    println!("Bundle refresh URL: {}", config.refresh_url());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

pub struct EmbeddedEndpoints {
    pub address: SocketAddr,
    pub base_url: String,
    pub refresh_path: String,
}

pub async fn serve_embedded(
    mut config: ServeConfig,
    shutdown: oneshot::Receiver<()>,
    ready: SyncSender<Result<EmbeddedEndpoints, String>>,
) -> Result<()> {
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = ready.send(Err(format!("could not bind managed transport: {error}")));
            return Err(error.into());
        }
    };
    let address = listener.local_addr()?;
    config.listen = address;
    config.expected_host = address.to_string();
    let config = Arc::new(config);
    let mut verifier = Verifier::default();
    let initialized = async {
        let (initial, origin_caches) = fetch_initial_bundle(&config, &mut verifier).await?;
        let state = Arc::new(ProxyState {
            active: RwLock::new(Arc::new(initial)),
            origin_caches: Mutex::new(origin_caches),
            config: Arc::clone(&config),
            refresh_lock: Mutex::new(()),
            verifier: Mutex::new(verifier),
        });
        tokio::spawn(refresh_loop(Arc::clone(&state)));
        let app = Router::new().fallback(any(proxy_request)).with_state(state);
        Ok::<_, anyhow::Error>(app)
    }
    .await;
    let app = match initialized {
        Ok(app) => app,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return Err(error);
        }
    };
    let endpoints = EmbeddedEndpoints {
        address,
        base_url: config.base_url(),
        refresh_path: config.refresh_path(),
    };
    if ready.send(Ok(endpoints)).is_err() {
        return Ok(());
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown.await;
        })
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn refresh_loop(state: Arc<ProxyState>) {
    loop {
        let refresh_at = {
            let active = state.active.read().await;
            replacement_refresh_at(
                &active.output,
                wall_clock_ms(),
                state.config.bundle_refresh_interval,
            )
        };
        sleep_until_wall_clock(refresh_at).await;

        loop {
            if refresh_once(&state).await.is_ok() {
                break;
            }
            tokio::time::sleep(refresh_retry_delay()).await;
        }
    }
}

fn replacement_refresh_at(
    output: &VerificationOutput,
    now_unix_ms: i64,
    refresh_interval: Duration,
) -> i64 {
    let bundle_lead_seconds =
        rand::rng().random_range(MIN_BUNDLE_REFRESH_LEAD_SECONDS..=MAX_BUNDLE_REFRESH_LEAD_SECONDS);
    replacement_refresh_at_with_lead(output, now_unix_ms, refresh_interval, bundle_lead_seconds)
}

fn replacement_refresh_at_with_lead(
    output: &VerificationOutput,
    now_unix_ms: i64,
    refresh_interval: Duration,
    bundle_lead_seconds: i64,
) -> i64 {
    let interval_ms = i64::try_from(refresh_interval.as_millis()).unwrap_or(i64::MAX);
    let scheduled = now_unix_ms.saturating_add(interval_ms);
    let expiry_refresh = output
        .bundle
        .expires_at_unix_ms
        .saturating_sub(bundle_lead_seconds * 1000);
    if expiry_refresh <= now_unix_ms {
        return now_unix_ms
            .saturating_add(i64::try_from(MIN_REFRESH_RETRY_SECONDS * 1_000).unwrap_or(i64::MAX));
    }
    scheduled
        .min(expiry_refresh)
        .max(now_unix_ms.saturating_add(1_000))
}

fn refresh_retry_delay() -> Duration {
    Duration::from_secs(
        rand::rng().random_range(MIN_REFRESH_RETRY_SECONDS..=MAX_REFRESH_RETRY_SECONDS),
    )
}

async fn sleep_until_wall_clock(deadline_ms: i64) {
    let delay_ms = deadline_ms.saturating_sub(wall_clock_ms());
    if let Ok(delay) = u64::try_from(delay_ms) {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

async fn fetch_initial_bundle(
    config: &ServeConfig,
    verifier: &mut Verifier,
) -> Result<(ActiveBundle, HashMap<String, OriginCacheState>)> {
    let mut errors = Vec::new();
    for bundle_url in randomized_bundle_urls(config) {
        match fetch_bundle_origin(config, bundle_url.clone(), None).await {
            Ok(BundleFetch::Changed(candidate)) => match activate_bundle(
                config,
                &candidate.bytes,
                candidate.origin_cache.bundle_sha256,
                wall_clock_ms(),
                verifier,
            ) {
                Ok(active) => {
                    let mut origin_caches = HashMap::new();
                    origin_caches.insert(bundle_url.to_string(), candidate.origin_cache);
                    return Ok((active, origin_caches));
                }
                Err(error) => errors.push(format!("{bundle_url}: {error}")),
            },
            Ok(BundleFetch::Unchanged) => {
                errors.push(format!(
                    "{bundle_url}: returned an unexpected unchanged response"
                ));
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    bail!("every evidence origin failed: {}", errors.join("; "))
}

async fn refresh_once(state: &ProxyState) -> Result<bool> {
    let _guard = state.refresh_lock.lock().await;
    let current = {
        let active = state.active.read().await;
        Arc::clone(&active)
    };
    let mut errors = Vec::new();
    for bundle_url in randomized_bundle_urls(&state.config) {
        let previous = {
            let origin_caches = state.origin_caches.lock().await;
            origin_caches.get(bundle_url.as_str()).cloned()
        };
        match fetch_bundle_origin(&state.config, bundle_url.clone(), previous).await {
            Ok(BundleFetch::Unchanged) => return Ok(false),
            Ok(BundleFetch::Changed(candidate)) => {
                if candidate.origin_cache.bundle_sha256 == current.bundle_sha256 {
                    state
                        .origin_caches
                        .lock()
                        .await
                        .insert(bundle_url.to_string(), candidate.origin_cache);
                    return Ok(false);
                }
                let origin_cache = candidate.origin_cache.clone();
                let activated = {
                    let mut verifier = state.verifier.lock().await;
                    activate_bundle(
                        &state.config,
                        &candidate.bytes,
                        candidate.origin_cache.bundle_sha256,
                        wall_clock_ms(),
                        &mut verifier,
                    )
                };
                let candidate = match activated {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        errors.push(format!("{bundle_url}: {error}"));
                        continue;
                    }
                };
                if !candidate_snapshot_advances(&current.output, &candidate.output) {
                    errors.push(format!(
                        "{bundle_url}: returned a non-advancing verified snapshot"
                    ));
                    continue;
                }
                {
                    let mut origin_caches = state.origin_caches.lock().await;
                    origin_caches.clear();
                    origin_caches.insert(bundle_url.to_string(), origin_cache);
                }
                *state.active.write().await = Arc::new(candidate);
                return Ok(true);
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    bail!("every evidence origin failed: {}", errors.join("; "))
}

fn randomized_bundle_urls(config: &ServeConfig) -> Vec<Url> {
    let mut urls = config.bundle_urls.clone();
    if urls.len() == 2 && rand::rng().random_bool(0.5) {
        urls.swap(0, 1);
    }
    urls
}

const fn candidate_snapshot_advances(
    current: &VerificationOutput,
    candidate: &VerificationOutput,
) -> bool {
    candidate.bundle.created_at_unix_ms > current.bundle.created_at_unix_ms
}

async fn fetch_bundle_origin(
    config: &ServeConfig,
    bundle_url: Url,
    previous: Option<OriginCacheState>,
) -> Result<BundleFetch> {
    let mut request = config.bundle_fetcher.get(bundle_url.clone());
    if let Some(etag) = previous.as_ref().and_then(|cache| cache.etag.as_deref()) {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let response = request.send().await.with_context(|| {
        format!(
            "{} bundle fetch failed",
            bundle_url.host_str().unwrap_or("evidence")
        )
    })?;
    if response.status() == StatusCode::NOT_MODIFIED {
        if previous.is_none() {
            bail!("{bundle_url} returned 304 without a prior ETag");
        }
        return Ok(BundleFetch::Unchanged);
    }
    let response = response.error_for_status().with_context(|| {
        format!(
            "{} bundle fetch failed",
            bundle_url.host_str().unwrap_or("evidence")
        )
    })?;
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = bounded_response(response, MAX_BUNDLE_BYTES).await?;
    let sha256 = bundle_sha256(&bytes);
    if previous
        .as_ref()
        .is_some_and(|cache| cache.bundle_sha256 == sha256)
    {
        return Ok(BundleFetch::Unchanged);
    }
    Ok(BundleFetch::Changed(BundleCandidate {
        bytes,
        origin_cache: OriginCacheState {
            etag,
            bundle_sha256: sha256,
        },
    }))
}

fn bundle_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn activate_bundle(
    config: &ServeConfig,
    bytes: &[u8],
    bundle_sha256: [u8; 32],
    now_unix_ms: i64,
    verifier: &mut Verifier,
) -> Result<ActiveBundle> {
    let output = verifier.verify_bundle(bytes, now_unix_ms, &config.environment)?;
    let client = pinned_client(&output.bundle.nodes)?;
    let recipients = recipients_from_verified_bundle(&output)?;
    Ok(ActiveBundle {
        output,
        client,
        recipients,
        bundle_sha256,
    })
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
    let browser_origin = allowed_browser_origin(&state.config, request.headers());
    let mut response = match proxy_request_inner(&state, request).await {
        Ok(response) => response,
        Err((status, message)) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(message))
            .unwrap_or_else(|_| Response::new(Body::empty())),
    };
    if let Some(origin) = browser_origin {
        add_browser_response_headers(&mut response, origin);
    }
    response
}

async fn proxy_request_inner(
    state: &ProxyState,
    request: Request,
) -> Result<Response<Body>, (StatusCode, &'static str)> {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(state.config.expected_host.as_str())
    {
        return Err((StatusCode::MISDIRECTED_REQUEST, "invalid Host header"));
    }

    let origin = request.headers().get(header::ORIGIN);
    if request.uri().path() == state.config.refresh_path() {
        if request.method() != Method::POST || origin.is_some() {
            return Err((StatusCode::METHOD_NOT_ALLOWED, "invalid refresh request"));
        }
        let changed = refresh_once(state)
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "bundle refresh failed"))?;
        if wall_clock_ms() >= state.active.read().await.output.bundle.expires_at_unix_ms {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "verified bundle remains expired",
            ));
        }
        return Ok(Response::builder()
            .status(if changed {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            })
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty())));
    }
    let browser = match (origin, &state.config.browser) {
        (Some(origin), Some(browser)) if origin.to_str().ok() == Some(browser.origin.as_str()) => {
            Some(browser)
        }
        (Some(_), _) => return Err((StatusCode::FORBIDDEN, "browser origin is not allowed")),
        (None, _) => None,
    };
    let upstream_path = routed_path(
        request.uri().path(),
        browser,
        state.config.client_capability.as_deref(),
    )?
    .to_owned();
    if request.method() == Method::OPTIONS && browser.is_some() {
        return browser_preflight(&request);
    }
    if !upstream_path.starts_with("/v1/") {
        return Err((StatusCode::NOT_FOUND, "only /v1/* is available"));
    }
    let active = state.active.read().await.clone();
    let now_unix_ms = wall_clock_ms();
    if now_unix_ms >= active.output.bundle.expires_at_unix_ms {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "verified bundle expired"));
    }

    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_REQUEST_BYTES)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"))?;
    if state.config.security != SecurityMode::Tls && is_inference_path(&upstream_path) {
        let client = if state.config.security == SecurityMode::Both {
            &active.client
        } else {
            &state.config.upstream_client
        };
        return e2ee::send(e2ee::RequestContext {
            client,
            upstream_origin: &state.config.upstream,
            path: &upstream_path,
            parts: &parts,
            body,
            bundle_sha256: &active.bundle_sha256,
            recipients: &active.recipients,
            now_unix_ms,
        })
        .await;
    }

    let client = if state.config.security == SecurityMode::E2ee {
        &state.config.upstream_client
    } else {
        &active.client
    };
    send_upstream(client, &state.config.upstream, &parts, &upstream_path, body)
        .await
        .map_err(|error| {
            if error.is_connect() && state.config.security != SecurityMode::E2ee {
                eprintln!("verified upstream TLS connection failed: {error:#}");
                (StatusCode::BAD_GATEWAY, VERIFIED_TLS_CONNECTION_ERROR)
            } else {
                eprintln!("upstream request failed: {error:#}");
                (StatusCode::BAD_GATEWAY, "upstream request failed")
            }
        })
}

fn is_inference_path(path: &str) -> bool {
    matches!(path, "/v1/chat/completions" | "/v1/responses")
}

fn routed_path<'a>(
    path: &'a str,
    browser: Option<&BrowserAccess>,
    client_capability: Option<&str>,
) -> Result<&'a str, (StatusCode, &'static str)> {
    let capability = browser
        .map(|browser| browser.capability.as_str())
        .or(client_capability);
    let Some(capability) = capability else {
        return Ok(path);
    };
    let prefix = format!("/{capability}");
    path.strip_prefix(&prefix)
        .filter(|path| path.starts_with("/v1/"))
        .ok_or((StatusCode::NOT_FOUND, "invalid browser base URL"))
}

fn browser_preflight(request: &Request) -> Result<Response<Body>, (StatusCode, &'static str)> {
    let method = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .ok_or((StatusCode::BAD_REQUEST, "invalid browser preflight"))?;
    if !matches!(
        method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "browser method is not allowed",
        ));
    }
    if let Some(headers) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        let headers = headers
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid browser preflight"))?;
        if headers.len() > 2_048
            || headers.split(',').any(|name| {
                let name = name.trim();
                name.is_empty()
                    || HeaderName::from_bytes(name.as_bytes()).is_err()
                    || matches!(
                        name.to_ascii_lowercase().as_str(),
                        "cookie" | "host" | "origin"
                    )
            })
        {
            return Err((StatusCode::BAD_REQUEST, "invalid browser preflight"));
        }
    }

    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        )
        .header(header::ACCESS_CONTROL_MAX_AGE, "600");
    if let Some(headers) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        response = response.header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers);
    }
    if request
        .headers()
        .get("access-control-request-private-network")
        == Some(&HeaderValue::from_static("true"))
    {
        response = response.header("access-control-allow-private-network", "true");
    }
    Ok(response
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

fn allowed_browser_origin<'a>(
    config: &'a ServeConfig,
    headers: &axum::http::HeaderMap,
) -> Option<&'a str> {
    let browser = config.browser.as_ref()?;
    (headers.get(header::ORIGIN)?.to_str().ok()? == browser.origin)
        .then_some(browser.origin.as_str())
}

fn add_browser_response_headers(response: &mut Response<Body>, origin: &str) {
    if let Ok(origin) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

async fn send_upstream(
    client: &reqwest::Client,
    upstream_origin: &Url,
    parts: &axum::http::request::Parts,
    upstream_path: &str,
    body: Bytes,
) -> reqwest::Result<Response<Body>> {
    let mut url = upstream_origin.clone();
    url.set_path(upstream_path);
    url.set_query(parts.uri.query());
    let mut request = client.request(parts.method.clone(), url);
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name)
            && !is_local_browser_header(name)
            && name != header::HOST
            && name != header::CONTENT_LENGTH
        {
            request = request.header(name, value);
        }
    }
    let upstream = request.body(body).send().await?;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let stream = upstream.bytes_stream();
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !is_hop_by_hop(name) && !name.as_str().starts_with("access-control-") {
            response = response.header(name, value);
        }
    }
    Ok(response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

fn is_local_browser_header(name: &HeaderName) -> bool {
    name == header::ORIGIN || name.as_str().starts_with("access-control-")
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
        let spki_sha256 = decode_sha256(&node.report_data.tls_spki_sha256)?;
        let certificate_sha256 = node
            .report_data
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
    let (remaining, certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(RustlsError::InvalidCertificate(
            CertificateError::BadEncoding,
        ));
    }
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
    let provider = post_quantum_tls_provider();
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
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .build()?)
}

fn post_quantum_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

fn compatible_webpki_tls_config() -> Result<ClientConfig> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    compatible_webpki_tls_config_with_roots(roots)
}

fn compatible_webpki_tls_config_with_roots(roots: RootCertStore) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hpke::{Kem as _, Serializable as _, kem::XWing};
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use stogas_verifier::{
        AllowedCatalog, DrandBeacon, ReleaseProvenance, ReportData, VerifiedCatalogRelease,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::oneshot;
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
                chip_id: "00".repeat(64),
                drand_round: 0,
                drand_round_time_unix_ms: 0,
                evidence_age_ms: 0,
                node_id: "node".into(),
                quote: "verified-quote".into(),
                quote_verified_at_unix_ms: 0,
                region: "test".into(),
                report_data: ReportData {
                    active_cert_sha256: cert_hash.clone(),
                    accepted_cert_sha256: vec![cert_hash],
                    catalog: stogas_verifier::CatalogIdentity {
                        digest: format!("sha256:{}", "22".repeat(32)),
                        sequence: 1,
                    },
                    drand: DrandBeacon {
                        chain_hash: String::new(),
                        network: String::new(),
                        randomness: String::new(),
                        round: 0,
                        signature: String::new(),
                    },
                    ed25519_public_key: String::new(),
                    hpke_public_key: String::new(),
                    schema: "stogas.node-report.v1".into(),
                    tls_spki_sha256: spki_hash,
                },
                report_data_sha512: "00".repeat(64),
                release_measurement: "00".repeat(48),
                reported_tcb: "0000000000000000".into(),
            },
        }
    }

    fn test_output(expires_at_unix_ms: i64) -> VerificationOutput {
        let mut node = test_certificate().node;
        node.report_data.hpke_public_key =
            URL_SAFE_NO_PAD.encode(XWing::gen_keypair().1.to_bytes());
        let catalog_evidence: AllowedCatalog = serde_json::from_value(serde_json::json!({
            "github_in_toto": [{}],
            "signed_release": {
                "keyId": "test",
                "manifest": {
                    "catalogSchema": 1,
                    "public": format!("sha256:{}", "11".repeat(32)),
                    "runtime": format!("sha256:{}", "22".repeat(32)),
                    "schema": "stogas.catalog.release.v1",
                    "sequence": 1,
                    "source": {
                        "commit": "33".repeat(20),
                        "repository": "https://github.com/StogasAI/catalog",
                        "tag": "catalog-v1",
                        "tree": "44".repeat(20)
                    }
                },
                "schema": "stogas.catalog.signed.v1",
                "signature": "test"
            }
        }))
        .unwrap();
        let original = serde_json::from_value(serde_json::json!({
            "body": {
                "allowed_catalogs": [catalog_evidence],
                "allowed_igvms": [],
                "created_at": "2026-07-23T16:00:00.000Z",
                "expires_at": "2026-07-23T16:15:00.000Z",
                "nodes": [],
                "schema": "stogas.confidential-bundle.v1",
                "sequence": 1,
                "ttl_ms": 900_000,
                "vendor_collateral": []
            },
            "body_sha256": "00".repeat(32)
        }))
        .unwrap();
        VerificationOutput {
            bundle: stogas_verifier::VerifiedBundle {
                catalogs: vec![VerifiedCatalogRelease {
                    evidence: catalog_evidence,
                    github_integrated_time_unix_ms: Some(0),
                    provenance: ReleaseProvenance::Github,
                    public_digest: format!("sha256:{}", "11".repeat(32)),
                    runtime_digest: format!("sha256:{}", "22".repeat(32)),
                    sequence: 1,
                    source_commit: "33".repeat(20),
                    source_repository: "https://github.com/StogasAI/catalog".into(),
                    source_tag: "catalog-v1".into(),
                    source_tree: "44".repeat(20),
                    stogas_signing_key_id: "test".into(),
                }],
                sequence: 1,
                created_at_unix_ms: 0,
                expires_at_unix_ms,
                excluded_nodes: Vec::new(),
                releases: Vec::new(),
                nodes: vec![node],
                original,
            },
        }
    }

    async fn tls_server(certificate: TestCertificate, attempts: usize) -> SocketAddr {
        tls_server_with_provider(certificate, attempts, post_quantum_tls_provider()).await
    }

    async fn tls_server_with_provider(
        certificate: TestCertificate,
        attempts: usize,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> SocketAddr {
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificate.chain, certificate.key)
            .unwrap();
        tls_server_with_config(config, attempts).await
    }

    async fn tls12_server(certificate: TestCertificate, attempts: usize) -> SocketAddr {
        let config = rustls::ServerConfig::builder_with_provider(classical_tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificate.chain, certificate.key)
            .unwrap();
        tls_server_with_config(config, attempts).await
    }

    async fn tls_server_with_config(config: rustls::ServerConfig, attempts: usize) -> SocketAddr {
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

    fn classical_tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        Arc::new(provider)
    }

    async fn capturing_tls_server(
        certificate: TestCertificate,
    ) -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
        let config = rustls::ServerConfig::builder_with_provider(post_quantum_tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificate.chain, certificate.key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let _ = request_tx.send(request);
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nx-upstream: preserved\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        (address, request_rx)
    }

    fn roots(ca: CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        roots
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .use_preconfigured_tls(compatible_webpki_tls_config().unwrap())
            .build()
            .unwrap()
    }

    fn proxy_state(
        client: reqwest::Client,
        upstream: &str,
        bundle_url: &str,
        expires_at_unix_ms: i64,
    ) -> ProxyState {
        proxy_state_with_browser(client, upstream, bundle_url, expires_at_unix_ms, None)
    }

    fn proxy_state_with_browser(
        client: reqwest::Client,
        upstream: &str,
        bundle_url: &str,
        expires_at_unix_ms: i64,
        browser_origin: Option<&str>,
    ) -> ProxyState {
        let output = test_output(expires_at_unix_ms);
        let bundle = b"test bundle";
        let recipients = recipients_from_verified_bundle(&output).unwrap();
        ProxyState {
            active: RwLock::new(Arc::new(ActiveBundle {
                output,
                client,
                recipients,
                bundle_sha256: bundle_sha256(bundle),
            })),
            origin_caches: Mutex::new(HashMap::new()),
            config: Arc::new(
                ServeConfig::new(ServeConfigInput {
                    bundle_url,
                    upstream,
                    listen: "127.0.0.1:8787",
                    environment: Environment::stogas(),
                    bundle_refresh_interval: Duration::from_mins(1),
                    security: SecurityMode::Tls,
                    browser_origin,
                    protect_loopback_path: false,
                })
                .unwrap(),
            ),
            refresh_lock: Mutex::new(()),
            verifier: Mutex::new(Verifier::default()),
        }
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
    async fn managed_transport_rejects_classical_tls_fallback() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let node = certificate.node.clone();
        let address = tls_server_with_provider(certificate, 1, classical_tls_provider()).await;
        let client = pinned_client_with_roots(&[node], roots(ca)).unwrap();
        let state = proxy_state(
            client,
            &format!("https://localhost:{}", address.port()),
            "https://evidence.example/bundles/latest.json",
            i64::MAX,
        );
        let request = Request::builder()
            .method(Method::GET)
            .uri("/v1/test")
            .header(header::HOST, "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        let Err(error) = proxy_request_inner(&state, request).await else {
            panic!("classical TLS fallback was accepted");
        };
        assert_eq!(
            error,
            (StatusCode::BAD_GATEWAY, VERIFIED_TLS_CONNECTION_ERROR)
        );
    }

    #[tokio::test]
    async fn e2ee_https_client_accepts_modern_tls12() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let address = tls12_server(certificate, 1).await;
        let tls = compatible_webpki_tls_config_with_roots(roots(ca)).unwrap();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .unwrap();
        let response = client
            .get(format!("https://localhost:{}/v1/test", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn accepts_the_matching_certificate_in_either_rotation_slot() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let mut node = certificate.node.clone();
        node.report_data
            .accepted_cert_sha256
            .insert(0, "11".repeat(32));
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
    async fn preserves_openai_request_response_and_chunked_body_bytes() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let node = certificate.node.clone();
        let client = pinned_client_with_roots(&[node], roots(ca)).unwrap();
        let (address, captured_request) = capturing_tls_server(certificate).await;
        let state = proxy_state(
            client,
            &format!("https://localhost:{}", address.port()),
            "https://evidence.example/bundles/latest.json",
            i64::MAX,
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions?stream=true")
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::AUTHORIZATION, "Bearer test-secret")
            .header("x-stogas-test", "preserved")
            .body(Body::from(r#"{"stream":true}"#))
            .unwrap();

        let response = proxy_request_inner(&state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-upstream"], "preserved");
        assert!(!response.headers().contains_key(header::CONNECTION));
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "hello world"
        );

        let request = String::from_utf8(captured_request.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /v1/chat/completions?stream=true HTTP/1.1\r\n"));
        assert!(request.contains("authorization: Bearer test-secret\r\n"));
        assert!(request.contains("x-stogas-test: preserved\r\n"));
        assert!(request.ends_with(r#"{"stream":true}"#));
    }

    #[tokio::test]
    async fn browser_request_strips_local_routing_and_cors_headers_before_upstream() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let node = certificate.node.clone();
        let client = pinned_client_with_roots(&[node], roots(ca)).unwrap();
        let (address, captured_request) = capturing_tls_server(certificate).await;
        let state = Arc::new(proxy_state_with_browser(
            client,
            &format!("https://localhost:{}", address.port()),
            "https://evidence.example/bundles/latest.json",
            i64::MAX,
            Some("https://client.example"),
        ));
        let capability = state.config.browser.as_ref().unwrap().capability.clone();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/{capability}/v1/chat/completions?stream=true"))
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::ORIGIN, "https://client.example")
            .header(header::AUTHORIZATION, "Bearer test-secret")
            .body(Body::from(r#"{"stream":true}"#))
            .unwrap();

        let response = proxy_request(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://client.example"
        );

        let request = String::from_utf8(captured_request.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /v1/chat/completions?stream=true HTTP/1.1\r\n"));
        assert!(!request.contains("origin:"));
        assert!(!request.contains(&capability));
    }

    #[tokio::test]
    async fn rejects_valid_webpki_certificate_when_pin_is_not_trusted() {
        let certificate = test_certificate();
        let ca = certificate.ca.clone();
        let mut node = certificate.node.clone();
        node.report_data.accepted_cert_sha256 = vec!["11".repeat(32)];
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

    #[tokio::test]
    async fn rejects_browser_origin_bad_host_non_v1_path_and_expired_trust() {
        let state = proxy_state(
            test_http_client(),
            "https://api.example",
            "https://evidence.example/bundles/latest.json",
            i64::MAX,
        );
        let request = |path: &str, host: &str, origin: Option<&str>| {
            let mut request = Request::builder().uri(path).header(header::HOST, host);
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            request.body(Body::empty()).unwrap()
        };

        assert_eq!(
            proxy_request_inner(
                &state,
                request("/v1/models", "127.0.0.1:8787", Some("https://example.com"))
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            proxy_request_inner(&state, request("/v1/models", "localhost:8787", None))
                .await
                .unwrap_err()
                .0,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            proxy_request_inner(&state, request("/health", "127.0.0.1:8787", None))
                .await
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        let refresh_path = state.config.refresh_path();
        let refresh_get = Request::builder()
            .uri(&refresh_path)
            .header(header::HOST, "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            proxy_request_inner(&state, refresh_get)
                .await
                .unwrap_err()
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        let browser_refresh = Request::builder()
            .method(Method::POST)
            .uri(&refresh_path)
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::ORIGIN, "https://client.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            proxy_request_inner(&state, browser_refresh)
                .await
                .unwrap_err()
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(state.config.refresh_url().ends_with(&refresh_path));

        let expired = proxy_state(
            test_http_client(),
            "https://api.example",
            "https://evidence.example/bundles/latest.json",
            0,
        );
        assert_eq!(
            proxy_request_inner(&expired, request("/v1/models", "127.0.0.1:8787", None))
                .await
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn browser_access_requires_exact_origin_and_capability_and_handles_preflight() {
        let state = proxy_state_with_browser(
            test_http_client(),
            "https://api.example",
            "https://evidence.example/bundles/latest.json",
            i64::MAX,
            Some("https://client.example"),
        );
        let capability = &state.config.browser.as_ref().unwrap().capability;
        let path = format!("/{capability}/v1/chat/completions");
        let preflight = Request::builder()
            .method(Method::OPTIONS)
            .uri(&path)
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::ORIGIN, "https://client.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization, content-type",
            )
            .header("access-control-request-private-network", "true")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request_inner(&state, preflight).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers()["access-control-allow-private-network"],
            "true"
        );
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
            "authorization, content-type"
        );

        let wrong_capability = Request::builder()
            .uri("/wrong/v1/models")
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::ORIGIN, "https://client.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            proxy_request_inner(&state, wrong_capability)
                .await
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );

        let wrong_origin = Request::builder()
            .uri(path)
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::ORIGIN, "https://attacker.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            proxy_request_inner(&state, wrong_origin)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn failed_refresh_keeps_the_active_bundle_untouched() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let state = proxy_state(
            test_http_client(),
            "https://api.example",
            &format!("https://127.0.0.1:{}/bundles/latest.json", address.port()),
            i64::MAX,
        );
        let before = state.active.read().await.output.bundle.sequence;

        assert!(refresh_once(&state).await.is_err());
        assert_eq!(state.active.read().await.output.bundle.sequence, before);
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
            ServeConfig::new(ServeConfigInput {
                bundle_url: "https://evidence.example",
                upstream: "https://api.example",
                listen: "0.0.0.0:8787",
                environment: Environment::stogas(),
                bundle_refresh_interval: Duration::from_mins(1),
                security: SecurityMode::Tls,
                browser_origin: None,
                protect_loopback_path: false,
            })
            .is_err()
        );
        assert!(secure_base_url("http://api.example", "upstream URL").is_err());
        assert!(secure_base_url("https://user@api.example", "upstream URL").is_err());
        assert!(secure_base_url("https://api.example/path", "upstream URL").is_err());
        assert!(secure_bundle_url("https://evidence.example/bundles/latest.json").is_ok());
        assert!(secure_bundle_url("https://evidence.example/latest.json?redirect=1").is_err());
        assert_eq!(secure_bundle_urls(PRODUCTION_BUNDLE_URL).unwrap().len(), 2);
        assert_eq!(
            secure_bundle_urls("https://evidence.example/bundles/latest.json")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            secure_browser_origin("https://client.example/").unwrap(),
            "https://client.example"
        );
        assert_eq!(
            secure_browser_origin("http://127.0.0.1:5173").unwrap(),
            "http://127.0.0.1:5173"
        );
        assert_eq!(
            secure_browser_origin("http://localhost:5173").unwrap(),
            "http://localhost:5173"
        );
        assert!(secure_browser_origin("http://client.example").is_err());
        assert!(secure_browser_origin("https://client.example/path").is_err());
    }

    #[test]
    fn replacement_retry_delay_is_jittered_within_its_small_final_window() {
        for _ in 0..100 {
            let delay = refresh_retry_delay().as_secs();
            assert!((MIN_REFRESH_RETRY_SECONDS..=MAX_REFRESH_RETRY_SECONDS).contains(&delay));
        }
    }

    #[test]
    fn replacement_fetch_uses_the_interval_or_the_safe_expiry_lead() {
        let output = test_output(1_000_000);
        assert_eq!(
            replacement_refresh_at_with_lead(&output, 100_000, Duration::from_mins(1), 70,),
            160_000
        );
        for _ in 0..100 {
            let lead_seconds = (output.bundle.expires_at_unix_ms
                - replacement_refresh_at(&output, 100_000, Duration::from_mins(15)))
                / 1000;
            assert!(
                (MIN_BUNDLE_REFRESH_LEAD_SECONDS..=MAX_BUNDLE_REFRESH_LEAD_SECONDS)
                    .contains(&lead_seconds)
            );
        }
        assert_eq!(
            replacement_refresh_at_with_lead(&output, 950_000, Duration::from_secs(1), 70),
            954_000
        );
    }

    #[test]
    fn identical_bundle_bytes_reuse_the_active_verification() {
        let cache = OriginCacheState {
            etag: Some("\"bundle-etag\"".into()),
            bundle_sha256: bundle_sha256(b"same bundle"),
        };
        assert_eq!(cache.bundle_sha256, bundle_sha256(b"same bundle"));
        assert_ne!(cache.bundle_sha256, bundle_sha256(b"new bundle"));
    }

    #[test]
    fn snapshot_order_ignores_untrusted_sequence_values() {
        let mut current = test_output(1_000_000);
        current.bundle.created_at_unix_ms = 100_000;
        current.bundle.sequence = u64::MAX;
        let mut candidate = test_output(1_000_000);
        candidate.bundle.created_at_unix_ms = 100_001;
        candidate.bundle.sequence = 1;
        assert!(candidate_snapshot_advances(&current, &candidate));

        candidate.bundle.created_at_unix_ms = 100_000;
        assert!(!candidate_snapshot_advances(&current, &candidate));

        candidate.bundle.created_at_unix_ms = 99_999;
        candidate.bundle.sequence = u64::MAX;
        assert!(!candidate_snapshot_advances(&current, &candidate));
    }
}
