use crate::{
    SecurityMode, TransportOptions, encrypted_client, evidence_client::EvidenceClient, http2_pool,
    native_http,
};
use anyhow::{Context as _, Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::any,
};
use futures_util::{StreamExt as _, stream};
use rand::Rng as _;
use rustls::pki_types::ServerName;
use std::{
    collections::HashSet,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{Arc, mpsc::SyncSender},
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};
use url::Url;

const SETUP_BUDGET: Duration = Duration::from_secs(15);
const REQUEST_BUDGET: Duration = Duration::from_hours(1);
const CLOSE_BUDGET: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;

pub struct ServeConfig {
    options: TransportOptions,
    upstream: Url,
    listen: SocketAddr,
    expected_host: String,
    control_capability: String,
    client_capability: String,
    browser: Option<BrowserAccess>,
}
struct BrowserAccess {
    origin: String,
    capability: String,
}
impl ServeConfig {
    pub fn new(
        options: &TransportOptions,
        listen: &str,
        browser_origin: Option<&str>,
    ) -> Result<Self> {
        options.validate()?;
        let origin = options
            .base_url
            .as_deref()
            .unwrap_or_else(|| match options.security {
                SecurityMode::Tls => options.environment.api_origin(),
                SecurityMode::E2ee => options.environment.e2ee_origin(),
            });
        let upstream = secure_base_url(origin, "upstream URL")?;
        let listen: SocketAddr = listen.parse().context("invalid listen address")?;
        if !listen.ip().is_loopback() {
            bail!("serve listener must use a loopback address");
        }
        Ok(Self {
            options: options.clone(),
            upstream,
            listen,
            expected_host: listen.to_string(),
            control_capability: random_capability(),
            client_capability: random_capability(),
            browser: browser_origin
                .map(|origin| {
                    Ok::<_, anyhow::Error>(BrowserAccess {
                        origin: secure_browser_origin(origin)?,
                        capability: random_capability(),
                    })
                })
                .transpose()?,
        })
    }
    fn capability(&self) -> &str {
        self.browser
            .as_ref()
            .map_or(&self.client_capability, |browser| &browser.capability)
    }
    fn base_url(&self) -> String {
        format!("http://{}/{}/v1", self.expected_host, self.capability())
    }
    fn refresh_url(&self) -> String {
        format!("http://{}{}", self.expected_host, self.refresh_path())
    }
    fn refresh_path(&self) -> String {
        format!("/_stogas/{}/refresh", self.control_capability)
    }
}

enum Upstream {
    Tls(native_http::Client),
    E2ee(encrypted_client::Client),
}
struct ProxyState {
    config: ServeConfig,
    evidence: Arc<EvidenceClient>,
    upstream: Upstream,
}
impl ProxyState {
    async fn new(config: ServeConfig) -> Result<Self> {
        let environment = config.options.environment;
        let evidence = Arc::new(EvidenceClient::new(
            environment,
            environment.stogas_root()?,
        )?);
        evidence.refresh(Instant::now() + SETUP_BUDGET).await?;
        let maximum = NonZeroUsize::new(config.options.max_connections)
            .context("invalid connection maximum")?;
        let upstream = match config.options.security {
            SecurityMode::Tls => {
                let host = config
                    .upstream
                    .host_str()
                    .context("missing upstream host")?
                    .to_owned();
                let server_name = ServerName::try_from(host.clone())?;
                let port = config
                    .upstream
                    .port_or_known_default()
                    .context("missing upstream port")?;
                let limits = http2_pool::Limits {
                    connections: maximum,
                    waiting_requests: NonZeroUsize::new(1024).context("invalid wait count")?,
                    waiting_bytes: NonZeroUsize::new(256 * 1024 * 1024)
                        .context("invalid wait bytes")?,
                };
                Upstream::Tls(native_http::Client::new(
                    Arc::clone(&evidence),
                    move || {
                        let host = host.clone();
                        async move { tokio::net::TcpStream::connect((host.as_str(), port)).await }
                    },
                    server_name,
                    limits,
                ))
            }
            SecurityMode::E2ee => Upstream::E2ee(encrypted_client::Client::new(
                Arc::clone(&evidence),
                config.upstream.join("/v1/session")?,
                environment,
                maximum,
            )),
        };
        Ok(Self {
            config,
            evidence,
            upstream,
        })
    }
    async fn close(&self, deadline: Instant) {
        match &self.upstream {
            Upstream::Tls(client) => {
                let _ = client.close(deadline).await;
            }
            Upstream::E2ee(client) => {
                let _ = client.close(deadline).await;
            }
        }
    }
}

pub struct EmbeddedEndpoints {
    pub address: SocketAddr,
    pub base_url: String,
    pub refresh_path: String,
}
pub async fn serve(config: ServeConfig) -> Result<()> {
    run(
        config,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        None,
    )
    .await
}
pub async fn serve_embedded(
    config: ServeConfig,
    shutdown: oneshot::Receiver<()>,
    ready: SyncSender<Result<EmbeddedEndpoints>>,
) -> Result<()> {
    run(
        config,
        async {
            let _ = shutdown.await;
        },
        Some(ready),
    )
    .await
}
async fn run(
    mut config: ServeConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
    ready: Option<SyncSender<Result<EmbeddedEndpoints>>>,
) -> Result<()> {
    let initialized = async {
        let listener = tokio::net::TcpListener::bind(config.listen).await?;
        let address = listener.local_addr()?;
        config.listen = address;
        config.expected_host = address.to_string();
        Ok::<_, anyhow::Error>((listener, Arc::new(ProxyState::new(config).await?)))
    }
    .await;
    let (listener, state) = match initialized {
        Ok(value) => value,
        Err(error) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(error));
                return Ok(());
            }
            return Err(error);
        }
    };
    if let Some(ready) = ready {
        if ready
            .send(Ok(EmbeddedEndpoints {
                address: state.config.listen,
                base_url: state.config.base_url(),
                refresh_path: state.config.refresh_path(),
            }))
            .is_err()
        {
            return Ok(());
        }
    } else {
        println!("OpenAI base URL: {}", state.config.base_url());
        println!("Evidence refresh URL: {}", state.config.refresh_url());
    }
    let app = Router::new()
        .fallback(any(proxy_request))
        .with_state(Arc::clone(&state));
    let (stop, stopped) = oneshot::channel();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .into_future();
    tokio::pin!(server);
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut server => result?,
        () = &mut shutdown => {
            let _ = stop.send(());
            let deadline = Instant::now() + CLOSE_BUDGET;
            tokio::join!(state.close(deadline), async { let _ = timeout_at(deadline, &mut server).await; });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Failure {
    status: StatusCode,
    phase: &'static str,
    submission: &'static str,
    reason: &'static str,
    message: String,
}
impl Failure {
    fn before(status: StatusCode, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            phase: "request",
            submission: "not_sent",
            reason,
            message: message.into(),
        }
    }
    fn evidence(error: &crate::evidence_client::Error) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            phase: "setup",
            submission: "not_sent",
            reason: error.code(),
            message: error.to_string(),
        }
    }
    fn native(error: &native_http::Error) -> Self {
        let submitted = matches!(
            &error,
            native_http::Error::Receipt(_)
                | native_http::Error::Pool(
                    http2_pool::Error::ResponseDeadline
                        | http2_pool::Error::Request {
                            not_sent: false,
                            ..
                        }
                )
        );
        Self {
            status: StatusCode::BAD_GATEWAY,
            phase: if submitted { "response" } else { "setup" },
            submission: if submitted {
                "execution_unknown"
            } else {
                "not_sent"
            },
            reason: error.code(),
            message: error.to_string(),
        }
    }
    fn encrypted(error: &encrypted_client::Error) -> Self {
        let submitted = matches!(
            &error,
            encrypted_client::Error::Receipt(_)
                | encrypted_client::Error::Http(
                    encrypted_http::Error::Deadline
                        | encrypted_http::Error::Http(_)
                        | encrypted_http::Error::Response
                        | encrypted_http::Error::Metadata
                        | encrypted_http::Error::Record(_)
                )
        );
        Self {
            status: StatusCode::BAD_GATEWAY,
            phase: if submitted { "response" } else { "setup" },
            submission: if submitted {
                "execution_unknown"
            } else {
                "not_sent"
            },
            reason: error.code(),
            message: error.to_string(),
        }
    }
}
use crate::encrypted_http;

async fn proxy_request(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let origin = allowed_browser_origin(&state.config, request.headers()).map(str::to_owned);
    let mut response = match proxy_request_inner(&state, request).await {
        Ok(response) => response,
        Err(error) => Response::builder().status(error.status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(serde_json::json!({"error":{"type":"stogas_transport_error","message":error.message,"code":error.reason,"stogas":{"phase":error.phase,"submission":error.submission,"reason":error.reason}}}).to_string()))
            .unwrap_or_else(|_| Response::new(Body::empty())),
    };
    if let Some(origin) = origin {
        add_browser_response_headers(&mut response, &origin);
    }
    response
}
#[derive(Debug)]
enum Route {
    Refresh,
    Preflight,
    Inference(String),
}
fn route(config: &ServeConfig, request: &Request) -> Result<Route, Failure> {
    if request.headers().get_all(header::HOST).iter().count() != 1
        || request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            != Some(config.expected_host.as_str())
    {
        return Err(Failure::before(
            StatusCode::MISDIRECTED_REQUEST,
            "invalid_host",
            "invalid Host header",
        ));
    }
    if request.uri().query().is_some() {
        return Err(Failure::before(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "query parameters are not supported",
        ));
    }
    let origin = request.headers().get(header::ORIGIN);
    if request.uri().path() == config.refresh_path() {
        if request.method() != Method::POST || origin.is_some() {
            return Err(Failure::before(
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_refresh",
                "invalid refresh request",
            ));
        }
        return Ok(Route::Refresh);
    }
    let browser = match (origin, &config.browser) {
        (Some(origin), Some(browser))
            if request.headers().get_all(header::ORIGIN).iter().count() == 1
                && origin.to_str().ok() == Some(browser.origin.as_str()) =>
        {
            Some(browser)
        }
        (Some(_), _) => {
            return Err(Failure::before(
                StatusCode::FORBIDDEN,
                "invalid_origin",
                "browser origin is not allowed",
            ));
        }
        (None, _) => None,
    };
    let path = routed_path(request.uri().path(), browser, Some(config.capability()))
        .map_err(|(status, message)| Failure::before(status, "invalid_path", message))?
        .to_owned();
    if !matches!(path.as_str(), "/v1/chat/completions" | "/v1/responses") {
        return Err(Failure::before(
            StatusCode::NOT_FOUND,
            "unsupported_path",
            "only chat completions and responses are supported",
        ));
    }
    if request.method() == Method::OPTIONS && browser.is_some() {
        return Ok(Route::Preflight);
    }
    if request.method() != Method::POST {
        return Err(Failure::before(
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported_method",
            "inference requires POST",
        ));
    }
    Ok(Route::Inference(path))
}

async fn proxy_request_inner(
    state: &ProxyState,
    request: Request,
) -> Result<Response<Body>, Failure> {
    match route(&state.config, &request)? {
        Route::Refresh => {
            let original = state
                .evidence
                .current()
                .map_err(|error| Failure::evidence(&error))?;
            let snapshot = state
                .evidence
                .refresh(Instant::now() + SETUP_BUDGET)
                .await
                .map_err(|error| Failure::evidence(&error))?;
            let changed = original.is_none_or(|old| old.body_sha256() != snapshot.body_sha256());
            Ok(Response::builder()
                .status(if changed {
                    StatusCode::OK
                } else {
                    StatusCode::NO_CONTENT
                })
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }
        Route::Preflight => browser_preflight(&request)
            .map_err(|(status, message)| Failure::before(status, "invalid_preflight", message)),
        Route::Inference(path) => forward_request(state, request, &path).await,
    }
}

async fn forward_request(
    state: &ProxyState,
    request: Request,
    path: &str,
) -> Result<Response<Body>, Failure> {
    let deadline = Instant::now() + REQUEST_BUDGET;
    let (mut parts, body) = request.into_parts();
    let body = timeout_at(deadline, to_bytes(body, MAX_REQUEST_BYTES))
        .await
        .map_err(|_| {
            Failure::before(
                StatusCode::REQUEST_TIMEOUT,
                "deadline",
                "request upload deadline expired",
            )
        })?
        .map_err(|_| {
            Failure::before(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body",
                "request body exceeds its byte limit or was interrupted",
            )
        })?;
    let hop_headers: HashSet<String> = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|name| name.trim().to_ascii_lowercase()))
        .collect();
    let names: Vec<_> = parts
        .headers
        .keys()
        .filter(|name| {
            is_hop_by_hop(name)
                || is_local_browser_header(name)
                || **name == header::HOST
                || **name == header::CONTENT_LENGTH
                || hop_headers.contains(name.as_str())
        })
        .cloned()
        .collect();
    for name in names {
        parts.headers.remove(name);
    }
    let mut url = state.config.upstream.clone();
    url.set_path(path);
    parts.uri = url.as_str().parse().map_err(|_| {
        Failure::before(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "invalid upstream URI",
        )
    })?;
    let request = Request::from_parts(parts, body);
    let response = match &state.upstream {
        Upstream::Tls(client) => client
            .send(request, deadline)
            .await
            .map_err(|error| Failure::native(&error))?,
        Upstream::E2ee(client) => client
            .send(request, deadline)
            .await
            .map_err(|error| Failure::encrypted(&error))?,
    };
    let (mut parts, body) = response.into_parts();
    let names: Vec<_> = parts
        .headers
        .keys()
        .filter(|name| is_hop_by_hop(name) || **name == header::SET_COOKIE)
        .cloned()
        .collect();
    for name in names {
        parts.headers.remove(name);
    }
    let source = body.into_data_stream();
    let body = Body::from_stream(stream::unfold(Some(source), move |source| async move {
        let mut source = source?;
        match timeout_at(deadline, source.next()).await {
            Ok(Some(Ok(bytes))) => Some((Ok::<_, std::io::Error>(bytes), Some(source))),
            Ok(Some(Err(error))) => Some((Err(std::io::Error::other(error)), None)),
            Ok(None) => None,
            Err(_) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "response deadline expired; execution is unknown",
                )),
                None,
            )),
        }
    }));
    Ok(Response::from_parts(parts, body))
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
    if method != Method::POST {
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
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS")
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

#[cfg(test)]
mod tests;
