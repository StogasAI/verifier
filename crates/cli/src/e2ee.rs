use axum::{
    body::{Body, Bytes},
    http::{HeaderName, HeaderValue, StatusCode, header, request::Parts},
    response::Response,
};
use futures_util::{Stream, StreamExt as _, stream};
use std::{collections::VecDeque, io, pin::Pin, time::Duration};
use stogas_verifier::e2ee::{
    CONTENT_TYPE, Recipient, Request as EncryptedRequest, ResponseDecoder, ResponseEvent,
    ResponseMetadata, UpstreamCredentials, seal_request,
};
use url::Url;

const REQUEST_ACCEPTANCE_WINDOW: Duration = Duration::from_mins(1);
const UPSTREAM_ANTHROPIC_HEADER: &str = "x-stogas-upstream-anthropic-api-key";
const UPSTREAM_CHUTES_HEADER: &str = "x-stogas-upstream-chutes-api-key";
const UPSTREAM_OPENAI_HEADER: &str = "x-stogas-upstream-openai-api-key";
const LEGACY_UPSTREAM_PROVIDER_HEADER: &str = "x-stogas-upstream-provider";
const LEGACY_UPSTREAM_API_KEY_HEADER: &str = "x-stogas-upstream-api-key";
const E2EE_TRANSCRIPT_HEADER: &str = "x-stogas-e2ee-transcript-sha256";
const E2EE_HTTPS_CONNECTION_ERROR: &str =
    "E2EE HTTPS connection failed. Check the upstream URL, network, and WebPKI certificate.";

type TransportError = (StatusCode, &'static str);
type UpstreamStream = Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + 'static>>;

struct ResponseStream {
    upstream: UpstreamStream,
    decoder: ResponseDecoder,
    pending: VecDeque<Bytes>,
}

pub struct RequestContext<'a> {
    pub client: &'a reqwest::Client,
    pub upstream_origin: &'a Url,
    pub path: &'a str,
    pub parts: &'a Parts,
    pub body: Bytes,
    pub bundle_sha256: &'a [u8; 32],
    pub recipients: &'a [Recipient],
    pub now_unix_ms: i64,
    pub receipt: bool,
}

pub async fn send(request: RequestContext<'_>) -> Result<Response<Body>, TransportError> {
    if request.parts.method != axum::http::Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "encrypted inference requires POST",
        ));
    }
    if request.parts.uri.query().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "encrypted inference does not accept URL query parameters",
        ));
    }
    let sealed = seal(&request)?;
    let mut url = request.upstream_origin.clone();
    url.set_path(request.path);
    let upstream = request
        .client
        .post(url)
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .header(header::ACCEPT, CONTENT_TYPE)
        .header(header::CACHE_CONTROL, "no-store")
        .body(sealed.body)
        .send()
        .await
        .map_err(|error| {
            eprintln!("encrypted upstream request failed: {error:?}");
            if error.is_connect() {
                (StatusCode::BAD_GATEWAY, E2EE_HTTPS_CONNECTION_ERROR)
            } else {
                (StatusCode::BAD_GATEWAY, "encrypted upstream request failed")
            }
        })?;
    if upstream.status() != StatusCode::OK
        || upstream
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(CONTENT_TYPE)
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            "upstream did not return an encrypted response",
        ));
    }
    let mut state = ResponseStream {
        upstream: upstream.bytes_stream().boxed(),
        decoder: sealed.response,
        pending: VecDeque::new(),
    };
    let metadata = read_metadata(&mut state).await?;
    build_response(metadata, state, &sealed.transcript_sha256)
}

fn seal(
    request: &RequestContext<'_>,
) -> Result<stogas_verifier::e2ee::SealedRequest, TransportError> {
    let api_key = bearer_api_key(&request.parts.headers)?;
    let accept = optional_header(
        &request.parts.headers,
        &header::ACCEPT,
        "invalid Accept header",
    )?;
    let upstream_credentials = pass_through_credentials(&request.parts.headers)?;
    let expires_at_unix_ms = request
        .now_unix_ms
        .saturating_add(i64::try_from(REQUEST_ACCEPTANCE_WINDOW.as_millis()).unwrap_or(i64::MAX));
    seal_request(&EncryptedRequest {
        path: request.path,
        request_id: None,
        now_unix_ms: request.now_unix_ms,
        expires_at_unix_ms,
        bundle_sha256: &hex::encode(request.bundle_sha256),
        recipients: request.recipients,
        api_key,
        accept,
        receipt: request.receipt,
        upstream_credentials,
        body: &request.body,
    })
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "request cannot be encoded for encrypted inference",
        )
    })
}

fn build_response(
    metadata: ResponseMetadata,
    state: ResponseStream,
    transcript_sha256: &str,
) -> Result<Response<Body>, TransportError> {
    let status = StatusCode::from_u16(metadata.status_code).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "encrypted upstream response metadata is invalid",
        )
    })?;
    let content_type = HeaderValue::from_str(&metadata.content_type).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "encrypted upstream response metadata is invalid",
        )
    })?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(E2EE_TRANSCRIPT_HEADER, transcript_sha256);
    for (name, value) in metadata.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "encrypted upstream response metadata is invalid",
            )
        })?;
        let value = HeaderValue::from_str(&value).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "encrypted upstream response metadata is invalid",
            )
        })?;
        if !is_hop_by_hop(&name)
            && name != header::CONTENT_LENGTH
            && name != header::CONTENT_TYPE
            && !name.as_str().starts_with("access-control-")
        {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from_stream(decrypted_body(state)))
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "encrypted upstream response metadata is invalid",
            )
        })
}

fn bearer_api_key(headers: &axum::http::HeaderMap) -> Result<&str, TransportError> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "exactly one Bearer authorization value is required",
        ));
    }
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "exactly one Bearer authorization value is required",
        ))?;
    let (scheme, api_key) = value.split_once(' ').ok_or((
        StatusCode::UNAUTHORIZED,
        "a Bearer authorization value is required",
    ))?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || api_key.is_empty()
        || api_key.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "a Bearer authorization value is required",
        ));
    }
    Ok(api_key)
}

fn optional_header<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &HeaderName,
    message: &'static str,
) -> Result<Option<&'a str>, TransportError> {
    if headers.get_all(name).iter().count() > 1 {
        return Err((StatusCode::BAD_REQUEST, message));
    }
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| (StatusCode::BAD_REQUEST, message))
        })
        .transpose()
}

fn pass_through_credentials(
    headers: &axum::http::HeaderMap,
) -> Result<Option<UpstreamCredentials<'_>>, TransportError> {
    if headers.contains_key(LEGACY_UPSTREAM_PROVIDER_HEADER)
        || headers.contains_key(LEGACY_UPSTREAM_API_KEY_HEADER)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "generic upstream credential headers are unsupported",
        ));
    }
    let anthropic = optional_header(
        headers,
        &HeaderName::from_static(UPSTREAM_ANTHROPIC_HEADER),
        "invalid Anthropic pass-through credential",
    )?;
    let chutes = optional_header(
        headers,
        &HeaderName::from_static(UPSTREAM_CHUTES_HEADER),
        "invalid Chutes pass-through credential",
    )?;
    let openai = optional_header(
        headers,
        &HeaderName::from_static(UPSTREAM_OPENAI_HEADER),
        "invalid OpenAI pass-through credential",
    )?;
    if anthropic.is_none() && chutes.is_none() && openai.is_none() {
        Ok(None)
    } else {
        Ok(Some(UpstreamCredentials {
            anthropic,
            chutes,
            openai,
        }))
    }
}

async fn read_metadata(state: &mut ResponseStream) -> Result<ResponseMetadata, TransportError> {
    loop {
        let chunk = state.upstream.next().await.ok_or((
            StatusCode::BAD_GATEWAY,
            "encrypted upstream response was truncated",
        ))?;
        let chunk = chunk.map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "encrypted upstream response failed",
            )
        })?;
        let events = state.decoder.push(&chunk).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "encrypted upstream response is invalid",
            )
        })?;
        let mut metadata = None;
        for event in events {
            match event {
                ResponseEvent::Metadata(value) => metadata = Some(value),
                ResponseEvent::Data(bytes) => state.pending.push_back(Bytes::from(bytes)),
                ResponseEvent::Final => {}
            }
        }
        if let Some(metadata) = metadata {
            return Ok(metadata);
        }
    }
}

fn decrypted_body(
    state: ResponseStream,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    stream::try_unfold(state, |mut state| async move {
        loop {
            if let Some(bytes) = state.pending.pop_front() {
                return Ok(Some((bytes, state)));
            }
            if state.decoder.is_finished() {
                state
                    .decoder
                    .finish()
                    .map_err(|error| io::Error::other(error.to_string()))?;
                return Ok(None);
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    let events = state
                        .decoder
                        .push(&chunk)
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    for event in events {
                        match event {
                            ResponseEvent::Metadata(_) => {
                                return Err(io::Error::other(
                                    "duplicate encrypted response metadata",
                                ));
                            }
                            ResponseEvent::Data(bytes) => {
                                state.pending.push_back(Bytes::from(bytes));
                            }
                            ResponseEvent::Final => {}
                        }
                    }
                }
                Some(Err(error)) => return Err(io::Error::other(error)),
                None => {
                    state
                        .decoder
                        .finish()
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    return Ok(None);
                }
            }
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_auth_is_strict_and_case_insensitive() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bEaReR secret"),
        );
        assert_eq!(bearer_api_key(&headers).unwrap(), "secret");

        for value in ["Basic secret", "Bearer ", "Bearer secret value"] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            assert!(bearer_api_key(&headers).is_err());
        }
    }

    #[test]
    fn pass_through_headers_form_a_bounded_provider_pool() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(pass_through_credentials(&headers).unwrap().is_none());

        headers.insert(
            HeaderName::from_static(UPSTREAM_OPENAI_HEADER),
            HeaderValue::from_static("openai-secret"),
        );
        headers.insert(
            HeaderName::from_static(UPSTREAM_ANTHROPIC_HEADER),
            HeaderValue::from_static("anthropic-secret"),
        );
        let credentials = pass_through_credentials(&headers).unwrap().unwrap();
        assert_eq!(credentials.openai, Some("openai-secret"));
        assert_eq!(credentials.anthropic, Some("anthropic-secret"));
        assert_eq!(credentials.chutes, None);

        headers.insert(
            HeaderName::from_static(LEGACY_UPSTREAM_PROVIDER_HEADER),
            HeaderValue::from_static("openai"),
        );
        assert!(pass_through_credentials(&headers).is_err());
    }
}
