use axum::{
    body::{Body, Bytes},
    http::{HeaderName, HeaderValue, StatusCode, header, request::Parts},
    response::Response,
};
use futures_util::{Stream, StreamExt as _, stream};
use std::{collections::VecDeque, io, pin::Pin, time::Duration};
use stogas_verifier::e2ee::{
    RESPONSE_CONTENT_TYPE, Recipient, Request as EncryptedRequest, ResponseDecoder, ResponseEvent,
    ResponseMetadata, UpstreamCredential, seal_request,
};
use url::Url;

const REQUEST_ACCEPTANCE_WINDOW: Duration = Duration::from_mins(1);
const EXTRA_FIELDS_HEADER: &str = "x-stogas-extra-fields";
const UPSTREAM_PROVIDER_HEADER: &str = "x-stogas-upstream-provider";
const UPSTREAM_API_KEY_HEADER: &str = "x-stogas-upstream-api-key";
const E2EE_RESPONSE_HEADER: &str = "x-stogas-e2ee";
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
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, RESPONSE_CONTENT_TYPE)
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
            != Some(RESPONSE_CONTENT_TYPE)
        || upstream
            .headers()
            .get(E2EE_RESPONSE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("1")
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
    let extra_fields = match optional_header(
        &request.parts.headers,
        &HeaderName::from_static(EXTRA_FIELDS_HEADER),
        "invalid Stogas response field header",
    )? {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "X-Stogas-Extra-Fields must be true or false",
            ));
        }
    };
    let upstream_credential = pass_through_credential(&request.parts.headers)?;
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
        extra_fields,
        upstream_credential,
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

fn pass_through_credential(
    headers: &axum::http::HeaderMap,
) -> Result<Option<UpstreamCredential<'_>>, TransportError> {
    let upstream_provider = optional_header(
        headers,
        &HeaderName::from_static(UPSTREAM_PROVIDER_HEADER),
        "invalid pass-through provider credential",
    )?;
    let upstream_api_key = optional_header(
        headers,
        &HeaderName::from_static(UPSTREAM_API_KEY_HEADER),
        "invalid pass-through provider credential",
    )?;
    match (upstream_provider, upstream_api_key) {
        (Some("azure"), Some(_)) => Err((
            StatusCode::BAD_REQUEST,
            "Azure pass-through credentials are not supported",
        )),
        (Some(provider), Some(api_key)) => Ok(Some(UpstreamCredential { provider, api_key })),
        (None, None) => Ok(None),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "an upstream provider and API key are required together",
        )),
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
    fn pass_through_headers_are_complete_and_reject_azure() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(pass_through_credential(&headers).unwrap().is_none());

        headers.insert(
            HeaderName::from_static(UPSTREAM_API_KEY_HEADER),
            HeaderValue::from_static("provider-secret"),
        );
        assert!(pass_through_credential(&headers).is_err());

        headers.insert(
            HeaderName::from_static(UPSTREAM_PROVIDER_HEADER),
            HeaderValue::from_static("openai"),
        );
        let credential = pass_through_credential(&headers).unwrap().unwrap();
        assert_eq!(credential.provider, "openai");
        assert_eq!(credential.api_key, "provider-secret");

        headers.insert(
            HeaderName::from_static(UPSTREAM_PROVIDER_HEADER),
            HeaderValue::from_static("azure"),
        );
        assert!(pass_through_credential(&headers).is_err());
    }
}
