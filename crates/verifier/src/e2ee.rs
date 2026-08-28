//! Shared Stogas E2EE v1 request cryptography and response framing.
//!
//! HTTP runtimes remain thin adapters: they verify and select a bundle, call [`seal_request`],
//! send the returned JSON to the ordinary inference endpoint, then feed response bytes into
//! [`ResponseDecoder`]. The API deliberately owns no network, retry, or scheduling behavior.

use crate::{VerificationOutput, strict_json};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
    aes::cipher::consts::U12,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::AesGcm256, kdf::HkdfSha256, kem::XWing,
    setup_sender,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use sha2_v11::Sha256 as Sha256V11;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

/// Outer request and response media type for E2EE inference.
pub const CONTENT_TYPE: &str = "application/vnd.stogas.e2ee";
/// Current wire protocol version.
pub const VERSION: u8 = 1;
/// Maximum encoded E2EE request size accepted by the gateway.
pub const MAX_REQUEST_WIRE_BYTES: usize = 128 * 1024 * 1024;
/// Maximum encrypted inner request size.
pub const MAX_CIPHERTEXT_BYTES: usize = 94 * 1024 * 1024;
/// Maximum request acceptance interval allowed by a gateway.
pub const MAX_ACCEPTANCE_WINDOW_MS: i64 = 2 * 60 * 1_000;
/// Wall-clock skew accepted by a gateway when evaluating the request deadline.
pub const CLOCK_SKEW_ALLOWANCE_MS: i64 = 30 * 1_000;
/// Maximum authenticated plaintext bytes in one encrypted response body.
pub const MAX_RESPONSE_BODY_BYTES: usize = 65 * 1024 * 1024;
/// Maximum encrypted response bytes accepted from the network.
pub const MAX_RESPONSE_WIRE_BYTES: usize = 66 * 1024 * 1024;

const CONTENT_KEY_BYTES: usize = 32;
const KEY_ID_BYTES: usize = 32;
const RECIPIENT_PUBLIC_KEY_BYTES: usize = 1_216;
const MAX_V1_RECIPIENTS: usize = u16::MAX as usize;
const RESPONSE_TAG_BYTES: usize = 16;
const RESPONSE_RECORD_HEADER_BYTES: usize = 4;
const RESPONSE_NONCE_BYTES: usize = 12;
const MAX_RESPONSE_DATA_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_METADATA_BYTES: usize = 64 * 1024;
const RESPONSE_MAGIC: [u8; 5] = [b'S', b'T', b'G', b'E', VERSION];
const RESPONSE_PREAMBLE_BYTES: usize = RESPONSE_MAGIC.len() + RESPONSE_NONCE_BYTES;

type Kem = XWing;

/// E2EE protocol failure. No partially decrypted request or response is returned after an error.
#[derive(Debug, Error)]
pub enum Error {
    /// Caller-provided request or bundle material is invalid.
    #[error("invalid E2EE request: {0}")]
    InvalidRequest(String),
    /// Random generation or a cryptographic operation failed.
    #[error("E2EE cryptographic operation failed")]
    Crypto,
    /// The encrypted response is malformed, unauthenticated, or out of order.
    #[error("invalid E2EE response: {0}")]
    InvalidResponse(String),
    /// The response ended without an authenticated terminal record.
    #[error("encrypted response ended before its authenticated final record")]
    TruncatedResponse,
}

/// One quote-bound HPKE public key selected from a verified bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    /// Serialized MLKEM768-X25519 (X-Wing) public key bytes.
    pub public_key: Vec<u8>,
}

/// Optional provider credentials carried only inside the encrypted request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UpstreamCredentials<'a> {
    /// Anthropic API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<&'a str>,
    /// Chutes API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chutes: Option<&'a str>,
    /// OpenAI API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai: Option<&'a str>,
}

/// Complete input to one encrypted inference request.
pub struct Request<'a> {
    /// Existing OpenAI-compatible endpoint path.
    pub path: &'a str,
    /// Optional canonical UUID. A `UUIDv7` is generated when omitted.
    pub request_id: Option<&'a str>,
    /// One captured client wall-clock time.
    pub now_unix_ms: i64,
    /// Short request acceptance deadline.
    pub expires_at_unix_ms: i64,
    /// SHA-256 of the exact verified bundle bytes used to select recipients.
    pub bundle_sha256: &'a str,
    /// All nodes in the locally verified trust set.
    pub recipients: &'a [Recipient],
    /// Stogas API key, carried only inside the encrypted request.
    pub api_key: &'a str,
    /// Optional desired response media type.
    pub accept: Option<&'a str>,
    /// Request the v1 signed Stogas receipt.
    pub receipt: bool,
    /// Optional bounded pass-through provider credential pool.
    pub upstream_credentials: Option<UpstreamCredentials<'a>>,
    /// Ordinary JSON body for the selected inference endpoint.
    pub body: &'a [u8],
}

/// JSON body and response state produced for one encrypted request.
pub struct SealedRequest {
    /// JSON body sent to the ordinary inference endpoint.
    pub body: Vec<u8>,
    /// Unique ID cryptographically bound to this request and claimed once by the gateway.
    pub request_id: String,
    /// SHA-256 of the complete request transcript, retained for later receipt verification.
    pub transcript_sha256: String,
    /// Stateful authenticated response decoder for this request.
    pub response: ResponseDecoder,
}

/// Authenticated inner HTTP response metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMetadata {
    /// Inner HTTP status code.
    #[serde(rename = "status")]
    pub status_code: u16,
    /// Inner response content type.
    pub content_type: String,
    /// Bounded response headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// One incrementally authenticated response event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseEvent {
    /// First record containing the inner status, media type, and safe headers.
    Metadata(ResponseMetadata),
    /// One body or SSE byte segment.
    Data(Vec<u8>),
    /// Authenticated empty record at the clean end of response.
    Final,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    request_id: String,
    bundle_sha256: String,
    expires_at_ms: i64,
    recipients: Vec<WrappedRecipient>,
    ciphertext: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WrappedRecipient {
    key_id: String,
    encapsulated_key: String,
    wrapped_key: String,
}

#[derive(Serialize)]
struct InnerRequest<'a> {
    api_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    accept: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_credentials: Option<UpstreamCredentials<'a>>,
    body: &'a RawValue,
}

struct PreparedRecipient {
    key_id: [u8; KEY_ID_BYTES],
    public_key: <Kem as hpke::Kem>::PublicKey,
}

/// Return the exact-byte SHA-256 identifier carried in an E2EE request transcript.
#[must_use]
pub fn bundle_sha256(bundle_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bundle_bytes))
}

/// Extract the HPKE recipients from the locally trusted node set of an accepted bundle.
///
/// # Errors
///
/// Returns an error if the verified output unexpectedly contains malformed or duplicate keys.
pub fn recipients_from_verified_bundle(
    output: &VerificationOutput,
) -> Result<Vec<Recipient>, Error> {
    let recipients = output
        .bundle
        .nodes
        .iter()
        .map(|node| {
            let public_key =
                decode_canonical_base64(&node.report_data.hpke_public_key, "node HPKE public key")?;
            if public_key.len() != RECIPIENT_PUBLIC_KEY_BYTES {
                return Err(Error::InvalidRequest(
                    "node HPKE public key must contain 1216 bytes".into(),
                ));
            }
            Ok(Recipient { public_key })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    prepare_recipients(&recipients)?;
    Ok(recipients)
}

/// Encrypt one request to every node in a verified trust set.
///
/// # Errors
///
/// Returns an error for invalid input, random generation failure, or cryptographic failure.
pub fn seal_request(request: &Request<'_>) -> Result<SealedRequest, Error> {
    validate_request(request)?;
    let request_id = request.request_id.map_or_else(
        || generate_uuid_v7(request.now_unix_ms),
        |value| {
            parse_canonical_uuid(value)?;
            Ok(value.to_owned())
        },
    )?;
    let uuid = parse_canonical_uuid(&request_id)?;
    let bundle_hash = decode_lower_hex_32(request.bundle_sha256, "bundle_sha256")?;
    let recipients = prepare_recipients(request.recipients)?;
    let key_ids = recipients
        .iter()
        .map(|recipient| recipient.key_id)
        .collect::<Vec<_>>();
    let transcript = build_transcript(
        request.path,
        uuid,
        bundle_hash,
        request.expires_at_unix_ms,
        &key_ids,
    )?;
    let transcript_hash: [u8; 32] = Sha256::digest(&transcript).into();

    let mut content_key = Zeroizing::new([0_u8; CONTENT_KEY_BYTES]);
    getrandom::fill(content_key.as_mut()).map_err(|_| Error::Crypto)?;
    let raw_body = std::str::from_utf8(request.body)
        .map_err(|_| Error::InvalidRequest("inner body must be UTF-8 JSON".into()))?;
    let raw_body = RawValue::from_string(raw_body.to_owned())
        .map_err(|_| Error::InvalidRequest("inner body must be valid JSON".into()))?;
    let inner = Zeroizing::new(
        serde_json::to_vec(&InnerRequest {
            api_key: request.api_key,
            accept: request.accept,
            receipt: request.receipt.then_some("v1"),
            upstream_credentials: request.upstream_credentials,
            body: &raw_body,
        })
        .map_err(|_| Error::InvalidRequest("inner request could not be encoded".into()))?,
    );
    let (request_cipher, request_nonce, response_cipher) =
        derive_ciphers(content_key.as_ref(), &transcript_hash)?;
    let request_nonce_ref: &Nonce<U12> = request_nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto)?;
    let ciphertext = request_cipher
        .encrypt(
            request_nonce_ref,
            Payload {
                msg: inner.as_ref(),
                aad: &transcript,
            },
        )
        .map_err(|_| Error::Crypto)?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(Error::InvalidRequest(
            "encrypted inner request exceeds the protocol limit".into(),
        ));
    }

    let info = hpke_info(&transcript_hash);
    let mut wrapped_recipients = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let (encapsulated_key, mut sender) = setup_sender::<AesGcm256, HkdfSha256, Kem>(
            &OpModeS::Base,
            &recipient.public_key,
            &info,
        )
        .map_err(|_| Error::Crypto)?;
        let wrapped_key = sender
            .seal(content_key.as_ref(), &transcript)
            .map_err(|_| Error::Crypto)?;
        wrapped_recipients.push(WrappedRecipient {
            key_id: URL_SAFE_NO_PAD.encode(recipient.key_id),
            encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated_key.to_bytes()),
            wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
        });
    }

    let body = serde_json::to_vec(&Envelope {
        version: VERSION,
        request_id: request_id.clone(),
        bundle_sha256: request.bundle_sha256.to_owned(),
        expires_at_ms: request.expires_at_unix_ms,
        recipients: wrapped_recipients,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(|_| Error::Crypto)?;
    validate_request_wire_size(body.len())?;
    Ok(SealedRequest {
        body,
        request_id,
        transcript_sha256: hex::encode(transcript_hash),
        response: ResponseDecoder::new(response_cipher, transcript_hash),
    })
}

fn validate_request(request: &Request<'_>) -> Result<(), Error> {
    if !matches!(request.path, "/v1/chat/completions" | "/v1/responses") {
        return Err(Error::InvalidRequest(
            "path must be /v1/chat/completions or /v1/responses".into(),
        ));
    }
    if request.expires_at_unix_ms <= request.now_unix_ms {
        return Err(Error::InvalidRequest(
            "acceptance deadline must be in the future".into(),
        ));
    }
    if request.expires_at_unix_ms > request.now_unix_ms.saturating_add(MAX_ACCEPTANCE_WINDOW_MS) {
        return Err(Error::InvalidRequest(
            "acceptance deadline exceeds two minutes".into(),
        ));
    }
    if !valid_credential(request.api_key) {
        return Err(Error::InvalidRequest(
            "api_key must contain 1 to 4096 visible ASCII bytes".into(),
        ));
    }
    if let Some(credentials) = request.upstream_credentials {
        if credentials.anthropic.is_none()
            && credentials.chutes.is_none()
            && credentials.openai.is_none()
        {
            return Err(Error::InvalidRequest(
                "upstream_credentials must not be empty".into(),
            ));
        }
        for credential in [
            credentials.anthropic,
            credentials.chutes,
            credentials.openai,
        ]
        .into_iter()
        .flatten()
        {
            if !valid_credential(credential) {
                return Err(Error::InvalidRequest(
                    "upstream credential is invalid".into(),
                ));
            }
        }
    }
    for (name, value, max) in [("accept", request.accept, 256)] {
        if let Some(value) = value
            && (value.len() > max || !valid_http_field_value(value, false))
        {
            return Err(Error::InvalidRequest(format!("{name} is too large")));
        }
    }
    if request.body.is_empty() || request.body.len() > MAX_CIPHERTEXT_BYTES - RESPONSE_TAG_BYTES {
        return Err(Error::InvalidRequest(
            "inner body is empty or exceeds the protocol limit".into(),
        ));
    }
    Ok(())
}

fn valid_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4 * 1024
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_http_field_value(value: &str, allow_empty: bool) -> bool {
    if value.is_empty() {
        return allow_empty;
    }
    value.trim() == value
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn valid_http_field_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_content_type(value: &str) -> bool {
    if value.len() > 256 || !valid_http_field_value(value, false) {
        return false;
    }
    let media_type = value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type);
    let Some((major, minor)) = media_type.split_once('/') else {
        return false;
    };
    !minor.contains('/') && valid_http_field_name(major) && valid_http_field_name(minor)
}

fn prepare_recipients(recipients: &[Recipient]) -> Result<Vec<PreparedRecipient>, Error> {
    validate_recipient_count(recipients.len())?;
    let mut prepared = recipients
        .iter()
        .map(|recipient| {
            if recipient.public_key.len() != RECIPIENT_PUBLIC_KEY_BYTES {
                return Err(Error::InvalidRequest(
                    "recipient X-Wing public key must contain 1216 bytes".into(),
                ));
            }
            let public_key = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient.public_key)
                .map_err(|_| Error::InvalidRequest("invalid recipient X-Wing public key".into()))?;
            Ok(PreparedRecipient {
                key_id: Sha256::digest(&recipient.public_key).into(),
                public_key,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    prepared.sort_unstable_by_key(|recipient| recipient.key_id);
    if prepared
        .windows(2)
        .any(|window| window[0].key_id == window[1].key_id)
    {
        return Err(Error::InvalidRequest("duplicate recipient".into()));
    }
    Ok(prepared)
}

fn validate_recipient_count(count: usize) -> Result<u16, Error> {
    if count == 0 {
        return Err(Error::InvalidRequest(
            "at least one recipient is required".into(),
        ));
    }
    u16::try_from(count).map_err(|_| {
        Error::InvalidRequest(format!(
            "recipient count exceeds the E2EE v1 wire limit of {MAX_V1_RECIPIENTS}"
        ))
    })
}

fn validate_request_wire_size(size: usize) -> Result<(), Error> {
    if size > MAX_REQUEST_WIRE_BYTES {
        return Err(Error::InvalidRequest(
            "encoded E2EE envelope exceeds the protocol limit".into(),
        ));
    }
    Ok(())
}

fn build_transcript(
    path: &str,
    request_id: [u8; 16],
    bundle_hash: [u8; 32],
    expires_at_unix_ms: i64,
    key_ids: &[[u8; KEY_ID_BYTES]],
) -> Result<Vec<u8>, Error> {
    let count = validate_recipient_count(key_ids.len())?;
    let mut output = Vec::with_capacity(128 + key_ids.len() * KEY_ID_BYTES);
    output.extend_from_slice(b"stogas.e2ee.request.v1");
    output.push(0);
    write_length_prefixed(&mut output, b"POST")?;
    write_length_prefixed(&mut output, path.as_bytes())?;
    output.extend_from_slice(&request_id);
    output.extend_from_slice(&bundle_hash);
    output.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for key_id in key_ids {
        output.extend_from_slice(key_id);
    }
    Ok(output)
}

fn write_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let length = u16::try_from(value.len())
        .map_err(|_| Error::InvalidRequest("transcript field is too large".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn derive_ciphers(
    content_key: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<(Aes256Gcm, [u8; 12], Aes256Gcm), Error> {
    let hkdf = Hkdf::<Sha256V11>::new(Some(transcript_hash), content_key);
    let mut request_key = Zeroizing::new([0_u8; 32]);
    let mut request_nonce = [0_u8; 12];
    let mut response_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(b"stogas.e2ee.request.key.v1", request_key.as_mut())
        .map_err(|_| Error::Crypto)?;
    hkdf.expand(b"stogas.e2ee.request.nonce.v1", &mut request_nonce)
        .map_err(|_| Error::Crypto)?;
    hkdf.expand(b"stogas.e2ee.response.key.v1", response_key.as_mut())
        .map_err(|_| Error::Crypto)?;
    let request = Aes256Gcm::new_from_slice(request_key.as_ref()).map_err(|_| Error::Crypto)?;
    let response = Aes256Gcm::new_from_slice(response_key.as_ref()).map_err(|_| Error::Crypto)?;
    Ok((request, request_nonce, response))
}

fn hpke_info(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(32 + 30);
    info.extend_from_slice(b"stogas.e2ee.content-key.v1");
    info.push(0);
    info.extend_from_slice(transcript_hash);
    info
}

fn decode_lower_hex_32(value: &str, name: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidRequest(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        )));
    }
    let decoded =
        hex::decode(value).map_err(|_| Error::InvalidRequest(format!("invalid {name}")))?;
    decoded
        .try_into()
        .map_err(|_| Error::InvalidRequest(format!("invalid {name}")))
}

fn decode_canonical_base64(value: &str, name: &str) -> Result<Vec<u8>, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidRequest(format!("invalid {name}")))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(Error::InvalidRequest(format!(
            "{name} must use canonical unpadded base64url"
        )));
    }
    Ok(decoded)
}

fn generate_uuid_v7(now_unix_ms: i64) -> Result<String, Error> {
    let timestamp = u64::try_from(now_unix_ms)
        .map_err(|_| Error::InvalidRequest("wall clock is before the Unix epoch".into()))?;
    if timestamp >= (1_u64 << 48) {
        return Err(Error::InvalidRequest(
            "wall clock is outside the UUIDv7 range".into(),
        ));
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Crypto)?;
    let encoded_timestamp = timestamp.to_be_bytes();
    bytes[..6].copy_from_slice(&encoded_timestamp[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format_uuid(bytes))
}

fn parse_canonical_uuid(value: &str) -> Result<[u8; 16], Error> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(Error::InvalidRequest(
            "request_id must be a canonical UUID".into(),
        ));
    }
    let mut compact = [0_u8; 32];
    let mut cursor = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return Err(Error::InvalidRequest(
                "request_id must be a lowercase canonical UUID".into(),
            ));
        }
        compact[cursor] = byte;
        cursor += 1;
    }
    let decoded = hex::decode(compact)
        .map_err(|_| Error::InvalidRequest("request_id must be a canonical UUID".into()))?;
    decoded
        .try_into()
        .map_err(|_| Error::InvalidRequest("request_id must be a canonical UUID".into()))
}

fn format_uuid(bytes: [u8; 16]) -> String {
    let encoded = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..]
    )
}

/// Incremental decoder for authenticated buffered and SSE responses.
pub struct ResponseDecoder {
    cipher: Aes256Gcm,
    base_nonce: [u8; RESPONSE_NONCE_BYTES],
    transcript_hash: [u8; 32],
    buffer: Vec<u8>,
    offset: usize,
    wire_bytes: usize,
    body_bytes: usize,
    sequence: u64,
    state: ResponseDecoderState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseDecoderState {
    AwaitingPreamble,
    AwaitingMetadata,
    Streaming,
    Finished,
    Failed,
}

impl ResponseDecoder {
    const fn new(cipher: Aes256Gcm, transcript_hash: [u8; 32]) -> Self {
        Self {
            cipher,
            base_nonce: [0; RESPONSE_NONCE_BYTES],
            transcript_hash,
            buffer: Vec::new(),
            offset: 0,
            wire_bytes: 0,
            body_bytes: 0,
            sequence: 0,
            state: ResponseDecoderState::AwaitingPreamble,
        }
    }

    /// Authenticate and consume another network chunk.
    ///
    /// # Errors
    ///
    /// Returns an error on any malformed, reordered, oversized, or unauthenticated record.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<ResponseEvent>, Error> {
        if self.state == ResponseDecoderState::Failed {
            return Err(Error::InvalidResponse("response decoder has failed".into()));
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.state = ResponseDecoderState::Failed;
            self.buffer.zeroize();
            self.buffer.clear();
            self.offset = 0;
        }
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> Result<Vec<ResponseEvent>, Error> {
        if self.state == ResponseDecoderState::Finished {
            return Ok(Vec::new());
        }
        let remaining = MAX_RESPONSE_WIRE_BYTES.saturating_sub(self.wire_bytes);
        let accepted = bytes.len().min(remaining);
        self.wire_bytes += accepted;
        self.buffer.extend_from_slice(&bytes[..accepted]);
        let exceeded_wire_limit = accepted != bytes.len();
        let mut events = Vec::new();
        if !self.consume_preamble()? {
            if exceeded_wire_limit {
                return Err(Error::InvalidResponse(
                    "encrypted response is too large".into(),
                ));
            }
            return Ok(events);
        }
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        self.compact();
        if exceeded_wire_limit && self.state != ResponseDecoderState::Finished {
            return Err(Error::InvalidResponse(
                "encrypted response is too large".into(),
            ));
        }
        Ok(events)
    }

    /// Require an authenticated clean end of stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedResponse`] unless a final record was consumed.
    pub fn finish(&self) -> Result<(), Error> {
        if self.state == ResponseDecoderState::Failed {
            return Err(Error::InvalidResponse("response decoder has failed".into()));
        }
        if self.state != ResponseDecoderState::Finished || self.available() != 0 {
            return Err(Error::TruncatedResponse);
        }
        Ok(())
    }

    /// Whether the authenticated final record has been consumed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.state, ResponseDecoderState::Finished)
    }

    const fn available(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    fn peek(&self, length: usize) -> &[u8] {
        &self.buffer[self.offset..self.offset + length]
    }

    fn compact(&mut self) {
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        } else if self.offset >= MAX_RESPONSE_DATA_BYTES {
            self.buffer.drain(..self.offset);
            self.offset = 0;
        }
    }

    fn consume_preamble(&mut self) -> Result<bool, Error> {
        if self.state != ResponseDecoderState::AwaitingPreamble {
            return Ok(true);
        }
        if self.available() < RESPONSE_PREAMBLE_BYTES {
            return Ok(false);
        }
        if self.peek(RESPONSE_MAGIC.len()) != RESPONSE_MAGIC {
            return Err(Error::InvalidResponse("invalid response magic".into()));
        }
        let response_nonce: [u8; RESPONSE_NONCE_BYTES] = self.buffer
            [self.offset + RESPONSE_MAGIC.len()..self.offset + RESPONSE_PREAMBLE_BYTES]
            .try_into()
            .map_err(|_| Error::InvalidResponse("invalid response nonce".into()))?;
        self.base_nonce = response_nonce;
        self.offset += RESPONSE_PREAMBLE_BYTES;
        self.state = ResponseDecoderState::AwaitingMetadata;
        Ok(true)
    }

    fn next_event(&mut self) -> Result<Option<ResponseEvent>, Error> {
        if self.available() < RESPONSE_RECORD_HEADER_BYTES {
            return Ok(None);
        }
        let header: [u8; RESPONSE_RECORD_HEADER_BYTES] = self
            .peek(RESPONSE_RECORD_HEADER_BYTES)
            .try_into()
            .map_err(|_| Error::InvalidResponse("invalid record header".into()))?;
        let ciphertext_length = parse_response_record_length(header, self.sequence)?;
        let record_length = RESPONSE_RECORD_HEADER_BYTES
            .checked_add(ciphertext_length)
            .ok_or_else(|| Error::InvalidResponse("invalid record length".into()))?;
        if self.available() < record_length {
            return Ok(None);
        }
        let plaintext = self.decrypt_record(record_length)?;
        let sequence = self.sequence;
        self.offset += record_length;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::InvalidResponse("response sequence exhausted".into()))?;
        self.apply_record(sequence, plaintext).map(Some)
    }

    fn decrypt_record(&self, record_length: usize) -> Result<Vec<u8>, Error> {
        let ciphertext =
            &self.buffer[self.offset + RESPONSE_RECORD_HEADER_BYTES..self.offset + record_length];
        let nonce = response_nonce(self.base_nonce, self.sequence);
        let aad = response_aad(&self.transcript_hash, self.sequence);
        self.cipher
            .decrypt(
                <&Nonce<U12>>::try_from(nonce.as_slice())
                    .map_err(|_| Error::InvalidResponse("invalid response nonce".into()))?,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::InvalidResponse("response record authentication failed".into()))
    }

    fn apply_record(&mut self, sequence: u64, plaintext: Vec<u8>) -> Result<ResponseEvent, Error> {
        if sequence == 0 {
            return self.apply_metadata(&plaintext);
        }
        if self.state != ResponseDecoderState::Streaming {
            return Err(Error::InvalidResponse(
                "response record is out of order".into(),
            ));
        }
        if plaintext.is_empty() {
            self.state = ResponseDecoderState::Finished;
            self.offset = self.buffer.len();
            return Ok(ResponseEvent::Final);
        }
        self.body_bytes = self
            .body_bytes
            .checked_add(plaintext.len())
            .filter(|size| *size <= MAX_RESPONSE_BODY_BYTES)
            .ok_or_else(|| Error::InvalidResponse("response body is too large".into()))?;
        Ok(ResponseEvent::Data(plaintext))
    }

    fn apply_metadata(&mut self, plaintext: &[u8]) -> Result<ResponseEvent, Error> {
        if self.state != ResponseDecoderState::AwaitingMetadata {
            return Err(Error::InvalidResponse(
                "metadata record is out of order".into(),
            ));
        }
        let value = strict_json::from_slice(plaintext)
            .map_err(|_| Error::InvalidResponse("invalid response metadata JSON".into()))?;
        let metadata: ResponseMetadata = serde_json::from_value(value)
            .map_err(|_| Error::InvalidResponse("invalid response metadata".into()))?;
        validate_response_metadata(&metadata)?;
        self.state = ResponseDecoderState::Streaming;
        Ok(ResponseEvent::Metadata(metadata))
    }
}

fn parse_response_record_length(
    header: [u8; RESPONSE_RECORD_HEADER_BYTES],
    sequence: u64,
) -> Result<usize, Error> {
    let ciphertext_length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| Error::InvalidResponse("invalid record length".into()))?;
    let plaintext_limit = if sequence == 0 {
        MAX_RESPONSE_METADATA_BYTES
    } else {
        MAX_RESPONSE_DATA_BYTES
    };
    if ciphertext_length < RESPONSE_TAG_BYTES
        || ciphertext_length > plaintext_limit + RESPONSE_TAG_BYTES
    {
        return Err(Error::InvalidResponse(
            "response record exceeds its size limit".into(),
        ));
    }
    Ok(ciphertext_length)
}

impl Drop for ResponseDecoder {
    fn drop(&mut self) {
        self.base_nonce.zeroize();
        self.transcript_hash.zeroize();
        self.buffer.zeroize();
    }
}

fn validate_response_metadata(metadata: &ResponseMetadata) -> Result<(), Error> {
    if !(200..=599).contains(&metadata.status_code) {
        return Err(Error::InvalidResponse(
            "inner HTTP status is invalid".into(),
        ));
    }
    if !valid_content_type(&metadata.content_type) {
        return Err(Error::InvalidResponse(
            "inner Content-Type is invalid".into(),
        ));
    }
    if metadata.headers.len() > 32 {
        return Err(Error::InvalidResponse(
            "too many inner response headers".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for (name, value) in &metadata.headers {
        if name.len() > 128
            || value.len() > 16 * 1024
            || !valid_http_field_name(name)
            || !valid_http_field_value(value, true)
            || !seen.insert(name.to_ascii_lowercase())
        {
            return Err(Error::InvalidResponse(
                "inner response header is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn response_aad(transcript_hash: &[u8; 32], sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(72);
    aad.extend_from_slice(b"stogas.e2ee.response.record.v1");
    aad.push(0);
    aad.extend_from_slice(transcript_hash);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn response_nonce(mut base_nonce: [u8; 12], sequence: u64) -> [u8; 12] {
    let encoded = sequence.to_be_bytes();
    for (target, source) in base_nonce[4..].iter_mut().zip(encoded) {
        *target ^= source;
    }
    base_nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Kem as _;
    use serde_json::Value;

    const NOW_MS: i64 = 1_800_000_000_000;
    const REQUEST_ID: &str = "018f4f70-7c88-7b9a-baf8-31a93d2cf613";
    const BUNDLE_HASH: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    #[test]
    fn seal_request_builds_a_canonical_multi_recipient_envelope() {
        let mut recipients = vec![recipient(), recipient(), recipient()];
        recipients.reverse();
        let sealed = seal_request(&Request {
            path: "/v1/responses",
            request_id: Some(REQUEST_ID),
            now_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 60_000,
            bundle_sha256: BUNDLE_HASH,
            recipients: &recipients,
            api_key: "sk-stogas-secret",
            accept: Some("text/event-stream"),
            receipt: true,
            upstream_credentials: Some(UpstreamCredentials {
                anthropic: Some("sk-anthropic-secret"),
                chutes: None,
                openai: Some("sk-provider-secret"),
            }),
            body: br#"{"model":"gpt-5","input":"hello"}"#,
        })
        .unwrap();
        assert_eq!(sealed.request_id, REQUEST_ID);
        assert_eq!(sealed.transcript_sha256.len(), 64);
        assert!(
            sealed
                .transcript_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let value: Value = serde_json::from_slice(&sealed.body).unwrap();
        let envelope = &value;
        assert_eq!(envelope["version"], VERSION);
        assert_eq!(envelope["request_id"], REQUEST_ID);
        assert_eq!(envelope["bundle_sha256"], BUNDLE_HASH);
        let wrapped = envelope["recipients"].as_array().unwrap();
        assert_eq!(wrapped.len(), 3);
        let ids = wrapped
            .iter()
            .map(|entry| {
                decode_canonical_base64(entry["key_id"].as_str().unwrap(), "key id").unwrap()
            })
            .collect::<Vec<_>>();
        assert!(ids.windows(2).all(|window| window[0] < window[1]));
        assert!(!String::from_utf8_lossy(&sealed.body).contains("sk-stogas-secret"));
        assert!(!String::from_utf8_lossy(&sealed.body).contains("sk-provider-secret"));
        assert!(!String::from_utf8_lossy(&sealed.body).contains("hello"));
    }

    #[test]
    fn generated_request_id_is_canonical_uuid_v7() {
        let recipients = [recipient()];
        let sealed = seal_request(&Request {
            path: "/v1/chat/completions",
            request_id: None,
            now_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 60_000,
            bundle_sha256: BUNDLE_HASH,
            recipients: &recipients,
            api_key: "sk-stogas-secret",
            accept: None,
            receipt: false,
            upstream_credentials: None,
            body: br#"{"model":"gpt-5","messages":[]}"#,
        })
        .unwrap();
        let parsed = parse_canonical_uuid(&sealed.request_id).unwrap();
        assert_eq!(parsed[6] >> 4, 7);
        assert_eq!(parsed[8] >> 6, 2);
        assert_eq!(
            &parsed[..6],
            &u64::try_from(NOW_MS).unwrap().to_be_bytes()[2..]
        );
    }

    #[test]
    fn seal_request_rejects_invalid_route_identity_and_timing() {
        let valid_recipient = recipient();
        let mut request = valid_request(&valid_recipient);
        request.path = "/v1/unknown";
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.request_id = Some("not-a-uuid");
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.expires_at_unix_ms = NOW_MS;
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.expires_at_unix_ms = NOW_MS + MAX_ACCEPTANCE_WINDOW_MS + 1;
        assert_invalid_request(&request);
    }

    #[test]
    fn seal_request_rejects_invalid_recipient_sets() {
        let valid_recipient = recipient();
        let duplicate = [valid_recipient.clone(), valid_recipient.clone()];
        let mut request = valid_request(&valid_recipient);
        request.recipients = &[];
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.recipients = &duplicate;
        assert_invalid_request(&request);
    }

    #[test]
    fn seal_request_accepts_sixty_five_recipients() {
        let recipients = (0..65).map(|_| recipient()).collect::<Vec<_>>();
        let mut request = valid_request(&recipients[0]);
        request.recipients = &recipients;
        let sealed = seal_request(&request).unwrap();
        let envelope: Envelope = serde_json::from_slice(&sealed.body).unwrap();
        assert_eq!(envelope.recipients.len(), recipients.len());
        assert!(sealed.body.len() <= MAX_REQUEST_WIRE_BYTES);
    }

    #[test]
    fn recipient_count_cannot_overflow_the_v1_transcript() {
        let key_ids = vec![[0_u8; KEY_ID_BYTES]; MAX_V1_RECIPIENTS + 1];
        assert!(build_transcript("/v1/responses", [0; 16], [0; 32], NOW_MS, &key_ids).is_err());
    }

    #[test]
    fn request_wire_size_accepts_the_boundary_and_rejects_larger_envelopes() {
        assert!(validate_request_wire_size(MAX_REQUEST_WIRE_BYTES).is_ok());
        assert!(validate_request_wire_size(MAX_REQUEST_WIRE_BYTES + 1).is_err());
    }

    #[test]
    fn seal_request_rejects_invalid_inner_request() {
        let valid_recipient = recipient();
        let mut request = valid_request(&valid_recipient);
        request.api_key = "sk-test\r\nX-Evil: yes";
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.api_key = "sk test";
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.api_key = "sk-tést";
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.accept = Some("application/json\u{1}");
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.accept = Some(" application/json");
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.upstream_credentials = Some(UpstreamCredentials {
            anthropic: None,
            chutes: None,
            openai: Some("provider key with spaces"),
        });
        assert_invalid_request(&request);
        request = valid_request(&valid_recipient);
        request.body = b"{";
        assert_invalid_request(&request);
    }

    #[test]
    fn response_decoder_streams_authenticates_and_requires_final() {
        let mut decoder = sealed_request().response;
        let encoded = encode_response(
            &decoder,
            &ResponseMetadata {
                status_code: 200,
                content_type: "text/event-stream".into(),
                headers: BTreeMap::from([("Cache-Control".into(), "no-cache".into())]),
            },
            &[b"data: one\n\n", b"data: two\n\n"],
        );
        let mut events = Vec::new();
        for byte in encoded {
            events.extend(decoder.push(&[byte]).unwrap());
        }
        decoder.finish().unwrap();
        assert_eq!(
            events,
            vec![
                ResponseEvent::Metadata(ResponseMetadata {
                    status_code: 200,
                    content_type: "text/event-stream".into(),
                    headers: BTreeMap::from([("Cache-Control".into(), "no-cache".into())]),
                }),
                ResponseEvent::Data(b"data: one\n\n".to_vec()),
                ResponseEvent::Data(b"data: two\n\n".to_vec()),
                ResponseEvent::Final,
            ]
        );
    }

    #[test]
    fn response_decoder_rejects_tampering_truncation_and_reordering_then_stops_at_final() {
        let metadata = ResponseMetadata {
            status_code: 200,
            content_type: "application/json".into(),
            headers: BTreeMap::new(),
        };
        let mut decoder = baseline_response_decoder();
        let mut tampered = encode_response(&decoder, &metadata, &[br#"{"ok":true}"#]);
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(decoder.push(&tampered).is_err());

        let mut truncated = baseline_response_decoder();
        let encoded = encode_response(&truncated, &metadata, &[br#"{"ok":true}"#]);
        truncated.push(&encoded[..encoded.len() - 1]).unwrap();
        assert!(matches!(truncated.finish(), Err(Error::TruncatedResponse)));

        let mut trailing = baseline_response_decoder();
        let mut with_trailing = encode_response(&trailing, &metadata, &[br#"{"ok":true}"#]);
        with_trailing.push(0);
        assert!(
            trailing
                .push(&with_trailing)
                .unwrap()
                .contains(&ResponseEvent::Final)
        );
        assert!(trailing.push(b"later network chunk").unwrap().is_empty());
        trailing.finish().unwrap();

        let mut bounded_trailing = baseline_response_decoder();
        let encoded = encode_response(&bounded_trailing, &metadata, &[br#"{"ok":true}"#]);
        let final_record_bytes = RESPONSE_RECORD_HEADER_BYTES + RESPONSE_TAG_BYTES;
        let final_record_start = encoded.len() - final_record_bytes;
        bounded_trailing
            .push(&encoded[..final_record_start])
            .unwrap();
        bounded_trailing.wire_bytes = MAX_RESPONSE_WIRE_BYTES - final_record_bytes;
        let mut final_with_excess = encoded[final_record_start..].to_vec();
        final_with_excess.push(0);
        assert_eq!(
            bounded_trailing.push(&final_with_excess).unwrap(),
            vec![ResponseEvent::Final]
        );
        bounded_trailing.finish().unwrap();

        let mut early_final = baseline_response_decoder();
        let authenticated_trailing = encode_response(&early_final, &metadata, &[b"", b"later"]);
        assert_eq!(
            early_final.push(&authenticated_trailing).unwrap(),
            vec![
                ResponseEvent::Metadata(metadata.clone()),
                ResponseEvent::Final,
            ]
        );
        early_final.finish().unwrap();

        let mut reordered_decoder = baseline_response_decoder();
        let encoded = encode_response(&reordered_decoder, &metadata, &[br#"{"ok":true}"#]);
        let metadata_end = response_record_end(&encoded, RESPONSE_PREAMBLE_BYTES);
        let body_end = response_record_end(&encoded, metadata_end);
        let mut reordered = encoded[..RESPONSE_PREAMBLE_BYTES].to_vec();
        reordered.extend_from_slice(&encoded[metadata_end..body_end]);
        reordered.extend_from_slice(&encoded[RESPONSE_PREAMBLE_BYTES..metadata_end]);
        reordered.extend_from_slice(&encoded[body_end..]);
        assert!(reordered_decoder.push(&reordered).is_err());
    }

    #[test]
    fn response_decoder_rejects_unsupported_or_tampered_nonce_preambles_permanently() {
        let metadata = ResponseMetadata {
            status_code: 200,
            content_type: "application/json".into(),
            headers: BTreeMap::new(),
        };

        let mut unsupported_decoder = baseline_response_decoder();
        let mut unsupported = encode_response(&unsupported_decoder, &metadata, &[]);
        unsupported[4] = VERSION + 1;
        assert!(unsupported_decoder.push(&unsupported).is_err());
        assert!(unsupported_decoder.push(&[]).is_err());
        assert!(!unsupported_decoder.is_finished());

        let mut tampered_decoder = baseline_response_decoder();
        let mut tampered = encode_response_with_nonce(
            &tampered_decoder,
            &metadata,
            &[],
            [0x5a; RESPONSE_NONCE_BYTES],
        );
        tampered[RESPONSE_MAGIC.len()] ^= 1;
        assert!(tampered_decoder.push(&tampered).is_err());
        assert!(tampered_decoder.finish().is_err());
    }

    #[test]
    fn response_decoder_enforces_aggregate_wire_and_body_limits() {
        let metadata = ResponseMetadata {
            status_code: 200,
            content_type: "application/json".into(),
            headers: BTreeMap::new(),
        };
        let mut wire_decoder = baseline_response_decoder();
        wire_decoder.wire_bytes = MAX_RESPONSE_WIRE_BYTES;
        assert!(wire_decoder.push(&[0]).is_err());

        let mut body_decoder = baseline_response_decoder();
        body_decoder.body_bytes = MAX_RESPONSE_BODY_BYTES;
        let encoded = encode_response(&body_decoder, &metadata, &[b"x"]);
        assert!(body_decoder.push(&encoded).is_err());
    }

    #[test]
    fn response_decoder_rejects_invalid_authenticated_metadata() {
        for metadata in [
            ResponseMetadata {
                status_code: 199,
                content_type: "application/json".into(),
                headers: BTreeMap::new(),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: String::new(),
                headers: BTreeMap::new(),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "applicationjson".into(),
                headers: BTreeMap::new(),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "application/json\u{1}".into(),
                headers: BTreeMap::new(),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "application/json".into(),
                headers: BTreeMap::from([("X-Test\r\nX-Evil".into(), "yes".into())]),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "application/json".into(),
                headers: BTreeMap::from([("X Test".into(), "yes".into())]),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "application/json".into(),
                headers: BTreeMap::from([("X-Test".into(), "yes\u{1}".into())]),
            },
            ResponseMetadata {
                status_code: 200,
                content_type: "application/json".into(),
                headers: BTreeMap::from([
                    ("X-Test".into(), "one".into()),
                    ("x-test".into(), "two".into()),
                ]),
            },
        ] {
            let mut decoder = baseline_response_decoder();
            let encoded = encode_response(&decoder, &metadata, &[]);
            assert!(decoder.push(&encoded).is_err());
        }
    }

    #[test]
    fn committed_vector_opens_with_rust_and_go_compatible_primitives() {
        use hpke::{OpModeR, setup_receiver};

        #[derive(Deserialize)]
        struct Fixture {
            schema: String,
            node_private_key_hex: String,
            request: Value,
            expected_inner: Value,
            response_metadata: ResponseMetadata,
            response_body_base64: String,
            response_base64: String,
        }

        let fixture: Fixture =
            serde_json::from_slice(include_bytes!("../tests/fixtures/e2ee-rust-go-v1.json"))
                .unwrap();
        assert_eq!(fixture.schema, "stogas.e2ee.interop.v1");
        let envelope: Envelope = serde_json::from_value(fixture.request).unwrap();
        let private_key = <Kem as hpke::Kem>::PrivateKey::from_bytes(
            &hex::decode(fixture.node_private_key_hex).unwrap(),
        )
        .unwrap();
        let key_ids = envelope
            .recipients
            .iter()
            .map(|recipient| {
                decode_canonical_base64(&recipient.key_id, "key id")
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<[u8; KEY_ID_BYTES]>>();
        let transcript = build_transcript(
            "/v1/responses",
            parse_canonical_uuid(&envelope.request_id).unwrap(),
            decode_lower_hex_32(&envelope.bundle_sha256, "bundle hash").unwrap(),
            envelope.expires_at_ms,
            &key_ids,
        )
        .unwrap();
        let transcript_hash: [u8; 32] = Sha256::digest(&transcript).into();
        let recipient = &envelope.recipients[0];
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(
            &decode_canonical_base64(&recipient.encapsulated_key, "encapsulated key").unwrap(),
        )
        .unwrap();
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            &hpke_info(&transcript_hash),
        )
        .unwrap();
        let content_key = receiver
            .open(
                &decode_canonical_base64(&recipient.wrapped_key, "wrapped key").unwrap(),
                &transcript,
            )
            .unwrap();
        let (request_cipher, request_nonce, response_cipher) =
            derive_ciphers(&content_key, &transcript_hash).unwrap();
        let nonce: &Nonce<U12> = request_nonce.as_slice().try_into().unwrap();
        let inner = request_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &decode_canonical_base64(&envelope.ciphertext, "ciphertext").unwrap(),
                    aad: &transcript,
                },
            )
            .unwrap();
        assert_eq!(
            strict_json::from_slice(&inner).unwrap(),
            fixture.expected_inner
        );

        let mut decoder = ResponseDecoder::new(response_cipher, transcript_hash);
        let events = decoder
            .push(&decode_canonical_base64(&fixture.response_base64, "response fixture").unwrap())
            .unwrap();
        decoder.finish().unwrap();
        assert_eq!(
            events,
            vec![
                ResponseEvent::Metadata(fixture.response_metadata),
                ResponseEvent::Data(
                    decode_canonical_base64(
                        &fixture.response_body_base64,
                        "response body fixture",
                    )
                    .unwrap(),
                ),
                ResponseEvent::Final,
            ]
        );
    }

    fn recipient() -> Recipient {
        let (_, public_key) = Kem::gen_keypair();
        Recipient {
            public_key: public_key.to_bytes().to_vec(),
        }
    }

    fn sealed_request() -> SealedRequest {
        let recipients = [recipient()];
        seal_request(&Request {
            path: "/v1/responses",
            request_id: Some(REQUEST_ID),
            now_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 60_000,
            bundle_sha256: BUNDLE_HASH,
            recipients: &recipients,
            api_key: "sk-test",
            accept: None,
            receipt: false,
            upstream_credentials: None,
            body: b"{}",
        })
        .unwrap()
    }

    fn valid_request(recipient: &Recipient) -> Request<'_> {
        Request {
            path: "/v1/responses",
            request_id: Some(REQUEST_ID),
            now_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 60_000,
            bundle_sha256: BUNDLE_HASH,
            recipients: std::slice::from_ref(recipient),
            api_key: "sk-test",
            accept: None,
            receipt: false,
            upstream_credentials: None,
            body: b"{}",
        }
    }

    fn assert_invalid_request(request: &Request<'_>) {
        assert!(matches!(
            seal_request(request),
            Err(Error::InvalidRequest(_))
        ));
    }

    fn baseline_response_decoder() -> ResponseDecoder {
        sealed_request().response
    }

    fn encode_response(
        decoder: &ResponseDecoder,
        metadata: &ResponseMetadata,
        chunks: &[&[u8]],
    ) -> Vec<u8> {
        encode_response_with_nonce(decoder, metadata, chunks, [0; RESPONSE_NONCE_BYTES])
    }

    fn encode_response_with_nonce(
        decoder: &ResponseDecoder,
        metadata: &ResponseMetadata,
        chunks: &[&[u8]],
        response_nonce: [u8; RESPONSE_NONCE_BYTES],
    ) -> Vec<u8> {
        let mut encoded = RESPONSE_MAGIC.to_vec();
        encoded.extend_from_slice(&response_nonce);
        append_record(
            &mut encoded,
            decoder,
            response_nonce,
            0,
            &serde_json::to_vec(metadata).unwrap(),
        );
        for (index, chunk) in chunks.iter().enumerate() {
            append_record(
                &mut encoded,
                decoder,
                response_nonce,
                u64::try_from(index).unwrap() + 1,
                chunk,
            );
        }
        append_record(
            &mut encoded,
            decoder,
            response_nonce,
            u64::try_from(chunks.len()).unwrap() + 1,
            &[],
        );
        encoded
    }

    fn append_record(
        encoded: &mut Vec<u8>,
        decoder: &ResponseDecoder,
        base_nonce: [u8; 12],
        sequence: u64,
        plaintext: &[u8],
    ) {
        let nonce = response_nonce(base_nonce, sequence);
        let nonce: &Nonce<U12> = nonce.as_slice().try_into().unwrap();
        let ciphertext = decoder
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &response_aad(&decoder.transcript_hash, sequence),
                },
            )
            .unwrap();
        encoded.extend_from_slice(&u32::try_from(ciphertext.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(&ciphertext);
    }

    fn response_record_end(encoded: &[u8], start: usize) -> usize {
        let ciphertext_length = usize::try_from(u32::from_be_bytes(
            encoded[start..start + RESPONSE_RECORD_HEADER_BYTES]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        start + RESPONSE_RECORD_HEADER_BYTES + ciphertext_length
    }
}
