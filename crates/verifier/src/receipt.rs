//! One signature over exact content hashes and the canonical Stogas metadata bag.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::evidence::boot::VerifiedBoot;

pub(crate) mod http;

pub const SCHEMA: &str = "stogas.receipt.v1";
pub const MAX_BYTES: usize = 5 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024 + MAX_METADATA_BYTES + 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid content receipt")]
    Invalid,
    #[error("receipt does not match the request or response")]
    Content,
    #[error("receipt does not identify the verified boot")]
    Identity,
    #[error("receipt signature failed")]
    Signature,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub boot_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub signature: String,
}

/// This confirms content and metadata under an appraised boot key; it does not
/// renew the boot's authorization or establish when inference ran.
#[derive(Debug, Serialize)]
pub struct VerifiedReceipt {
    pub node_id: String,
    pub boot_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
}

impl Receipt {
    /// # Errors
    /// Rejects malformed/ambiguous JSON, unknown fields and oversized receipts.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        serde_json::from_value(crate::strict_json::from_slice(bytes).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)
    }

    /// Verify using the retained request appraisal or an independently verified
    /// historical boot. The caller supplies exact-body hashes computed locally.
    ///
    /// # Errors
    /// Rejects altered content, boot references, schema, keys or signatures.
    pub fn verify(
        &self,
        boot: &VerifiedBoot,
        request: &[u8; 32],
        response: &[u8; 32],
        metadata: &serde_json::Value,
    ) -> Result<VerifiedReceipt, Error> {
        self.verify_key(
            &boot.record().report_data.signing_public_key,
            boot.document_sha256(),
            request,
            response,
            &metadata_digest(metadata)?,
        )?;
        Ok(VerifiedReceipt {
            node_id: boot.hardware().node_id().to_owned(),
            boot_sha256: self.boot_sha256.clone(),
            request_sha256: self.request_sha256.clone(),
            response_sha256: self.response_sha256.clone(),
        })
    }

    fn verify_key(
        &self,
        public_key: &str,
        boot: &[u8; 32],
        request: &[u8; 32],
        response: &[u8; 32],
        metadata: &[u8; 32],
    ) -> Result<(), Error> {
        if self.schema != SCHEMA {
            return Err(Error::Invalid);
        }
        if self.boot_sha256 != hex::encode(boot) {
            return Err(Error::Identity);
        }
        if self.request_sha256 != hex::encode(request)
            || self.response_sha256 != hex::encode(response)
        {
            return Err(Error::Content);
        }
        let key = decode(public_key)?;
        if key.len() != crate::signing::PUBLIC_KEY_BYTES {
            return Err(Error::Identity);
        }
        let signature = decode(&self.signature)?;
        let mut message = Vec::with_capacity(SCHEMA.len() + 1 + 96);
        message.extend_from_slice(SCHEMA.as_bytes());
        message.push(0);
        message.extend_from_slice(request);
        message.extend_from_slice(response);
        message.extend_from_slice(metadata);
        crate::signing::verify(&key, &message, &[], &signature).map_err(|_| Error::Signature)
    }
}

/// The complete metadata bag is authenticated, excluding the receipt itself.
#[derive(Debug, Serialize)]
pub struct VerifiedMetadata {
    pub metadata: serde_json::Value,
    pub receipt: VerifiedReceipt,
}

/// Verify the appended receipt without reserializing the provider response being hashed.
///
/// # Errors
/// Rejects malformed/oversized responses and incorrect signatures or content.
pub fn verify_buffered(
    boot: &VerifiedBoot,
    request: &[u8; 32],
    body: &[u8],
) -> Result<VerifiedMetadata, Error> {
    use sha2::{Digest as _, Sha256};
    let (metadata, content) =
        http::split_buffered_response(body, 64 * 1024 * 1024).map_err(|_| Error::Invalid)?;
    verify_metadata(&metadata, boot, request, &Sha256::digest(content).into())
}

/// Streaming exact-content verification. The terminal delimiter is withheld until `finish`.
pub struct Stream {
    request: [u8; 32],
    body: http::SseBody,
}

/// SSE framing guard for encrypted responses even when receipts were not requested.
/// Release the terminal delimiter only after authenticated record completion and outer EOF.
pub struct StreamCompletion(http::SseBody);
impl Default for StreamCompletion {
    fn default() -> Self {
        Self(http::SseBody::transport())
    }
}
impl StreamCompletion {
    /// # Errors
    /// Rejects malformed or post-terminal SSE framing.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.0.push(bytes).map_err(|_| Error::Invalid)
    }
    /// # Errors
    /// Rejects truncated streams. The caller must first authenticate record completion and EOF.
    pub fn finish(self) -> Result<(), Error> {
        self.0.require_complete().map_err(|_| Error::Invalid)
    }
}
impl Stream {
    #[must_use]
    pub fn new(request: [u8; 32]) -> Self {
        Self {
            request,
            body: http::SseBody::new(),
        }
    }
    /// # Errors
    /// Rejects malformed, repeated, misplaced or oversized stream metadata.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.body.push(bytes).map_err(|_| Error::Invalid)
    }
    /// The caller must observe transport EOF, then append `\n\n` only after this succeeds.
    ///
    /// # Errors
    /// Rejects incomplete streams, changed content and invalid receipt signatures.
    pub fn finish(self, boot: &VerifiedBoot) -> Result<VerifiedMetadata, Error> {
        let (metadata, response) = self.body.finish().map_err(|_| Error::Invalid)?;
        verify_metadata(&metadata, boot, &self.request, &response)
    }
}

/// Verify a detached final `stogas` bag and locally computed content hashes.
///
/// # Errors
/// Rejects malformed metadata, changed content and invalid signatures.
pub fn verify_metadata(
    bytes: &[u8],
    boot: &VerifiedBoot,
    request: &[u8; 32],
    response: &[u8; 32],
) -> Result<VerifiedMetadata, Error> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::Invalid);
    }
    let metadata = crate::strict_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let receipt = metadata.get("receipt").ok_or(Error::Invalid)?;
    let receipt = Receipt::parse(&serde_json::to_vec(receipt).map_err(|_| Error::Invalid)?)?;
    let receipt = receipt.verify(boot, request, response, &metadata)?;
    Ok(VerifiedMetadata { metadata, receipt })
}

fn metadata_digest(metadata: &serde_json::Value) -> Result<[u8; 32], Error> {
    use sha2::{Digest as _, Sha256};
    let mut object = metadata.as_object().ok_or(Error::Invalid)?.clone();
    object.remove("receipt");
    let canonical = serde_json_canonicalizer::to_vec(&object).map_err(|_| Error::Invalid)?;
    if canonical.len() > MAX_METADATA_BYTES {
        return Err(Error::Invalid);
    }
    Ok(Sha256::digest(canonical).into())
}

fn decode(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn unsigned_sse_cannot_release_completion_before_transport_finishes() {
        for terminal in [
            b"data: [DONE]\n\n".as_slice(),
            b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
            b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n",
        ] {
            let wire = [
                b": STOGAS PROCESSING\n\ndata: hello\n\n".as_slice(),
                terminal,
            ]
            .concat();
            for split in 0..=wire.len() {
                let mut guard = StreamCompletion::default();
                let output = [
                    guard.push(&wire[..split]).unwrap().concat(),
                    guard.push(&wire[split..]).unwrap().concat(),
                ]
                .concat();
                assert_eq!(output, wire[..wire.len() - 2]);
                guard.finish().unwrap();
            }
            for end in 0..wire.len() {
                let mut guard = StreamCompletion::default();
                guard.push(&wire[..end]).unwrap();
                assert!(guard.finish().is_err());
            }
            let mut guard = StreamCompletion::default();
            guard.push(&wire).unwrap();
            assert!(guard.push(b"extra").is_err());
            assert!(guard.finish().is_err());
        }
    }

    #[test]
    fn go_receipt_vector_binds_content_metadata_and_the_resolved_boot_key() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/content-receipt-v1.json"
        ))
        .unwrap();
        let receipt = Receipt::parse(&serde_json::to_vec(&vector["receipt"]).unwrap()).unwrap();
        let key = vector["public_key"].as_str().unwrap();
        let metadata = metadata_digest(&vector["metadata"]).unwrap();
        let boot: [u8; 32] = hex::decode(&receipt.boot_sha256)
            .unwrap()
            .try_into()
            .unwrap();
        let request: [u8; 32] =
            Sha256::digest(vector["request"].as_str().unwrap().as_bytes()).into();
        let response: [u8; 32] =
            Sha256::digest(vector["response"].as_str().unwrap().as_bytes()).into();
        receipt
            .verify_key(key, &boot, &request, &response, &metadata)
            .unwrap();
        let mut bag = vector["metadata"].clone();
        bag["receipt"] = vector["receipt"].clone();
        assert_eq!(metadata_digest(&bag).unwrap(), metadata);
        bag["provider"]["instance"] = serde_json::json!("substituted");
        assert!(
            receipt
                .verify_key(
                    key,
                    &boot,
                    &request,
                    &response,
                    &metadata_digest(&bag).unwrap()
                )
                .is_err()
        );
        assert!(matches!(
            receipt.verify_key(key, &[0; 32], &request, &response, &metadata),
            Err(Error::Identity)
        ));
        assert!(matches!(
            receipt.verify_key(key, &boot, &response, &request, &metadata),
            Err(Error::Content)
        ));
        assert!(
            receipt
                .verify_key(
                    &URL_SAFE_NO_PAD.encode([4; 32]),
                    &boot,
                    &request,
                    &response,
                    &metadata
                )
                .is_err()
        );
        for field in [
            "schema",
            "boot_sha256",
            "request_sha256",
            "response_sha256",
            "signature",
        ] {
            let mut changed = vector["receipt"].clone();
            changed[field] = serde_json::json!("invalid");
            let receipt = Receipt::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                receipt
                    .verify_key(key, &boot, &request, &response, &metadata)
                    .is_err(),
                "{field}"
            );
        }
        let raw = serde_json::to_string(&vector["receipt"]).unwrap();
        assert!(Receipt::parse(raw.replace('{', "{\"schema\":\"other\",").as_bytes()).is_err());
        assert!(Receipt::parse(raw.replace('{', "{\"durability\":true,").as_bytes()).is_err());
        assert!(Receipt::parse(&[b' '; MAX_BYTES + 1]).is_err());
    }
}

#[cfg(all(test, feature = "staging"))]
mod http_tests {
    use super::*;
    use crate::signing::SigningKey;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    fn peer() -> crate::evidence::VerifiedSession {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let mut verifier = crate::evidence::Verifier::new(
            crate::approvals::Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap();
        let now = fixture["verified_at_ms"].as_i64().unwrap();
        let snapshot = verifier
            .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
            .unwrap();
        snapshot
            .verify_native_certificate(
                &URL_SAFE_NO_PAD
                    .decode(fixture["certificate"].as_str().unwrap())
                    .unwrap(),
                hex::decode(fixture["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                now,
            )
            .unwrap()
    }
    fn metadata(boot: &VerifiedBoot, request: [u8; 32], response: &[u8]) -> Value {
        let response: [u8; 32] = Sha256::digest(response).into();
        let digest = metadata_digest(&json!({"billed_cost_usd":"0.01"})).unwrap();
        let message = [SCHEMA.as_bytes(), b"\0", &request, &response, &digest].concat();
        // Public deterministic key used only by the isolated diagnostic fixture.
        let key = SigningKey::from_seed(&[42; 32]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.public_key()),
            boot.record().report_data.signing_public_key
        );
        json!({"receipt": {
            "schema":SCHEMA, "boot_sha256":hex::encode(boot.document_sha256()),
            "request_sha256":hex::encode(request), "response_sha256":hex::encode(response),
            "signature":URL_SAFE_NO_PAD.encode(key.sign(&message, &[]).unwrap())
        }, "billed_cost_usd":"0.01"})
    }
    #[test]
    fn buffered_metadata_verifies_content_and_metadata_under_the_original_hardware_key() {
        let peer = peer();
        let request = Sha256::digest(b"request").into();
        let content = br#"{"choices":[],"usage":{"output_tokens":2}}"#;
        let mut bag = metadata(peer.boot(), request, content);
        let encode = |bag: &Value| {
            [
                &content[..content.len() - 1],
                b",\"stogas\":",
                &serde_json::to_vec(bag).unwrap(),
                b"}",
            ]
            .concat()
        };
        let result = verify_buffered(peer.boot(), &request, &encode(&bag)).unwrap();
        assert_eq!(result.receipt.node_id, peer.boot().hardware().node_id());
        bag["billed_cost_usd"] = json!("0.02");
        assert!(verify_buffered(peer.boot(), &request, &encode(&bag)).is_err());
        bag["billed_cost_usd"] = json!("0.01");
        let changed = String::from_utf8(encode(&bag))
            .unwrap()
            .replace("output_tokens\":2", "output_tokens\":3");
        assert!(verify_buffered(peer.boot(), &request, changed.as_bytes()).is_err());
        bag["receipt"]["boot_sha256"] = json!("00".repeat(32));
        assert!(verify_buffered(peer.boot(), &request, &encode(&bag)).is_err());
        assert!(verify_buffered(peer.boot(), &request, b"{}").is_err());
    }
    #[test]
    fn sse_receipts_cover_terminal_content_and_exclude_only_complete_keepalives() {
        let peer = peer();
        let request = Sha256::digest(b"request").into();
        let event = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n";
        let keepalive = b": STOGAS PROCESSING\n\n";
        for terminal in [
            b"data: [DONE]\n\n".as_slice(),
            b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
            b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n",
        ] {
            let bag = metadata(peer.boot(), request, &[event.as_slice(), terminal].concat());
            let comment = [
                b": stogas ".as_slice(),
                &serde_json::to_vec(&bag).unwrap(),
                b"\n\n",
            ]
            .concat();
            let wire = [keepalive.as_slice(), event, keepalive, &comment, terminal].concat();
            let response = Sha256::digest([event.as_slice(), terminal].concat());
            let metadata_bytes = serde_json::to_vec(&bag).unwrap();
            for split in 0..=wire.len() {
                let mut stream = Stream::new(request);
                let mut returned = stream.push(&wire[..split]).unwrap().concat();
                returned.extend(stream.push(&wire[split..]).unwrap().concat());
                assert_eq!(returned, wire[..wire.len() - 2]);
                // Every split must produce the same signed bytes. Repeating ML-DSA
                // verification for each byte boundary adds no cryptographic coverage.
                let (actual_metadata, actual_response) = stream.body.finish().unwrap();
                assert_eq!(actual_metadata, metadata_bytes);
                assert_eq!(actual_response.as_slice(), response.as_slice());
            }
            let mut stream = Stream::new(request);
            stream.push(&wire).unwrap();
            stream.finish(peer.boot()).unwrap();
            for injected in [
                b": STOGAS PROCESSING\ndata: injected\n\n".as_slice(),
                b": unrelated\ndata: injected\n\n",
            ] {
                let mut stream = Stream::new(request);
                stream
                    .push(&[injected, event, &comment, terminal].concat())
                    .unwrap();
                assert!(stream.finish(peer.boot()).is_err());
            }
            for length in 0..wire.len() {
                let mut stream = Stream::new(request);
                if stream.push(&wire[..length]).is_ok() {
                    assert!(stream.finish(peer.boot()).is_err());
                }
            }
            for bad in [
                [&wire[..], b"trailing"].concat(),
                [event.as_slice(), &comment, &comment, terminal].concat(),
                [event.as_slice(), &comment, event, terminal].concat(),
            ] {
                let mut stream = Stream::new(request);
                assert!(stream.push(&bad).is_err());
                assert!(stream.push(terminal).is_err());
                assert!(stream.finish(peer.boot()).is_err());
            }
        }
    }
}
