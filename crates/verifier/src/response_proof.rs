//! Compact signed response fields from a bundle-attested gateway node.

use crate::{
    Error, VerificationOutput, VerifiedCatalogRelease, VerifiedNodeLedgerRecord, strict_json,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Response-proof schema emitted by the gateway.
pub const SCHEMA_V1: &str = "stogas.response-proof.v1";
/// Maximum serialized response-proof size.
pub const MAX_PROOF_BYTES: usize = 8 * 1024;
/// Maximum request or response body accepted by one-shot proof verification.
pub const MAX_BODY_BYTES: usize = 128 * 1024 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"stogas.response-proof.v1\0";
const SSE_RECEIPT_PREFIX: &[u8] = b": stogas ";
const SSE_CHAT_TERMINAL_PREFIX: &[u8] = b"data: [DONE]";
const SSE_RESPONSES_TERMINAL_PREFIX: &[u8] = b"event: response.completed\n";
const SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX: &[u8] = b"event: response.incomplete\n";
const SSE_EVENT_END: &[u8] = b"\n\n";
const BUFFERED_STOGAS_FIELD: &[u8] = b",\"stogas\":";
const BUFFERED_ONLY_STOGAS_FIELD: &[u8] = b"{\"stogas\":";
const MAX_CATALOG_ID_BYTES: usize = 128;
const MAX_METERS: usize = 64;
const CATALOG_NODE_KINDS: [&str; 5] = ["author", "model", "deployment", "route", "provider"];

/// Exact catalog identity and selected graph path for one request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCatalog {
    pub digest: String,
    pub sequence: u64,
    pub selection_ids: Vec<String>,
}

/// One priced usage meter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMeter {
    pub quantity: String,
    pub rate_key: String,
    pub rate_usd_atoms: String,
    pub usd_atoms: String,
}

/// Final request price. `total_cost_usd_atoms` is the Stogas charge. A BYOK
/// request also reports the estimated provider charge paid through that key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePricing {
    pub meters: BTreeMap<String, ResponseMeter>,
    pub total_cost_usd_atoms: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byok_cost_usd_atoms: Option<String>,
}

/// Gateway-observed request timing.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTiming {
    pub total_ms: u32,
    pub provider_ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u32>,
}

/// Exact transcript hashes and the node signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProofClaims {
    pub request_sha256: String,
    pub response_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_transcript_sha256: Option<String>,
    pub signature: String,
}

/// Signed response fields returned in the response `stogas` object or final `stogas` SSE comment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProof {
    pub schema: String,
    pub request_id: String,
    pub created_at: String,
    pub node_id: String,
    pub catalog: ResponseCatalog,
    pub pricing: ResponsePricing,
    pub timing: ResponseTiming,
    pub proof: ResponseProofClaims,
}

/// Response fields covered directly by the signature.
#[derive(Serialize)]
struct ResponseProofPayload<'a> {
    schema: &'a str,
    request_id: &'a str,
    created_at: &'a str,
    node_id: &'a str,
    catalog: &'a ResponseCatalog,
    pricing: &'a ResponsePricing,
    timing: &'a ResponseTiming,
    proof: ResponseProofPayloadClaims<'a>,
}

#[derive(Serialize)]
struct ResponseProofPayloadClaims<'a> {
    #[serde(rename = "request_sha256")]
    request: &'a str,
    #[serde(rename = "response_sha256")]
    response: &'a str,
    #[serde(
        rename = "e2ee_transcript_sha256",
        skip_serializing_if = "Option::is_none"
    )]
    e2ee_transcript: Option<&'a str>,
}

/// Authenticated request data after exact-body and attested-node verification.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedResponseProof {
    pub schema: String,
    pub request_id: String,
    pub created_at: String,
    pub node_id: String,
    pub catalog: ResponseCatalog,
    pub pricing: ResponsePricing,
    pub timing: ResponseTiming,
    pub proof: ResponseProofClaims,
}

/// Exact-byte SSE receipt filter used by managed transports.
///
/// The filter forwards ordinary events immediately, removes the receipt from the response hash,
/// and withholds the terminal event delimiter until the signature has verified. It accepts only
/// the two terminal forms emitted by the `OpenAI` Chat Completions and Responses endpoints.
pub struct ResponseProofSseStream {
    request_sha256: String,
    response_hasher: Sha256,
    buffer: Vec<u8>,
    state: SseState,
    proof_bytes: Option<Vec<u8>>,
    receipt_frame: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SseState {
    Boundary,
    Regular,
    Receipt,
    ChatTerminal,
    ResponsesTerminal,
    AfterTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushAction {
    Continue,
    Stop,
}

impl ResponseProofSseStream {
    /// Start filtering one plaintext SSE response for the exact request bytes sent by the client.
    #[must_use]
    pub fn new(request_body: &[u8]) -> Self {
        Self::from_request_sha256(hex::encode(Sha256::digest(request_body)))
    }

    /// Start filtering when the request hash was already calculated by the caller.
    ///
    /// # Errors
    ///
    /// The hash is validated when [`Self::finish`] verifies the receipt.
    #[must_use]
    pub fn from_request_sha256(request_sha256: String) -> Self {
        Self {
            request_sha256,
            response_hasher: Sha256::new(),
            buffer: Vec::new(),
            state: SseState::Boundary,
            proof_bytes: None,
            receipt_frame: None,
        }
    }

    /// Consume another arbitrary network chunk and return bytes that are safe to release.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, duplicated, misplaced, or post-terminal receipt frame.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.state == SseState::AfterTerminal && !chunk.is_empty() {
            return Err(stream_error(
                "stream contains bytes after its terminal event",
            ));
        }
        self.buffer.extend_from_slice(chunk);
        let mut output = Vec::new();
        loop {
            let action = match self.state {
                SseState::Boundary => self.push_boundary(&mut output)?,
                SseState::Regular => self.push_regular(&mut output),
                SseState::Receipt => self.push_receipt()?,
                SseState::ChatTerminal => self.push_chat_terminal(&mut output)?,
                SseState::ResponsesTerminal => self.push_responses_terminal(&mut output)?,
                SseState::AfterTerminal => self.push_after_terminal()?,
            };
            if action == PushAction::Stop {
                break;
            }
        }
        Ok(output)
    }

    /// Verify the complete stream and release its withheld terminal delimiter.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation or any receipt, hash, signature, node, catalog, expiry, or
    /// E2EE transcript mismatch.
    pub fn finish(
        self,
        expected_e2ee_transcript_sha256: Option<&str>,
        now_unix_ms: i64,
        bundle: &VerificationOutput,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.state != SseState::AfterTerminal || !self.buffer.is_empty() {
            return Err(stream_error(
                "stream ended before its signed terminal event",
            ));
        }
        let proof_bytes = self
            .proof_bytes
            .ok_or_else(|| stream_error("stream has no receipt"))?;
        verify_with_bundle_hashes(
            &proof_bytes,
            &self.request_sha256,
            &hex::encode(self.response_hasher.finalize()),
            expected_e2ee_transcript_sha256,
            now_unix_ms,
            bundle,
        )?;
        Ok(vec![SSE_EVENT_END.to_vec()])
    }

    fn begin_terminal(&mut self, output: &mut Vec<Vec<u8>>, state: SseState) -> Result<(), Error> {
        let receipt = self
            .receipt_frame
            .take()
            .ok_or_else(|| stream_error("terminal event arrived before the receipt"))?;
        output.push(receipt);
        self.state = state;
        Ok(())
    }

    fn push_boundary(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        if self.buffer.is_empty() {
            return Ok(PushAction::Stop);
        }
        match classify_sse_boundary(&self.buffer) {
            BoundaryKind::NeedMore => return Ok(PushAction::Stop),
            BoundaryKind::Receipt => {
                if self.proof_bytes.is_some() {
                    return Err(stream_error("stream contains more than one receipt"));
                }
                self.state = SseState::Receipt;
            }
            BoundaryKind::ChatTerminal => {
                self.begin_terminal(output, SseState::ChatTerminal)?;
            }
            BoundaryKind::ResponsesTerminal => {
                self.begin_terminal(output, SseState::ResponsesTerminal)?;
            }
            BoundaryKind::Regular => {
                if self.proof_bytes.is_some() {
                    return Err(stream_error(
                        "the receipt is not immediately before the terminal event",
                    ));
                }
                self.state = SseState::Regular;
            }
        }
        Ok(PushAction::Continue)
    }

    fn push_regular(&mut self, output: &mut Vec<Vec<u8>>) -> PushAction {
        if let Some(end) = find_bytes(&self.buffer, SSE_EVENT_END) {
            let bytes = self.take_buffer_prefix(end + SSE_EVENT_END.len());
            self.hash_and_forward(bytes, output);
            self.state = SseState::Boundary;
            return PushAction::Continue;
        }
        let safe = self.safe_incomplete_length();
        if safe > 0 {
            let bytes = self.take_buffer_prefix(safe);
            self.hash_and_forward(bytes, output);
        }
        PushAction::Stop
    }

    fn push_receipt(&mut self) -> Result<PushAction, Error> {
        let Some(end) = find_bytes(&self.buffer, SSE_EVENT_END) else {
            if self.buffer.len() > SSE_RECEIPT_PREFIX.len() + MAX_PROOF_BYTES + SSE_EVENT_END.len()
            {
                return Err(stream_error("stream receipt exceeds its size limit"));
            }
            return Ok(PushAction::Stop);
        };
        let frame = self.take_buffer_prefix(end + SSE_EVENT_END.len());
        let proof_end = frame.len() - SSE_EVENT_END.len();
        let proof = &frame[SSE_RECEIPT_PREFIX.len()..proof_end];
        if proof.is_empty() || proof.len() > MAX_PROOF_BYTES || proof.contains(&b'\n') {
            return Err(stream_error(
                "stream receipt has an invalid size or encoding",
            ));
        }
        self.proof_bytes = Some(proof.to_vec());
        self.receipt_frame = Some(frame);
        self.state = SseState::Boundary;
        Ok(PushAction::Continue)
    }

    fn push_chat_terminal(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        let mut expected = Vec::with_capacity(SSE_CHAT_TERMINAL_PREFIX.len() + SSE_EVENT_END.len());
        expected.extend_from_slice(SSE_CHAT_TERMINAL_PREFIX);
        expected.extend_from_slice(SSE_EVENT_END);
        if self.buffer.len() < expected.len() {
            if !expected.starts_with(&self.buffer) {
                return Err(stream_error("Chat terminal event is malformed"));
            }
            return Ok(PushAction::Stop);
        }
        let frame = self.take_buffer_prefix(expected.len());
        if frame != expected {
            return Err(stream_error("Chat terminal event is malformed"));
        }
        self.finish_terminal_frame(&frame, output)?;
        Ok(PushAction::Stop)
    }

    fn push_responses_terminal(&mut self, output: &mut Vec<Vec<u8>>) -> Result<PushAction, Error> {
        if let Some(end) = find_bytes(&self.buffer, SSE_EVENT_END) {
            let frame = self.take_buffer_prefix(end + SSE_EVENT_END.len());
            self.finish_terminal_frame(&frame, output)?;
            return Ok(PushAction::Stop);
        }
        let safe = self.safe_incomplete_length();
        if safe > 0 {
            let bytes = self.take_buffer_prefix(safe);
            self.hash_and_forward(bytes, output);
        }
        Ok(PushAction::Stop)
    }

    fn finish_terminal_frame(
        &mut self,
        frame: &[u8],
        output: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        self.response_hasher.update(frame);
        output.push(frame[..frame.len() - SSE_EVENT_END.len()].to_vec());
        self.state = SseState::AfterTerminal;
        self.push_after_terminal().map(|_| ())
    }

    fn push_after_terminal(&self) -> Result<PushAction, Error> {
        if !self.buffer.is_empty() {
            return Err(stream_error(
                "stream contains bytes after its terminal event",
            ));
        }
        Ok(PushAction::Stop)
    }

    fn safe_incomplete_length(&self) -> usize {
        self.buffer
            .len()
            .saturating_sub(usize::from(self.buffer.last() == Some(&b'\n')))
    }

    fn take_buffer_prefix(&mut self, length: usize) -> Vec<u8> {
        let remainder = self.buffer.split_off(length);
        std::mem::replace(&mut self.buffer, remainder)
    }

    fn hash_and_forward(&mut self, bytes: Vec<u8>, output: &mut Vec<Vec<u8>>) {
        self.response_hasher.update(&bytes);
        output.push(bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryKind {
    NeedMore,
    Receipt,
    ChatTerminal,
    ResponsesTerminal,
    Regular,
}

fn classify_sse_boundary(buffer: &[u8]) -> BoundaryKind {
    for (prefix, kind) in [
        (SSE_RECEIPT_PREFIX, BoundaryKind::Receipt),
        (SSE_CHAT_TERMINAL_PREFIX, BoundaryKind::ChatTerminal),
        (
            SSE_RESPONSES_TERMINAL_PREFIX,
            BoundaryKind::ResponsesTerminal,
        ),
        (
            SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX,
            BoundaryKind::ResponsesTerminal,
        ),
    ] {
        if buffer.starts_with(prefix) {
            return kind;
        }
    }
    if [
        SSE_RECEIPT_PREFIX,
        SSE_CHAT_TERMINAL_PREFIX,
        SSE_RESPONSES_TERMINAL_PREFIX,
        SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX,
    ]
    .iter()
    .any(|prefix| prefix.starts_with(buffer))
    {
        BoundaryKind::NeedMore
    } else {
        BoundaryKind::Regular
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn stream_error(message: &str) -> Error {
    Error::ResponseProof(message.to_owned())
}

/// Verify response fields against an unexpired, already verified bundle.
///
/// `response_body` is the complete buffered JSON response with its final `stogas` object.
///
/// # Errors
///
/// Returns an error for malformed fields, body mismatches, signature failures,
/// unknown nodes, expired bundle state, or a mismatched E2EE transcript.
pub fn verify_with_bundle(
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    bundle: &VerificationOutput,
) -> Result<VerifiedResponseProof, Error> {
    if request_body.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "request body must not exceed {MAX_BODY_BYTES} bytes in one-shot verification"
        )));
    }
    let (proof_bytes, unsigned_response) = split_buffered_response(response_body)?;
    verify_with_bundle_hashes(
        &proof_bytes,
        &hex::encode(Sha256::digest(request_body)),
        &hex::encode(Sha256::digest(&unsigned_response)),
        expected_e2ee_transcript_sha256,
        now_unix_ms,
        bundle,
    )
}

/// Verify a buffered response when the exact request hash was retained instead of its body.
///
/// # Errors
///
/// Returns the same failures as [`verify_with_bundle`], including non-canonical request hashes.
pub fn verify_buffered_with_bundle_request_hash(
    request_sha256: &str,
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    bundle: &VerificationOutput,
) -> Result<VerifiedResponseProof, Error> {
    let (proof_bytes, unsigned_response) = split_buffered_response(response_body)?;
    verify_with_bundle_hashes(
        &proof_bytes,
        request_sha256,
        &hex::encode(Sha256::digest(unsigned_response)),
        expected_e2ee_transcript_sha256,
        now_unix_ms,
        bundle,
    )
}

/// Verify response fields against an unexpired bundle and locally computed body hashes.
///
/// This constant-memory entry point is for clients that hash response bytes as they stream.
/// The caller must compute both hashes over the exact plaintext bytes used by one-shot
/// verification.
///
/// # Errors
///
/// Returns an error for malformed fields, hash mismatches, signature failures, unknown nodes,
/// expired bundle state, or a mismatched E2EE transcript.
pub fn verify_with_bundle_hashes(
    proof_bytes: &[u8],
    request_sha256: &str,
    response_sha256: &str,
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    bundle: &VerificationOutput,
) -> Result<VerifiedResponseProof, Error> {
    if now_unix_ms >= bundle.bundle.expires_at_unix_ms {
        return Err(Error::ResponseProof(
            "the bundle used to verify the response proof has expired".into(),
        ));
    }
    let proof = parse_and_validate_hashes(
        proof_bytes,
        request_sha256,
        response_sha256,
        expected_e2ee_transcript_sha256,
    )?;
    let Some(catalog) = bundle.bundle.catalogs.iter().find(|catalog| {
        catalog.runtime_digest == proof.catalog.digest && catalog.sequence == proof.catalog.sequence
    }) else {
        return Err(Error::ResponseProof(
            "the response catalog is not authorized by the verified bundle".into(),
        ));
    };
    let mut node_matches = bundle
        .bundle
        .nodes
        .iter()
        .filter(|node| node.node_id == proof.node_id);
    let node = node_matches.next().ok_or_else(|| {
        Error::ResponseProof("the response node is not in the verified bundle".into())
    })?;
    if node_matches.next().is_some()
        || bundle.bundle.nodes.iter().any(|candidate| {
            candidate.node_id != node.node_id
                && candidate.report_data.ed25519_public_key == node.report_data.ed25519_public_key
        })
    {
        return Err(Error::ResponseProof(
            "the response node identity is ambiguous in the verified bundle".into(),
        ));
    }
    let release = bundle
        .bundle
        .releases
        .iter()
        .find(|release| release.measurement == node.release_measurement)
        .ok_or_else(|| {
            Error::ResponseProof("the response node release is not authorized".into())
        })?;
    if release.sequence < catalog.minimum_gateway_sequence {
        return Err(Error::ResponseProof(
            "the response catalog requires a newer gateway release".into(),
        ));
    }
    verify_signature(&proof, &node.report_data.ed25519_public_key)?;
    Ok(verified_output(proof))
}

/// Verify response fields against an already verified historical node record.
///
/// # Errors
///
/// Returns an error for malformed fields, body mismatches, signature failures,
/// a different historical node, or a mismatched E2EE transcript.
pub fn verify_with_ledger(
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    ledger: &VerifiedNodeLedgerRecord,
    catalog: &VerifiedCatalogRelease,
) -> Result<VerifiedResponseProof, Error> {
    if request_body.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "request body must not exceed {MAX_BODY_BYTES} bytes in one-shot verification"
        )));
    }
    let (proof_bytes, unsigned_response) = split_buffered_response(response_body)?;
    verify_with_ledger_hashes(
        &proof_bytes,
        &hex::encode(Sha256::digest(request_body)),
        &hex::encode(Sha256::digest(&unsigned_response)),
        expected_e2ee_transcript_sha256,
        ledger,
        catalog,
    )
}

/// Verify response fields against historical evidence and locally computed body hashes.
///
/// # Errors
///
/// Returns an error for malformed fields, hash mismatches, signature failures, a different
/// historical node or catalog, or a mismatched E2EE transcript.
pub fn verify_with_ledger_hashes(
    proof_bytes: &[u8],
    request_sha256: &str,
    response_sha256: &str,
    expected_e2ee_transcript_sha256: Option<&str>,
    ledger: &VerifiedNodeLedgerRecord,
    catalog: &VerifiedCatalogRelease,
) -> Result<VerifiedResponseProof, Error> {
    let proof = parse_and_validate_hashes(
        proof_bytes,
        request_sha256,
        response_sha256,
        expected_e2ee_transcript_sha256,
    )?;
    if proof.node_id != ledger.node.node_id {
        return Err(Error::ResponseProof(
            "the response node differs from the historical node record".into(),
        ));
    }
    if proof.catalog.digest != catalog.runtime_digest || proof.catalog.sequence != catalog.sequence
    {
        return Err(Error::ResponseProof(
            "the response catalog differs from the historical catalog approval".into(),
        ));
    }
    if ledger.release.sequence < catalog.minimum_gateway_sequence {
        return Err(Error::ResponseProof(
            "the historical response catalog requires a newer gateway release".into(),
        ));
    }
    verify_signature(&proof, &ledger.node.report_data.ed25519_public_key)?;
    Ok(verified_output(proof))
}

fn parse_and_validate_hashes(
    proof_bytes: &[u8],
    request_sha256: &str,
    response_sha256: &str,
    expected_e2ee_transcript_sha256: Option<&str>,
) -> Result<ResponseProof, Error> {
    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ResponseProof(format!(
            "proof exceeds {MAX_PROOF_BYTES} bytes"
        )));
    }
    if !is_lower_hex(request_sha256, 32) || !is_lower_hex(response_sha256, 32) {
        return Err(Error::ResponseProof(
            "locally computed body hashes must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    let value = strict_json::from_slice(proof_bytes)
        .map_err(|error| Error::ResponseProof(format!("invalid JSON: {error}")))?;
    let proof: ResponseProof = serde_json::from_value(value)
        .map_err(|error| Error::ResponseProof(format!("invalid response proof: {error}")))?;
    validate_shape(&proof)?;

    if request_sha256 != proof.proof.request_sha256 {
        return Err(Error::ResponseProof("request body SHA-256 differs".into()));
    }
    if response_sha256 != proof.proof.response_sha256 {
        return Err(Error::ResponseProof("response body SHA-256 differs".into()));
    }
    if proof.proof.e2ee_transcript_sha256.as_deref() != expected_e2ee_transcript_sha256 {
        return Err(Error::ResponseProof(
            "E2EE transcript binding differs".into(),
        ));
    }
    Ok(proof)
}

fn split_buffered_response(response_body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if response_body.len() > MAX_BODY_BYTES + MAX_PROOF_BYTES + 16 {
        return Err(Error::ResponseProof(format!(
            "buffered response exceeds {} bytes",
            MAX_BODY_BYTES + MAX_PROOF_BYTES + 16
        )));
    }
    if response_body.first() != Some(&b'{') || response_body.last() != Some(&b'}') {
        return Err(Error::ResponseProof(
            "buffered response must be compact JSON with a final stogas object".into(),
        ));
    }
    let (field_start, proof_start, empty_response) = response_body
        .windows(BUFFERED_STOGAS_FIELD.len())
        .rposition(|part| part == BUFFERED_STOGAS_FIELD)
        .map(|position| (position, position + BUFFERED_STOGAS_FIELD.len(), false))
        .or_else(|| {
            response_body
                .starts_with(BUFFERED_ONLY_STOGAS_FIELD)
                .then_some((0, BUFFERED_ONLY_STOGAS_FIELD.len(), true))
        })
        .ok_or_else(|| {
            Error::ResponseProof("buffered response has no final stogas object".into())
        })?;
    let proof_bytes = &response_body[proof_start..response_body.len() - 1];
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ResponseProof(
            "buffered response stogas object has an invalid size".into(),
        ));
    }
    let value = strict_json::from_slice(proof_bytes)
        .map_err(|error| Error::ResponseProof(format!("invalid stogas object: {error}")))?;
    if !value.is_object() {
        return Err(Error::ResponseProof(
            "buffered response stogas field must be an object".into(),
        ));
    }
    let unsigned_response = if empty_response {
        b"{}".to_vec()
    } else {
        let mut value = Vec::with_capacity(field_start + 1);
        value.extend_from_slice(&response_body[..field_start]);
        value.push(b'}');
        value
    };
    if unsigned_response.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "response body must not exceed {MAX_BODY_BYTES} bytes in one-shot verification"
        )));
    }
    Ok((proof_bytes.to_vec(), unsigned_response))
}

fn validate_shape(proof: &ResponseProof) -> Result<(), Error> {
    if proof.schema != SCHEMA_V1 {
        return Err(Error::ResponseProof(
            "unsupported response proof schema".into(),
        ));
    }
    if proof.request_id.is_empty()
        || proof.request_id.len() > 128
        || proof.request_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::ResponseProof("request ID is invalid".into()));
    }
    if !is_canonical_created_at(&proof.created_at) {
        return Err(Error::ResponseProof(
            "created_at must be canonical UTC time with millisecond precision".into(),
        ));
    }
    if !is_lower_hex(&proof.node_id, 32) {
        return Err(Error::ResponseProof(
            "node ID must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    if !proof.catalog.digest.starts_with("sha256:")
        || !is_lower_hex(&proof.catalog.digest["sha256:".len()..], 32)
    {
        return Err(Error::ResponseProof("catalog identity is invalid".into()));
    }
    if proof.catalog.selection_ids.len() != CATALOG_NODE_KINDS.len()
        || proof
            .catalog
            .selection_ids
            .iter()
            .zip(CATALOG_NODE_KINDS)
            .any(|(value, kind)| {
                value
                    .strip_prefix(kind)
                    .and_then(|suffix| suffix.strip_prefix(':'))
                    .is_none_or(|id| !is_identifier(id))
            })
    {
        return Err(Error::ResponseProof(
            "catalog selection IDs must contain author, model, deployment, route, and provider in canonical order".into(),
        ));
    }
    if proof.pricing.meters.len() > MAX_METERS
        || !is_decimal(&proof.pricing.total_cost_usd_atoms)
        || proof
            .pricing
            .byok_cost_usd_atoms
            .as_ref()
            .is_some_and(|value| !is_decimal(value))
        || proof.pricing.meters.iter().any(|(key, meter)| {
            !is_identifier(key)
                || !is_identifier(&meter.rate_key)
                || !is_decimal(&meter.quantity)
                || !is_decimal(&meter.rate_usd_atoms)
                || !is_decimal(&meter.usd_atoms)
        })
    {
        return Err(Error::ResponseProof("pricing fields are invalid".into()));
    }
    if proof.timing.provider_ms > proof.timing.total_ms
        || proof
            .timing
            .ttft_ms
            .is_some_and(|value| value > proof.timing.total_ms)
    {
        return Err(Error::ResponseProof("timing fields are invalid".into()));
    }
    for (value, label) in [
        (&proof.proof.request_sha256, "request SHA-256"),
        (&proof.proof.response_sha256, "response SHA-256"),
    ] {
        if !is_lower_hex(value, 32) {
            return Err(Error::ResponseProof(format!(
                "{label} must be 64 lowercase hexadecimal characters"
            )));
        }
    }
    if proof
        .proof
        .e2ee_transcript_sha256
        .as_ref()
        .is_some_and(|value| !is_lower_hex(value, 32))
    {
        return Err(Error::ResponseProof(
            "E2EE transcript hash must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    decode_canonical_base64(&proof.proof.signature, 64, "signature")?;
    Ok(())
}

fn verify_signature(proof: &ResponseProof, public_key: &str) -> Result<(), Error> {
    let public_key = decode_canonical_base64(public_key, 32, "trusted node signing public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::ResponseProof("signing public key must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::ResponseProof("signing public key is invalid".into()))?;
    let signature = decode_canonical_base64(&proof.proof.signature, 64, "signature")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| Error::ResponseProof("signature must be 64 bytes".into()))?;
    let payload = ResponseProofPayload {
        schema: &proof.schema,
        request_id: &proof.request_id,
        created_at: &proof.created_at,
        node_id: &proof.node_id,
        catalog: &proof.catalog,
        pricing: &proof.pricing,
        timing: &proof.timing,
        proof: ResponseProofPayloadClaims {
            request: &proof.proof.request_sha256,
            response: &proof.proof.response_sha256,
            e2ee_transcript: proof.proof.e2ee_transcript_sha256.as_deref(),
        },
    };
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| Error::ResponseProof(format!("could not encode payload: {error}")))?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + payload.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&payload);
    key.verify(&message, &signature)
        .map_err(|_| Error::ResponseProof("signature is invalid".into()))
}

fn verified_output(proof: ResponseProof) -> VerifiedResponseProof {
    VerifiedResponseProof {
        schema: proof.schema,
        request_id: proof.request_id,
        created_at: proof.created_at,
        node_id: proof.node_id,
        catalog: proof.catalog,
        pricing: proof.pricing,
        timing: proof.timing,
        proof: proof.proof,
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CATALOG_ID_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_canonical_created_at(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value)
        .is_ok_and(|parsed| parsed.to_rfc3339_opts(SecondsFormat::Millis, true) == value)
}

fn decode_canonical_base64(
    value: &str,
    expected_len: usize,
    label: &str,
) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::ResponseProof(format!("{label} is not base64url")))?;
    if bytes.len() != expected_len || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::ResponseProof(format!(
            "{label} must be canonical unpadded base64url encoding of {expected_len} bytes"
        )));
    }
    Ok(bytes)
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllowedCatalog, AllowedIgvm, BundleEnvelope, DrandBeacon, HardwarePolicySource,
        ReleaseProvenance, ReportData, VerifiedBundle, VerifiedCatalogRelease,
        VerifiedHardwarePolicy, VerifiedNode, VerifiedNodeLedgerRecord, VerifiedRelease,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    const NOW: i64 = 1_784_838_400_000;
    const REQUEST: &[u8] = br#"{"model":"gpt-5.5"}"#;
    const RESPONSE: &[u8] = br#"{"id":"resp_1"}"#;

    fn node(key: &SigningKey) -> VerifiedNode {
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        VerifiedNode {
            chip_id: "22".repeat(64),
            drand_round: 123,
            drand_round_time_unix_ms: NOW - 1_000,
            evidence_age_ms: 0,
            node_id: "33".repeat(32),
            quote: "verified-quote".into(),
            quote_verified_at_unix_ms: NOW,
            report_data: ReportData {
                accepted_cert_sha256: vec!["11".repeat(32)],
                drand: DrandBeacon {
                    chain_hash: "55".repeat(32),
                    network: "quicknet".into(),
                    randomness: "66".repeat(32),
                    round: 123,
                    signature: "77".repeat(48),
                },
                ed25519_public_key: public_key,
                hpke_public_key: URL_SAFE_NO_PAD.encode([4_u8; 1_216]),
                schema: "stogas.node-report.v1".into(),
                tls_spki_sha256: "88".repeat(32),
            },
            report_data_sha512: "99".repeat(64),
            release_measurement: "aa".repeat(48),
            reported_tcb: "0x0102030405060708".into(),
        }
    }

    fn catalog_evidence() -> AllowedCatalog {
        serde_json::from_value(json!({
            "github_in_toto": [{}],
            "signed_release": {
                "keyId": "test",
                "manifest": {
                    "catalogSchema": 1,
                    "minimumGatewaySequence": 1,
                    "public": format!("sha256:{}", "55".repeat(32)),
                    "runtime": format!("sha256:{}", "44".repeat(32)),
                    "schema": "stogas.catalog.release.v1",
                    "sequence": 7,
                    "source": {
                        "commit": "11".repeat(20),
                        "repository": "https://github.com/StogasAI/catalog",
                        "tag": "catalog-v7",
                        "tree": "22".repeat(20)
                    }
                },
                "schema": "stogas.catalog.signed.v1",
                "signature": "test"
            }
        }))
        .unwrap()
    }

    fn verified_catalog(
        runtime_digest: &str,
        sequence: u64,
        minimum_gateway_sequence: u64,
    ) -> VerifiedCatalogRelease {
        let mut evidence = catalog_evidence();
        evidence.signed_release.manifest.runtime = runtime_digest.into();
        evidence.signed_release.manifest.sequence = sequence;
        evidence.signed_release.manifest.minimum_gateway_sequence = minimum_gateway_sequence;
        evidence.signed_release.manifest.source.tag = format!("catalog-v{sequence}");
        let manifest = evidence.signed_release.manifest.clone();
        VerifiedCatalogRelease {
            evidence,
            github_integrated_time_unix_ms: Some(NOW - 10_000),
            minimum_gateway_sequence,
            provenance: ReleaseProvenance::Github,
            public_digest: manifest.public,
            runtime_digest: manifest.runtime,
            sequence,
            source_commit: manifest.source.commit,
            source_repository: manifest.source.repository,
            source_tag: manifest.source.tag,
            source_tree: manifest.source.tree,
            stogas_signing_key_id: "test".into(),
        }
    }

    fn release_evidence() -> AllowedIgvm {
        serde_json::from_value(json!({
            "github_in_toto": [{}],
            "release_manifest": {
                "artifacts": {
                    "gateway.igvm": {"sha256": "bb".repeat(32), "sizeBytes": 1},
                    "snp-launch-policies.json": {"sha256": "cc".repeat(32), "sizeBytes": 1}
                },
                "build": {
                    "cmdlineSha256": "01".repeat(32),
                    "coreGoModSha256": "02".repeat(32),
                    "coreGoSumSha256": "03".repeat(32),
                    "environment": {"lcAll": "C", "sourceDateEpoch": "1", "tz": "UTC", "umask": "022"},
                    "goModSha256": "04".repeat(32),
                    "goSumSha256": "05".repeat(32),
                    "goVendorTreeSha256": "06".repeat(32),
                    "goVersion": "go1.25.0",
                    "guestCaBundlePath": "/etc/ssl/certs/ca-certificates.crt",
                    "guestCaBundleSha256": "07".repeat(32),
                    "guixChannelCommit": "08".repeat(20),
                    "inputSha256": {
                        "source": "09".repeat(32),
                        "stogas/release/snp-launch-policies.json": "cc".repeat(32)
                    },
                    "kernelConfigSha256": "0a".repeat(32),
                    "kernelVersion": "6.12.0",
                    "linuxBzImageSha256": "0b".repeat(32),
                    "osReleaseSha256": "0c".repeat(32),
                    "ovmfSha256": "0d".repeat(32),
                    "pinsLockSha256": "0e".repeat(32),
                    "systemdStubSha256": "0f".repeat(32),
                    "ukiSha256": "10".repeat(32)
                },
                "git": {
                    "commit": "11".repeat(20),
                    "ref": "refs/tags/v0.0.1",
                    "repository": "https://github.com/StogasAI/gateway",
                    "tag": "v0.0.1",
                    "tree": "12".repeat(20)
                },
                "schema": "stogas.gateway.release.v1",
                "sequence": 1,
                "sevSnp": {
                    "checkKvm": true,
                    "launchMeasurement": "aa".repeat(48),
                    "launchPolicies": {
                        "policies": [{
                            "chip_ids": ["22".repeat(64)],
                            "launch": {
                                "author_key_digest": "00".repeat(48),
                                "family_id": "00".repeat(16),
                                "host_data": "00".repeat(32),
                                "id_key_digest": "00".repeat(48),
                                "image_id": "00".repeat(16),
                                "policy": "0x00030000",
                                "vmpl": 0
                            }
                        }],
                        "schema": "stogas.snp-launch-policies.v1"
                    },
                    "measurementCommand": "igvmmeasure gateway.igvm measure",
                    "measurementTool": "igvmmeasure",
                    "measurementToolSha256": "13".repeat(32),
                    "measurementToolVersion": "0.3.1",
                    "platform": "SEV_SNP",
                    "vcpuCount": 4,
                    "vmm": "qemu-kvm"
                }
            },
            "stogas_signature": {
                "algorithm": "Ed25519",
                "key_id": "test-release",
                "schema": "stogas.gateway.counterbuild-signature.v1",
                "signature": "test",
                "signed": "release-manifest.json"
            }
        }))
        .unwrap()
    }

    fn bundle(node: VerifiedNode) -> VerificationOutput {
        let catalog_evidence = catalog_evidence();
        let release_evidence = release_evidence();
        let verified_release = VerifiedRelease {
            evidence: release_evidence.clone(),
            github_integrated_time_unix_ms: Some(NOW - 10_000),
            igvm_sha256: "bb".repeat(32),
            launch_policies: release_evidence
                .release_manifest
                .sev_snp
                .launch_policies
                .clone(),
            measurement: "aa".repeat(48),
            provenance: ReleaseProvenance::Github,
            release_manifest_sha256: "dd".repeat(32),
            release_tag: "v0.0.1".into(),
            sequence: 1,
            source_commit: "11".repeat(20),
            source_repository: "https://github.com/StogasAI/gateway".into(),
            source_tree: "12".repeat(20),
            stogas_signing_key_id: "test-release".into(),
            vcpu_count: 4,
        };
        let original: BundleEnvelope = serde_json::from_value(json!({
            "body": {
                "catalogs": [catalog_evidence],
                "allowed_igvms": [release_evidence],
                "created_at": "2026-07-23T16:00:00.000Z",
                "expires_at": "2026-07-23T16:15:00.000Z",
                "hardware_policy": {
                    "policy": {
                        "policies": [{
                            "chip_ids": ["22".repeat(64)],
                            "cpuid_family": 25,
                            "cpuid_model": 1,
                            "cpuid_stepping": 1,
                            "forbidden_platform_info_mask": "0x0000000000000001",
                            "minimum_tcb": {"bootloader": 4, "microcode": 222, "snp": 29, "tee": 0},
                            "required_current_mitigation_mask": "0x000000000000000b",
                            "required_launch_mitigation_mask": "0x000000000000000b",
                            "required_platform_info_mask": "0x0000000000000024"
                        }],
                        "schema": "stogas.hardware-policies.v1"
                    },
                    "sigstore": {}
                },
                "nodes": [],
                "schema": "stogas.confidential-bundle.v1",
                "sequence": 1,
                "vendor_collateral": []
            },
            "body_sha256": "00".repeat(32)
        }))
        .unwrap();
        VerificationOutput {
            bundle: VerifiedBundle {
                catalogs: vec![verified_catalog(
                    &format!("sha256:{}", "44".repeat(32)),
                    7,
                    1,
                )],
                sequence: 1,
                created_at_unix_ms: NOW - 60_000,
                expires_at_unix_ms: NOW + 15 * 60_000,
                excluded_nodes: Vec::new(),
                hardware_policy: VerifiedHardwarePolicy {
                    chip_ids: vec!["22".repeat(64)],
                    policy_count: 1,
                    rekor_integrated_time_unix_ms: None,
                    sha256: "00".repeat(32),
                    source: HardwarePolicySource::StogasBundle,
                    stogas_signing_key_id: Some("test".into()),
                },
                releases: vec![verified_release],
                nodes: vec![node],
                original,
            },
        }
    }

    fn ledger(node: VerifiedNode) -> VerifiedNodeLedgerRecord {
        let trusted = bundle(node);
        let node = trusted.bundle.nodes[0].clone();
        VerifiedNodeLedgerRecord {
            admitted_at_unix_ms: NOW - 60_000,
            node_id: node.node_id.clone(),
            node,
            release: trusted.bundle.releases[0].clone(),
        }
    }

    fn unsigned_receipt(
        request: &[u8],
        response: &[u8],
        transcript: Option<&str>,
    ) -> ResponseProof {
        ResponseProof {
            schema: SCHEMA_V1.into(),
            request_id: "018f4f70-7c88-7b9a-baf8-31a93d2cf613".into(),
            created_at: "2026-08-24T12:34:56.789Z".into(),
            node_id: "33".repeat(32),
            catalog: ResponseCatalog {
                digest: format!("sha256:{}", "44".repeat(32)),
                sequence: 7,
                selection_ids: vec![
                    "author:openai".into(),
                    "model:gpt-5.5".into(),
                    "deployment:gpt-5.5".into(),
                    "route:openai-responses".into(),
                    "provider:openai".into(),
                ],
            },
            pricing: ResponsePricing {
                meters: BTreeMap::from([(
                    "input_tokens".into(),
                    ResponseMeter {
                        quantity: "12".into(),
                        rate_key: "per_million_tokens".into(),
                        rate_usd_atoms: "100".into(),
                        usd_atoms: "1".into(),
                    },
                )]),
                total_cost_usd_atoms: "1".into(),
                byok_cost_usd_atoms: None,
            },
            timing: ResponseTiming {
                total_ms: 20,
                provider_ms: 15,
                ttft_ms: Some(5),
            },
            proof: ResponseProofClaims {
                request_sha256: hex::encode(Sha256::digest(request)),
                response_sha256: hex::encode(Sha256::digest(response)),
                e2ee_transcript_sha256: transcript.map(str::to_owned),
                signature: String::new(),
            },
        }
    }

    fn sign_receipt(key: &SigningKey, mut proof: ResponseProof) -> Vec<u8> {
        proof.proof.signature.clear();
        let payload = ResponseProofPayload {
            schema: &proof.schema,
            request_id: &proof.request_id,
            created_at: &proof.created_at,
            node_id: &proof.node_id,
            catalog: &proof.catalog,
            pricing: &proof.pricing,
            timing: &proof.timing,
            proof: ResponseProofPayloadClaims {
                request: &proof.proof.request_sha256,
                response: &proof.proof.response_sha256,
                e2ee_transcript: proof.proof.e2ee_transcript_sha256.as_deref(),
            },
        };
        let mut message = SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
        proof.proof.signature = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes());
        serde_json::to_vec(&proof).unwrap()
    }

    fn receipt(
        key: &SigningKey,
        request: &[u8],
        response: &[u8],
        transcript: Option<&str>,
    ) -> Vec<u8> {
        sign_receipt(key, unsigned_receipt(request, response, transcript))
    }

    fn buffered_response(response: &[u8], proof: &[u8]) -> Vec<u8> {
        let mut body = response[..response.len() - 1].to_vec();
        body.extend_from_slice(b",\"stogas\":");
        body.extend_from_slice(proof);
        body.push(b'}');
        body
    }

    fn sse_response(unsigned: &[u8], proof: &[u8], terminal_start: usize) -> Vec<u8> {
        let mut response = unsigned[..terminal_start].to_vec();
        response.extend_from_slice(SSE_RECEIPT_PREFIX);
        response.extend_from_slice(proof);
        response.extend_from_slice(SSE_EVENT_END);
        response.extend_from_slice(&unsigned[terminal_start..]);
        response
    }

    #[test]
    fn verifies_exact_bodies_signed_fields_bundle_node_and_e2ee_transcript() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let transcript = "ab".repeat(32);
        let proof = receipt(&key, REQUEST, RESPONSE, Some(&transcript));
        let response = buffered_response(RESPONSE, &proof);
        let output = verify_with_bundle(
            REQUEST,
            &response,
            Some(&transcript),
            NOW,
            &bundle(node(&key)),
        )
        .unwrap();
        assert_eq!(output.node_id, "33".repeat(32));
        assert_eq!(output.created_at, "2026-08-24T12:34:56.789Z");
        assert_eq!(output.catalog.sequence, 7);
        assert_eq!(output.pricing.total_cost_usd_atoms, "1");
        assert_eq!(
            output.proof.request_sha256,
            hex::encode(Sha256::digest(REQUEST))
        );
        assert!(!output.proof.signature.is_empty());

        let hashed_output = verify_with_bundle_hashes(
            &proof,
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            Some(&transcript),
            NOW,
            &bundle(node(&key)),
        )
        .unwrap();
        assert_eq!(hashed_output.node_id, output.node_id);
    }

    #[test]
    fn active_receipts_require_an_exact_approved_catalog_identity() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let current_digest = format!("sha256:{}", "44".repeat(32));
        let next_digest = format!("sha256:{}", "55".repeat(32));
        let mut trusted = bundle(node(&key));
        trusted
            .bundle
            .catalogs
            .push(verified_catalog(&next_digest, 8, 1));

        let mut next = unsigned_receipt(REQUEST, RESPONSE, None);
        next.catalog.digest.clone_from(&next_digest);
        next.catalog.sequence = 8;
        let next = sign_receipt(&key, next);
        let output = verify_with_bundle_hashes(
            &next,
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap();
        assert_eq!(output.catalog.digest, next_digest);
        assert_eq!(output.catalog.sequence, 8);

        for (digest, sequence) in [
            (format!("sha256:{}", "66".repeat(32)), 7),
            (current_digest, 8),
            (format!("sha256:{}", "55".repeat(32)), 7),
        ] {
            let mut proof = unsigned_receipt(REQUEST, RESPONSE, None);
            proof.catalog.digest = digest;
            proof.catalog.sequence = sequence;
            let error = verify_with_bundle_hashes(
                &sign_receipt(&key, proof),
                &hex::encode(Sha256::digest(REQUEST)),
                &hex::encode(Sha256::digest(RESPONSE)),
                None,
                NOW,
                &trusted,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("response catalog is not authorized by the verified bundle")
            );
        }

        trusted.bundle.catalogs[1].minimum_gateway_sequence = 2;
        let error = verify_with_bundle_hashes(
            &next,
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("response catalog requires a newer gateway release")
        );
    }

    #[test]
    fn historical_receipts_require_the_exact_node_catalog_and_compatible_release() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let digest = format!("sha256:{}", "44".repeat(32));
        let ledger = ledger(node(&key));
        let approval = verified_catalog(&digest, 7, 1);
        let valid = receipt(&key, REQUEST, RESPONSE, None);
        let request_sha256 = hex::encode(Sha256::digest(REQUEST));
        let response_sha256 = hex::encode(Sha256::digest(RESPONSE));

        verify_with_ledger_hashes(
            &valid,
            &request_sha256,
            &response_sha256,
            None,
            &ledger,
            &approval,
        )
        .unwrap();

        for mismatched in [
            verified_catalog(&format!("sha256:{}", "55".repeat(32)), 7, 1),
            verified_catalog(&digest, 8, 1),
        ] {
            let error = verify_with_ledger_hashes(
                &valid,
                &request_sha256,
                &response_sha256,
                None,
                &ledger,
                &mismatched,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("response catalog differs from the historical catalog approval")
            );
        }

        let incompatible = verified_catalog(&digest, 7, 2);
        let error = verify_with_ledger_hashes(
            &valid,
            &request_sha256,
            &response_sha256,
            None,
            &ledger,
            &incompatible,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("historical response catalog requires a newer gateway release")
        );

        let mut other_node = unsigned_receipt(REQUEST, RESPONSE, None);
        other_node.node_id = "66".repeat(32);
        let error = verify_with_ledger_hashes(
            &sign_receipt(&key, other_node),
            &request_sha256,
            &response_sha256,
            None,
            &ledger,
            &approval,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("response node differs from the historical node record")
        );
    }

    #[test]
    fn node_signature_covers_node_and_every_catalog_claim() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let next_digest = format!("sha256:{}", "55".repeat(32));
        let mut trusted = bundle(node(&key));
        trusted
            .bundle
            .catalogs
            .push(verified_catalog(&next_digest, 8, 1));
        let signed = receipt(&key, REQUEST, RESPONSE, None);

        let mut changed_identity: ResponseProof = serde_json::from_slice(&signed).unwrap();
        changed_identity.catalog.digest = next_digest;
        changed_identity.catalog.sequence = 8;
        let error = verify_with_bundle_hashes(
            &serde_json::to_vec(&changed_identity).unwrap(),
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));

        let signed: ResponseProof = serde_json::from_slice(&signed).unwrap();
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        verify_signature(&signed, &public_key).unwrap();

        let mut changed_node = signed.clone();
        changed_node.node_id = "66".repeat(32);
        assert!(verify_signature(&changed_node, &public_key).is_err());

        let mut changed_digest = signed.clone();
        changed_digest.catalog.digest = format!("sha256:{}", "66".repeat(32));
        assert!(verify_signature(&changed_digest, &public_key).is_err());

        let mut changed_sequence = signed.clone();
        changed_sequence.catalog.sequence += 1;
        assert!(verify_signature(&changed_sequence, &public_key).is_err());

        let mut changed_selection = signed;
        changed_selection.catalog.selection_ids[1] = "model:gpt-5.6".into();
        assert!(verify_signature(&changed_selection, &public_key).is_err());
    }

    #[test]
    fn active_receipts_require_the_exact_signed_node_id() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let trusted = bundle(node(&key));
        let mut proof = unsigned_receipt(REQUEST, RESPONSE, None);
        proof.node_id = "66".repeat(32);
        let error = verify_with_bundle_hashes(
            &sign_receipt(&key, proof),
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("response node is not in the verified bundle")
        );
    }

    #[test]
    fn rejects_ambiguous_node_ids_and_response_signing_keys_during_response_verification() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let proof = receipt(&key, REQUEST, RESPONSE, None);

        let mut trusted = bundle(node(&key));
        let other_key = SigningKey::from_bytes(&[8_u8; 32]);
        trusted.bundle.nodes.push(node(&other_key));
        let error = verify_with_bundle_hashes(
            &proof,
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap_err();
        assert!(error.to_string().contains("node identity is ambiguous"));

        let mut trusted = bundle(node(&key));
        let mut duplicate_key_node = node(&key);
        duplicate_key_node.node_id = "44".repeat(32);
        trusted.bundle.nodes.push(duplicate_key_node);

        let error = verify_with_bundle_hashes(
            &proof,
            &hex::encode(Sha256::digest(REQUEST)),
            &hex::encode(Sha256::digest(RESPONSE)),
            None,
            NOW,
            &trusted,
        )
        .unwrap_err();
        assert!(error.to_string().contains("node identity is ambiguous"));
    }

    #[test]
    fn validates_request_scoped_ttft() {
        let key = SigningKey::from_bytes(&[8_u8; 32]);
        let encoded = receipt(&key, REQUEST, RESPONSE, None);
        let mut proof: ResponseProof = serde_json::from_slice(&encoded).unwrap();

        proof.timing.ttft_ms = Some(proof.timing.provider_ms + 1);
        assert!(validate_shape(&proof).is_ok());

        proof.timing.ttft_ms = Some(proof.timing.total_ms + 1);
        assert!(validate_shape(&proof).is_err());

        proof.timing.ttft_ms = None;
        assert!(validate_shape(&proof).is_ok());
    }

    #[test]
    fn sse_filter_verifies_all_openai_terminal_forms_at_every_chunk_boundary() {
        let key = SigningKey::from_bytes(&[10_u8; 32]);
        let transcript = "12".repeat(32);
        let cases = [
            (
                b"data: {\"id\":\"chatcmpl_1\",\"delta\":\"hello\"}\n\ndata: [DONE]\n\n".as_slice(),
                SSE_CHAT_TERMINAL_PREFIX,
            ),
            (
                b"event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\n\n"
                    .as_slice(),
                SSE_RESPONSES_TERMINAL_PREFIX,
            ),
            (
                b"event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\nevent: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_1\"}}\n\n"
                    .as_slice(),
                SSE_RESPONSES_INCOMPLETE_TERMINAL_PREFIX,
            ),
        ];
        for (unsigned, terminal_prefix) in cases {
            let terminal_start = unsigned
                .windows(terminal_prefix.len())
                .position(|part| part == terminal_prefix)
                .unwrap();
            let proof = receipt(&key, REQUEST, unsigned, Some(&transcript));
            let encoded = sse_response(unsigned, &proof, terminal_start);

            for split in 0..=encoded.len() {
                let mut stream = ResponseProofSseStream::new(REQUEST);
                let mut output = Vec::new();
                for chunk in [&encoded[..split], &encoded[split..]] {
                    output.extend(stream.push(chunk).unwrap().into_iter().flatten());
                }
                output.extend(
                    stream
                        .finish(Some(&transcript), NOW, &bundle(node(&key)))
                        .unwrap()
                        .into_iter()
                        .flatten(),
                );
                assert_eq!(output, encoded, "split at byte {split}");
            }

            let mut stream = ResponseProofSseStream::new(REQUEST);
            let mut output = Vec::new();
            for byte in &encoded {
                output.extend(
                    stream
                        .push(std::slice::from_ref(byte))
                        .unwrap()
                        .into_iter()
                        .flatten(),
                );
            }
            output.extend(
                stream
                    .finish(Some(&transcript), NOW, &bundle(node(&key)))
                    .unwrap()
                    .into_iter()
                    .flatten(),
            );
            assert_eq!(output, encoded);
        }
    }

    #[test]
    fn sse_filter_rejects_mutation_truncation_misplacement_duplication_and_trailing_bytes() {
        let key = SigningKey::from_bytes(&[11_u8; 32]);
        let unsigned = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n";
        let terminal_start = unsigned
            .windows(SSE_CHAT_TERMINAL_PREFIX.len())
            .position(|part| part == SSE_CHAT_TERMINAL_PREFIX)
            .unwrap();
        let proof = receipt(&key, REQUEST, unsigned, None);
        let valid = sse_response(unsigned, &proof, terminal_start);

        let mut changed = valid.clone();
        let changed_at = changed
            .windows(b"hello".len())
            .position(|part| part == b"hello")
            .unwrap();
        changed[changed_at] = b'j';
        let mut stream = ResponseProofSseStream::new(REQUEST);
        let _ = stream.push(&changed).unwrap();
        assert!(stream.finish(None, NOW, &bundle(node(&key))).is_err());

        let mut stream = ResponseProofSseStream::new(b"changed request");
        let _ = stream.push(&valid).unwrap();
        assert!(stream.finish(None, NOW, &bundle(node(&key))).is_err());

        let no_receipt = unsigned.to_vec();
        let mut stream = ResponseProofSseStream::new(REQUEST);
        assert!(stream.push(&no_receipt).is_err());

        let receipt_frame = {
            let mut frame = SSE_RECEIPT_PREFIX.to_vec();
            frame.extend_from_slice(&proof);
            frame.extend_from_slice(SSE_EVENT_END);
            frame
        };
        let mut misplaced = unsigned[..terminal_start].to_vec();
        misplaced.extend_from_slice(&receipt_frame);
        misplaced.extend_from_slice(b"data: {\"late\":true}\n\n");
        misplaced.extend_from_slice(&unsigned[terminal_start..]);
        let mut stream = ResponseProofSseStream::new(REQUEST);
        assert!(stream.push(&misplaced).is_err());

        let mut duplicate = unsigned[..terminal_start].to_vec();
        duplicate.extend_from_slice(&receipt_frame);
        duplicate.extend_from_slice(&receipt_frame);
        duplicate.extend_from_slice(&unsigned[terminal_start..]);
        let mut stream = ResponseProofSseStream::new(REQUEST);
        assert!(stream.push(&duplicate).is_err());

        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"data: unsigned\n\n");
        let mut stream = ResponseProofSseStream::new(REQUEST);
        assert!(stream.push(&trailing).is_err());

        let mut stream = ResponseProofSseStream::new(REQUEST);
        let _ = stream.push(&valid[..valid.len() - 1]).unwrap();
        assert!(stream.finish(None, NOW, &bundle(node(&key))).is_err());
    }

    #[test]
    fn rejects_body_transcript_node_key_and_expiry_mismatches() {
        let key = SigningKey::from_bytes(&[8_u8; 32]);
        let transcript = "cd".repeat(32);
        let proof = receipt(&key, REQUEST, RESPONSE, Some(&transcript));
        let response = buffered_response(RESPONSE, &proof);
        let trusted = bundle(node(&key));
        assert!(
            verify_with_bundle(b"changed", &response, Some(&transcript), NOW, &trusted).is_err()
        );
        assert!(
            verify_with_bundle_hashes(
                &proof,
                &hex::encode(Sha256::digest(REQUEST)),
                &"00".repeat(32),
                Some(&transcript),
                NOW,
                &trusted,
            )
            .is_err()
        );
        let changed_response = buffered_response(br#"{"id":"resp_2"}"#, &proof);
        assert!(
            verify_with_bundle(REQUEST, &changed_response, Some(&transcript), NOW, &trusted)
                .is_err()
        );
        assert!(
            verify_with_bundle(REQUEST, &response, Some(&"ef".repeat(32)), NOW, &trusted).is_err()
        );

        let mut changed: ResponseProof = serde_json::from_slice(&proof).unwrap();
        changed.created_at = "2026-08-24T12:34:56.790Z".into();
        let changed = buffered_response(RESPONSE, &serde_json::to_vec(&changed).unwrap());
        assert!(verify_with_bundle(REQUEST, &changed, Some(&transcript), NOW, &trusted).is_err());

        let mut noncanonical: ResponseProof = serde_json::from_slice(&proof).unwrap();
        noncanonical.created_at = "2026-08-24T12:34:56Z".into();
        assert!(validate_shape(&noncanonical).is_err());

        let mut noncanonical: ResponseProof = serde_json::from_slice(&proof).unwrap();
        noncanonical.pricing.total_cost_usd_atoms = "01".into();
        assert!(validate_shape(&noncanonical).is_err());
        let other_key = SigningKey::from_bytes(&[9_u8; 32]);
        assert!(
            verify_with_bundle(
                REQUEST,
                &response,
                Some(&transcript),
                NOW,
                &bundle(node(&other_key))
            )
            .is_err()
        );
        assert!(
            verify_with_bundle(
                REQUEST,
                &response,
                Some(&transcript),
                trusted.bundle.expires_at_unix_ms,
                &trusted
            )
            .is_err()
        );
    }
}
