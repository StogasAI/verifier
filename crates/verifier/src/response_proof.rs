//! Compact post-facto response receipts signed by a bundle-attested guest key.

use crate::{
    DRAND_GENESIS_SECONDS, DRAND_PERIOD_SECONDS, Environment, Error, VerificationOutput,
    VerifiedNode, VerifiedNodeLedgerRecord, strict_json, verify_node_ledger_record,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Receipt schema emitted by the gateway.
pub const SCHEMA_V1: &str = "stogas.response-proof.v1";
/// Maximum serialized receipt size.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;
/// Maximum request or response body accepted by one-shot proof verification.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

const MAX_CATALOG_NODE_IDS: usize = 64;
const MAX_CATALOG_NODE_ID_BYTES: usize = 256;
const CLOCK_SKEW_MS: i64 = 60_000;
const SIGNATURE_DOMAIN: &[u8] = b"stogas.response-proof.v1\0";

/// Signed receipt returned in `X-Stogas-Proof` or the final `stogas.proof` SSE event.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProof {
    pub schema: String,
    pub request_id: String,
    pub request_path: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub catalog_node_ids: Vec<String>,
    pub drand_round: u64,
    pub streaming: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_transcript_sha256: Option<String>,
    pub proof_hash: String,
    pub signature: String,
    pub signing_public_key: String,
}

/// Receipt fields covered by `proof_hash`.
#[derive(Clone, Debug, Serialize)]
struct ResponseProofPayload<'a> {
    schema: &'a str,
    request_id: &'a str,
    request_path: &'a str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    catalog_node_ids: &'a [String],
    drand_round: u64,
    streaming: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    e2ee_transcript_sha256: Option<&'a str>,
}

/// Authenticated receipt metadata after body and attested-key verification.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedResponseProof {
    pub node_id: String,
    pub proof_hash: String,
    pub request_id: String,
    pub request_sha256: String,
    pub response_sha256: String,
}

/// Verify a receipt against an unexpired, already verified bundle.
///
/// `response_body` is the exact buffered response body. For streaming receipts it is the
/// concatenation of every client-visible SSE frame except the `stogas.proof` event itself.
///
/// # Errors
///
/// Returns an error for malformed receipts, body mismatches, signature failures, unknown keys,
/// invalid drand claims, expired bundle state, or a mismatched E2EE transcript.
pub fn verify_with_bundle(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    bundle: &VerificationOutput,
) -> Result<VerifiedResponseProof, Error> {
    if now_unix_ms >= bundle.bundle.expires_at_unix_ms {
        return Err(Error::ResponseProof(
            "the bundle used to verify the response proof has expired".into(),
        ));
    }
    let proof = parse_and_verify_bodies(
        proof_bytes,
        request_body,
        response_body,
        expected_e2ee_transcript_sha256,
    )?;
    let matching = bundle
        .bundle
        .nodes
        .iter()
        .filter(|node| node.report_data.ed25519_public_key == proof.signing_public_key)
        .collect::<Vec<_>>();
    let [node] = matching.as_slice() else {
        return Err(Error::ResponseProof(
            "the signing key does not identify exactly one trusted bundle node".into(),
        ));
    };
    verify_for_node(proof, node, now_unix_ms)
}

/// Verify a receipt against an already verified historical node-ledger record.
///
/// # Errors
///
/// Returns an error for malformed receipts, body mismatches, signature failures, a different
/// historical node key, invalid drand claims, or a mismatched E2EE transcript.
pub fn verify_with_ledger(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    ledger: &VerifiedNodeLedgerRecord,
) -> Result<VerifiedResponseProof, Error> {
    let proof = parse_and_verify_bodies(
        proof_bytes,
        request_body,
        response_body,
        expected_e2ee_transcript_sha256,
    )?;
    if ledger.node.report_data.ed25519_public_key != proof.signing_public_key {
        return Err(Error::ResponseProof(
            "the signing key differs from the historical node ledger".into(),
        ));
    }
    verify_for_node(proof, &ledger.node, now_unix_ms)
}

/// Verify the historical node ledger and receipt together.
///
/// # Errors
///
/// Returns an error when either trust chain or their signing-key binding is invalid.
pub fn verify_with_ledger_bytes(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    ledger_bytes: &[u8],
    environment: &Environment,
) -> Result<VerifiedResponseProof, Error> {
    let ledger = verify_node_ledger_record(ledger_bytes, environment)?;
    verify_with_ledger(
        proof_bytes,
        request_body,
        response_body,
        expected_e2ee_transcript_sha256,
        now_unix_ms,
        &ledger,
    )
}

fn parse_and_verify_bodies(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
) -> Result<ResponseProof, Error> {
    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ResponseProof(format!(
            "proof exceeds {MAX_PROOF_BYTES} bytes"
        )));
    }
    if request_body.len() > MAX_BODY_BYTES || response_body.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "request and response bodies must not exceed {MAX_BODY_BYTES} bytes"
        )));
    }
    let value = strict_json::from_slice(proof_bytes)
        .map_err(|error| Error::ResponseProof(format!("invalid JSON: {error}")))?;
    let proof: ResponseProof = serde_json::from_value(value)
        .map_err(|error| Error::ResponseProof(format!("invalid receipt: {error}")))?;
    validate_shape(&proof)?;

    let actual_request_hash = hex::encode(Sha256::digest(request_body));
    if actual_request_hash != proof.request_sha256 {
        return Err(Error::ResponseProof("request body SHA-256 differs".into()));
    }
    let actual_response_hash = hex::encode(Sha256::digest(response_body));
    if actual_response_hash != proof.response_sha256 {
        return Err(Error::ResponseProof("response body SHA-256 differs".into()));
    }
    if proof.e2ee_transcript_sha256.as_deref() != expected_e2ee_transcript_sha256 {
        return Err(Error::ResponseProof(
            "E2EE transcript binding differs".into(),
        ));
    }

    let payload = ResponseProofPayload {
        schema: &proof.schema,
        request_id: &proof.request_id,
        request_path: &proof.request_path,
        request_sha256: &proof.request_sha256,
        response_sha256: &proof.response_sha256,
        catalog_node_ids: &proof.catalog_node_ids,
        drand_round: proof.drand_round,
        streaming: proof.streaming,
        e2ee_transcript_sha256: proof.e2ee_transcript_sha256.as_deref(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| Error::ResponseProof(format!("could not encode payload: {error}")))?;
    let actual_proof_hash = hex::encode(Sha256::digest(payload_bytes));
    if actual_proof_hash != proof.proof_hash {
        return Err(Error::ResponseProof("proof hash differs".into()));
    }
    verify_signature(&proof)?;
    Ok(proof)
}

fn validate_shape(proof: &ResponseProof) -> Result<(), Error> {
    if proof.schema != SCHEMA_V1 {
        return Err(Error::ResponseProof(
            "unsupported response proof schema".into(),
        ));
    }
    validate_canonical_uuid(&proof.request_id)?;
    if !matches!(
        proof.request_path.as_str(),
        "/v1/responses" | "/v1/chat/completions"
    ) {
        return Err(Error::ResponseProof(
            "request path is not an inference endpoint".into(),
        ));
    }
    for (value, label) in [
        (&proof.request_sha256, "request SHA-256"),
        (&proof.response_sha256, "response SHA-256"),
        (&proof.proof_hash, "proof hash"),
    ] {
        if !is_lower_hex(value, 32) {
            return Err(Error::ResponseProof(format!(
                "{label} must be 64 lowercase hexadecimal characters"
            )));
        }
    }
    if proof.catalog_node_ids.is_empty()
        || proof.catalog_node_ids.len() > MAX_CATALOG_NODE_IDS
        || proof.catalog_node_ids.iter().any(|id| {
            id.is_empty()
                || id.len() > MAX_CATALOG_NODE_ID_BYTES
                || id.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return Err(Error::ResponseProof(
            "resolved catalog node IDs are invalid".into(),
        ));
    }
    let mut sorted = proof.catalog_node_ids.clone();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::ResponseProof(
            "resolved catalog node IDs contain duplicates".into(),
        ));
    }
    if proof.drand_round == 0 {
        return Err(Error::ResponseProof("drand round must be positive".into()));
    }
    if proof
        .e2ee_transcript_sha256
        .as_ref()
        .is_some_and(|value| !is_lower_hex(value, 32))
    {
        return Err(Error::ResponseProof(
            "E2EE transcript hash must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    decode_canonical_base64(&proof.signing_public_key, 32, "signing public key")?;
    decode_canonical_base64(&proof.signature, 64, "signature")?;
    Ok(())
}

fn verify_signature(proof: &ResponseProof) -> Result<(), Error> {
    let public_key = decode_canonical_base64(&proof.signing_public_key, 32, "signing public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::ResponseProof("signing public key must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::ResponseProof("signing public key is invalid".into()))?;
    let signature = decode_canonical_base64(&proof.signature, 64, "signature")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| Error::ResponseProof("signature must be 64 bytes".into()))?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + proof.proof_hash.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(proof.proof_hash.as_bytes());
    key.verify(&message, &signature)
        .map_err(|_| Error::ResponseProof("signature is invalid".into()))
}

fn verify_for_node(
    proof: ResponseProof,
    node: &VerifiedNode,
    now_unix_ms: i64,
) -> Result<VerifiedResponseProof, Error> {
    if proof.drand_round < node.drand_round {
        return Err(Error::ResponseProof(
            "receipt drand round predates the node's admitted evidence".into(),
        ));
    }
    let round_time = drand_round_time_unix_ms(proof.drand_round)?;
    if round_time > now_unix_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(Error::ResponseProof(
            "receipt drand round is in the future".into(),
        ));
    }
    Ok(VerifiedResponseProof {
        node_id: node.node_id.clone(),
        proof_hash: proof.proof_hash,
        request_id: proof.request_id,
        request_sha256: proof.request_sha256,
        response_sha256: proof.response_sha256,
    })
}

fn drand_round_time_unix_ms(round: u64) -> Result<i64, Error> {
    let offset = i64::try_from(round.saturating_sub(1))
        .map_err(|_| Error::ResponseProof("drand round is too large".into()))?;
    offset
        .checked_mul(DRAND_PERIOD_SECONDS)
        .and_then(|seconds| DRAND_GENESIS_SECONDS.checked_add(seconds))
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(|| Error::ResponseProof("drand round time overflows".into()))
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

fn validate_canonical_uuid(value: &str) -> Result<(), Error> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 8 | 13 | 18 | 23)
                && !byte.is_ascii_digit()
                && !(b'a'..=b'f').contains(byte)
        })
    {
        return Err(Error::ResponseProof(
            "request ID must be a lowercase canonical UUID".into(),
        ));
    }
    Ok(())
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
    use crate::{BundleEnvelope, DrandBeacon, ReportData, VerifiedBundle, VerifiedNode};
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    const NOW: i64 = 1_784_838_400_000;
    const REQUEST_ID: &str = "018f4f70-7c88-7b9a-baf8-31a93d2cf613";
    const REQUEST: &[u8] = br#"{"model":"gpt-5.5"}"#;
    const RESPONSE: &[u8] = br#"{"id":"resp_1"}"#;

    fn current_round() -> u64 {
        u64::try_from((NOW / 1_000 - DRAND_GENESIS_SECONDS) / DRAND_PERIOD_SECONDS + 1).unwrap()
    }

    fn node(key: &SigningKey) -> VerifiedNode {
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        let round = current_round();
        VerifiedNode {
            accepted_cert_sha256: vec!["11".repeat(32)],
            chip_id: "22".repeat(64),
            drand_round: round,
            drand_round_time_unix_ms: drand_round_time_unix_ms(round).unwrap(),
            evidence_age_ms: 0,
            node_id: "33".repeat(32),
            quote_verified_at_unix_ms: NOW,
            region: "us-east-va".into(),
            report_data: ReportData {
                active_cert_sha256: "11".repeat(32),
                accepted_cert_sha256: vec!["11".repeat(32)],
                catalog_hash: "44".repeat(32),
                drand: DrandBeacon {
                    chain_hash: "55".repeat(32),
                    network: "quicknet".into(),
                    randomness: "66".repeat(32),
                    round,
                    signature: "77".repeat(48),
                },
                ed25519_public_key: public_key,
                hpke_public_key: URL_SAFE_NO_PAD.encode([4_u8; 65]),
                schema: "stogas.node-report.v1".into(),
                tls_spki_sha256: "88".repeat(32),
            },
            report_data_sha512: "99".repeat(64),
            release_measurement: "aa".repeat(48),
            reported_tcb: "0x0102030405060708".into(),
            tls_spki_sha256: "88".repeat(32),
        }
    }

    fn bundle(node: VerifiedNode) -> VerificationOutput {
        let original: BundleEnvelope = serde_json::from_value(json!({
            "body": {
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
            bundle: VerifiedBundle {
                sequence: 1,
                created_at_unix_ms: NOW - 60_000,
                expires_at_unix_ms: NOW + 15 * 60_000,
                excluded_nodes: Vec::new(),
                releases: Vec::new(),
                nodes: vec![node],
                original,
            },
        }
    }

    fn receipt(
        key: &SigningKey,
        request: &[u8],
        response: &[u8],
        transcript: Option<&str>,
    ) -> Vec<u8> {
        let payload = ResponseProofPayload {
            schema: SCHEMA_V1,
            request_id: REQUEST_ID,
            request_path: "/v1/responses",
            request_sha256: &hex::encode(Sha256::digest(request)),
            response_sha256: &hex::encode(Sha256::digest(response)),
            catalog_node_ids: &["route:responses".into(), "deployment:gpt-5.5".into()],
            drand_round: current_round(),
            streaming: false,
            e2ee_transcript_sha256: transcript,
        };
        let proof_hash = hex::encode(Sha256::digest(serde_json::to_vec(&payload).unwrap()));
        let mut message = SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(proof_hash.as_bytes());
        serde_json::to_vec(&ResponseProof {
            schema: payload.schema.into(),
            request_id: payload.request_id.into(),
            request_path: payload.request_path.into(),
            request_sha256: payload.request_sha256.into(),
            response_sha256: payload.response_sha256.into(),
            catalog_node_ids: payload.catalog_node_ids.to_vec(),
            drand_round: payload.drand_round,
            streaming: payload.streaming,
            e2ee_transcript_sha256: transcript.map(str::to_owned),
            proof_hash,
            signature: URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()),
            signing_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn verifies_exact_bodies_signature_bundle_key_and_e2ee_transcript() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let transcript = "ab".repeat(32);
        let proof = receipt(&key, REQUEST, RESPONSE, Some(&transcript));
        let output = verify_with_bundle(
            &proof,
            REQUEST,
            RESPONSE,
            Some(&transcript),
            NOW,
            &bundle(node(&key)),
        )
        .unwrap();
        assert_eq!(output.request_id, REQUEST_ID);
        assert_eq!(output.node_id, "33".repeat(32));
        assert_eq!(output.request_sha256, hex::encode(Sha256::digest(REQUEST)));
        assert_eq!(
            output.response_sha256,
            hex::encode(Sha256::digest(RESPONSE))
        );
    }

    #[test]
    fn rejects_body_transcript_key_and_expiry_mismatches() {
        let key = SigningKey::from_bytes(&[8_u8; 32]);
        let transcript = "cd".repeat(32);
        let proof = receipt(&key, REQUEST, RESPONSE, Some(&transcript));
        let trusted = bundle(node(&key));
        assert!(
            verify_with_bundle(
                &proof,
                b"changed",
                RESPONSE,
                Some(&transcript),
                NOW,
                &trusted
            )
            .is_err()
        );
        assert!(
            verify_with_bundle(
                &proof,
                REQUEST,
                RESPONSE,
                Some(&"ef".repeat(32)),
                NOW,
                &trusted
            )
            .is_err()
        );

        let other_key = SigningKey::from_bytes(&[9_u8; 32]);
        assert!(
            verify_with_bundle(
                &proof,
                REQUEST,
                RESPONSE,
                Some(&transcript),
                NOW,
                &bundle(node(&other_key))
            )
            .is_err()
        );
        assert!(
            verify_with_bundle(
                &proof,
                REQUEST,
                RESPONSE,
                Some(&transcript),
                trusted.bundle.expires_at_unix_ms,
                &trusted
            )
            .is_err()
        );
    }
}
