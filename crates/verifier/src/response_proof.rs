//! Compact post-facto response receipts signed by a bundle-attested guest key.

use crate::{
    Environment, Error, VerificationOutput, VerifiedNode, VerifiedNodeLedgerRecord, strict_json,
    verify_node_ledger_record,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Receipt schema emitted by the gateway.
pub const SCHEMA_V4: &str = "stogas.response-proof.v4";
/// Maximum serialized receipt size.
pub const MAX_PROOF_BYTES: usize = 4 * 1024;
/// Maximum request or response body accepted by one-shot proof verification.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

const MAX_CATALOG_ID_BYTES: usize = 128;
const SIGNATURE_DOMAIN: &[u8] = b"stogas.response-proof.v4\0";
const CATALOG_NODE_KINDS: [&str; 5] = ["author", "model", "deployment", "route", "provider"];

/// Signed receipt returned in `X-Stogas-Proof` or the final `stogas.proof` SSE event.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProof {
    pub schema: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub catalog_digest: String,
    pub catalog_node_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_transcript_sha256: Option<String>,
    pub signature: String,
}

/// Receipt fields covered directly by the signature.
#[derive(Clone, Debug, Serialize)]
struct ResponseProofPayload<'a> {
    schema: &'a str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    catalog_digest: &'a str,
    catalog_node_ids: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    e2ee_transcript_sha256: Option<&'a str>,
}

/// Authenticated routing identity after exact-body and attested-key verification.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedResponseProof {
    pub node_id: String,
    pub catalog_digest: String,
    pub catalog_node_ids: Vec<String>,
}

/// Verify a receipt against an unexpired, already verified bundle.
///
/// `response_body` is the exact buffered response body. For streaming receipts it is the
/// concatenation of every client-visible SSE frame except the `stogas.proof` event itself.
///
/// # Errors
///
/// Returns an error for malformed receipts, body mismatches, signature failures, unknown keys,
/// expired bundle state, or a mismatched E2EE transcript.
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
    let proof = parse_and_validate(
        proof_bytes,
        request_body,
        response_body,
        expected_e2ee_transcript_sha256,
    )?;
    let matching = bundle
        .bundle
        .nodes
        .iter()
        .filter(|node| verify_signature(&proof, &node.report_data.ed25519_public_key).is_ok())
        .collect::<Vec<_>>();
    let [node] = matching.as_slice() else {
        return Err(Error::ResponseProof(
            "the signature does not identify exactly one trusted bundle node".into(),
        ));
    };
    Ok(verified_output(proof, node))
}

/// Verify a receipt against an already verified historical node-ledger record.
///
/// # Errors
///
/// Returns an error for malformed receipts, body mismatches, signature failures, a different
/// historical node key, or a mismatched E2EE transcript.
pub fn verify_with_ledger(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    _now_unix_ms: i64,
    ledger: &VerifiedNodeLedgerRecord,
) -> Result<VerifiedResponseProof, Error> {
    let proof = parse_and_validate(
        proof_bytes,
        request_body,
        response_body,
        expected_e2ee_transcript_sha256,
    )?;
    verify_signature(&proof, &ledger.node.report_data.ed25519_public_key)?;
    Ok(verified_output(proof, &ledger.node))
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

fn parse_and_validate(
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

    if hex::encode(Sha256::digest(request_body)) != proof.request_sha256 {
        return Err(Error::ResponseProof("request body SHA-256 differs".into()));
    }
    if hex::encode(Sha256::digest(response_body)) != proof.response_sha256 {
        return Err(Error::ResponseProof("response body SHA-256 differs".into()));
    }
    if proof.e2ee_transcript_sha256.as_deref() != expected_e2ee_transcript_sha256 {
        return Err(Error::ResponseProof(
            "E2EE transcript binding differs".into(),
        ));
    }
    Ok(proof)
}

fn validate_shape(proof: &ResponseProof) -> Result<(), Error> {
    if proof.schema != SCHEMA_V4 {
        return Err(Error::ResponseProof(
            "unsupported response proof schema".into(),
        ));
    }
    for (value, label) in [
        (&proof.request_sha256, "request SHA-256"),
        (&proof.response_sha256, "response SHA-256"),
    ] {
        if !is_lower_hex(value, 32) {
            return Err(Error::ResponseProof(format!(
                "{label} must be 64 lowercase hexadecimal characters"
            )));
        }
    }
    if !proof.catalog_digest.starts_with("sha256:")
        || !is_lower_hex(&proof.catalog_digest["sha256:".len()..], 32)
    {
        return Err(Error::ResponseProof(
            "catalog digest must be sha256-prefixed lowercase hexadecimal".into(),
        ));
    }
    if proof.catalog_node_ids.len() != CATALOG_NODE_KINDS.len()
        || proof
            .catalog_node_ids
            .iter()
            .zip(CATALOG_NODE_KINDS)
            .any(|(value, kind)| {
                value
                    .strip_prefix(kind)
                    .and_then(|suffix| suffix.strip_prefix(':'))
                    .is_none_or(|id| !is_catalog_id(id))
            })
    {
        return Err(Error::ResponseProof(
            "catalog node IDs must contain author, model, deployment, route, and provider in canonical order".into(),
        ));
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
    decode_canonical_base64(&proof.signature, 64, "signature")?;
    Ok(())
}

fn verify_signature(proof: &ResponseProof, public_key: &str) -> Result<(), Error> {
    let public_key = decode_canonical_base64(public_key, 32, "trusted node signing public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::ResponseProof("signing public key must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::ResponseProof("signing public key is invalid".into()))?;
    let signature = decode_canonical_base64(&proof.signature, 64, "signature")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| Error::ResponseProof("signature must be 64 bytes".into()))?;
    let payload = ResponseProofPayload {
        schema: &proof.schema,
        request_sha256: &proof.request_sha256,
        response_sha256: &proof.response_sha256,
        catalog_digest: &proof.catalog_digest,
        catalog_node_ids: &proof.catalog_node_ids,
        e2ee_transcript_sha256: proof.e2ee_transcript_sha256.as_deref(),
    };
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| Error::ResponseProof(format!("could not encode payload: {error}")))?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + payload.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&payload);
    key.verify(&message, &signature)
        .map_err(|_| Error::ResponseProof("signature is invalid".into()))
}

fn verified_output(proof: ResponseProof, node: &VerifiedNode) -> VerifiedResponseProof {
    VerifiedResponseProof {
        node_id: node.node_id.clone(),
        catalog_digest: proof.catalog_digest,
        catalog_node_ids: proof.catalog_node_ids,
    }
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

fn is_catalog_id(value: &str) -> bool {
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
        BundleEnvelope, CatalogIdentity, DrandBeacon, ReportData, VerifiedBundle, VerifiedNode,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    const NOW: i64 = 1_784_838_400_000;
    const REQUEST: &[u8] = br#"{"model":"gpt-5.5"}"#;
    const RESPONSE: &[u8] = br#"{"id":"resp_1"}"#;

    fn node(key: &SigningKey) -> VerifiedNode {
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        VerifiedNode {
            accepted_cert_sha256: vec!["11".repeat(32)],
            catalog: CatalogIdentity {
                digest: format!("sha256:{}", "44".repeat(32)),
                sequence: 7,
            },
            chip_id: "22".repeat(64),
            drand_round: 123,
            drand_round_time_unix_ms: NOW - 1_000,
            evidence_age_ms: 0,
            node_id: "33".repeat(32),
            quote_verified_at_unix_ms: NOW,
            region: "us-east-va".into(),
            report_data: ReportData {
                active_cert_sha256: "11".repeat(32),
                accepted_cert_sha256: vec!["11".repeat(32)],
                drand: DrandBeacon {
                    chain_hash: "55".repeat(32),
                    network: "quicknet".into(),
                    randomness: "66".repeat(32),
                    round: 123,
                    signature: "77".repeat(48),
                },
                ed25519_public_key: public_key,
                hpke_public_key: URL_SAFE_NO_PAD.encode([4_u8; 65]),
                schema: "stogas.node-report.v2".into(),
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
        let request_hash = hex::encode(Sha256::digest(request));
        let response_hash = hex::encode(Sha256::digest(response));
        let catalog_digest = format!("sha256:{}", "44".repeat(32));
        let catalog_node_ids = vec![
            "author:openai".into(),
            "model:gpt-5.5".into(),
            "deployment:gpt-5.5".into(),
            "route:openai-responses".into(),
            "provider:openai".into(),
        ];
        let payload = ResponseProofPayload {
            schema: SCHEMA_V4,
            request_sha256: &request_hash,
            response_sha256: &response_hash,
            catalog_digest: &catalog_digest,
            catalog_node_ids: &catalog_node_ids,
            e2ee_transcript_sha256: transcript,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut message = SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&payload_bytes);
        let signature = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes());
        serde_json::to_vec(&ResponseProof {
            schema: SCHEMA_V4.into(),
            request_sha256: request_hash,
            response_sha256: response_hash,
            catalog_digest,
            catalog_node_ids: vec![
                "author:openai".into(),
                "model:gpt-5.5".into(),
                "deployment:gpt-5.5".into(),
                "route:openai-responses".into(),
                "provider:openai".into(),
            ],
            e2ee_transcript_sha256: transcript.map(str::to_owned),
            signature,
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
        assert_eq!(output.node_id, "33".repeat(32));
        assert_eq!(
            output.catalog_node_ids,
            [
                "author:openai",
                "model:gpt-5.5",
                "deployment:gpt-5.5",
                "route:openai-responses",
                "provider:openai",
            ]
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
