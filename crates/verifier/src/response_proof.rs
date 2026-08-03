//! Compact signed response fields from a bundle-attested gateway node.

use crate::{
    Error, VerificationOutput, VerifiedCatalogRelease, VerifiedNodeLedgerRecord, strict_json,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// Response-proof schema emitted by the gateway.
pub const SCHEMA_V1: &str = "stogas.response-proof.v1";
/// Maximum serialized response-proof size.
pub const MAX_PROOF_BYTES: usize = 8 * 1024;
/// Maximum request or response body accepted by one-shot proof verification.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"stogas.response-proof.v1\0";
const MAX_CATALOG_ID_BYTES: usize = 128;
const MAX_METERS: usize = 64;
const CATALOG_NODE_KINDS: [&str; 5] = ["author", "model", "deployment", "route", "provider"];

/// Exact catalog identity and selected graph path for one request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCatalog {
    pub digest: String,
    pub sequence: u64,
    pub node_ids: Vec<String>,
}

/// One priced usage meter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMeter {
    pub quantity: String,
    #[serde(rename = "rateKey")]
    pub rate_key: String,
    #[serde(rename = "rateUsdAtoms")]
    pub rate_usd_atoms: String,
    #[serde(rename = "usdAtoms")]
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
    pub time_to_first_output_ms: Option<u32>,
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

/// Signed response fields returned in `X-Stogas-Proof` or the final `stogas` SSE comment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProof {
    pub schema: String,
    pub request_id: String,
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
    pub node_id: String,
    pub catalog: ResponseCatalog,
    pub pricing: ResponsePricing,
    pub timing: ResponseTiming,
    pub proof: ResponseProofClaims,
}

/// Verify response fields against an unexpired, already verified bundle.
///
/// `response_body` is the exact buffered body. For a stream it is every
/// client-visible SSE byte except the final `stogas` comment.
///
/// # Errors
///
/// Returns an error for malformed fields, body mismatches, signature failures,
/// unknown nodes, expired bundle state, or a mismatched E2EE transcript.
pub fn verify_with_bundle(
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    now_unix_ms: i64,
    bundle: &VerificationOutput,
) -> Result<VerifiedResponseProof, Error> {
    if request_body.len() > MAX_BODY_BYTES || response_body.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "request and response bodies must not exceed {MAX_BODY_BYTES} bytes in one-shot verification"
        )));
    }
    verify_with_bundle_hashes(
        proof_bytes,
        &hex::encode(Sha256::digest(request_body)),
        &hex::encode(Sha256::digest(response_body)),
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
    if !bundle.bundle.catalogs.iter().any(|catalog| {
        catalog.runtime_digest == proof.catalog.digest && catalog.sequence == proof.catalog.sequence
    }) {
        return Err(Error::ResponseProof(
            "the response catalog is not authorized by the verified bundle".into(),
        ));
    }
    let node = bundle
        .bundle
        .nodes
        .iter()
        .find(|node| node.node_id == proof.node_id)
        .ok_or_else(|| {
            Error::ResponseProof("the response node is not in the verified bundle".into())
        })?;
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
    proof_bytes: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    expected_e2ee_transcript_sha256: Option<&str>,
    ledger: &VerifiedNodeLedgerRecord,
    catalog: &VerifiedCatalogRelease,
) -> Result<VerifiedResponseProof, Error> {
    if request_body.len() > MAX_BODY_BYTES || response_body.len() > MAX_BODY_BYTES {
        return Err(Error::ResponseProof(format!(
            "request and response bodies must not exceed {MAX_BODY_BYTES} bytes in one-shot verification"
        )));
    }
    verify_with_ledger_hashes(
        proof_bytes,
        &hex::encode(Sha256::digest(request_body)),
        &hex::encode(Sha256::digest(response_body)),
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
    if proof.catalog.node_ids.len() != CATALOG_NODE_KINDS.len()
        || proof
            .catalog
            .node_ids
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
            "catalog node IDs must contain author, model, deployment, route, and provider in canonical order".into(),
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
            .time_to_first_output_ms
            .is_some_and(|value| value > proof.timing.provider_ms)
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
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
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
        AllowedCatalog, BundleEnvelope, CatalogIdentity, DrandBeacon, ReleaseProvenance,
        ReportData, VerifiedBundle, VerifiedCatalogRelease, VerifiedNode,
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
            region: "us-east-va".into(),
            report_data: ReportData {
                active_cert_sha256: "11".repeat(32),
                accepted_cert_sha256: vec!["11".repeat(32)],
                catalog: CatalogIdentity {
                    digest: format!("sha256:{}", "44".repeat(32)),
                    sequence: 7,
                },
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

    fn bundle(node: VerifiedNode) -> VerificationOutput {
        let catalog_evidence: AllowedCatalog = serde_json::from_value(json!({
            "github_in_toto": [{}],
            "signed_release": {
                "keyId": "test",
                "manifest": {
                    "catalogSchema": 1,
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
        .unwrap();
        let original: BundleEnvelope = serde_json::from_value(json!({
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
            bundle: VerifiedBundle {
                catalogs: vec![VerifiedCatalogRelease {
                    evidence: catalog_evidence,
                    github_integrated_time_unix_ms: Some(NOW - 10_000),
                    provenance: ReleaseProvenance::Github,
                    public_digest: format!("sha256:{}", "55".repeat(32)),
                    runtime_digest: format!("sha256:{}", "44".repeat(32)),
                    sequence: 7,
                    source_commit: "11".repeat(20),
                    source_repository: "https://github.com/StogasAI/catalog".into(),
                    source_tag: "catalog-v7".into(),
                    source_tree: "22".repeat(20),
                    stogas_signing_key_id: "test".into(),
                }],
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
        let mut proof = ResponseProof {
            schema: SCHEMA_V1.into(),
            request_id: "018f4f70-7c88-7b9a-baf8-31a93d2cf613".into(),
            node_id: "33".repeat(32),
            catalog: ResponseCatalog {
                digest: format!("sha256:{}", "44".repeat(32)),
                sequence: 7,
                node_ids: vec![
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
                time_to_first_output_ms: Some(5),
            },
            proof: ResponseProofClaims {
                request_sha256: hex::encode(Sha256::digest(request)),
                response_sha256: hex::encode(Sha256::digest(response)),
                e2ee_transcript_sha256: transcript.map(str::to_owned),
                signature: String::new(),
            },
        };
        let payload = ResponseProofPayload {
            schema: &proof.schema,
            request_id: &proof.request_id,
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

    #[test]
    fn verifies_exact_bodies_signed_fields_bundle_node_and_e2ee_transcript() {
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
    fn rejects_body_transcript_node_key_and_expiry_mismatches() {
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
