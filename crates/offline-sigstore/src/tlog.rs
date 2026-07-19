//! Rekor SET, RFC 6962 inclusion proof, checkpoint, and body binding.

use crate::{
    crypto::verify_spki_auto,
    sigstore::{DsseEnvelope, TransparencyLogEntry},
    trust_root::TrustedRoot,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_PROOF_HASHES: usize = 64;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;

pub fn verify(
    entry: &TransparencyLogEntry,
    envelope: &DsseEnvelope,
    certificate_der: &[u8],
    certificate_not_before: i64,
    certificate_not_after: i64,
    now_seconds: i64,
    root: &TrustedRoot,
) -> Result<i64, String> {
    if entry.kind_version.kind != "dsse" || entry.kind_version.version != "0.0.1" {
        return Err("only Rekor DSSE v0.0.1 is supported for GitHub attestations".into());
    }
    let integrated_time = parse_i64(&entry.integrated_time, "integrated time")?;
    if integrated_time <= 0
        || integrated_time < certificate_not_before
        || integrated_time > certificate_not_after
        || integrated_time > now_seconds + 60
    {
        return Err(
            "Rekor integrated time is invalid, outside the certificate, or in the future".into(),
        );
    }
    let log_id = decode_32(&entry.log_id.key_id, "Rekor log id")?;
    let log_key = root.rekor_key_at(&log_id, integrated_time)?;
    verify_set(entry, &log_id, &log_key.spki)?;
    verify_inclusion(entry, &log_id, &log_key.spki)?;
    verify_body_binding(entry, envelope, certificate_der)?;
    Ok(integrated_time)
}

#[derive(Serialize)]
struct RekorSetPayload<'a> {
    body: &'a str,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

fn verify_set(entry: &TransparencyLogEntry, log_id: &[u8; 32], key: &[u8]) -> Result<(), String> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or_else(|| "GitHub Sigstore profile requires a Rekor SET".to_owned())?;
    let signature = STANDARD
        .decode(&promise.signed_entry_timestamp)
        .map_err(|error| format!("invalid Rekor SET encoding: {error}"))?;
    let payload = RekorSetPayload {
        body: &entry.canonicalized_body,
        integrated_time: parse_i64(&entry.integrated_time, "integrated time")?,
        log_index: parse_i64(&entry.log_index, "log index")?,
        log_id: hex::encode(log_id),
    };
    let canonical = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|error| format!("could not canonicalize Rekor SET: {error}"))?;
    verify_spki_auto(key, &canonical, &signature)
        .map_err(|error| format!("Rekor SET verification failed: {error}"))
}

fn verify_inclusion(
    entry: &TransparencyLogEntry,
    log_id: &[u8; 32],
    key: &[u8],
) -> Result<(), String> {
    let proof = entry
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| "GitHub Sigstore profile requires a Rekor inclusion proof".to_owned())?;
    if proof.hashes.len() > MAX_PROOF_HASHES
        || proof.checkpoint.envelope.len() > MAX_CHECKPOINT_BYTES
    {
        return Err("Rekor proof exceeds resource limits".into());
    }
    let leaf_index = parse_u64(&proof.log_index, "proof log index")?;
    let tree_size = parse_u64(&proof.tree_size, "proof tree size")?;
    let expected_root = decode_32(&proof.root_hash, "proof root hash")?;
    let siblings = proof
        .hashes
        .iter()
        .map(|hash| decode_32(hash, "proof sibling hash"))
        .collect::<Result<Vec<_>, _>>()?;
    let body = STANDARD
        .decode(&entry.canonicalized_body)
        .map_err(|error| format!("invalid Rekor body encoding: {error}"))?;
    verify_merkle(&body, leaf_index, tree_size, &siblings, &expected_root)?;
    verify_checkpoint(
        &proof.checkpoint.envelope,
        tree_size,
        &expected_root,
        log_id,
        key,
    )
}

fn verify_checkpoint(
    envelope: &str,
    expected_tree_size: u64,
    expected_root: &[u8; 32],
    log_id: &[u8; 32],
    key: &[u8],
) -> Result<(), String> {
    if envelope.contains('\r') {
        return Err("Rekor checkpoint must use canonical LF line endings".into());
    }
    let (body, signatures) = envelope
        .split_once("\n\n")
        .ok_or_else(|| "Rekor checkpoint has no signed-note separator".to_owned())?;
    if signatures.contains("\n\n") {
        return Err("Rekor checkpoint contains multiple signature sections".into());
    }
    let mut lines = body.lines();
    let origin = lines
        .next()
        .ok_or_else(|| "Rekor checkpoint origin is absent".to_owned())?;
    if !origin.starts_with("rekor.sigstore.dev - ") {
        return Err("Rekor checkpoint origin is not the public-good log".into());
    }
    let tree_size = lines
        .next()
        .ok_or_else(|| "Rekor checkpoint tree size is absent".to_owned())?
        .parse::<u64>()
        .map_err(|_| "Rekor checkpoint tree size is invalid".to_owned())?;
    let root_hash = decode_32(
        lines
            .next()
            .ok_or_else(|| "Rekor checkpoint root is absent".to_owned())?,
        "checkpoint root",
    )?;
    if tree_size != expected_tree_size || &root_hash != expected_root {
        return Err("Rekor checkpoint does not bind the inclusion proof tree".into());
    }
    if lines.any(|line| line.len() > 256) {
        return Err("Rekor checkpoint metadata exceeds resource limits".into());
    }
    let signed = format!("{body}\n");
    let expected_hint = &log_id[..4];
    let mut matching_signatures = 0usize;
    for line in signatures.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("—") || fields.next() != Some("rekor.sigstore.dev") {
            return Err("Rekor checkpoint signature line is malformed".into());
        }
        let encoded = fields
            .next()
            .ok_or_else(|| "Rekor checkpoint signature is absent".to_owned())?;
        if fields.next().is_some() {
            return Err("Rekor checkpoint signature has extra fields".into());
        }
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|error| format!("invalid checkpoint signature encoding: {error}"))?;
        if decoded.len() <= 4 || &decoded[..4] != expected_hint {
            continue;
        }
        verify_spki_auto(key, signed.as_bytes(), &decoded[4..])
            .map_err(|error| format!("Rekor checkpoint verification failed: {error}"))?;
        matching_signatures += 1;
    }
    if matching_signatures != 1 {
        return Err("Rekor checkpoint requires exactly one matching valid signature".into());
    }
    Ok(())
}

fn verify_merkle(
    body: &[u8],
    leaf_index: u64,
    tree_size: u64,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), String> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err("Rekor inclusion proof has an invalid index or tree size".into());
    }
    let expected_length = expected_proof_length(leaf_index, tree_size);
    if siblings.len() != expected_length {
        return Err(format!(
            "Rekor inclusion proof has {} siblings; expected {expected_length}",
            siblings.len()
        ));
    }
    let mut leaf_input = Vec::with_capacity(body.len() + 1);
    leaf_input.push(0);
    leaf_input.extend_from_slice(body);
    let mut hash: [u8; 32] = Sha256::digest(&leaf_input).into();
    let mut index = leaf_index;
    let mut last_node = tree_size - 1;
    for sibling in siblings {
        let (left, right) = if index % 2 == 1 || index == last_node {
            (sibling, &hash)
        } else {
            (&hash, sibling)
        };
        let mut input = Vec::with_capacity(65);
        input.push(1);
        input.extend_from_slice(left);
        input.extend_from_slice(right);
        hash = Sha256::digest(&input).into();
        index /= 2;
        last_node /= 2;
    }
    if &hash != expected_root {
        return Err("Rekor inclusion proof root differs".into());
    }
    Ok(())
}

const fn expected_proof_length(mut index: u64, mut size: u64) -> usize {
    let mut count = 0;
    while size > 1 {
        if !(size % 2 == 1 && index == size - 1) {
            count += 1;
        }
        index /= 2;
        size = size.div_ceil(2);
    }
    count
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorDsseBody {
    api_version: String,
    kind: String,
    spec: RekorDsseSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorDsseSpec {
    envelope_hash: RekorHash,
    payload_hash: RekorHash,
    signatures: Vec<RekorDsseSignature>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorHash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorDsseSignature {
    signature: String,
    verifier: String,
}

fn verify_body_binding(
    entry: &TransparencyLogEntry,
    envelope: &DsseEnvelope,
    certificate_der: &[u8],
) -> Result<(), String> {
    let canonical_body = STANDARD
        .decode(&entry.canonicalized_body)
        .map_err(|error| format!("invalid Rekor canonical body: {error}"))?;
    let body: RekorDsseBody = serde_json::from_slice(&canonical_body)
        .map_err(|error| format!("invalid Rekor DSSE body: {error}"))?;
    if body.api_version != "0.0.1"
        || body.kind != "dsse"
        || body.spec.payload_hash.algorithm != "sha256"
        || body.spec.envelope_hash.algorithm != "sha256"
        || body.spec.payload_hash.value.len() != 64
        || body.spec.envelope_hash.value.len() != 64
        || body.spec.signatures.len() != 1
        || envelope.signatures.len() != 1
    {
        return Err("unsupported or ambiguous Rekor DSSE body".into());
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|error| format!("invalid DSSE payload: {error}"))?;
    if hex::encode(Sha256::digest(payload)) != body.spec.payload_hash.value {
        return Err("Rekor payload hash does not bind the DSSE payload".into());
    }
    let rekor_signature = STANDARD
        .decode(&body.spec.signatures[0].signature)
        .map_err(|error| format!("invalid Rekor DSSE signature encoding: {error}"))?;
    let bundle_signature = STANDARD
        .decode(&envelope.signatures[0].sig)
        .map_err(|error| format!("invalid bundle DSSE signature encoding: {error}"))?;
    if rekor_signature != bundle_signature {
        return Err("Rekor DSSE signature differs from the bundle".into());
    }
    let verifier = STANDARD
        .decode(&body.spec.signatures[0].verifier)
        .map_err(|error| format!("invalid Rekor verifier encoding: {error}"))?;
    let pem = pem::parse(verifier)
        .map_err(|error| format!("invalid Rekor verifier certificate: {error}"))?;
    if pem.tag() != "CERTIFICATE" || pem.contents() != certificate_der {
        return Err("Rekor verifier certificate differs from the bundle".into());
    }
    Ok(())
}

fn parse_i64(value: &str, label: &str) -> Result<i64, String> {
    value.parse::<i64>().map_err(|_| format!("invalid {label}"))
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| format!("invalid {label}"))
}

fn decode_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    STANDARD
        .decode(value)
        .map_err(|error| format!("invalid {label} encoding: {error}"))?
        .try_into()
        .map_err(|_| format!("{label} must contain 32 bytes"))
}
