//! Rekor v1 hashedrekord: an expected submission key binds SHA-512 of exact artifact bytes.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256, Sha512};

use crate::{sigstore::TransparencyLogEntry, tlog, trust_root::TrustedRoot};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    message_signature: MessageSignature,
    verification_material: VerificationMaterial,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MessageSignature {
    message_digest: MessageDigest,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageDigest {
    algorithm: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationMaterial {
    public_key: PublicKeyHint,
    tlog_entries: Vec<TransparencyLogEntry>,
    #[serde(rename = "timestampVerificationData")]
    _timestamp_verification_data: Empty,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyHint {
    hint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Body {
    api_version: String,
    kind: String,
    spec: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    data: Data,
    signature: SubmissionSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    hash: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmissionSignature {
    content: String,
    public_key: PublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    content: String,
}

pub fn verify(
    value: &serde_json::Value,
    artifact: &[u8],
    submission_key_spki: &[u8],
    now_unix_ms: i64,
) -> Result<i64, String> {
    verify_with_root(
        value,
        artifact,
        submission_key_spki,
        now_unix_ms,
        &TrustedRoot::production()?,
    )
}

fn verify_with_root(
    value: &serde_json::Value,
    artifact: &[u8],
    submission_key_spki: &[u8],
    now_unix_ms: i64,
    root: &TrustedRoot,
) -> Result<i64, String> {
    let bundle: Bundle = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid Rekor document bundle: {error}"))?;
    if bundle.media_type != crate::SIGSTORE_BUNDLE_MEDIA_TYPE
        || bundle.verification_material.tlog_entries.len() != 1
    {
        return Err("unsupported or ambiguous Rekor document bundle".into());
    }
    let entry = &bundle.verification_material.tlog_entries[0];
    verify_binding(&bundle, artifact, submission_key_spki)?;
    tlog::verify_publication(entry, now_unix_ms.div_euclid(1000), root)
}

fn verify_binding(
    bundle: &Bundle,
    artifact: &[u8],
    submission_key_spki: &[u8],
) -> Result<(), String> {
    let entry = &bundle.verification_material.tlog_entries[0];
    if entry.kind_version.kind != "hashedrekord" || entry.kind_version.version != "0.0.1" {
        return Err("only Rekor hashedrekord v0.0.1 is supported for document inclusion".into());
    }
    let raw = decode(&entry.canonicalized_body)?;
    let body: Body = serde_json::from_value(
        crate::strict_json::from_slice(&raw).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("invalid Rekor document body: {error}"))?;
    let digest = Sha512::digest(artifact);
    if body.kind != "hashedrekord"
        || body.api_version != "0.0.1"
        || body.spec.data.hash.algorithm != "sha512"
        || body.spec.data.hash.value != hex::encode(digest)
        || bundle.message_signature.message_digest.algorithm != "SHA2_512"
        || decode(&bundle.message_signature.message_digest.digest)? != digest[..]
    {
        return Err("Rekor document hash does not bind the exact artifact bytes".into());
    }
    let pem = pem::parse(decode(&body.spec.signature.public_key.content)?)
        .map_err(|_| "invalid Rekor submission public key")?;
    if pem.tag() != "PUBLIC KEY"
        || pem.contents() != submission_key_spki
        || bundle.verification_material.public_key.hint
            != hex::encode(Sha256::digest(pem.contents()))
    {
        return Err("Rekor submission key differs from the expected key or hint".into());
    }
    let key = VerifyingKey::from_public_key_der(pem.contents())
        .map_err(|_| "Rekor document profile requires an Ed25519 submission key")?;
    let signature = decode(&body.spec.signature.content)?;
    if signature != decode(&bundle.message_signature.signature)? {
        return Err("Rekor submission signature differs from the bundle".into());
    }
    let signature =
        Signature::from_slice(&signature).map_err(|_| "invalid Rekor signature length")?;
    key.verify_prehashed_strict(Sha512::new_with_prefix(artifact), None, &signature)
        .map_err(|_| "invalid Rekor Ed25519ph submission signature".into())
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| "invalid Rekor base64 encoding".into())
}

#[cfg(test)]
mod tests;
