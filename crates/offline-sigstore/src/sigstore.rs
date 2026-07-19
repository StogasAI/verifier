//! Pure-Rust verification of the Sigstore v0.3 GitHub Actions profile.

use crate::{
    crypto::{Scheme, WEBPKI_ALGORITHMS, verify_spki},
    sct, tlog,
    trust_root::TrustedRoot,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use const_oid::{ObjectIdentifier, db::rfc5912::ID_KP_CODE_SIGNING};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_cert::{
    Certificate,
    der::{Any, Decode as _, Encode as _, Tag},
    ext::pkix::{SubjectAltName, name::GeneralName},
};

const FULCIO_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    pub dsse_envelope: DsseEnvelope,
    verification_material: VerificationMaterial,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload: String,
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    #[serde(default)]
    keyid: String,
    pub sig: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationMaterial {
    certificate: RawBytes,
    tlog_entries: Vec<TransparencyLogEntry>,
    #[serde(default)]
    timestamp_verification_data: TimestampVerificationData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawBytes {
    raw_bytes: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimestampVerificationData {
    #[serde(default)]
    rfc3161_timestamps: Vec<SignedTimestamp>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTimestamp {
    pub signed_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencyLogEntry {
    pub log_index: String,
    pub log_id: LogId,
    pub kind_version: KindVersion,
    pub integrated_time: String,
    pub inclusion_promise: Option<InclusionPromise>,
    pub inclusion_proof: Option<InclusionProof>,
    pub canonicalized_body: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogId {
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KindVersion {
    pub kind: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InclusionPromise {
    pub signed_entry_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InclusionProof {
    pub log_index: String,
    pub root_hash: String,
    pub tree_size: String,
    pub hashes: Vec<String>,
    pub checkpoint: CheckpointEnvelope,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointEnvelope {
    pub envelope: String,
}

#[derive(Debug)]
struct CertificateInfo {
    der: Vec<u8>,
    spki: Vec<u8>,
    identity: String,
    issuer: String,
    not_before: i64,
    not_after: i64,
}

pub fn verify(
    value: &serde_json::Value,
    expected_identity: &str,
    expected_issuer: &str,
    now_unix_ms: i64,
) -> Result<i64, String> {
    let bundle: Bundle = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid Sigstore v0.3 bundle: {error}"))?;
    if bundle.media_type != "application/vnd.dev.sigstore.bundle.v0.3+json"
        || bundle.dsse_envelope.payload_type != "application/vnd.in-toto+json"
        || bundle.dsse_envelope.signatures.len() != 1
        || !bundle.dsse_envelope.signatures[0].keyid.is_empty()
        || bundle.verification_material.tlog_entries.len() != 1
    {
        return Err("unsupported or ambiguous GitHub Sigstore bundle".into());
    }
    let root = TrustedRoot::production()?;
    let certificate_der = STANDARD
        .decode(&bundle.verification_material.certificate.raw_bytes)
        .map_err(|error| format!("invalid Fulcio certificate encoding: {error}"))?;
    let certificate = parse_certificate(certificate_der)?;
    if certificate.identity != expected_identity || certificate.issuer != expected_issuer {
        return Err("Fulcio identity or OIDC issuer differs from policy".into());
    }

    let entry = &bundle.verification_material.tlog_entries[0];
    let integrated_time = entry
        .integrated_time
        .parse::<i64>()
        .map_err(|_| "invalid Rekor integrated time".to_owned())?;
    let signature = STANDARD
        .decode(&bundle.dsse_envelope.signatures[0].sig)
        .map_err(|error| format!("invalid DSSE signature encoding: {error}"))?;
    let timestamp_time = crate::tsa::verify_all(
        &bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps,
        &signature,
        &root,
        now_unix_ms.div_euclid(1000),
    )?;
    let validation_time = timestamp_time.unwrap_or(integrated_time);
    let now_seconds = now_unix_ms.div_euclid(1000);
    if validation_time <= 0 || validation_time > now_seconds + 60 {
        return Err("authenticated Sigstore time is absent or in the future".into());
    }
    if validation_time < certificate.not_before || validation_time > certificate.not_after {
        return Err("Fulcio certificate was not valid at the authenticated signing time".into());
    }

    let issuer_spki = verify_certificate_chain(&certificate.der, validation_time, &root)?;
    sct::verify(&certificate.der, &issuer_spki, validation_time, &root)?;
    let verified_integrated_time = tlog::verify(
        entry,
        &bundle.dsse_envelope,
        &certificate.der,
        certificate.not_before,
        certificate.not_after,
        now_seconds,
        &root,
    )?;
    verify_dsse_signature(&bundle.dsse_envelope, &certificate.spki)?;
    Ok(verified_integrated_time)
}

fn parse_certificate(der: Vec<u8>) -> Result<CertificateInfo, String> {
    let certificate = Certificate::from_der(&der)
        .map_err(|error| format!("invalid Fulcio certificate: {error}"))?;
    let not_before = i64::try_from(
        certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| "Fulcio not-before is too large".to_owned())?;
    let not_after = i64::try_from(
        certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| "Fulcio not-after is too large".to_owned())?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| format!("could not encode Fulcio public key: {error}"))?;

    let (critical, names): (bool, SubjectAltName) = certificate
        .tbs_certificate
        .get()
        .map_err(|error| format!("could not parse Fulcio SAN: {error}"))?
        .ok_or_else(|| "Fulcio certificate has no SAN".to_owned())?;
    let identities = names
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !critical || identities.len() != 1 || names.0.len() != 1 {
        return Err("Fulcio certificate requires one critical URI SAN".into());
    }

    let issuers = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .into_iter()
        .flat_map(|extensions| extensions.iter())
        .filter(|extension| extension.extn_id == FULCIO_ISSUER_OID)
        .map(|extension| {
            let bytes = extension.extn_value.as_bytes();
            der::asn1::Utf8StringRef::from_der(bytes)
                .map(|issuer| issuer.to_string())
                .or_else(|_| {
                    std::str::from_utf8(bytes)
                        .map(str::to_owned)
                        .map_err(der::Error::from)
                })
                .map_err(|error| format!("malformed Fulcio issuer extension: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if issuers.len() != 1 {
        return Err("Fulcio certificate requires one OIDC issuer extension".into());
    }

    Ok(CertificateInfo {
        der,
        spki,
        identity: identities.into_iter().next().unwrap_or_default(),
        issuer: issuers.into_iter().next().unwrap_or_default(),
        not_before,
        not_after,
    })
}

fn verify_certificate_chain(
    certificate_der: &[u8],
    validation_time: i64,
    root: &TrustedRoot,
) -> Result<Vec<u8>, String> {
    let anchors = root
        .fulcio_certificates_at(validation_time)?
        .into_iter()
        .map(CertificateDer::from)
        .map(|certificate| {
            anchor_from_trusted_cert(&certificate)
                .map(|anchor| anchor.to_owned())
                .map_err(|error| format!("invalid embedded Fulcio anchor: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certificate_der = CertificateDer::from(certificate_der);
    let certificate = EndEntityCert::try_from(&certificate_der)
        .map_err(|error| format!("invalid Fulcio end-entity certificate: {error}"))?;
    let seconds =
        u64::try_from(validation_time).map_err(|_| "negative Fulcio validation time".to_owned())?;
    let path = certificate
        .verify_for_usage(
            WEBPKI_ALGORITHMS,
            &anchors,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None,
            None,
        )
        .map_err(|error| format!("Fulcio certificate-chain validation failed: {error}"))?;
    path.intermediate_certificates().next().map_or_else(
        || {
            Any::new(
                Tag::Sequence,
                path.anchor().subject_public_key_info.as_ref(),
            )
            .and_then(|spki| spki.to_der())
            .map_err(|error| format!("could not encode verified Fulcio issuer key: {error}"))
        },
        |issuer| Ok(issuer.subject_public_key_info().as_ref().to_vec()),
    )
}

fn verify_dsse_signature(envelope: &DsseEnvelope, spki: &[u8]) -> Result<(), String> {
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|error| format!("invalid DSSE payload encoding: {error}"))?;
    let signature = STANDARD
        .decode(&envelope.signatures[0].sig)
        .map_err(|error| format!("invalid DSSE signature encoding: {error}"))?;
    let pae = pae(&envelope.payload_type, &payload);
    verify_spki(spki, Scheme::EcdsaP256Sha256, &pae, &signature)
        .map_err(|error| format!("DSSE signature verification failed: {error}"))
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    encoded.extend_from_slice(payload);
    encoded
}
