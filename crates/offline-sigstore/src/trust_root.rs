//! Embedded Sigstore trusted-root snapshot with deterministic time selection.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

const MEDIA_TYPE: &str = "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedRootDocument {
    media_type: String,
    certificate_authorities: Vec<CertificateAuthority>,
    tlogs: Vec<TransparencyLog>,
    ctlogs: Vec<TransparencyLog>,
    timestamp_authorities: Vec<CertificateAuthority>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CertificateAuthority {
    subject: CertificateSubject,
    #[serde(default)]
    uri: Option<String>,
    cert_chain: CertificateChain,
    #[serde(default)]
    valid_for: Option<Validity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CertificateSubject {
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CertificateChain {
    certificates: Vec<CertificateEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CertificateEntry {
    raw_bytes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransparencyLog {
    base_url: String,
    hash_algorithm: String,
    public_key: PublicKey,
    log_id: LogId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicKey {
    raw_bytes: String,
    key_details: String,
    #[serde(default)]
    valid_for: Option<Validity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogId {
    key_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Validity {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

impl Validity {
    fn contains_seconds(&self, time: i64) -> Result<bool, String> {
        let start = self.start.as_deref().map(parse_time).transpose()?;
        let end = self.end.as_deref().map(parse_time).transpose()?;
        Ok(start.is_none_or(|start| time >= start) && end.is_none_or(|end| time <= end))
    }
}

#[derive(Clone, Debug)]
pub struct LogKey {
    pub id: Vec<u8>,
    pub spki: Vec<u8>,
    validity: Option<Validity>,
}

#[derive(Clone, Debug)]
pub struct Authority {
    pub certificates: Vec<Vec<u8>>,
    validity: Option<Validity>,
}

#[derive(Clone, Debug)]
pub struct TrustedRoot {
    fulcio: Vec<Authority>,
    rekor: Vec<LogKey>,
    ct: Vec<LogKey>,
    tsa: Vec<Authority>,
}

impl TrustedRoot {
    pub fn production() -> Result<Self, String> {
        let root = Self::from_json(include_str!("trusted_root.json"))?;
        if root.fulcio.is_empty() || root.rekor.is_empty() || root.ct.is_empty() {
            return Err("embedded Sigstore trusted root is incomplete".into());
        }
        Ok(root)
    }

    fn from_json(json: &str) -> Result<Self, String> {
        let document: TrustedRootDocument = serde_json::from_str(json)
            .map_err(|error| format!("invalid embedded Sigstore trusted root: {error}"))?;
        if document.media_type != MEDIA_TYPE {
            return Err("unsupported embedded Sigstore trusted-root media type".into());
        }
        let fulcio = parse_authorities(document.certificate_authorities, "Fulcio")?;
        let tsa = parse_authorities(document.timestamp_authorities, "TSA")?;
        let rekor = parse_logs(document.tlogs, "Rekor")?;
        let ct = parse_logs(document.ctlogs, "CT")?;
        Ok(Self {
            fulcio,
            rekor,
            ct,
            tsa,
        })
    }

    #[cfg(test)]
    pub fn tsa_test_root(json: &str) -> Result<Self, String> {
        Self::from_json(json)
    }

    pub fn fulcio_certificates_at(&self, time: i64) -> Result<Vec<Vec<u8>>, String> {
        certificates_at(&self.fulcio, time)
    }

    pub fn rekor_key_at(&self, id: &[u8], time: i64) -> Result<&LogKey, String> {
        key_at(&self.rekor, id, time, "Rekor")
    }

    pub fn ct_key_at(&self, id: &[u8], time: i64) -> Result<&LogKey, String> {
        key_at(&self.ct, id, time, "CT")
    }

    pub fn tsa_authorities_at(&self, time: i64) -> Result<Vec<&Authority>, String> {
        self.tsa
            .iter()
            .filter_map(|authority| {
                authority
                    .validity
                    .as_ref()
                    .map_or(Some(Ok(authority)), |validity| {
                        match validity.contains_seconds(time) {
                            Ok(true) => Some(Ok(authority)),
                            Ok(false) => None,
                            Err(error) => Some(Err(error)),
                        }
                    })
            })
            .collect()
    }
}

fn parse_authorities(
    authorities: Vec<CertificateAuthority>,
    label: &str,
) -> Result<Vec<Authority>, String> {
    let mut hashes = HashSet::new();
    authorities
        .into_iter()
        .map(|authority| {
            let _ = (
                authority.subject.organization,
                authority.subject.common_name,
                authority.uri,
            );
            if authority.cert_chain.certificates.is_empty() {
                return Err(format!("{label} authority contains no certificates"));
            }
            let certificates = authority
                .cert_chain
                .certificates
                .into_iter()
                .map(|certificate| decode(&certificate.raw_bytes, "certificate"))
                .collect::<Result<Vec<_>, _>>()?;
            for certificate in &certificates {
                if !hashes.insert(Sha256::digest(certificate).to_vec()) {
                    return Err(format!("duplicate {label} certificate"));
                }
            }
            Ok(Authority {
                certificates,
                validity: authority.valid_for,
            })
        })
        .collect()
}

fn parse_logs(logs: Vec<TransparencyLog>, label: &str) -> Result<Vec<LogKey>, String> {
    let mut ids = HashSet::new();
    logs.into_iter()
        .map(|log| {
            if log.hash_algorithm != "SHA2_256"
                || !log.base_url.starts_with("https://")
                || !matches!(
                    log.public_key.key_details.as_str(),
                    "PKIX_ECDSA_P256_SHA_256" | "PKIX_ED25519"
                )
            {
                return Err(format!("unsupported {label} log configuration"));
            }
            let spki = decode(&log.public_key.raw_bytes, "log public key")?;
            let id = decode(&log.log_id.key_id, "log id")?;
            if id.len() != 32 || !ids.insert(id.clone()) {
                return Err(format!("invalid or duplicate {label} log id"));
            }
            Ok(LogKey {
                id,
                spki,
                validity: log.public_key.valid_for,
            })
        })
        .collect()
}

fn key_at<'a>(keys: &'a [LogKey], id: &[u8], time: i64, label: &str) -> Result<&'a LogKey, String> {
    for key in keys.iter().filter(|key| key.id == id) {
        if key
            .validity
            .as_ref()
            .map_or(Ok(true), |validity| validity.contains_seconds(time))?
        {
            return Ok(key);
        }
    }
    Err(format!(
        "no {label} key was valid for the authenticated time"
    ))
}

fn certificates_at(authorities: &[Authority], time: i64) -> Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    for authority in authorities {
        if authority
            .validity
            .as_ref()
            .map_or(Ok(true), |validity| validity.contains_seconds(time))?
        {
            certificates.extend(authority.certificates.iter().cloned());
        }
    }
    if certificates.is_empty() {
        return Err("no certificate authority was valid for the authenticated time".into());
    }
    Ok(certificates)
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|error| format!("invalid base64 {label}: {error}"))
}

fn parse_time(value: &str) -> Result<i64, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc).timestamp())
        .map_err(|error| format!("invalid trusted-root time {value:?}: {error}"))
}
