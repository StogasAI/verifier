use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sev::certs::snp::{Certificate, Verifiable as _};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate, parse_x509_crl};

use super::{Error, Validity};

type IssuerId = [u8; 48];

#[derive(Debug)]
struct Crl {
    number: [u8; 20],
    contents: [u8; 32],
    der: Arc<[u8]>,
    validity: Validity,
    revoked: BTreeSet<Vec<u8>>,
}

#[derive(Debug)]
struct Issuer {
    certificate: Arc<[u8]>,
    latest: Option<Crl>,
    conflicting: bool,
}

/// The supported AMD profile uses full, direct ARK CRLs. Issuer SPKI identifies that scope;
/// scoped, indirect and delta CRLs cannot enter this store. There are only the pinned AMD roots.
#[derive(Debug, Default)]
pub(in crate::evidence) struct Revocations {
    issuers: Mutex<BTreeMap<IssuerId, Issuer>>,
}

impl Revocations {
    pub(in crate::evidence) fn observe(&self, body: &Value, now: i64) -> Result<(), Error> {
        let Some(rows) = body.get("vendor_collateral").and_then(Value::as_array) else {
            return Ok(());
        };
        if rows.len() > crate::MAX_VENDOR_COLLATERAL {
            return Err(Error::TooLarge);
        }
        // Missing or malformed unrelated objects cannot hide independently authenticated revocation.
        for row in rows.iter().filter(|row| row["collateral_type"] == "ark") {
            let Ok(der) = row_der(row) else { continue };
            let Ok((remaining, cert)) = parse_x509_certificate(&der) else {
                continue;
            };
            let id: IssuerId = Sha384::digest(cert.public_key().raw).into();
            if !remaining.is_empty()
                || cert.subject() != cert.issuer()
                || cert.signature_algorithm != cert.tbs_certificate.signature
                || !crate::AMD_PRODUCT_PROFILES
                    .iter()
                    .any(|profile| profile.root_spki_sha384 == hex::encode(id))
            {
                continue;
            }
            if self
                .issuers
                .lock()
                .map_err(collateral_error)?
                .contains_key(&id)
            {
                continue;
            }
            // The SPKI pin authenticates the key, not the delivered issuer name or
            // extensions used to match CRLs. Authenticate those before retaining them.
            // As with CRLs, expensive signature work must not hold the admission lock.
            let Ok(root) = Certificate::from_der(&der) else {
                continue;
            };
            if (&root, &root).verify().is_err() {
                continue;
            }
            self.issuers
                .lock()
                .map_err(collateral_error)?
                .entry(id)
                .or_insert_with(|| Issuer {
                    certificate: der.into(),
                    latest: None,
                    conflicting: false,
                });
        }
        let mut failure = None;
        for row in rows.iter().filter(|row| row["collateral_type"] == "crl") {
            let der = match row_der(row) {
                Ok(der) => der,
                Err(error) => {
                    failure.get_or_insert(error);
                    continue;
                }
            };
            if let Err(error) = self.observe_crl(&der, now) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn observe_crl(&self, der: &[u8], now: i64) -> Result<(), Error> {
        let issuers = self.issuers.lock().map_err(collateral_error)?;
        for issuer in issuers.values() {
            if issuer
                .latest
                .as_ref()
                .is_some_and(|old| old.der.as_ref() == der)
            {
                return if issuer.conflicting {
                    Err(Error::CrlOrder)
                } else {
                    Ok(())
                };
            }
        }
        let roots: Vec<_> = issuers
            .iter()
            .map(|(id, issuer)| (*id, Arc::clone(&issuer.certificate)))
            .collect();
        drop(issuers);
        // Signature verification does not hold the lock used by connection appraisal.
        for (id, root) in roots {
            if let Ok(crl) = authenticate_crl(&root, der, now) {
                return self
                    .issuers
                    .lock()
                    .map_err(collateral_error)?
                    .get_mut(&id)
                    .ok_or(Error::MissingCollateral)?
                    .learn(crl);
            }
        }
        Err(collateral_error("untrusted AMD CRL"))
    }

    fn validity(
        &self,
        issuer_id: &IssuerId,
        serial: &[u8],
        certificates: Validity,
        now: i64,
    ) -> Result<Validity, Error> {
        let issuers = self.issuers.lock().map_err(collateral_error)?;
        let issuer = issuers.get(issuer_id).ok_or(Error::MissingCollateral)?;
        let crl = issuer.latest.as_ref().ok_or(Error::MissingCollateral)?;
        if issuer.conflicting {
            return Err(Error::CrlOrder);
        }
        // A known revocation cannot become a positive appraisal when the CRL later expires.
        if crl.revoked.contains(serial) {
            return Err(Error::Revoked);
        }
        let validity = crl.validity;
        drop(issuers);
        certificates.intersect(validity).at(now)
    }
}

impl Issuer {
    fn learn(&mut self, crl: Crl) -> Result<(), Error> {
        if let Some(old) = &self.latest {
            if crl.number < old.number {
                return Err(Error::CrlOrder);
            }
            if crl.number == old.number {
                if crl.contents != old.contents {
                    self.conflicting = true;
                }
                return if self.conflicting {
                    Err(Error::CrlOrder)
                } else {
                    Ok(())
                };
            }
            if crl.validity.not_before_unix_ms < old.validity.not_before_unix_ms {
                return Err(Error::CrlOrder);
            }
        }
        self.latest = Some(crl);
        self.conflicting = false;
        Ok(())
    }
}

fn authenticate_crl(ark_der: &[u8], der: &[u8], now: i64) -> Result<Crl, Error> {
    let (remaining, ark) = parse_x509_certificate(ark_der).map_err(collateral_error)?;
    if !remaining.is_empty() {
        return Err(collateral_error("ARK trailing bytes"));
    }
    let (remaining, crl) = parse_x509_crl(der).map_err(collateral_error)?;
    if !remaining.is_empty() || crl.issuer() != ark.subject() {
        return Err(collateral_error("CRL issuer or framing"));
    }
    crate::verify_amd_crl_signature(&crl, &ark).map_err(collateral_error)?;
    let validity = Validity {
        not_before_unix_ms: crl
            .last_update()
            .timestamp()
            .checked_mul(1000)
            .ok_or_else(|| collateral_error("CRL date overflow"))?,
        not_after_unix_ms: crl
            .next_update()
            .ok_or_else(|| collateral_error("CRL nextUpdate absent"))?
            .timestamp()
            .checked_mul(1000)
            .ok_or_else(|| collateral_error("CRL date overflow"))?,
    };
    if validity.not_before_unix_ms > now.saturating_add(crate::MAX_CLOCK_SKEW_MS)
        || validity.not_after_unix_ms <= validity.not_before_unix_ms
    {
        return Err(collateral_error("CRL validity interval"));
    }
    let number = crl_number_and_scope(&crl, &ark)?;
    let mut revoked = BTreeSet::new();
    for entry in crl.iter_revoked_certificates() {
        let mut extensions = BTreeSet::new();
        for extension in entry.extensions() {
            let oid = extension.oid.to_id_string();
            if !extensions.insert(oid.clone())
                || extension.critical
                || oid == "2.5.29.29"
                || matches!(
                    extension.parsed_extension(),
                    ParsedExtension::ParseError { .. }
                )
            {
                return Err(collateral_error(
                    "unsupported revoked-certificate extension",
                ));
            }
        }
        if !revoked.insert(serial_bytes(entry.raw_serial()).to_vec()) {
            return Err(collateral_error("duplicate revoked certificate"));
        }
    }
    Ok(Crl {
        number,
        contents: Sha256::digest(crl.tbs_cert_list.as_ref()).into(),
        der: Arc::from(der),
        validity,
        revoked,
    })
}

fn crl_number_and_scope(
    crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    ark: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<[u8; 20], Error> {
    let mut extensions = BTreeSet::new();
    let mut authority_key_seen = false;
    for extension in crl.extensions() {
        let oid = extension.oid.to_id_string();
        if !extensions.insert(oid.clone()) {
            return Err(collateral_error("duplicate CRL extension"));
        }
        match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(authority) if !extension.critical => {
                let key = authority
                    .key_identifier
                    .as_ref()
                    .ok_or_else(|| collateral_error("CRL authority key absent"))?;
                let matches = ark.extensions().iter().any(|extension| {
                    matches!(extension.parsed_extension(), ParsedExtension::SubjectKeyIdentifier(subject) if subject.0 == key.0)
                });
                if !matches {
                    return Err(collateral_error("CRL authority key differs"));
                }
                authority_key_seen = true;
            }
            ParsedExtension::CRLNumber(_) if !extension.critical => {
                // Some ASN.1 unsigned-integer parsers also accept negative encodings.
                // This profile permits the canonical nonnegative DER integer only.
                let value = extension.value;
                if value.len() < 3
                    || value[0] != 2
                    || usize::from(value[1]) != value.len() - 2
                    || value[2] & 0x80 != 0
                    || (value.len() > 3 && value[2] == 0 && value[3] & 0x80 == 0)
                {
                    return Err(collateral_error("noncanonical CRL number"));
                }
            }
            ParsedExtension::ParseError { .. } => {
                return Err(collateral_error("invalid CRL extension"));
            }
            _ if extension.critical || matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28") => {
                return Err(collateral_error(
                    "unsupported CRL scope or critical extension",
                ));
            }
            _ => {}
        }
    }
    if !authority_key_seen {
        return Err(collateral_error("CRL authority key absent"));
    }
    let encoded_number = crl
        .crl_number()
        .ok_or_else(|| collateral_error("CRL number absent"))?
        .to_bytes_be();
    if encoded_number.len() > 20 {
        return Err(collateral_error("CRL number too large"));
    }
    let mut number = [0; 20];
    number[20 - encoded_number.len()..].copy_from_slice(&encoded_number);
    Ok(number)
}

#[derive(Debug)]
struct Platform {
    digest: String,
    issuer: IssuerId,
    ask_serial: Vec<u8>,
    certificates: Validity,
    vcek: Arc<[u8]>,
}

#[derive(Debug)]
pub(in crate::evidence) struct Store {
    platforms: BTreeMap<String, Arc<Platform>>,
    revocations: Arc<Revocations>,
}

impl Store {
    pub(in crate::evidence) fn summary(&self, now: i64) -> Vec<Value> {
        self.platforms
            .iter()
            .map(|(id, platform)| {
                match self.revocations.validity(
                    &platform.issuer,
                    &platform.ask_serial,
                    platform.certificates,
                    now,
                ) {
                    Ok(validity) => serde_json::json!({
                        "platform_id": id,
                        "not_before_unix_ms": validity.not_before_unix_ms,
                        "not_after_unix_ms": validity.not_after_unix_ms,
                        "error": null
                    }),
                    Err(error) => serde_json::json!({"platform_id": id, "error": error.code()}),
                }
            })
            .collect()
    }

    pub(in crate::evidence) fn verify(
        rows: &[BTreeMap<String, Value>],
        prior: Option<&Self>,
        revocations: Arc<Revocations>,
    ) -> Result<Self, Error> {
        if rows.len() > crate::MAX_VENDOR_COLLATERAL {
            return Err(Error::TooLarge);
        }
        let expanded = crate::expand_bundle_vendor_collateral(rows).map_err(collateral_error)?;
        let (common, vceks) =
            crate::parse_amd_collateral_entries(&expanded).map_err(collateral_error)?;
        let mut used = BTreeSet::new();
        let mut platforms = BTreeMap::new();
        for (id, vek) in vceks {
            let get = |kind: &str| {
                common
                    .get(&(vek.ca_product_name.clone(), kind.into()))
                    .ok_or(Error::MissingCollateral)
            };
            let ark = get("ark")?;
            let ask = get("ask")?;
            let crl = get("crl")?;
            used.extend([&ark.sha256, &ask.sha256, &crl.sha256]);
            // CRL freshness and revocation are checked independently on every use.
            let digest = format!("{}{}{}", ark.sha256, ask.sha256, vek.sha256);
            let cached = prior
                .and_then(|store| store.platforms.get(&id))
                .filter(|entry| entry.digest == digest);
            let platform = if let Some(cached) = cached {
                Arc::clone(cached)
            } else {
                Arc::new(verify_platform(ark, ask, &vek, digest)?)
            };
            platforms.insert(id, platform);
        }
        if used.len() != common.len() {
            return Err(collateral_error("unused product collateral"));
        }
        Ok(Self {
            platforms,
            revocations,
        })
    }

    pub(in crate::evidence) fn validity(
        &self,
        chip: &str,
        tcb: &str,
        now: i64,
    ) -> Result<Validity, Error> {
        let platform = self
            .platforms
            .get(&crate::amd_platform_key(chip, tcb))
            .ok_or(Error::MissingCollateral)?;
        self.revocations.validity(
            &platform.issuer,
            &platform.ask_serial,
            platform.certificates,
            now,
        )
    }

    pub(in crate::evidence) fn vcek(&self, chip: &str, tcb: &str) -> Result<&[u8], Error> {
        self.platforms
            .get(&crate::amd_platform_key(chip, tcb))
            .map(|platform| platform.vcek.as_ref())
            .ok_or(Error::MissingCollateral)
    }
}

fn verify_platform(
    ark: &crate::AmdCollateralEntry,
    ask: &crate::AmdCollateralEntry,
    vek: &crate::AmdCollateralEntry,
    digest: String,
) -> Result<Platform, Error> {
    let mut validity = Validity {
        not_before_unix_ms: i64::MIN,
        not_after_unix_ms: i64::MAX,
    };
    for der in [&ark.der, &ask.der, &vek.der] {
        let (remaining, cert) = parse_x509_certificate(der).map_err(collateral_error)?;
        if !remaining.is_empty() {
            return Err(collateral_error("certificate trailing bytes"));
        }
        validity = validity.intersect(Validity {
            not_before_unix_ms: cert
                .validity()
                .not_before
                .timestamp()
                .checked_mul(1000)
                .ok_or_else(|| collateral_error("certificate date overflow"))?,
            not_after_unix_ms: cert
                .validity()
                .not_after
                .timestamp()
                .checked_mul(1000)
                .ok_or_else(|| collateral_error("certificate date overflow"))?,
        });
    }
    validity.at(validity.not_before_unix_ms)?;
    let stack = crate::AmdCollateralStack {
        ark: ark.der.clone(),
        ask: ask.der.clone(),
        vek: vek.der.clone(),
    };
    crate::verify_amd_certificates(
        &stack,
        vek.chip_id.as_deref().ok_or(Error::MissingCollateral)?,
        vek.reported_tcb
            .as_deref()
            .ok_or(Error::MissingCollateral)?,
        validity.not_before_unix_ms,
        validity.not_after_unix_ms,
    )
    .map_err(collateral_error)?;
    let (_, root) = parse_x509_certificate(&ark.der).map_err(collateral_error)?;
    let (_, issuer) = parse_x509_certificate(&ask.der).map_err(collateral_error)?;
    Ok(Platform {
        digest,
        issuer: Sha384::digest(root.public_key().raw).into(),
        ask_serial: serial_bytes(issuer.raw_serial()).to_vec(),
        certificates: validity,
        vcek: Arc::from(vek.der.as_slice()),
    })
}

fn row_der(row: &Value) -> Result<Vec<u8>, Error> {
    let encoded = row["der_base64url"]
        .as_str()
        .ok_or_else(|| collateral_error("missing DER"))?;
    let der = URL_SAFE_NO_PAD.decode(encoded).map_err(collateral_error)?;
    if row["sha256"] != hex::encode(Sha256::digest(&der)) {
        return Err(collateral_error("DER digest differs"));
    }
    Ok(der)
}

fn serial_bytes(serial: &[u8]) -> &[u8] {
    &serial[serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len())..]
}

fn collateral_error(error: impl std::fmt::Display) -> Error {
    Error::Collateral(error.to_string())
}

#[cfg(test)]
#[path = "amd/tests.rs"]
mod tests;
