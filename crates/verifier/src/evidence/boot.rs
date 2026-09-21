//! Immutable boot identity. Registration freshness and public log inclusion are separate checks.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::VerifyingKey;
use hpke::{Deserializable as _, kem::XWing};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use super::{Error, Snapshot, VerifiedSnpReport};
use crate::approvals::Environment;

pub const BOOT_SCHEMA: &str = "stogas.node-boot.v1";
pub const BOOT_PAYLOAD_TYPE: &str = "application/vnd.stogas.node-boot.v1+json";
pub const REPORT_DATA_SCHEMA: &str = "stogas.node-report.v1";
const RENEWAL_DOMAIN: &[u8] = b"stogas.certificate-renewal.v1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRenewal {
    node_id: String,
    issued_at_ms: i64,
    signature: String,
}

/// Authenticate a bounded renewal request using the key from durable boot registration.
/// Renewal is idempotent and returns public material; retries need no replay database.
///
/// # Errors
/// Rejects another identity, bad signatures or a timestamp more than five minutes away.
pub fn verify_certificate_renewal(
    request: &[u8],
    expected_node_id: &str,
    public_key: &[u8; 32],
    now_unix_ms: i64,
) -> Result<(), Error> {
    if request.len() > 512 {
        return Err(Error::TooLarge);
    }
    let request: CertificateRenewal =
        serde_json::from_value(crate::strict_json::from_slice(request).map_err(invalid)?)
            .map_err(invalid)?;
    if request.node_id != expected_node_id
        || request.issued_at_ms <= 0
        || request.issued_at_ms.abs_diff(now_unix_ms) > 300_000
    {
        return Err(invalid("certificate renewal identity or time differs"));
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(invalid)?;
    let signature =
        ed25519_dalek::Signature::from_slice(&decode(&request.signature, 64)?).map_err(invalid)?;
    let message = [
        RENEWAL_DOMAIN,
        request.node_id.as_bytes(),
        b"\0",
        &request.issued_at_ms.to_be_bytes(),
    ]
    .concat();
    key.verify_strict(&message, &signature).map_err(invalid)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootReportData {
    pub schema: String,
    pub environment: Environment,
    pub ed25519_public_key: String,
    pub hpke_public_key: String,
    pub tls_spki_sha256: String,
    pub registration_challenge: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootRecord {
    pub schema: String,
    pub gateway_release_id: String,
    pub hardware_policy_sha256: String,
    /// Canonical unpadded base64url of the raw 1184-byte SNP report.
    pub report: String,
    pub report_data: BootReportData,
}

/// Hardware and registration checks passed. The Control transaction must still consume its
/// challenge atomically before releasing secrets to the bound provisioning recipient.
#[derive(Debug)]
pub struct VerifiedRegistration {
    record: BootRecord,
    hardware: VerifiedSnpReport,
    document_sha256: [u8; 32],
}

impl VerifiedRegistration {
    /// The boot quote authenticates the TLS key; PKCS #10 proves possession and
    /// restricts issuance to this environment's compiled API hostname.
    ///
    /// # Errors
    /// Rejects another key, invalid signatures, extra identities or malformed DER.
    pub fn verify_csr(&self, csr_der: &[u8]) -> Result<(), Error> {
        let hostname = self
            .record
            .report_data
            .environment
            .api_origin()
            .strip_prefix("https://")
            .ok_or_else(|| invalid("invalid compiled API origin"))?;
        crate::verify_certificate_csr(
            csr_der,
            &self.record.report_data.tls_spki_sha256,
            Some(hostname),
            vec![hostname.into()],
        )
        .map_err(invalid)
    }

    /// Authenticated identity fields for bindings; registration still needs atomic consumption.
    #[must_use]
    pub fn summary(&self) -> serde_json::Value {
        self.identity_summary(None)
    }

    fn identity_summary(&self, integrated_time_unix_ms: Option<i64>) -> serde_json::Value {
        serde_json::json!({
            "node_id": self.hardware.node_id(), "chip_id": self.hardware.chip_id(),
            "reported_tcb": self.hardware.reported_tcb(),
            "boot_sha256": hex::encode(self.document_sha256),
            "gateway_release_id": self.record.gateway_release_id,
            "ed25519_public_key": self.record.report_data.ed25519_public_key,
            "hpke_public_key": self.record.report_data.hpke_public_key,
            "tls_spki_sha256": self.record.report_data.tls_spki_sha256,
            "valid_from_unix_ms": self.hardware.validity().not_before_unix_ms,
            "valid_until_unix_ms": self.hardware.validity().not_after_unix_ms,
            "integrated_time_unix_ms": integrated_time_unix_ms
        })
    }

    #[must_use]
    pub const fn record(&self) -> &BootRecord {
        &self.record
    }

    #[must_use]
    pub const fn hardware(&self) -> &VerifiedSnpReport {
        &self.hardware
    }

    #[must_use]
    pub const fn document_sha256(&self) -> &[u8; 32] {
        &self.document_sha256
    }
}

/// Hardware boot identity plus verified inclusion of the exact document bytes.
#[derive(Debug)]
pub struct VerifiedBoot {
    identity: VerifiedRegistration,
    integrated_time_unix_ms: i64,
}

impl VerifiedBoot {
    /// Authenticated boot identity fields, including actual transparency inclusion time.
    #[must_use]
    pub fn summary(&self) -> serde_json::Value {
        self.identity
            .identity_summary(Some(self.integrated_time_unix_ms))
    }

    #[must_use]
    pub const fn record(&self) -> &BootRecord {
        &self.identity.record
    }

    #[must_use]
    pub const fn hardware(&self) -> &VerifiedSnpReport {
        &self.identity.hardware
    }

    #[must_use]
    pub const fn document_sha256(&self) -> &[u8; 32] {
        &self.identity.document_sha256
    }

    #[must_use]
    pub const fn integrated_time_unix_ms(&self) -> i64 {
        self.integrated_time_unix_ms
    }
}

impl BootReportData {
    /// Hash the canonical report-data object without a file newline.
    ///
    /// # Errors
    /// Rejects unknown versions, malformed/weak keys and noncanonical public fields.
    pub fn commitment(&self) -> Result<[u8; 64], Error> {
        if self.schema != REPORT_DATA_SCHEMA {
            return Err(invalid("unsupported boot report-data schema"));
        }
        lower_hex::<32>(&self.tls_spki_sha256)?;
        lower_hex::<32>(&self.registration_challenge)?;
        let node_key: [u8; 32] = decode(&self.ed25519_public_key, 32)?
            .try_into()
            .map_err(|_| invalid("node public key length"))?;
        if VerifyingKey::from_bytes(&node_key)
            .map_err(invalid)?
            .is_weak()
        {
            return Err(invalid("weak node signing key"));
        }
        let recipient = decode(&self.hpke_public_key, 1216)?;
        <XWing as hpke::Kem>::PublicKey::from_bytes(&recipient).map_err(invalid)?;
        let canonical = crate::canonical_json(&serde_json::to_value(self).map_err(invalid)?)
            .map_err(invalid)?;
        Ok(Sha512::digest(
            canonical
                .strip_suffix('\n')
                .ok_or_else(|| invalid("canonical encoding"))?,
        )
        .into())
    }
}

impl Snapshot {
    /// Verify the initial quote before logging or secret release. This never accepts a public
    /// archived quote as fresh without the expected one-use Control challenge.
    ///
    /// # Errors
    /// Rejects stale challenges, wrong environments, unapproved hardware/releases and invalid quotes.
    pub fn verify_registration(
        &self,
        document: &[u8],
        challenge: &[u8; 32],
        now_unix_ms: i64,
    ) -> Result<VerifiedRegistration, Error> {
        let record = parse_record(document)?;
        if lower_hex::<32>(&record.report_data.registration_challenge)? != *challenge {
            return Err(invalid("registration challenge differs"));
        }
        // The policy reference records what the guest fetched when preparing its
        // immutable boot. A publication may advance before this request arrives.
        // Authorization always comes from the current policy in verify_boot_report,
        // never from this historical reference.
        self.verify_boot_report(document, record, now_unix_ms)
    }

    /// Reappraise an exact boot already accepted by the registration authority. The expected
    /// digest must come from its durable registration, never from the requesting guest.
    /// Current policy appraises the report; the original policy reference remains historical.
    /// This does not establish a new registration or transparency inclusion.
    ///
    /// # Errors
    /// Rejects changed boot bytes and any failed current hardware/release appraisal.
    pub fn verify_registered_boot(
        &self,
        document: &[u8],
        registered_sha256: &[u8; 32],
        now_unix_ms: i64,
    ) -> Result<VerifiedRegistration, Error> {
        let record = parse_record(document)?;
        if <[u8; 32]>::from(Sha256::digest(document)) != *registered_sha256 {
            return Err(invalid("boot differs from registered digest"));
        }
        self.verify_boot_report(document, record, now_unix_ms)
    }

    /// Verify an immutable logged boot against current hardware/release authorization. Retired
    /// online keys can authenticate this history; they cannot authorize a current release list.
    ///
    /// # Errors
    /// Rejects wrong log payloads, unknown signers, malformed history or failed live appraisal.
    pub fn verify_logged_boot(
        &self,
        document: &[u8],
        inclusion: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedBoot, Error> {
        let record = parse_record(document)?;
        if document.len().saturating_add(inclusion.len())
            > crate::attestation::evidence::MAX_EVIDENCE_BYTES
        {
            return Err(Error::TooLarge);
        }
        let proof = crate::strict_json::from_slice(inclusion).map_err(invalid)?;
        let signer_id = proof["verificationMaterial"]["publicKey"]["hint"]
            .as_str()
            .ok_or_else(|| invalid("boot signer absent"))?;
        let keys = self.approvals.keys();
        let signer = std::iter::once(&keys.active_key)
            .chain(&keys.retired_keys)
            .find(|key| key.key_id == signer_id)
            .ok_or(Error::Approval(crate::approvals::Error::InactiveKey))?;
        let integrated = stogas_offline_sigstore::verify_keyed_dsse(
            &proof,
            document,
            BOOT_PAYLOAD_TYPE,
            &signer.key_id,
            &STANDARD.decode(&signer.public_key).map_err(invalid)?,
            now_unix_ms,
        )
        .map_err(invalid)?;
        let identity = self.verify_boot_report(document, record, now_unix_ms)?;
        Ok(VerifiedBoot {
            identity,
            integrated_time_unix_ms: integrated
                .checked_mul(1000)
                .ok_or_else(|| invalid("boot log time overflow"))?,
        })
    }

    fn verify_boot_report(
        &self,
        document: &[u8],
        record: BootRecord,
        now_unix_ms: i64,
    ) -> Result<VerifiedRegistration, Error> {
        if record.report_data.environment != self.approvals.keys().environment {
            return Err(Error::Approval(crate::approvals::Error::Authority));
        }
        let report = decode(&record.report, 0x4a0)?;
        let hardware = self.verify_snp_report(
            &report,
            &record.report_data.commitment()?,
            &record.gateway_release_id,
            now_unix_ms,
        )?;
        Ok(VerifiedRegistration {
            record,
            hardware,
            document_sha256: Sha256::digest(document).into(),
        })
    }
}

fn parse_record(document: &[u8]) -> Result<BootRecord, Error> {
    if document.len() > crate::attestation::evidence::MAX_EVIDENCE_BYTES {
        return Err(Error::TooLarge);
    }
    let value = crate::strict_json::from_slice(document).map_err(invalid)?;
    // One byte identity is used by the log, archive and live-session commitment.
    if crate::canonical_json(&value).map_err(invalid)?.as_bytes() != document {
        return Err(invalid("noncanonical boot document"));
    }
    let record: BootRecord = serde_json::from_value(value).map_err(invalid)?;
    if record.schema != BOOT_SCHEMA {
        return Err(invalid("unsupported boot schema"));
    }
    lower_hex::<32>(&record.gateway_release_id)?;
    lower_hex::<32>(&record.hardware_policy_sha256)?;
    Ok(record)
}

fn lower_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("noncanonical boot digest or challenge"));
    }
    hex::decode(value)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| invalid("boot digest length"))
}

fn decode(value: &str, size: usize) -> Result<Vec<u8>, Error> {
    if value.len() != (size * 8).div_ceil(6) {
        return Err(invalid("boot public field size"));
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(invalid)?;
    if bytes.len() != size || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(invalid("noncanonical boot public field"));
    }
    Ok(bytes)
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Attestation(error.to_string())
}

#[cfg(test)]
mod tests;
