//! Historical boot appraisal never installs current authorization or creates a live session.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::{Error, Verifier, boot::VerifiedBoot};

/// Maximum encoded boot archive size, including its inclusion proof.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    boot: Value,
    inclusion: Value,
    evidence_sha256: String,
}

#[cfg(all(test, feature = "staging"))]
mod tests {
    use super::*;
    use crate::{approvals::Environment, attestation::certificate::ParsedNativeCertificate};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    fn fixture() -> (Verifier, Value, Value, i64) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let verifier = Verifier::new(
            Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap();
        let certificate = URL_SAFE_NO_PAD
            .decode(fixture["certificate"].as_str().unwrap())
            .unwrap();
        let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
        let archive = json!({
            "boot": serde_json::from_slice::<Value>(parsed.evidence.boot_document).unwrap(),
            "inclusion": serde_json::from_slice::<Value>(parsed.evidence.boot_inclusion).unwrap(),
            "evidence_sha256": fixture["bundle"]["body_sha256"]
        });
        (
            verifier,
            archive,
            fixture["bundle"].clone(),
            fixture["verified_at_ms"].as_i64().unwrap(),
        )
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn history_survives_expiry_and_cannot_restore_current_key_authorization() {
        let (mut verifier, archive, bundle, now) = fixture();
        let current = verifier.refresh(&bytes(&bundle), now).unwrap();
        let rotation: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/logged-key-rotation.json"
        ))
        .unwrap();
        let later = now + 366 * 24 * 60 * 60 * 1000;
        verifier
            .verify_key_manifest(&bytes(&rotation["keys"]), later)
            .unwrap();
        assert!(current.require_current_keys().is_err());
        let approvals = verifier
            .verify_evidence_archive(&bytes(&bundle), later)
            .unwrap();
        assert_eq!(approvals["body_sha256"], bundle["body_sha256"]);
        assert_eq!(
            approvals["evidence"]["approvals"],
            bundle["body"]["approvals"]["manifest"]
        );
        let boot = verifier
            .verify_boot_archive(&bytes(&archive), &bytes(&bundle), later)
            .unwrap();
        assert!(boot.hardware().validity().not_after_unix_ms < later);
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &current));
        assert!(current.require_current_keys().is_err());
        assert!(verifier.refresh(&bytes(&bundle), later).is_err());
        assert!(
            verifier
                .verify_boot_archive(
                    &bytes(&archive),
                    &bytes(&bundle),
                    boot.integrated_time_unix_ms() - 1
                )
                .is_err()
        );
    }

    #[test]
    fn history_rejects_substituted_dependencies_signatures_times_and_hardware() {
        let (verifier, archive, bundle, now) = fixture();
        verifier
            .verify_boot_archive(&bytes(&archive), &bytes(&bundle), now)
            .unwrap();
        for (pointer, replacement) in [
            ("/evidence_sha256", json!("0".repeat(64))),
            ("/boot/report_data/tls_spki_sha256", json!("0".repeat(64))),
            (
                "/inclusion/verificationMaterial/tlogEntries/0/integratedTime",
                json!("1"),
            ),
            (
                "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
                json!("AAAA"),
            ),
            ("/inclusion/dsseEnvelope/signatures/0/sig", json!("AAAA")),
        ] {
            let mut changed = archive.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                verifier
                    .verify_boot_archive(&bytes(&changed), &bytes(&bundle), now)
                    .is_err(),
                "{pointer}"
            );
            assert!(verifier.current().is_none());
        }
        let mut changed = bundle.clone();
        changed["body"]["approvals"]["manifest"]["gateways"] = json!([]);
        assert!(
            verifier
                .verify_boot_archive(&bytes(&archive), &bytes(&changed), now)
                .is_err()
        );
        let mut extra = archive;
        extra["current"] = json!(true);
        assert!(
            verifier
                .verify_boot_archive(&bytes(&extra), &bytes(&bundle), now)
                .is_err()
        );
        for malformed in [
            b"{}".as_slice(),
            br#"{"boot":{},"boot":{}}"#,
            &vec![b' '; MAX_ARCHIVE_BYTES + 1],
        ] {
            assert!(
                verifier
                    .verify_boot_archive(malformed, &bytes(&bundle), now)
                    .is_err()
            );
        }
        assert!(verifier.current().is_none());
    }
}

impl Verifier {
    /// Verify archived approval and build evidence without installing it as current trust.
    /// Collateral is authenticated here; boot-specific historical validity is checked by
    /// `verify_boot_archive`. The returned summary cannot establish a live connection.
    ///
    /// # Errors
    /// Rejects malformed, incomplete or unauthenticated evidence.
    pub fn verify_evidence_archive(
        &self,
        evidence: &[u8],
        now_unix_ms: i64,
    ) -> Result<Value, Error> {
        let snapshot = self.historical_verifier()?.refresh(evidence, now_unix_ms)?;
        Ok(serde_json::json!({
            "body_sha256": snapshot.body_sha256(),
            "evidence": snapshot.summary()
        }))
    }

    fn historical_verifier(&self) -> Result<Self, Error> {
        Ok(Self {
            approvals: self.approvals.historical_authority()?,
            current: None,
            revocations: Arc::default(),
        })
    }

    /// Appraise an archived boot at its authenticated log-inclusion time using the exact
    /// referenced evidence bundle. This proves historical evidence, not current permission
    /// or that any particular HTTPS connection reached the node.
    ///
    /// # Errors
    /// Rejects malformed archives, substituted evidence, future/forged log times, failed
    /// hardware/signature checks or collateral invalid at the logged time.
    pub fn verify_boot_archive(
        &self,
        archive: &[u8],
        evidence: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedBoot, Error> {
        if archive.len() > MAX_ARCHIVE_BYTES || evidence.len() > crate::MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let archive: Archive = serde_json::from_value(
            crate::strict_json::from_slice(archive).map_err(super::invalid)?,
        )
        .map_err(super::invalid)?;
        let entries = archive.inclusion["verificationMaterial"]["tlogEntries"]
            .as_array()
            .filter(|entries| entries.len() == 1)
            .ok_or_else(|| super::invalid("boot archive requires one log entry"))?;
        // This is only a candidate clock. verify_logged_boot authenticates this exact
        // integratedTime before returning anything to the caller.
        let at = entries[0]["integratedTime"]
            .as_str()
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| value.checked_mul(1000))
            .filter(|value| *value > 0 && *value <= now_unix_ms)
            .ok_or_else(|| super::invalid("invalid boot archive log time"))?;
        let snapshot = self.historical_verifier()?.refresh(evidence, at)?;
        if snapshot.body_sha256() != archive.evidence_sha256 {
            return Err(super::invalid("boot archive evidence digest differs"));
        }
        let document = crate::canonical_json(&archive.boot).map_err(super::invalid)?;
        let inclusion = serde_json::to_vec(&archive.inclusion).map_err(super::invalid)?;
        let boot = snapshot.verify_logged_boot(document.as_bytes(), &inclusion, at)?;
        if boot.integrated_time_unix_ms() != at {
            return Err(super::invalid("boot archive log time differs"));
        }
        Ok(boot)
    }
}
