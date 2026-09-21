use super::{Error, Snapshot, Validity, VerifiedSnpReport, boot::VerifiedBoot};
use crate::attestation::{certificate::ParsedNativeCertificate, evidence::SessionEvidence};
use std::sync::Arc;

/// The live channel and its immutable boot belong to the same approved hardware guest.
#[derive(Debug)]
pub struct VerifiedSession {
    boot: VerifiedBoot,
    live: VerifiedSnpReport,
    validity: Validity,
    snapshot_identity: Arc<()>,
    artifacts: Arc<Artifacts>,
}

#[derive(Debug)]
struct Artifacts {
    report: Box<[u8]>,
    boot_document: Box<[u8]>,
    boot_inclusion: Box<[u8]>,
}

impl VerifiedSession {
    #[must_use]
    pub const fn boot(&self) -> &VerifiedBoot {
        &self.boot
    }

    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

impl Snapshot {
    /// Check current time and learned revocation without repeating immutable cryptography.
    /// Call `reappraise_session` first when the accepted snapshot changes.
    ///
    /// # Errors
    /// Rejects another snapshot, learned retirement/revocation, missing material or expiry.
    pub fn check_session(
        &self,
        session: &VerifiedSession,
        now_unix_ms: i64,
    ) -> Result<Validity, Error> {
        if !Arc::ptr_eq(&self.identity, &session.snapshot_identity) {
            return Err(invalid("session needs appraisal against this snapshot"));
        }
        self.require_current_keys()?;
        let boot = session.boot.hardware();
        Ok(self
            .collateral_validity(boot.chip_id(), boot.reported_tcb(), now_unix_ms)?
            .intersect(self.collateral_validity(
                session.live.chip_id(),
                session.live.reported_tcb(),
                now_unix_ms,
            )?))
    }

    /// Recheck an existing channel under updated approvals/collateral, retaining its original
    /// verified challenge/key binding. This does not authenticate a new transport connection.
    ///
    /// # Errors
    /// Rejects withdrawn releases/platforms, untrusted boot history or invalid current collateral.
    pub fn reappraise_session(
        &self,
        session: &VerifiedSession,
        now_unix_ms: i64,
    ) -> Result<VerifiedSession, Error> {
        self.appraise_session(Arc::clone(&session.artifacts), now_unix_ms)
    }

    /// Verify certificate evidence for this fresh client challenge. The TLS connector must
    /// independently require the hybrid TLS 1.3 profile and verify `CertificateVerify`.
    ///
    /// # Errors
    /// Rejects wrong challenges/signers, expired certificates, unlogged boots and failed appraisal.
    pub fn verify_native_certificate(
        &self,
        certificate: &[u8],
        challenge: [u8; 32],
        now_unix_ms: i64,
    ) -> Result<VerifiedSession, Error> {
        let parsed = ParsedNativeCertificate::parse(certificate).map_err(invalid)?;
        parsed.valid_at(now_unix_ms).map_err(invalid)?;
        parsed
            .evidence
            .verify_channel_binding(
                self.approvals.keys().environment,
                challenge,
                parsed.signer_spki_sha256,
            )
            .map_err(invalid)?;
        self.verify_session_identity(&parsed.evidence, now_unix_ms)
    }

    // The two protocol entry points verify their complete local binding before calling this.
    pub(crate) fn verify_session_identity(
        &self,
        evidence: &SessionEvidence<'_>,
        now_unix_ms: i64,
    ) -> Result<VerifiedSession, Error> {
        self.appraise_session(
            Arc::new(Artifacts {
                report: evidence.report.into(),
                boot_document: evidence.boot_document.into(),
                boot_inclusion: evidence.boot_inclusion.into(),
            }),
            now_unix_ms,
        )
    }

    fn appraise_session(
        &self,
        artifacts: Arc<Artifacts>,
        now_unix_ms: i64,
    ) -> Result<VerifiedSession, Error> {
        let boot = self.verify_logged_boot(
            &artifacts.boot_document,
            &artifacts.boot_inclusion,
            now_unix_ms,
        )?;
        let commitment = artifacts
            .report
            .get(0x50..0x90)
            .ok_or_else(|| invalid("report length"))?
            .try_into()
            .map_err(invalid)?;
        let live = self.verify_snp_report(
            &artifacts.report,
            &commitment,
            &boot.record().gateway_release_id,
            now_unix_ms,
        )?;
        if live.report_id() != boot.hardware().report_id()
            || live.chip_id() != boot.hardware().chip_id()
        {
            return Err(invalid("live report belongs to a different boot"));
        }
        let validity = boot.hardware().validity().intersect(live.validity());
        Ok(VerifiedSession {
            boot,
            live,
            validity,
            snapshot_identity: Arc::clone(&self.identity),
            artifacts,
        })
    }
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Attestation(error.to_string())
}

#[cfg(all(test, feature = "staging"))]
mod tests;
