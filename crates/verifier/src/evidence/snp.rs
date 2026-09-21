use super::{Error, Snapshot, Validity};

/// An SNP report appraised against this snapshot's approved release, hardware policy and
/// current vendor revocation state. This result does not itself establish session freshness.
#[derive(Debug)]
pub struct VerifiedSnpReport {
    node_id: String,
    report_id: [u8; 32],
    chip_id: String,
    reported_tcb: String,
    validity: Validity,
}

impl VerifiedSnpReport {
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub const fn report_id(&self) -> &[u8; 32] {
        &self.report_id
    }

    #[must_use]
    pub fn chip_id(&self) -> &str {
        &self.chip_id
    }

    #[must_use]
    pub fn reported_tcb(&self) -> &str {
        &self.reported_tcb
    }

    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

impl Snapshot {
    /// Verify a complete raw report against the caller's expected report-data commitment.
    /// Boot and session protocols supply their own commitments; neither accepts an arbitrary
    /// report's embedded report data as the expected binding.
    ///
    /// # Errors
    /// Rejects unapproved releases/platforms, wrong bindings, host/other-VMPL reports, weak
    /// launch policies, bad signatures and missing, revoked or expired vendor material.
    pub fn verify_snp_report(
        &self,
        report: &[u8],
        expected_report_data: &[u8; 64],
        release_id: &str,
        now_unix_ms: i64,
    ) -> Result<VerifiedSnpReport, Error> {
        self.require_current_keys()?;
        if report.len() != 0x4a0 {
            return Err(Error::Attestation("SNP report has the wrong size".into()));
        }
        let release = self.gateway(release_id).ok_or(Error::Approval(
            crate::approvals::Error::NotApproved("gateway"),
        ))?;
        let report_id = report[0x140..0x160].try_into().map_err(attestation_error)?;
        let node_id = crate::attestation::snp_node_id(&report_id);
        let chip_id = hex::encode(&report[0x1a0..0x1e0]);
        let reported_tcb = hex::encode(&report[0x180..0x188]);
        let launch = crate::compatible_launch_policy(&release.launch_policies, &chip_id)
            .map_err(attestation_error)?;
        let hardware =
            crate::compatible_hardware(&self.policy, &chip_id).map_err(attestation_error)?;
        crate::check_raw_report_bindings(
            crate::ExpectedSnpReport {
                node_id: &node_id,
                chip_id: &chip_id,
                reported_tcb: &reported_tcb,
                report_data_sha512: &hex::encode(expected_report_data),
            },
            &release.evidence.manifest,
            launch,
            report,
            Some(hardware),
        )
        .map_err(attestation_error)?;
        let vcek = self.collateral.vcek(&chip_id, &reported_tcb)?;
        let product =
            crate::validate_report_product_binding(vcek, report).map_err(attestation_error)?;
        let expected_policy =
            crate::parse_u64_hex(&launch.policy, "launch policy").map_err(attestation_error)?;
        crate::validate_snp_launch_policy(expected_policy, Some(product))
            .map_err(attestation_error)?;
        crate::verify_raw_snp_report_signature_with_vcek(report, vcek, &node_id)
            .map_err(attestation_error)?;
        // Consult shared CRL state after crypto work. An old retained snapshot cannot hide
        // a revocation learned while another evidence candidate was being installed.
        let validity = self.collateral_validity(&chip_id, &reported_tcb, now_unix_ms)?;
        Ok(VerifiedSnpReport {
            node_id,
            report_id,
            chip_id,
            reported_tcb,
            validity,
        })
    }
}

fn attestation_error(error: impl std::fmt::Display) -> Error {
    Error::Attestation(error.to_string())
}
