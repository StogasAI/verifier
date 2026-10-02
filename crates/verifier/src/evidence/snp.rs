use serde::{Deserialize, Serialize};

use super::{Error, Snapshot, Validity};
use crate::{AmdSevSnpPolicy, AmdTcb};

/// Hardware facts retained by an authority after authenticating a boot. These are
/// trusted database state, never a substitute for verifying caller-supplied evidence.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnpHardwareFacts {
    report_version: u32,
    cpuid: [u8; 3],
    current_tcb: AmdTcb,
    reported_tcb: AmdTcb,
    committed_tcb: AmdTcb,
    launch_tcb: AmdTcb,
    current_version: [u8; 3],
    committed_version: [u8; 3],
    #[serde(with = "hex_u64")]
    platform_info: u64,
    #[serde(with = "hex_u64")]
    launch_mitigations: u64,
    #[serde(with = "hex_u64")]
    current_mitigations: u64,
}

impl SnpHardwareFacts {
    pub(crate) fn from_report(report: &[u8]) -> Self {
        let mask =
            |offset| u64::from_le_bytes(report[offset..offset + 8].try_into().unwrap_or_default());
        Self {
            report_version: u32::from_le_bytes(report[0..4].try_into().unwrap_or_default()),
            cpuid: [report[0x188], report[0x189], report[0x18a]],
            current_tcb: crate::family19h_tcb(&report[0x38..0x40]),
            reported_tcb: crate::family19h_tcb(&report[0x180..0x188]),
            committed_tcb: crate::family19h_tcb(&report[0x1e0..0x1e8]),
            launch_tcb: crate::family19h_tcb(&report[0x1f0..0x1f8]),
            current_version: [report[0x1ea], report[0x1e9], report[0x1e8]],
            committed_version: [report[0x1ee], report[0x1ed], report[0x1ec]],
            platform_info: mask(0x40),
            launch_mitigations: mask(0x1f8),
            current_mitigations: mask(0x200),
        }
    }

    pub(crate) fn reported_tcb(&self) -> String {
        let tcb = self.reported_tcb;
        hex::encode([tcb.bootloader, tcb.tee, 0, 0, 0, 0, tcb.snp, tcb.microcode])
    }

    pub(crate) fn appraise(
        &self,
        profile: &AmdSevSnpPolicy,
        node_id: &str,
    ) -> Result<(), crate::Error> {
        let reject = |reason| crate::Error::Node(format!("{node_id} {reason}"));
        if self.report_version != 5 {
            return Err(reject("SNP report version is below hardware policy"));
        }
        if self.cpuid
            != [
                profile.cpuid_family,
                profile.cpuid_model,
                profile.cpuid_stepping,
            ]
        {
            return Err(reject("CPUID differs from hardware policy"));
        }
        for (label, actual) in [
            ("current", self.current_tcb),
            ("reported", self.reported_tcb),
            ("committed", self.committed_tcb),
            ("launch", self.launch_tcb),
        ] {
            if !crate::tcb_at_least(actual, profile.minimum_tcb) {
                return Err(crate::Error::Node(format!(
                    "{node_id} SNP {label} TCB is below hardware policy"
                )));
            }
        }
        if !crate::tcb_at_least(self.committed_tcb, self.reported_tcb)
            || !crate::tcb_at_least(self.current_tcb, self.committed_tcb)
        {
            return Err(reject("SNP TCB fields have an invalid downgrade order"));
        }
        if self.committed_version > self.current_version {
            return Err(reject(
                "SNP committed firmware version exceeds current version",
            ));
        }
        let platform = self.platform_info;
        let required = crate::parse_u64_hex(
            &profile.required_platform_info_mask,
            "required platform-info mask",
        )?;
        let forbidden = crate::parse_u64_hex(
            &profile.forbidden_platform_info_mask,
            "forbidden platform-info mask",
        )?;
        if platform & required != required || platform & forbidden != 0 {
            return Err(reject("SNP platform information is below hardware policy"));
        }
        for (actual, required, reason) in [
            (
                self.launch_mitigations,
                &profile.required_launch_mitigation_mask,
                "SNP launch mitigations are below hardware policy",
            ),
            (
                self.current_mitigations,
                &profile.required_current_mitigation_mask,
                "SNP current mitigations are below hardware policy",
            ),
        ] {
            let required = crate::parse_u64_hex(required, "required mitigation mask")?;
            if actual & required != required {
                return Err(reject(reason));
            }
        }
        Ok(())
    }
}

// JSON numbers cannot carry every hardware mask through JavaScript without loss.
// Keep masks numeric during appraisal and encode them only at the storage boundary.
mod hex_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "Serde requires a borrowed field for its serialize_with callback."
    )]
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{value:016x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        crate::parse_u64_hex(&value, "hardware mask").map_err(serde::de::Error::custom)
    }
}

/// An SNP report appraised against this snapshot's approved release, hardware policy and
/// current vendor revocation state. This result does not itself establish session freshness.
#[derive(Debug)]
pub struct VerifiedSnpReport {
    node_id: String,
    report_id: [u8; 32],
    chip_id: String,
    reported_tcb: String,
    facts: SnpHardwareFacts,
    validity: Validity,
}

impl VerifiedSnpReport {
    #[must_use]
    pub const fn facts(&self) -> &SnpHardwareFacts {
        &self.facts
    }

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
            Some(&self.hardware_evidence.policy),
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
            facts: SnpHardwareFacts::from_report(report),
            validity,
        })
    }
}

fn attestation_error(error: impl std::fmt::Display) -> Error {
    Error::Attestation(error.to_string())
}
