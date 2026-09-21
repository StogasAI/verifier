use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHardwarePolicy {
    pub policy: HardwarePolicy,
    pub sigstore: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwarePolicy {
    pub policies: Vec<AmdSevSnpPolicy>,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdSevSnpPolicy {
    pub chip_ids: Vec<String>,
    pub cpuid_family: u8,
    pub cpuid_model: u8,
    pub cpuid_stepping: u8,
    pub forbidden_platform_info_mask: String,
    pub minimum_tcb: AmdTcb,
    pub required_current_mitigation_mask: String,
    pub required_launch_mitigation_mask: String,
    pub required_platform_info_mask: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdTcb {
    pub bootloader: u8,
    pub microcode: u8,
    pub snp: u8,
    pub tee: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedCatalog {
    pub attested_builds: Vec<Value>,
    pub manifest: CatalogReleaseManifest,
    pub schema: String,
    pub signature: StogasSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReleaseManifest {
    #[serde(rename = "catalogSchema")]
    pub catalog_schema: u16,
    #[serde(rename = "minimumGatewaySequence")]
    pub minimum_gateway_sequence: u64,
    pub public: String,
    pub runtime: String,
    pub schema: String,
    pub sequence: u64,
    pub source: CatalogSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSource {
    pub commit: String,
    pub repository: String,
    pub tag: String,
    pub tree: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedIgvm {
    pub attested_builds: Vec<Value>,
    pub manifest: GatewayReleaseManifest,
    pub schema: String,
    pub signature: StogasSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseManifest {
    pub artifacts: GatewayReleaseArtifacts,
    pub build: GatewayReleaseBuild,
    pub git: GatewayReleaseGit,
    pub schema: String,
    pub sequence: u64,
    #[serde(rename = "sevSnp")]
    pub sev_snp: GatewayReleaseSevSnp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseArtifacts {
    #[serde(rename = "gateway.igvm")]
    pub gateway_igvm: GatewayReleaseArtifact,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayReleaseArtifact {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayReleaseBuild {
    pub environment: GatewayReleaseBuildEnvironment,
    pub go_vendor_tree_sha256: String,
    pub go_version: String,
    pub guest_ca_bundle_path: String,
    pub guix_channel_commit: String,
    pub input_sha256: BTreeMap<String, String>,
    pub kernel_config_sha256: String,
    pub kernel_version: String,
    pub linux_bz_image_sha256: String,
    pub ovmf_sha256: String,
    pub systemd_stub_sha256: String,
    pub uki_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayReleaseBuildEnvironment {
    pub lc_all: String,
    pub source_date_epoch: String,
    pub tz: String,
    pub umask: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseGit {
    pub commit: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub repository: String,
    pub tag: String,
    pub tree: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayReleaseSevSnp {
    pub check_kvm: bool,
    pub launch_measurement: String,
    pub launch_policies: LaunchPolicies,
    pub measurement_command: String,
    pub measurement_tool: String,
    pub measurement_tool_sha256: String,
    pub measurement_tool_version: String,
    pub platform: String,
    pub vcpu_count: u16,
    pub vmm: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchValues {
    pub author_key_digest: String,
    pub family_id: String,
    pub host_data: String,
    pub id_key_digest: String,
    pub image_id: String,
    pub policy: String,
    pub vmpl: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicies {
    pub policies: Vec<AmdSevSnpLaunchPolicy>,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdSevSnpLaunchPolicy {
    pub chip_ids: Vec<String>,
    pub launch: LaunchValues,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StogasSignature {
    pub key_id: String,
    pub signature: String,
}

/// Identity fields extracted from an untrusted raw report for collateral lookup only.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectedSnpQuote {
    pub chip_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_family: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_model: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_stepping: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    pub release_measurement: String,
    pub report_version: u32,
    pub reported_tcb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VendorCollateral {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_id: Option<String>,
    pub collateral_type: String,
    pub fetched_at: String,
    pub payload: BTreeMap<String, Value>,
    pub sha256: String,
    pub source_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseProvenance {
    Github,
    #[cfg(feature = "staging")]
    Staging,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedRelease {
    pub evidence: AllowedIgvm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_integrated_time_unix_ms: Option<i64>,
    pub igvm_sha256: String,
    pub launch_policies: LaunchPolicies,
    pub measurement: String,
    pub provenance: ReleaseProvenance,
    pub release_tag: String,
    pub release_manifest_sha256: String,
    pub sequence: u64,
    pub source_commit: String,
    pub source_repository: String,
    pub source_tree: String,
    pub stogas_signing_key_id: String,
    pub vcpu_count: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedCatalogRelease {
    pub evidence: AllowedCatalog,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_integrated_time_unix_ms: Option<i64>,
    pub minimum_gateway_sequence: u64,
    pub provenance: ReleaseProvenance,
    pub public_digest: String,
    pub runtime_digest: String,
    pub sequence: u64,
    pub source_commit: String,
    pub source_repository: String,
    pub source_tag: String,
    pub source_tree: String,
    pub stogas_signing_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwarePolicySource {
    Local,
    StogasBundle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedHardwarePolicy {
    pub chip_ids: Vec<String>,
    pub policy_count: usize,
    pub rekor_integrated_time_unix_ms: Option<i64>,
    pub sha256: String,
    pub source: HardwarePolicySource,
    pub stogas_signing_key_id: Option<String>,
}
