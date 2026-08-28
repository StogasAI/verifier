use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEnvelope {
    pub body: BundleBody,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleBody {
    pub catalogs: Vec<AllowedCatalog>,
    pub allowed_igvms: Vec<AllowedIgvm>,
    pub created_at: String,
    pub expires_at: String,
    pub hardware_policy: SignedHardwarePolicy,
    pub nodes: Vec<BundleNode>,
    pub schema: String,
    pub sequence: u64,
    pub vendor_collateral: Vec<BTreeMap<String, Value>>,
}

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
    pub github_in_toto: Vec<Value>,
    pub signed_release: SignedCatalogRelease,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCatalogRelease {
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub manifest: CatalogReleaseManifest,
    pub schema: String,
    pub signature: String,
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
    pub github_in_toto: Vec<Value>,
    pub release_manifest: GatewayReleaseManifest,
    pub stogas_signature: CounterbuildSignature,
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
    #[serde(rename = "snp-launch-policies.json")]
    pub snp_launch_policies: GatewayReleaseArtifact,
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
    pub cmdline_sha256: String,
    pub core_go_mod_sha256: String,
    pub core_go_sum_sha256: String,
    pub environment: GatewayReleaseBuildEnvironment,
    pub go_mod_sha256: String,
    pub go_sum_sha256: String,
    pub go_vendor_tree_sha256: String,
    pub go_version: String,
    pub guest_ca_bundle_path: String,
    pub guest_ca_bundle_sha256: String,
    pub guix_channel_commit: String,
    pub input_sha256: BTreeMap<String, String>,
    pub kernel_config_sha256: String,
    pub kernel_version: String,
    pub linux_bz_image_sha256: String,
    pub os_release_sha256: String,
    pub ovmf_sha256: String,
    pub pins_lock_sha256: String,
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
pub struct CounterbuildSignature {
    pub algorithm: String,
    pub key_id: String,
    pub schema: String,
    pub signature: String,
    pub signed: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogIdentity {
    pub digest: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub cert_expires_at: String,
    pub chip_id: String,
    pub health: NodeHealth,
    pub node_id: String,
    pub quote: String,
    pub quote_verified_at: String,
    pub region: String,
    pub release_measurement: String,
    pub reported_tcb: String,
    pub report_data: ReportData,
    pub report_data_sha512: String,
}

/// Minimal public node evidence. Hardware identity and the report-data digest are derived from
/// the signed report during verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleNode {
    pub node_id: String,
    pub quote: String,
    pub report_data: ReportData,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_quote_failure_class: Option<String>,
    pub ready: bool,
    pub secret_versions: BTreeMap<String, String>,
}

/// Untrusted heartbeat payload received by Control before admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatCandidate {
    pub active_cert_sha256: String,
    pub cert_expires_at: String,
    pub catalog: CatalogIdentity,
    pub health: NodeHealth,
    pub node_id: String,
    pub observed_at: String,
    pub quote: String,
    pub quote_generated_at: String,
    pub report_data: ReportData,
    pub report_data_sha512: String,
    pub signature: String,
}

/// Deterministic inputs for verifying one Control heartbeat admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    pub hardware_policy: SignedHardwarePolicy,
    pub heartbeat: HeartbeatCandidate,
    pub release_manifests: Vec<GatewayReleaseManifest>,
    pub region: String,
    pub trusted_chip_ids: Vec<String>,
    pub vendor_collateral: Vec<VendorCollateral>,
}

/// Explicitly local-only inputs for Control's emulated guest admission path.
///
/// This keeps parsing and cryptographic checks in the Rust verifier while making the absence of
/// production AMD collateral impossible to confuse with a real admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAdmissionRequest {
    pub attester_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amd_report_signing_public_key: Option<String>,
    pub heartbeat: HeartbeatCandidate,
    pub release_manifests: Vec<GatewayReleaseManifest>,
    pub region: String,
    pub trusted_chip_ids: Vec<String>,
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

/// A heartbeat accepted by the same cryptographic implementation used by clients.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAdmission {
    pub node: Node,
    pub verified: VerifiedNode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportData {
    pub accepted_cert_sha256: Vec<String>,
    pub drand: DrandBeacon,
    pub ed25519_public_key: String,
    pub hpke_public_key: String,
    pub schema: String,
    pub tls_spki_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrandBeacon {
    pub chain_hash: String,
    pub network: String,
    pub randomness: String,
    pub round: u64,
    pub signature: String,
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

/// Exact AMD collateral stack that Control proposes to activate for one platform.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdCollateralAdmissionRequest {
    pub chip_id: String,
    pub reported_tcb: String,
    pub vendor_collateral: Vec<VendorCollateral>,
}

/// Digests of an AMD collateral stack accepted for database activation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAmdCollateral {
    pub chip_id: String,
    pub reported_tcb: String,
    pub sha256: Vec<String>,
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
pub struct VerifiedNode {
    pub chip_id: String,
    pub drand_round: u64,
    pub drand_round_time_unix_ms: i64,
    pub evidence_age_ms: i64,
    pub node_id: String,
    pub quote: String,
    pub quote_verified_at_unix_ms: i64,
    pub report_data: ReportData,
    pub report_data_sha512: String,
    pub release_measurement: String,
    pub reported_tcb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExcludedNode {
    pub drand_round: u64,
    pub drand_round_time_unix_ms: i64,
    pub evidence_age_ms: i64,
    pub node_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedBundle {
    pub catalogs: Vec<VerifiedCatalogRelease>,
    pub sequence: u64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub excluded_nodes: Vec<ExcludedNode>,
    pub hardware_policy: VerifiedHardwarePolicy,
    pub releases: Vec<VerifiedRelease>,
    pub nodes: Vec<VerifiedNode>,
    pub original: BundleEnvelope,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwarePolicyFleetRequest {
    pub hardware_policy: SignedHardwarePolicy,
    pub nodes: Vec<BundleNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedHardwarePolicyNode {
    pub chip_id: String,
    pub node_id: String,
    pub reported_tcb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedHardwarePolicyFleet {
    pub hardware_policy: VerifiedHardwarePolicy,
    pub nodes: Vec<VerifiedHardwarePolicyNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationOutput {
    pub bundle: VerifiedBundle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEvidence {
    pub admitted_at: String,
    pub admission: NodeLedgerAdmission,
    pub hardware_policy_sha256: String,
    pub node_id: String,
    pub release_measurement: String,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HydratedNodeEvidence {
    pub certificates: NodeCertificateHistory,
    pub evidence: NodeEvidence,
    pub hardware_policy: SignedHardwarePolicy,
    pub release: AllowedIgvm,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCertificateHistory {
    pub certificates: Vec<NodeCertificateHistoryEntry>,
    pub node_id: String,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCertificateHistoryEntry {
    pub certificate_chain_pem: String,
    pub first_observed_at: String,
    pub leaf_der: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLedgerAdmission {
    pub cert_expires_at: String,
    pub chip_id: String,
    pub endorsements: Vec<VendorCollateral>,
    pub quote: String,
    pub quote_verified_at: String,
    pub region: String,
    pub report_data: ReportData,
    pub report_data_sha512: String,
    pub reported_tcb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedNodeLedgerRecord {
    pub admitted_at_unix_ms: i64,
    pub node_id: String,
    pub node: VerifiedNode,
    pub release: VerifiedRelease,
}
