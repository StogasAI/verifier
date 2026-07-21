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
    pub allowed_igvms: Vec<AllowedIgvm>,
    pub created_at: String,
    pub expires_at: String,
    pub nodes: Vec<Node>,
    pub schema: String,
    pub sequence: u64,
    pub ttl_ms: u64,
    pub vendor_collateral: Vec<VendorCollateral>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedIgvm {
    pub github_in_toto: Vec<Value>,
    pub launch_policy: LaunchPolicy,
    pub stogas_signature: ReleaseSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicy {
    pub igvm_sha256: String,
    pub launch: LaunchValues,
    pub measurement: String,
    pub name: String,
    pub release_tag: String,
    pub schema: String,
    pub sequence: u64,
    pub source: Source,
    pub vcpu_count: u16,
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
pub struct Source {
    pub commit: String,
    pub repository: String,
    pub tree: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignature {
    pub algorithm: String,
    pub key_id: String,
    pub schema: String,
    pub signature: String,
    pub signed: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_quote_error: Option<String>,
    pub ready: bool,
    pub secret_versions: BTreeMap<String, String>,
}

/// Untrusted heartbeat payload received by Control before admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatCandidate {
    pub cert_expires_at: String,
    pub health: NodeHealth,
    pub node_id: String,
    pub observed_at: String,
    pub quote: String,
    pub quote_generated_at: String,
    pub report_data: ReportData,
    pub report_data_sha512: String,
}

/// Deterministic inputs for verifying one Control heartbeat admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    pub heartbeat: HeartbeatCandidate,
    pub launch_policies: Vec<LaunchPolicy>,
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
    pub launch_policies: Vec<LaunchPolicy>,
    pub region: String,
    pub trusted_platforms: Vec<TrustedPlatform>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPlatform {
    pub chip_id: String,
    pub reported_tcb: String,
}

/// Identity fields extracted from an untrusted raw report for collateral lookup only.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectedSnpQuote {
    pub chip_id: String,
    pub release_measurement: String,
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
    pub active_cert_sha256: String,
    pub accepted_cert_sha256: Vec<String>,
    pub catalog_hash: String,
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
    Staging,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedRelease {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_integrated_time_unix_ms: Option<i64>,
    pub igvm_sha256: String,
    pub launch: LaunchValues,
    pub launch_policy_sha256: String,
    pub measurement: String,
    pub provenance: ReleaseProvenance,
    pub release_tag: String,
    pub sequence: u64,
    pub source_commit: String,
    pub source_repository: String,
    pub source_tree: String,
    pub stogas_signing_key_id: String,
    pub vcpu_count: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedNode {
    pub accepted_cert_sha256: Vec<String>,
    pub drand_round: u64,
    pub drand_round_time_unix_ms: i64,
    pub evidence_age_ms: i64,
    pub node_id: String,
    pub quote_verified_at_unix_ms: i64,
    pub region: String,
    pub report_data: ReportData,
    pub report_data_sha512: String,
    pub release_measurement: String,
    pub tls_spki_sha256: String,
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
    pub sequence: u64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub excluded_nodes: Vec<ExcludedNode>,
    pub releases: Vec<VerifiedRelease>,
    pub nodes: Vec<VerifiedNode>,
    pub original: BundleEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationOutput {
    pub bundle: VerifiedBundle,
}
