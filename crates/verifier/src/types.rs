use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEnvelope {
    pub body: BundleBody,
    pub body_sha256: String,
    pub signature: Signature,
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
pub struct Signature {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_verifier_jwt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_verifier: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedRelease {
    pub igvm_sha256: String,
    pub measurement: String,
    pub release_tag: String,
    pub source_commit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedNode {
    pub accepted_cert_sha256: Vec<String>,
    pub node_id: String,
    pub region: String,
    pub release_measurement: String,
    pub tls_spki_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedBundle {
    pub sequence: u64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub releases: Vec<VerifiedRelease>,
    pub nodes: Vec<VerifiedNode>,
    pub original: BundleEnvelope,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierState {
    pub version: u8,
    pub highest_bundle_sequence: u64,
    pub highest_observed_time_unix_ms: i64,
    pub highest_drand_round_by_node: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationOutput {
    pub bundle: VerifiedBundle,
    pub next_state: VerifierState,
}
