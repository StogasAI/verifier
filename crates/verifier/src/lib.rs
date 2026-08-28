//! Deterministic, networkless verification for Stogas confidential bundles.

pub(crate) use stogas_offline_sigstore::strict_json;
mod types;

pub mod e2ee;
pub mod response_proof;
pub mod secret_release;
pub use types::*;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey, pkcs8::DecodePublicKey};
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use stogas_offline_sigstore::{
    GithubPolicy, Subject, verify_github_attestation, verify_keyed_dsse,
};
use thiserror::Error;
use x509_parser::{
    cri_attributes::ParsedCriAttribute,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256},
    prelude::{
        FromDer as _, GeneralName, ParsedExtension, X509CertificationRequest,
        X509CertificationRequestInfo, X509Version,
    },
};

/// Maximum serialized bundle or heartbeat-admission request accepted by public adapters.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 1_024;
const MAX_VENDOR_COLLATERAL: usize = 4_096;
const MAX_BUNDLE_VALIDITY_MS: i64 = 15 * 60 * 1000;
const MAX_BUNDLE_AGE_MS: i64 = 3 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: i64 = 60_000;
const DRAND_CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const DRAND_GENESIS_SECONDS: i64 = 1_692_803_367;
const DRAND_PERIOD_SECONDS: i64 = 3;
const DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS: i64 = 2 * 60 * 1000;
const MAX_NODE_EVIDENCE_AGE_MS: i64 = 2 * 60 * 1000;
const AMD_COLLATERAL_VALIDITY_MS: i64 = 24 * 60 * 60 * 1000;
const SNP_POLICY_PAGE_SWAP_DISABLE: u64 = 1 << 25;
const SNP_POLICY_MEM_AES_256_XTS: u64 = 1 << 22;
const SNP_POLICY_CXL_ALLOW: u64 = 1 << 21;
const SNP_POLICY_SINGLE_SOCKET: u64 = 1 << 20;
const SNP_POLICY_DEBUG: u64 = 1 << 19;
const SNP_POLICY_MIGRATE_MA: u64 = 1 << 18;
const SNP_POLICY_RESERVED_MUST_BE_ONE: u64 = 1 << 17;
const SNP_POLICY_COMMON_REQUIRED: u64 =
    SNP_POLICY_PAGE_SWAP_DISABLE | SNP_POLICY_SINGLE_SOCKET | SNP_POLICY_RESERVED_MUST_BE_ONE;
const SNP_POLICY_COMMON_FORBIDDEN: u64 =
    SNP_POLICY_CXL_ALLOW | SNP_POLICY_DEBUG | SNP_POLICY_MIGRATE_MA;
const STOGAS_RELEASE_KEY_ID: &str = "stogas-ed25519-stamp-v1";
const STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64: &str =
    "MCowBQYDK2VwAyEAByVn3LvWVbf3YkokMZPvir70vcDu0nNflgXoM0Y8aQU=";
#[cfg(feature = "staging")]
const STAGING_PROVENANCE_TYPE: &str = "https://stogas.ai/attestations/staging-development/v1";
const HEARTBEAT_SIGNATURE_DOMAIN: &[u8] = b"stogas.gateway-heartbeat.v1\0";
const CSR_SIGNATURE_DOMAIN: &[u8] = b"stogas.gateway-csr-submission.v1\0";
const HARDWARE_POLICY_DSSE_PAYLOAD_TYPE: &str = "application/vnd.stogas.hardware-policies.v1+json";
const SNP_PLATFORM_INFO_KNOWN_MASK: u64 = 0xbf;

fn stogas_release_key(key_id: &str) -> Option<&'static str> {
    (key_id == STOGAS_RELEASE_KEY_ID).then_some(STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AmdTcbLayout {
    Family19h,
    Family1ah,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AmdProductProfile {
    product_name: &'static str,
    root_spki_sha384: &'static str,
    struct_version: u8,
    tcb_layout: AmdTcbLayout,
    minimum_policy_abi: (u8, u8),
    required_policy_bits: u64,
}

// AMD publication 57230 product policy. Future products remain fail-closed until their CPUID
// range, KDS name, certificate layout, and pinned ARK are added together here.
const AMD_PRODUCT_PROFILES: [AmdProductProfile; 4] = [
    AmdProductProfile {
        product_name: "Milan",
        root_spki_sha384: "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: 0,
    },
    AmdProductProfile {
        product_name: "Genoa",
        root_spki_sha384: "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
    AmdProductProfile {
        product_name: "Siena",
        root_spki_sha384: "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
    AmdProductProfile {
        product_name: "Turin",
        root_spki_sha384: "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
        struct_version: 1,
        tcb_layout: AmdTcbLayout::Family1ah,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
];

fn validate_snp_launch_policy(
    policy: u64,
    product: Option<&AmdProductProfile>,
) -> Result<(), Error> {
    if policy >> 26 != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy sets reserved high bits".into(),
        ));
    }
    let required =
        SNP_POLICY_COMMON_REQUIRED | product.map_or(0, |profile| profile.required_policy_bits);
    if policy & required != required {
        let product_name = product.map_or("admitted platform", |profile| profile.product_name);
        return Err(Error::Node(format!(
            "authorized SNP launch policy lacks required {product_name} protections"
        )));
    }
    if policy & SNP_POLICY_COMMON_FORBIDDEN != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy permits CXL, debugging, or migration".into(),
        ));
    }
    let minimum_abi = product.map_or((1, 58), |profile| profile.minimum_policy_abi);
    let policy_abi = (((policy >> 8) & 0xff) as u8, (policy & 0xff) as u8);
    if policy_abi < minimum_abi {
        return Err(Error::Node(format!(
            "authorized SNP launch policy ABI {}.{} is older than required {}.{}",
            policy_abi.0, policy_abi.1, minimum_abi.0, minimum_abi.1
        )));
    }
    Ok(())
}

fn amd_product_from_cpuid(family: u8, model: u8) -> Option<&'static AmdProductProfile> {
    let extended_model = model >> 4;
    let product_name = match (family, extended_model) {
        (0x19, 0x0) => "Milan",
        (0x19, 0x1) => "Genoa",
        (0x19, 0xa) => "Siena",
        (0x1a, 0x0 | 0x1) => "Turin",
        _ => return None,
    };
    AMD_PRODUCT_PROFILES
        .iter()
        .find(|profile| profile.product_name == product_name)
}

type InspectedReportProduct = (
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<&'static AmdProductProfile>,
);

fn inspect_report_product(
    report: &[u8],
    report_version: u32,
) -> Result<InspectedReportProduct, Error> {
    if report_version == 2 {
        if report[0x1a8..0x1e0].iter().all(|byte| *byte == 0)
            && report[0x1a0..0x1a8].iter().any(|byte| *byte != 0)
        {
            return Err(Error::Node(
                "Family 1Ah-shaped CHIP_ID requires a report with CPUID fields".into(),
            ));
        }
        return Ok((None, None, None, None));
    }

    let family = report[0x188];
    let model = report[0x189];
    let stepping = report[0x18a];
    let product = amd_product_from_cpuid(family, model)
        .ok_or_else(|| Error::Node("unsupported AMD processor family or model".into()))?;
    if product.tcb_layout == AmdTcbLayout::Family1ah && report_version < 5 {
        return Err(Error::Node(
            "Family 1Ah requires SNP attestation report version 5 or newer".into(),
        ));
    }
    Ok((Some(family), Some(model), Some(stepping), Some(product)))
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentProvenance {
    #[serde(rename = "_type")]
    statement_type: String,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: StagingDevelopmentPredicate,
    subject: Vec<StagingDevelopmentSubject>,
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentPredicate {
    environment: String,
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentSubject {
    digest: BTreeMap<String, String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateCsrSubmission {
    csr_der: String,
    node_id: String,
    order_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateCsrTrustedContext {
    attested_node_ed25519_public_key: String,
    expected_common_name: Option<String>,
    expected_dns_names: Vec<String>,
    expected_tls_spki_sha256: String,
    node_id: String,
    order_id: String,
}

/// Complete verification failure. No state may be persisted after this error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("bundle exceeds {MAX_INPUT_BYTES} bytes")]
    TooLarge,
    #[error("invalid bundle JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported or invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("bundle checksum failed: {0}")]
    BundleChecksum(String),
    #[error("release verification failed: {0}")]
    Release(String),
    #[error("node verification failed: {0}")]
    Node(String),
    #[error("heartbeat replay protection failed: {0}")]
    Replay(String),
    #[error("response proof verification failed: {0}")]
    ResponseProof(String),
}

/// Verifier with a bounded in-memory cache for immutable release and catalog approvals.
///
/// The cache is only a performance optimization. It is deliberately ephemeral and cannot change
/// the compiled provenance policy for new approval bytes.
#[derive(Debug, Default)]
pub struct Verifier {
    active_bundle: Option<VerificationOutput>,
    verified_catalogs: BTreeMap<ApprovalCacheKey, VerifiedCatalogRelease>,
    verified_releases: BTreeMap<ApprovalCacheKey, VerifiedRelease>,
}

type ApprovalCacheKey = [u8; 32];

struct VerificationCache {
    catalogs: BTreeMap<ApprovalCacheKey, VerifiedCatalogRelease>,
    releases: BTreeMap<ApprovalCacheKey, VerifiedRelease>,
}

/// Exact bytes required to verify one historical response receipt.
pub struct HistoricalResponseProofInput<'a> {
    /// Exact plaintext request body.
    pub request_body: &'a [u8],
    /// Complete buffered JSON response with its final `stogas` object.
    pub response_body: &'a [u8],
    /// Expected E2EE transcript hash when application encryption was used.
    pub expected_e2ee_transcript_sha256: Option<&'a str>,
    /// One captured verification wall-clock value.
    pub now_unix_ms: i64,
    /// Immutable node-admission ledger bytes.
    pub ledger_bytes: &'a [u8],
    /// Immutable catalog approval bytes selected by the signed catalog sequence.
    pub catalog_approval_bytes: &'a [u8],
}

/// Locally computed hashes for constant-memory historical verification.
pub struct HistoricalResponseProofHashInput<'a> {
    /// Compact response receipt bytes.
    pub proof_bytes: &'a [u8],
    /// SHA-256 of the exact plaintext request body.
    pub request_sha256: &'a str,
    /// SHA-256 of the exact plaintext response body.
    pub response_sha256: &'a str,
    /// Expected E2EE transcript hash when application encryption was used.
    pub expected_e2ee_transcript_sha256: Option<&'a str>,
    /// One captured verification wall-clock value.
    pub now_unix_ms: i64,
    /// Immutable node-admission ledger bytes.
    pub ledger_bytes: &'a [u8],
    /// Immutable catalog approval bytes selected by the signed catalog sequence.
    pub catalog_approval_bytes: &'a [u8],
}

impl Verifier {
    /// Verify a bundle and retain only the release results referenced by that accepted bundle.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the approval caches.
    pub fn verify_bundle(
        &mut self,
        bundle_bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerificationOutput, Error> {
        self.verify_bundle_using_policy(bundle_bytes, None, now_unix_ms)
    }

    /// Verify a bundle while replacing only its mutable hardware appraisal rules.
    ///
    /// The bundled Stogas policy signature is still checked. The local policy cannot disable
    /// quote signatures, certificate chains, report bindings, launch policy, or freshness checks.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active bundle or approval caches.
    pub fn verify_bundle_with_policy(
        &mut self,
        bundle_bytes: &[u8],
        local_policy_bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerificationOutput, Error> {
        self.verify_bundle_using_policy(bundle_bytes, Some(local_policy_bytes), now_unix_ms)
    }

    fn verify_bundle_using_policy(
        &mut self,
        bundle_bytes: &[u8],
        local_policy_bytes: Option<&[u8]>,
        now_unix_ms: i64,
    ) -> Result<VerificationOutput, Error> {
        let (output, next_cache) = verify_bundle_inner(
            bundle_bytes,
            local_policy_bytes,
            now_unix_ms,
            &self.verified_catalogs,
            &self.verified_releases,
        )?;
        self.verified_catalogs = next_cache.catalogs;
        self.verified_releases = next_cache.releases;
        self.active_bundle = Some(output.clone());
        Ok(output)
    }

    /// Verify one response receipt against the active verified bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if no bundle has been accepted or any receipt, body, signature, node,
    /// drand, or E2EE transcript binding differs.
    pub fn verify_response_proof(
        &self,
        request_body: &[u8],
        response_body: &[u8],
        expected_e2ee_transcript_sha256: Option<&str>,
        now_unix_ms: i64,
    ) -> Result<response_proof::VerifiedResponseProof, Error> {
        let bundle = self.active_bundle.as_ref().ok_or_else(|| {
            Error::ResponseProof("a bundle must be verified before a response proof".into())
        })?;
        response_proof::verify_with_bundle(
            request_body,
            response_body,
            expected_e2ee_transcript_sha256,
            now_unix_ms,
            bundle,
        )
    }

    /// Verify one response receipt from body hashes computed by the local caller.
    ///
    /// # Errors
    ///
    /// Returns an error if no bundle has been accepted or any receipt, hash, signature, node,
    /// drand, or E2EE transcript binding differs.
    pub fn verify_response_proof_hashes(
        &self,
        proof_bytes: &[u8],
        request_sha256: &str,
        response_sha256: &str,
        expected_e2ee_transcript_sha256: Option<&str>,
        now_unix_ms: i64,
    ) -> Result<response_proof::VerifiedResponseProof, Error> {
        let bundle = self.active_bundle.as_ref().ok_or_else(|| {
            Error::ResponseProof("a bundle must be verified before a response proof".into())
        })?;
        response_proof::verify_with_bundle_hashes(
            proof_bytes,
            request_sha256,
            response_sha256,
            expected_e2ee_transcript_sha256,
            now_unix_ms,
            bundle,
        )
    }

    /// Verify a response receipt and its immutable historical node ledger together.
    ///
    /// # Errors
    ///
    /// Returns an error when either cryptographic trust chain or their signing-key binding fails.
    pub fn verify_historical_response_proof(
        &self,
        input: &HistoricalResponseProofInput<'_>,
    ) -> Result<response_proof::VerifiedResponseProof, Error> {
        let ledger = verify_node_ledger_record(input.ledger_bytes)?;
        let catalog = verify_catalog_approval(input.catalog_approval_bytes, input.now_unix_ms)?;
        response_proof::verify_with_ledger(
            input.request_body,
            input.response_body,
            input.expected_e2ee_transcript_sha256,
            &ledger,
            &catalog,
        )
    }

    /// Verify historical evidence from body hashes computed by the local caller.
    ///
    /// # Errors
    ///
    /// Returns an error when either cryptographic trust chain, body hash, or signing-key binding
    /// fails.
    pub fn verify_historical_response_proof_hashes(
        &self,
        input: &HistoricalResponseProofHashInput<'_>,
    ) -> Result<response_proof::VerifiedResponseProof, Error> {
        let ledger = verify_node_ledger_record(input.ledger_bytes)?;
        let catalog = verify_catalog_approval(input.catalog_approval_bytes, input.now_unix_ms)?;
        response_proof::verify_with_ledger_hashes(
            input.proof_bytes,
            input.request_sha256,
            input.response_sha256,
            input.expected_e2ee_transcript_sha256,
            &ledger,
            &catalog,
        )
    }
}

/// Verify a bundle using one captured wall-clock time.
///
/// # Errors
///
/// Returns an error if any parsing, cryptographic, policy, or freshness check fails.
pub fn verify_bundle(bundle_bytes: &[u8], now_unix_ms: i64) -> Result<VerificationOutput, Error> {
    Verifier::default().verify_bundle(bundle_bytes, now_unix_ms)
}

/// Verify a bundle with caller-owned hardware appraisal rules.
///
/// # Errors
///
/// Returns an error if either the bundle or the local policy is invalid.
pub fn verify_bundle_with_policy(
    bundle_bytes: &[u8],
    local_policy_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerificationOutput, Error> {
    Verifier::default().verify_bundle_with_policy(bundle_bytes, local_policy_bytes, now_unix_ms)
}

/// Verify one release authorization before Control persists it.
///
/// This applies the same built-in Stogas release key, canonical launch-policy signature, and
/// GitHub/Sigstore provenance policy used when verifying a complete bundle.
///
/// # Errors
///
/// Returns an error when parsing, the Stogas signature, provenance, identity, subjects, or signing
/// time is invalid.
pub fn verify_release_approval(
    release_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedRelease, Error> {
    if release_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(release_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let release: AllowedIgvm =
        serde_json::from_value(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    verify_release(&release, now_unix_ms)
}

/// Verify one catalog authorization before Control persists it.
///
/// This verifies the Stogas signature over the independently produced manifest, the GitHub
/// Actions provenance over both catalog artifacts, and equality of both parties' hashes.
///
/// # Errors
///
/// Returns an error when the shape, signature, source identity, provenance, or artifact hashes
/// differ.
pub fn verify_catalog_approval(
    approval_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    if approval_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(approval_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let catalog: AllowedCatalog =
        serde_json::from_value(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    verify_catalog(&catalog, now_unix_ms)
}

/// Verify one historical node-admission evidence response.
///
/// Verification is anchored to the recorded admission time, so an expired certificate or AMD
/// collateral does not invalidate evidence that was valid when Control admitted the node.
/// The node ID is independently re-derived from the quote-bound chip and TLS identities.
///
/// # Errors
///
/// Returns an error when the release provenance, SNP quote, AMD collateral, report data, drand
/// evidence, or node identity is invalid.
pub fn verify_node_ledger_record(record_bytes: &[u8]) -> Result<VerifiedNodeLedgerRecord, Error> {
    if record_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(record_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let hydrated: HydratedNodeEvidence = serde_json::from_value(value).map_err(|error| {
        Error::InvalidBundle(format!("invalid hydrated node evidence: {error}"))
    })?;
    let record = &hydrated.evidence;
    if record.schema != "stogas.node-evidence.v1" || !is_lower_hex(&record.node_id, 32) {
        return Err(Error::InvalidBundle(
            "unsupported or invalid node evidence".into(),
        ));
    }
    if !is_lower_hex(&record.release_measurement, 32)
        && !is_lower_hex(&record.release_measurement, 48)
    {
        return Err(Error::InvalidBundle(
            "node ledger release measurement is invalid".into(),
        ));
    }
    if record.release_measurement != hydrated.release.release_manifest.sev_snp.launch_measurement {
        return Err(Error::InvalidBundle(
            "node ledger release reference differs from its stapled provenance".into(),
        ));
    }
    let admitted_at = parse_time(&record.admitted_at)?;
    if parse_time(&record.admission.quote_verified_at)? != admitted_at {
        return Err(Error::InvalidBundle(
            "node ledger admission timestamps differ".into(),
        ));
    }
    validate_node_certificate_history(record, &hydrated.certificates, admitted_at)?;
    let release = verify_release(&hydrated.release, admitted_at)?;
    let hardware_policy = verify_signed_hardware_policy(&hydrated.hardware_policy, admitted_at)?;
    if hardware_policy.verified.sha256 != record.hardware_policy_sha256 {
        return Err(Error::InvalidBundle(
            "node ledger hardware policy reference differs from its stapled policy".into(),
        ));
    }
    let node = ledger_record_node(record);
    let hardware_policy = compatible_hardware(&hardware_policy.policy, &node.chip_id)?;
    validate_node_shape(&node)?;
    verify_node_id(
        &record.node_id,
        &node.chip_id,
        &node.report_data.tls_spki_sha256,
    )?;
    let release_manifests = BTreeMap::from([(
        record.release_measurement.as_str(),
        &hydrated.release.release_manifest,
    )]);
    let amd_node_identities = [AmdNodeIdentity {
        chip_id: node.chip_id.clone(),
        node_id: node.node_id.clone(),
        reported_tcb: node.reported_tcb.clone(),
    }];
    let amd_stacks = verified_amd_stacks(
        &record.admission.endorsements,
        &amd_node_identities,
        admitted_at,
        admitted_at,
    )?;
    let verified_node = verify_node(
        &node,
        NodeVerificationTime::at(admitted_at),
        &release_manifests,
        &amd_stacks,
        hardware_policy,
    )?;
    Ok(VerifiedNodeLedgerRecord {
        admitted_at_unix_ms: admitted_at,
        node_id: record.node_id.clone(),
        node: verified_node,
        release,
    })
}

/// Verify one Stogas hardware policy, its Ed25519 DSSE signature, and its Rekor inclusion proof.
///
/// # Errors
///
/// Returns an error when the document, trusted key, signature, Rekor body, checkpoint, or Merkle
/// inclusion proof is invalid.
pub fn verify_hardware_policy(
    policy_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedHardwarePolicy, Error> {
    if policy_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(policy_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let policy: SignedHardwarePolicy = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid hardware policy: {error}")))?;
    Ok(verify_signed_hardware_policy(&policy, now_unix_ms)?.verified)
}

/// Reappraise the exact signed reports for all live nodes before a hardware policy is activated.
///
/// The reports come from Control's previously verified database rows, so this repeats only the
/// checks that the candidate policy can change.
///
/// # Errors
///
/// Returns an error if the policy proof is invalid or any node does not meet the candidate policy.
pub fn verify_hardware_policy_fleet(
    request_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedHardwarePolicyFleet, Error> {
    if request_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(request_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let request: HardwarePolicyFleetRequest = serde_json::from_value(value).map_err(|error| {
        Error::InvalidBundle(format!("invalid hardware policy fleet appraisal: {error}"))
    })?;
    if request.nodes.len() > MAX_NODES {
        return Err(Error::InvalidBundle(
            "hardware policy fleet appraisal has too many nodes".into(),
        ));
    }
    let selected = verify_signed_hardware_policy(&request.hardware_policy, now_unix_ms)?;
    let mut seen = BTreeSet::new();
    let mut nodes = Vec::with_capacity(request.nodes.len());
    for node in &request.nodes {
        if !seen.insert(node.node_id.as_str()) {
            return Err(Error::InvalidBundle(
                "hardware policy fleet appraisal has a duplicate node".into(),
            ));
        }
        let evidence = inspect_bundle_node(node)?;
        let policy = compatible_hardware(&selected.policy, &evidence.identity.chip_id)?;
        appraise_stored_node_hardware(&evidence, policy)?;
        nodes.push(VerifiedHardwarePolicyNode {
            chip_id: evidence.identity.chip_id,
            node_id: node.node_id.clone(),
            reported_tcb: evidence.identity.reported_tcb,
        });
    }
    nodes.sort_unstable_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(VerifiedHardwarePolicyFleet {
        hardware_policy: selected.verified,
        nodes,
    })
}

fn validate_node_certificate_history(
    record: &NodeEvidence,
    history: &NodeCertificateHistory,
    admitted_at: i64,
) -> Result<(), Error> {
    use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

    if history.schema != "stogas.node-certificate-history.v1"
        || history.node_id != record.node_id
        || history.certificates.len() > 256
    {
        return Err(Error::InvalidBundle(
            "unsupported or invalid node certificate history".into(),
        ));
    }
    let mut certificate_hashes = BTreeSet::new();
    let mut previous_certificate = None;
    for certificate in &history.certificates {
        if !is_lower_hex(&certificate.sha256, 32) {
            return Err(Error::InvalidBundle(
                "node ledger certificate history contains an invalid SHA-256".into(),
            ));
        }
        let observed_at = parse_time(&certificate.first_observed_at)?;
        if observed_at < admitted_at {
            return Err(Error::InvalidBundle(
                "node ledger certificate predates generation admission".into(),
            ));
        }
        let ordering_key = (observed_at, certificate.sha256.as_str());
        if previous_certificate.is_some_and(|previous| previous >= ordering_key) {
            return Err(Error::InvalidBundle(
                "node ledger certificate history is not canonically ordered".into(),
            ));
        }
        previous_certificate = Some(ordering_key);
        if !certificate_hashes.insert(certificate.sha256.as_str()) {
            return Err(Error::InvalidBundle(
                "node ledger certificate history contains a duplicate".into(),
            ));
        }
        let leaf_der = URL_SAFE_NO_PAD.decode(&certificate.leaf_der).map_err(|_| {
            Error::InvalidBundle("node certificate history contains invalid leaf DER".into())
        })?;
        if URL_SAFE_NO_PAD.encode(&leaf_der) != certificate.leaf_der
            || hex::encode(Sha256::digest(&leaf_der)) != certificate.sha256
        {
            return Err(Error::InvalidBundle(
                "node certificate history leaf DER differs from its SHA-256".into(),
            ));
        }
        let (_, pem) =
            parse_x509_pem(certificate.certificate_chain_pem.as_bytes()).map_err(|_| {
                Error::InvalidBundle(
                    "node certificate history contains an invalid PEM chain".into(),
                )
            })?;
        if pem.label != "CERTIFICATE" || pem.contents != leaf_der {
            return Err(Error::InvalidBundle(
                "node certificate history chain differs from its leaf DER".into(),
            ));
        }
        let (remaining, _) = parse_x509_certificate(&leaf_der).map_err(|_| {
            Error::InvalidBundle("node certificate history contains an invalid certificate".into())
        })?;
        if !remaining.is_empty() {
            return Err(Error::InvalidBundle(
                "node certificate history leaf DER has trailing data".into(),
            ));
        }
    }
    if record
        .admission
        .report_data
        .accepted_cert_sha256
        .iter()
        .any(|certificate| !certificate_hashes.contains(certificate.as_str()))
    {
        return Err(Error::InvalidBundle(
            "node ledger omits an admission certificate".into(),
        ));
    }
    Ok(())
}

fn ledger_record_node(record: &NodeEvidence) -> Node {
    Node {
        cert_expires_at: record.admission.cert_expires_at.clone(),
        chip_id: record.admission.chip_id.clone(),
        health: NodeHealth {
            last_quote_failure_class: None,
            ready: true,
            secret_versions: BTreeMap::new(),
        },
        node_id: record.node_id.clone(),
        quote: record.admission.quote.clone(),
        quote_verified_at: record.admission.quote_verified_at.clone(),
        region: record.admission.region.clone(),
        release_measurement: record.release_measurement.clone(),
        reported_tcb: record.admission.reported_tcb.clone(),
        report_data: record.admission.report_data.clone(),
        report_data_sha512: record.admission.report_data_sha512.clone(),
    }
}

/// Verify one exact AMD collateral stack before Control makes it active.
///
/// This enforces the same AMD root, certificate-chain, chip/TCB extension, CRL, digest, and
/// lifetime policy used by complete heartbeat and bundle verification.
///
/// # Errors
///
/// Returns an error without producing an activation result when any collateral is untrusted.
pub fn verify_amd_collateral_admission(
    request_bytes: &[u8],
    now_unix_ms: i64,
    required_until_unix_ms: i64,
) -> Result<VerifiedAmdCollateral, Error> {
    if request_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    if required_until_unix_ms < now_unix_ms
        || required_until_unix_ms > now_unix_ms + AMD_COLLATERAL_VALIDITY_MS
    {
        return Err(Error::InvalidBundle(
            "AMD collateral required-until time is invalid".into(),
        ));
    }
    let value = strict_json::from_slice(request_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let request: AmdCollateralAdmissionRequest =
        serde_json::from_value(value).map_err(|error| {
            Error::InvalidBundle(format!("invalid AMD collateral admission request: {error}"))
        })?;
    if request.vendor_collateral.len() != 4 {
        return Err(Error::InvalidBundle(
            "AMD collateral admission requires exactly ARK, ASK, CRL, and VCEK".into(),
        ));
    }
    let stack = exact_amd_stack(
        &request.vendor_collateral,
        &request.chip_id,
        &request.reported_tcb,
        now_unix_ms,
        required_until_unix_ms,
    )?;
    verify_amd_collateral_stack(
        &stack,
        &request.chip_id,
        &request.reported_tcb,
        now_unix_ms,
        required_until_unix_ms,
    )?;
    let mut sha256 = request
        .vendor_collateral
        .iter()
        .map(|row| row.sha256.clone())
        .collect::<Vec<_>>();
    sha256.sort_unstable();
    Ok(VerifiedAmdCollateral {
        chip_id: request.chip_id.to_lowercase(),
        reported_tcb: request.reported_tcb.to_lowercase(),
        sha256,
    })
}

/// Decode only the routing identity from a raw SNP report.
///
/// This result is untrusted and exists solely so Control can select the candidate AMD collateral.
/// Call [`verify_heartbeat_admission`] before using any returned field as trusted state.
///
/// # Errors
///
/// Returns an error for a malformed, unsupported, or incorrectly sized quote envelope/report.
pub fn inspect_snp_quote(quote: &str) -> Result<InspectedSnpQuote, Error> {
    let report = decode_snp_report(quote, "heartbeat")?;
    let report_version = u32::from_le_bytes(report[0x00..0x04].try_into().unwrap_or_default());
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node("unsupported SNP report version".into()));
    }
    let (cpuid_family, cpuid_model, cpuid_stepping, product_name) =
        inspect_report_product(&report, report_version)?;
    Ok(InspectedSnpQuote {
        chip_id: hex::encode(&report[0x1a0..0x1e0]),
        cpuid_family,
        cpuid_model,
        cpuid_stepping,
        product_name: product_name.map(|profile| profile.product_name.into()),
        release_measurement: hex::encode(&report[0x90..0xc0]),
        report_version,
        reported_tcb: hex::encode(&report[0x180..0x188]),
    })
}

fn validate_admission_request_bounds(
    request: &AdmissionRequest,
    now_unix_ms: i64,
) -> Result<(), Error> {
    if request.release_manifests.is_empty() || request.release_manifests.len() > 2 {
        return Err(Error::InvalidBundle(
            "admission requires one or two release manifests".into(),
        ));
    }
    if request.vendor_collateral.len() > MAX_VENDOR_COLLATERAL {
        return Err(Error::InvalidBundle(
            "admission contains too many collateral records".into(),
        ));
    }
    for (label, value) in [
        ("heartbeat observation", &request.heartbeat.observed_at),
        ("quote generation", &request.heartbeat.quote_generated_at),
    ] {
        if parse_time(value)? > now_unix_ms + MAX_CLOCK_SKEW_MS {
            return Err(Error::Node(format!("{label} time is in the future")));
        }
    }
    Ok(())
}

/// Verify one heartbeat admission using the same SNP, AMD, report-data, and drand code as bundle
/// verification. Release provenance must have been authorized before its launch policy is supplied.
///
/// # Errors
///
/// Returns an error without producing a normalized node when any input or cryptographic check fails.
pub fn verify_heartbeat_admission(
    request_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedAdmission, Error> {
    if request_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(request_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let request: AdmissionRequest = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid admission request: {error}")))?;
    let hardware_policy = verify_signed_hardware_policy(&request.hardware_policy, now_unix_ms)?;
    validate_admission_request_bounds(&request, now_unix_ms)?;
    let heartbeat = &request.heartbeat;
    let identity = inspect_snp_quote(&heartbeat.quote)?;
    if !request
        .trusted_chip_ids
        .iter()
        .any(|chip| chip.eq_ignore_ascii_case(&identity.chip_id))
    {
        return Err(Error::Node("unknown chip id".into()));
    }
    let mut release_manifests = BTreeMap::new();
    for manifest in &request.release_manifests {
        validate_gateway_release_manifest(manifest)?;
        if release_manifests
            .insert(manifest.sev_snp.launch_measurement.as_str(), manifest)
            .is_some()
        {
            return Err(Error::InvalidBundle(
                "admission release manifests contain a duplicate measurement".into(),
            ));
        }
    }
    if !release_manifests.contains_key(identity.release_measurement.as_str()) {
        return Err(Error::Node(
            "SNP measurement is absent from the authorized release stack".into(),
        ));
    }
    let hardware_policy = compatible_hardware(&hardware_policy.policy, &identity.chip_id)?;
    validate_heartbeat_operational_state(heartbeat)?;
    if parse_time(&heartbeat.cert_expires_at)? <= now_unix_ms {
        return Err(Error::Node("active certificate is expired".into()));
    }
    let node_id = normalize_admission_node_id(
        &heartbeat.node_id,
        &identity.chip_id,
        &heartbeat.report_data,
    )?;
    let node = Node {
        cert_expires_at: heartbeat.cert_expires_at.clone(),
        chip_id: identity.chip_id,
        health: heartbeat.health.clone(),
        node_id,
        quote: heartbeat.quote.clone(),
        quote_verified_at: DateTime::<Utc>::from_timestamp_millis(now_unix_ms)
            .ok_or_else(|| Error::Node("captured time is out of range".into()))?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        region: request.region,
        release_measurement: identity.release_measurement,
        reported_tcb: identity.reported_tcb,
        report_data: heartbeat.report_data.clone(),
        report_data_sha512: heartbeat.report_data_sha512.clone(),
    };
    let amd_node_identities = [AmdNodeIdentity {
        chip_id: node.chip_id.clone(),
        node_id: node.node_id.clone(),
        reported_tcb: node.reported_tcb.clone(),
    }];
    let amd_stacks = verified_amd_stacks(
        &request.vendor_collateral,
        &amd_node_identities,
        now_unix_ms,
        now_unix_ms,
    )?;
    let verified = verify_node(
        &node,
        NodeVerificationTime::at(now_unix_ms),
        &release_manifests,
        &amd_stacks,
        hardware_policy,
    )?;
    verify_heartbeat_candidate_signature(heartbeat, &heartbeat.report_data.ed25519_public_key)?;
    Ok(VerifiedAdmission { node, verified })
}

/// Verify a recognized generation heartbeat with its already-attested Ed25519 key.
///
/// This is the inexpensive authentication step between periodic full SNP verification
/// checkpoints. The caller must source `public_key_b64url` from a previously verified generation,
/// never from the untrusted heartbeat itself.
///
/// # Errors
///
/// Returns an error for malformed input, a malformed key/signature, or a changed signed field.
pub fn verify_recognized_heartbeat_signature(
    heartbeat_bytes: &[u8],
    public_key_b64url: &str,
) -> Result<(), Error> {
    if heartbeat_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(heartbeat_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let heartbeat: HeartbeatCandidate = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid heartbeat: {error}")))?;
    verify_heartbeat_candidate_signature(&heartbeat, public_key_b64url)
}

/// Verify a gateway CSR, its proof of possession, its exact requested identity, and the
/// node-key authorization over the submission.
///
/// # Errors
///
/// Returns an error unless the CSR is a complete canonical P-256/SHA-256 request whose SPKI,
/// subject, and DNS SAN set exactly match Control's independently loaded certificate order.
pub fn verify_certificate_csr_submission(
    submission_bytes: &[u8],
    trusted_context_bytes: &[u8],
) -> Result<(), Error> {
    if submission_bytes.len() > MAX_INPUT_BYTES || trusted_context_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(submission_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let submission: CertificateCsrSubmission = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid CSR submission: {error}")))?;
    let value = strict_json::from_slice(trusted_context_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let trusted: CertificateCsrTrustedContext = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid trusted CSR context: {error}")))?;
    if submission.node_id != trusted.node_id || submission.order_id != trusted.order_id {
        return Err(Error::Node(
            "certificate CSR submission differs from the trusted certificate order".into(),
        ));
    }

    let csr_der = URL_SAFE_NO_PAD
        .decode(&submission.csr_der)
        .map_err(|_| Error::Node("certificate CSR is not base64url".into()))?;
    if csr_der.is_empty() {
        return Err(Error::Node("certificate CSR is empty".into()));
    }
    let mut authorization = Vec::with_capacity(160);
    authorization.extend_from_slice(CSR_SIGNATURE_DOMAIN);
    for field in [
        submission.node_id.as_bytes(),
        submission.order_id.as_bytes(),
        &Sha256::digest(&csr_der)[..],
    ] {
        append_transcript_field(&mut authorization, field)?;
    }
    verify_raw_ed25519(
        &trusted.attested_node_ed25519_public_key,
        &authorization,
        &submission.signature,
        "certificate CSR submission",
    )?;

    let (remaining, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|_| Error::Node("certificate CSR is not valid DER".into()))?;
    if !remaining.is_empty() || csr.as_raw().len() != csr_der.len() {
        return Err(Error::Node("certificate CSR contains trailing data".into()));
    }
    verify_certificate_csr_key_and_signature(&csr, &trusted.expected_tls_spki_sha256)?;
    verify_certificate_csr_subject(
        &csr.certification_request_info,
        trusted.expected_common_name.as_deref(),
    )?;
    verify_certificate_csr_dns_names(&csr, trusted.expected_dns_names)
}

fn verify_certificate_csr_key_and_signature(
    csr: &X509CertificationRequest<'_>,
    expected_tls_spki_sha256: &str,
) -> Result<(), Error> {
    if csr.certification_request_info.version != X509Version::V1 {
        return Err(Error::Node(
            "certificate CSR must use PKCS #10 version 1".into(),
        ));
    }
    if csr.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256
        || csr.signature_algorithm.parameters().is_some()
        || csr.signature_value.unused_bits != 0
    {
        return Err(Error::Node(
            "certificate CSR must use canonical ECDSA with SHA-256".into(),
        ));
    }
    let spki = &csr.certification_request_info.subject_pki;
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters()
            .and_then(|parameters| parameters.as_oid().ok())
            .as_ref()
            != Some(&OID_EC_P256)
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(Error::Node(
            "certificate CSR must contain a P-256 public key".into(),
        ));
    }
    let verifying_key = P256VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data)
        .map_err(|_| Error::Node("certificate CSR P-256 public key is invalid".into()))?;
    let signature = P256Signature::from_der(&csr.signature_value.data)
        .map_err(|_| Error::Node("certificate CSR signature is not canonical DER".into()))?;
    verifying_key
        .verify(csr.certification_request_info.raw, &signature)
        .map_err(|_| Error::Node("certificate CSR proof of possession is invalid".into()))?;

    let derived_spki_sha256 = hex::encode(Sha256::digest(spki.raw));
    if derived_spki_sha256 != expected_tls_spki_sha256 {
        return Err(Error::Node(
            "certificate CSR SPKI does not match the attested node key".into(),
        ));
    }
    Ok(())
}

fn verify_certificate_csr_subject(
    request_info: &X509CertificationRequestInfo<'_>,
    expected_common_name: Option<&str>,
) -> Result<(), Error> {
    let common_names = request_info
        .subject
        .iter_common_name()
        .map(|attribute| {
            attribute
                .as_str()
                .map(str::to_owned)
                .map_err(|_| Error::Node("certificate CSR common name is not UTF-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_common_names = expected_common_name.into_iter().collect::<Vec<_>>();
    if common_names != expected_common_names {
        return Err(Error::Node(
            "certificate CSR common name differs from the certificate order".into(),
        ));
    }
    let subject_attribute_count = request_info
        .subject
        .iter()
        .flat_map(x509_parser::prelude::RelativeDistinguishedName::iter)
        .count();
    if subject_attribute_count != common_names.len() {
        return Err(Error::Node(
            "certificate CSR contains unexpected subject attributes".into(),
        ));
    }
    Ok(())
}

fn verify_certificate_csr_dns_names(
    csr: &X509CertificationRequest<'_>,
    expected_dns_names: Vec<String>,
) -> Result<(), Error> {
    let mut dns_names = BTreeSet::new();
    let mut san_extensions = 0_u8;
    let [attribute] = csr.certification_request_info.attributes() else {
        return Err(Error::Node(
            "certificate CSR must contain exactly one extension-request attribute".into(),
        ));
    };
    let ParsedCriAttribute::ExtensionRequest(requested) = attribute.parsed_attribute() else {
        return Err(Error::Node(
            "certificate CSR contains an unexpected attribute".into(),
        ));
    };
    for extension in &requested.extensions {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                san_extensions = san_extensions.saturating_add(1);
                for name in &san.general_names {
                    let GeneralName::DNSName(name) = name else {
                        return Err(Error::Node(
                            "certificate CSR SANs must contain only DNS names".into(),
                        ));
                    };
                    let normalized = name.trim().to_ascii_lowercase();
                    if normalized.is_empty() || !dns_names.insert(normalized) {
                        return Err(Error::Node(
                            "certificate CSR contains an empty or duplicate DNS SAN".into(),
                        ));
                    }
                }
            }
            _ => {
                return Err(Error::Node(
                    "certificate CSR contains an unexpected requested extension".into(),
                ));
            }
        }
    }
    if san_extensions != 1 {
        return Err(Error::Node(
            "certificate CSR must contain exactly one DNS SAN extension".into(),
        ));
    }
    let expected_dns_names = expected_dns_names
        .into_iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if expected_dns_names.is_empty()
        || expected_dns_names.len() != dns_names.len()
        || expected_dns_names != dns_names
    {
        return Err(Error::Node(
            "certificate CSR DNS SANs differ from the certificate order".into(),
        ));
    }
    Ok(())
}

/// Verify one explicitly local Control heartbeat without treating emulated evidence as AMD trust.
///
/// Local mock/native quotes are useful for exercising the complete guest and Control lifecycle,
/// while a local raw-report mode additionally verifies an injected software P-384 signing key.
/// Neither path is reachable from the production admission API.
///
/// # Errors
///
/// Returns an error without producing a normalized node when parsing, binding, time, replay, or
/// configured local signature checks fail.
pub fn verify_local_heartbeat_admission(
    request_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedAdmission, Error> {
    let request = parse_local_admission_request(request_bytes)?;
    let heartbeat = &request.heartbeat;
    validate_local_heartbeat(heartbeat, now_unix_ms)?;

    let identity = inspect_local_quote(&request, now_unix_ms)?;
    if !request
        .trusted_chip_ids
        .iter()
        .any(|chip_id| chip_id.eq_ignore_ascii_case(&identity.chip_id))
    {
        return Err(Error::Node("unknown local chip id".into()));
    }
    let release_manifest = request
        .release_manifests
        .iter()
        .find(|manifest| {
            manifest
                .sev_snp
                .launch_measurement
                .eq_ignore_ascii_case(&identity.release_measurement)
        })
        .ok_or_else(|| {
            Error::Node("local SNP measurement is absent from the authorized release stack".into())
        })?;

    let quote_verified_at = DateTime::<Utc>::from_timestamp_millis(now_unix_ms)
        .ok_or_else(|| Error::Node("captured time is out of range".into()))?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let node = Node {
        cert_expires_at: heartbeat.cert_expires_at.clone(),
        chip_id: identity.chip_id,
        health: heartbeat.health.clone(),
        node_id: heartbeat.node_id.clone(),
        quote: heartbeat.quote.clone(),
        quote_verified_at,
        region: request.region,
        release_measurement: identity.release_measurement,
        reported_tcb: identity.reported_tcb,
        report_data: heartbeat.report_data.clone(),
        report_data_sha512: heartbeat.report_data_sha512.clone(),
    };

    let (drand_round_time_unix_ms, evidence_age_ms) = if request.attester_mode == "sev-snp" {
        let round_time = validate_node_evidence_time(
            &node.node_id,
            node.report_data.drand.round,
            now_unix_ms,
            now_unix_ms,
        )?;
        verify_quicknet(&node.report_data.drand)?;
        if let Some(report) = identity.raw_report.as_deref() {
            verify_local_raw_snp_report(
                &node,
                release_manifest,
                report,
                request.amd_report_signing_public_key.as_deref(),
            )?;
        }
        (round_time, now_unix_ms.saturating_sub(round_time).max(0))
    } else {
        (now_unix_ms, 0)
    };

    let verified = VerifiedNode {
        chip_id: node.chip_id.clone(),
        drand_round: node.report_data.drand.round,
        drand_round_time_unix_ms,
        evidence_age_ms,
        node_id: node.node_id.clone(),
        quote: node.quote.clone(),
        quote_verified_at_unix_ms: now_unix_ms,
        report_data: node.report_data.clone(),
        report_data_sha512: node.report_data_sha512.clone(),
        release_measurement: node.release_measurement.clone(),
        reported_tcb: node.reported_tcb.clone(),
    };
    verify_heartbeat_candidate_signature(heartbeat, &heartbeat.report_data.ed25519_public_key)?;
    Ok(VerifiedAdmission { node, verified })
}

fn verify_heartbeat_candidate_signature(
    heartbeat: &HeartbeatCandidate,
    public_key_b64url: &str,
) -> Result<(), Error> {
    let transcript = heartbeat_signature_transcript(heartbeat)?;
    verify_raw_ed25519(
        public_key_b64url,
        &transcript,
        &heartbeat.signature,
        "heartbeat",
    )
}

fn heartbeat_signature_transcript(heartbeat: &HeartbeatCandidate) -> Result<Vec<u8>, Error> {
    let quote = URL_SAFE_NO_PAD
        .decode(&heartbeat.quote)
        .map_err(|_| Error::Node("heartbeat quote encoding is invalid".into()))?;
    let quote_sha256 = Sha256::digest(&quote);
    let report_sha512 = hex::decode(&heartbeat.report_data_sha512)
        .map_err(|_| Error::Node("heartbeat report-data digest is not hex".into()))?;
    if report_sha512.len() != 64 {
        return Err(Error::Node(
            "heartbeat report-data digest must be 64 bytes".into(),
        ));
    }

    let mut transcript = Vec::with_capacity(512);
    let catalog_sequence = heartbeat.catalog.sequence.to_string();
    transcript.extend_from_slice(HEARTBEAT_SIGNATURE_DOMAIN);
    for field in [
        heartbeat.node_id.as_bytes(),
        heartbeat.active_cert_sha256.as_bytes(),
        heartbeat.cert_expires_at.as_bytes(),
        heartbeat.catalog.digest.as_bytes(),
        catalog_sequence.as_bytes(),
        heartbeat.observed_at.as_bytes(),
        heartbeat.quote_generated_at.as_bytes(),
        &quote_sha256[..],
        report_sha512.as_slice(),
        if heartbeat.health.ready {
            &[1_u8][..]
        } else {
            &[0_u8][..]
        },
        heartbeat
            .health
            .last_quote_failure_class
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    ] {
        append_transcript_field(&mut transcript, field)?;
    }
    let secret_count = u32::try_from(heartbeat.health.secret_versions.len())
        .map_err(|_| Error::Node("heartbeat has too many secret versions".into()))?;
    transcript.extend_from_slice(&secret_count.to_be_bytes());
    for (name, version) in &heartbeat.health.secret_versions {
        append_transcript_field(&mut transcript, name.as_bytes())?;
        append_transcript_field(&mut transcript, version.as_bytes())?;
    }
    Ok(transcript)
}

fn append_transcript_field(transcript: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len())
        .map_err(|_| Error::Node("signed transcript field is too large".into()))?;
    transcript.extend_from_slice(&len.to_be_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}

fn verify_raw_ed25519(
    public_key_b64url: &str,
    payload: &[u8],
    signature_b64url: &str,
    label: &str,
) -> Result<(), Error> {
    use ed25519_dalek::Verifier as _;

    let public_key = URL_SAFE_NO_PAD
        .decode(public_key_b64url)
        .map_err(|_| Error::Node(format!("{label} public key is not base64url")))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::Node(format!("{label} public key must be 32 bytes")))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::Node(format!("{label} public key is invalid")))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .map_err(|_| Error::Node(format!("{label} signature is not base64url")))?;
    let signature = Ed25519Signature::from_slice(&signature)
        .map_err(|_| Error::Node(format!("{label} signature must be 64 bytes")))?;
    key.verify(payload, &signature)
        .map_err(|_| Error::Node(format!("{label} signature is invalid")))
}

fn parse_local_admission_request(request_bytes: &[u8]) -> Result<LocalAdmissionRequest, Error> {
    if request_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(request_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let request: LocalAdmissionRequest = serde_json::from_value(value).map_err(|error| {
        Error::InvalidBundle(format!("invalid local admission request: {error}"))
    })?;
    if request.release_manifests.is_empty() || request.release_manifests.len() > 2 {
        return Err(Error::InvalidBundle(
            "local admission requires one or two release manifests".into(),
        ));
    }
    for manifest in &request.release_manifests {
        validate_gateway_release_manifest(manifest)?;
    }
    if request.trusted_chip_ids.is_empty()
        || request.trusted_chip_ids.len() > 16
        || request
            .trusted_chip_ids
            .iter()
            .any(|chip_id| !is_lower_hex(chip_id, 64))
    {
        return Err(Error::InvalidBundle(
            "local admission requires one to sixteen trusted chip ids".into(),
        ));
    }
    if !matches!(
        request.attester_mode.as_str(),
        "mock" | "igvm-native" | "sev-snp"
    ) {
        return Err(Error::InvalidBundle(
            "local admission has an unsupported attester mode".into(),
        ));
    }
    Ok(request)
}

fn validate_local_heartbeat(heartbeat: &HeartbeatCandidate, now_unix_ms: i64) -> Result<(), Error> {
    validate_heartbeat_operational_state(heartbeat)?;
    for (label, value) in [
        ("heartbeat observation", &heartbeat.observed_at),
        ("quote generation", &heartbeat.quote_generated_at),
    ] {
        if parse_time(value)? > now_unix_ms + MAX_CLOCK_SKEW_MS {
            return Err(Error::Node(format!("{label} time is in the future")));
        }
    }
    if parse_time(&heartbeat.cert_expires_at)? <= now_unix_ms {
        return Err(Error::Node("active certificate is expired".into()));
    }
    let canonical_report = canonical_report_data(&heartbeat.report_data)?;
    if hex::encode(Sha512::digest(canonical_report.as_bytes())) != heartbeat.report_data_sha512 {
        return Err(Error::Node("report-data hash differs".into()));
    }
    Ok(())
}

fn validate_heartbeat_operational_state(heartbeat: &HeartbeatCandidate) -> Result<(), Error> {
    if !is_lower_hex(&heartbeat.active_cert_sha256, 32)
        || !is_sha256_identity(&heartbeat.catalog.digest)
    {
        return Err(Error::Node(
            "heartbeat certificate or catalog state is invalid".into(),
        ));
    }
    Ok(())
}

struct LocalQuoteIdentity {
    chip_id: String,
    raw_report: Option<Vec<u8>>,
    release_measurement: String,
    reported_tcb: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalMockQuote {
    attester_mode: String,
    quote_generated_at: String,
    report_data_sha512: String,
    schema: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalStructuredQuote {
    attester_mode: String,
    chip_id: String,
    collateral_expires_at: String,
    quote_generated_at: String,
    release_measurement: String,
    report_data_sha512: String,
    reported_tcb: String,
    schema: String,
    tcb_status: String,
}

fn inspect_local_quote(
    request: &LocalAdmissionRequest,
    now_unix_ms: i64,
) -> Result<LocalQuoteIdentity, Error> {
    let quote_json = URL_SAFE_NO_PAD
        .decode(&request.heartbeat.quote)
        .map_err(|_| Error::Node("local quote encoding is invalid".into()))?;
    let value = strict_json::from_slice(&quote_json)
        .map_err(|_| Error::Node("local quote JSON is invalid".into()))?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Node("local quote schema is missing".into()))?;

    match schema {
        "stogas.local-mock-quote.v1" => inspect_local_mock_quote(request, value, now_unix_ms),
        "stogas.structured-snp-quote.v1" => {
            inspect_local_structured_quote(request, value, now_unix_ms)
        }
        "stogas.sev-snp-quote-envelope.v1" => inspect_local_raw_quote(request),
        _ => Err(Error::Node("unsupported local quote schema".into())),
    }
}

fn inspect_local_mock_quote(
    request: &LocalAdmissionRequest,
    value: Value,
    now_unix_ms: i64,
) -> Result<LocalQuoteIdentity, Error> {
    if request.attester_mode == "sev-snp" {
        return Err(Error::Node(
            "SEV-SNP local mode requires a raw SNP report".into(),
        ));
    }
    let quote: LocalMockQuote = serde_json::from_value(value)
        .map_err(|error| Error::Node(format!("invalid local mock quote: {error}")))?;
    if quote.schema != "stogas.local-mock-quote.v1"
        || quote.attester_mode != request.attester_mode
        || quote.report_data_sha512 != request.heartbeat.report_data_sha512
        || quote.quote_generated_at != request.heartbeat.quote_generated_at
        || parse_time(&quote.quote_generated_at)? > now_unix_ms + MAX_CLOCK_SKEW_MS
    {
        return Err(Error::Node("local mock quote binding differs".into()));
    }
    if request.trusted_chip_ids.len() != 1 || request.release_manifests.len() != 1 {
        return Err(Error::Node(
            "local mock admission requires exactly one chip and release".into(),
        ));
    }
    Ok(LocalQuoteIdentity {
        chip_id: request.trusted_chip_ids[0].to_lowercase(),
        raw_report: None,
        release_measurement: request.release_manifests[0]
            .sev_snp
            .launch_measurement
            .to_lowercase(),
        reported_tcb: "0000000000000000".into(),
    })
}

fn inspect_local_structured_quote(
    request: &LocalAdmissionRequest,
    value: Value,
    now_unix_ms: i64,
) -> Result<LocalQuoteIdentity, Error> {
    let quote: LocalStructuredQuote = serde_json::from_value(value)
        .map_err(|error| Error::Node(format!("invalid structured local quote: {error}")))?;
    if quote.schema != "stogas.structured-snp-quote.v1"
        || quote.attester_mode != request.attester_mode
        || quote.report_data_sha512 != request.heartbeat.report_data_sha512
        || quote.quote_generated_at != request.heartbeat.quote_generated_at
    {
        return Err(Error::Node("structured local quote binding differs".into()));
    }
    if quote.tcb_status != "up_to_date" {
        return Err(Error::Node("local AMD TCB status is below policy".into()));
    }
    if parse_time(&quote.collateral_expires_at)? <= now_unix_ms {
        return Err(Error::Node("local AMD collateral expired".into()));
    }
    if parse_time(&quote.quote_generated_at)? > now_unix_ms + MAX_CLOCK_SKEW_MS {
        return Err(Error::Node(
            "local quote evidence timestamp is in the future".into(),
        ));
    }
    Ok(LocalQuoteIdentity {
        chip_id: quote.chip_id.to_lowercase(),
        raw_report: None,
        release_measurement: quote.release_measurement.to_lowercase(),
        reported_tcb: quote.reported_tcb.to_lowercase(),
    })
}

fn inspect_local_raw_quote(request: &LocalAdmissionRequest) -> Result<LocalQuoteIdentity, Error> {
    if request.attester_mode != "sev-snp" {
        return Err(Error::Node(
            "raw SNP report requires the local SEV-SNP attester mode".into(),
        ));
    }
    let report = decode_snp_report(&request.heartbeat.quote, &request.heartbeat.node_id)?;
    Ok(LocalQuoteIdentity {
        chip_id: hex::encode(&report[0x1a0..0x1e0]),
        raw_report: Some(report.clone()),
        release_measurement: hex::encode(&report[0x90..0xc0]),
        reported_tcb: hex::encode(&report[0x180..0x188]),
    })
}

#[cfg(feature = "snp")]
fn verify_local_raw_snp_report(
    node: &Node,
    release_manifest: &GatewayReleaseManifest,
    report: &[u8],
    public_key: Option<&str>,
) -> Result<(), Error> {
    let launch =
        compatible_launch_policy(&release_manifest.sev_snp.launch_policies, &node.chip_id)?;
    let report_version = u32::from_le_bytes(report[0x00..0x04].try_into().unwrap_or_default());
    let product = inspect_report_product(report, report_version)?
        .3
        .ok_or_else(|| Error::Node("local SNP report has no processor generation".into()))?;
    let evidence = AttestedNode {
        chip_id: &node.chip_id,
        node_id: &node.node_id,
        quote: &node.quote,
        release_measurement: &node.release_measurement,
        report_data: &node.report_data,
        report_data_sha512: &node.report_data_sha512,
        reported_tcb: &node.reported_tcb,
    };
    check_raw_report_bindings(&evidence, release_manifest, launch, report, None)?;
    let expected_policy = u64::from_str_radix(launch.policy.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Node("invalid launch policy value".into()))?;
    validate_snp_launch_policy(expected_policy, Some(product))?;
    verify_local_raw_report_signature(report, public_key)
}

#[cfg(not(feature = "snp"))]
fn verify_local_raw_snp_report(
    _node: &Node,
    _release_manifest: &GatewayReleaseManifest,
    report: &[u8],
    public_key: Option<&str>,
) -> Result<(), Error> {
    verify_local_raw_report_signature(report, public_key)
}

#[cfg(feature = "snp")]
fn verify_local_raw_report_signature(report: &[u8], public_key: Option<&str>) -> Result<(), Error> {
    let public_key = public_key
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::Node("local AMD report signing key is not configured".into()))?;
    let der = decode_public_key_material(public_key)?;
    verify_raw_snp_report_signature(report, &der, "local")
}

#[cfg(feature = "snp")]
fn verify_raw_snp_report_signature_with_vcek(
    report: &[u8],
    vcek_der: &[u8],
    node_id: &str,
) -> Result<(), Error> {
    use x509_parser::parse_x509_certificate;

    let (remaining, vcek) = parse_x509_certificate(vcek_der)
        .map_err(|error| Error::Node(format!("{node_id} AMD VCEK: {error}")))?;
    if !remaining.is_empty() {
        return Err(Error::Node(format!(
            "{node_id} AMD VCEK contains trailing data"
        )));
    }
    verify_raw_snp_report_signature(report, vcek.public_key().raw, node_id)
}

#[cfg(feature = "snp")]
fn verify_raw_snp_report_signature(
    report: &[u8],
    public_key_der: &[u8],
    label: &str,
) -> Result<(), Error> {
    use p384::{
        ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _},
        pkcs8::DecodePublicKey as _,
    };
    use sha2::Sha384;

    if report.len() != 0x4a0 {
        return Err(Error::Node(format!(
            "{label} SNP report has the wrong size"
        )));
    }
    let key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|error| Error::Node(format!("{label} AMD report signing key: {error}")))?;
    let signature = &report[0x2a0..0x4a0];
    if signature[48..72].iter().any(|byte| *byte != 0)
        || signature[120..144].iter().any(|byte| *byte != 0)
        || signature[144..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Node(format!(
            "{label} SNP signature reserved bytes are nonzero"
        )));
    }
    let mut r = [0_u8; 48];
    let mut s = [0_u8; 48];
    for index in 0..48 {
        r[index] = signature[47 - index];
        s[index] = signature[72 + 47 - index];
    }
    let signature = Signature::from_scalars(r, s)
        .map_err(|error| Error::Node(format!("{label} SNP signature encoding: {error}")))?;
    let digest = Sha384::digest(&report[..0x2a0]);
    key.verify_prehash(&digest, &signature)
        .map_err(|error| Error::Node(format!("{label} SNP signature: {error}")))
}

#[cfg(not(feature = "snp"))]
fn verify_local_raw_report_signature(
    _report: &[u8],
    _public_key: Option<&str>,
) -> Result<(), Error> {
    Err(Error::Node(
        "local SNP signature verification is unavailable in this build".into(),
    ))
}

#[cfg(feature = "snp")]
fn decode_public_key_material(value: &str) -> Result<Vec<u8>, Error> {
    let trimmed = value.trim();
    let encoded = if trimmed.contains("-----BEGIN") {
        trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
    } else {
        trimmed
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect()
    };
    STANDARD
        .decode(&encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&encoded))
        .map_err(|_| Error::Node("local AMD report signing key encoding is invalid".into()))
}

struct SelectedHardwarePolicy {
    policy: HardwarePolicy,
    verified: VerifiedHardwarePolicy,
}

fn select_hardware_policy(
    signed: &SignedHardwarePolicy,
    local_policy_bytes: Option<&[u8]>,
    now_unix_ms: i64,
) -> Result<SelectedHardwarePolicy, Error> {
    let selected = verify_signed_hardware_policy(signed, now_unix_ms)?;
    let Some(local_policy_bytes) = local_policy_bytes else {
        return Ok(selected);
    };
    if local_policy_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(local_policy_bytes)
        .map_err(|error| Error::InvalidJson(format!("invalid local hardware policy: {error}")))?;
    let policy: HardwarePolicy = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid local hardware policy: {error}")))?;
    let canonical = validate_hardware_policy(&policy)?;
    let signed_assignments = selected
        .policy
        .policies
        .iter()
        .flat_map(|policy| policy.chip_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let local_assignments = policy
        .policies
        .iter()
        .flat_map(|policy| policy.chip_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if local_assignments != signed_assignments {
        return Err(Error::InvalidBundle(
            "local hardware policy must keep the signed chip IDs".into(),
        ));
    }
    Ok(SelectedHardwarePolicy {
        verified: verified_hardware_policy(
            &policy,
            &canonical,
            HardwarePolicySource::Local,
            None,
            None,
        ),
        policy,
    })
}

fn verify_signed_hardware_policy(
    signed: &SignedHardwarePolicy,
    now_unix_ms: i64,
) -> Result<SelectedHardwarePolicy, Error> {
    let key_id = signed
        .sigstore
        .pointer("/dsseEnvelope/signatures/0/keyid")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidBundle("hardware policy signing key id is absent".into()))?;
    let key = stogas_release_key(key_id)
        .ok_or_else(|| Error::InvalidBundle("hardware policy signing key is not trusted".into()))?;
    let canonical = validate_hardware_policy(&signed.policy)?;
    let public_key_spki = STANDARD.decode(key).map_err(|error| {
        Error::InvalidBundle(format!("hardware policy public key encoding: {error}"))
    })?;
    let integrated_time = verify_keyed_dsse(
        &signed.sigstore,
        canonical.as_bytes(),
        HARDWARE_POLICY_DSSE_PAYLOAD_TYPE,
        key_id,
        &public_key_spki,
        now_unix_ms,
    )
    .map_err(|error| Error::InvalidBundle(format!("hardware policy transparency: {error}")))?;
    let integrated_time_unix_ms = rekor_seconds_to_millis(integrated_time)?;
    Ok(SelectedHardwarePolicy {
        verified: verified_hardware_policy(
            &signed.policy,
            &canonical,
            HardwarePolicySource::StogasBundle,
            Some(key_id.to_owned()),
            Some(integrated_time_unix_ms),
        ),
        policy: signed.policy.clone(),
    })
}

fn rekor_seconds_to_millis(seconds: i64) -> Result<i64, Error> {
    seconds.checked_mul(1000).ok_or_else(|| {
        Error::InvalidBundle("hardware policy transparency time is out of range".into())
    })
}

fn verified_hardware_policy(
    policy: &HardwarePolicy,
    canonical: &str,
    source: HardwarePolicySource,
    stogas_signing_key_id: Option<String>,
    rekor_integrated_time_unix_ms: Option<i64>,
) -> VerifiedHardwarePolicy {
    let mut chip_ids = policy
        .policies
        .iter()
        .flat_map(|policy| policy.chip_ids.iter().cloned())
        .collect::<Vec<_>>();
    chip_ids.sort_unstable();
    VerifiedHardwarePolicy {
        chip_ids,
        policy_count: policy.policies.len(),
        rekor_integrated_time_unix_ms,
        sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
        source,
        stogas_signing_key_id,
    }
}

fn validate_hardware_policy(policy: &HardwarePolicy) -> Result<String, Error> {
    if policy.schema != "stogas.hardware-policies.v1"
        || policy.policies.is_empty()
        || policy.policies.len() > MAX_NODES
    {
        return Err(Error::InvalidBundle(
            "unsupported or invalid hardware policy".into(),
        ));
    }
    let mut chip_ids = BTreeSet::new();
    let mut previous_group_first: Option<&str> = None;
    for profile in &policy.policies {
        if profile.chip_ids.is_empty() || profile.chip_ids.len() > MAX_NODES {
            return Err(Error::InvalidBundle(
                "hardware policy group has no chip ids or is too large".into(),
            ));
        }
        let mut previous_chip: Option<&str> = None;
        for chip_id in &profile.chip_ids {
            if !is_lower_hex(chip_id, 64)
                || previous_chip.is_some_and(|previous| previous >= chip_id.as_str())
                || !chip_ids.insert(chip_id.as_str())
            {
                return Err(Error::InvalidBundle(
                    "hardware policy has an invalid, unsorted, or duplicate chip id".into(),
                ));
            }
            previous_chip = Some(chip_id);
        }
        let group_first = profile.chip_ids[0].as_str();
        if previous_group_first.is_some_and(|previous| previous >= group_first) {
            return Err(Error::InvalidBundle(
                "hardware policy groups are not canonically ordered".into(),
            ));
        }
        previous_group_first = Some(group_first);
        let built_in = amd_product_from_cpuid(profile.cpuid_family, profile.cpuid_model)
            .ok_or_else(|| {
                Error::InvalidBundle("hardware policy has an unsupported CPUID".into())
            })?;
        if built_in.tcb_layout != AmdTcbLayout::Family19h {
            return Err(Error::InvalidBundle(
                "hardware policy CPUID is not supported by this policy format".into(),
            ));
        }
        let required_platform = parse_u64_hex(
            &profile.required_platform_info_mask,
            "required platform-info mask",
        )?;
        let forbidden_platform = parse_u64_hex(
            &profile.forbidden_platform_info_mask,
            "forbidden platform-info mask",
        )?;
        if required_platform & forbidden_platform != 0
            || required_platform & !SNP_PLATFORM_INFO_KNOWN_MASK != 0
            || forbidden_platform & !SNP_PLATFORM_INFO_KNOWN_MASK != 0
        {
            return Err(Error::InvalidBundle(
                "hardware policy has invalid platform-info masks".into(),
            ));
        }
        parse_u64_hex(
            &profile.required_launch_mitigation_mask,
            "required launch mitigation mask",
        )?;
        parse_u64_hex(
            &profile.required_current_mitigation_mask,
            "required current mitigation mask",
        )?;
    }
    let value = serde_json::to_value(policy)
        .map_err(|error| Error::InvalidBundle(format!("hardware policy: {error}")))?;
    canonical_json(&value)
}

fn compatible_hardware<'a>(
    policy: &'a HardwarePolicy,
    chip_id: &str,
) -> Result<&'a AmdSevSnpPolicy, Error> {
    policy
        .policies
        .iter()
        .find(|policy| {
            policy
                .chip_ids
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(chip_id))
        })
        .ok_or_else(|| Error::Node("chip id is absent from the signed hardware policy".into()))
}

fn parse_u64_hex(value: &str, label: &str) -> Result<u64, Error> {
    let hex = value
        .strip_prefix("0x")
        .filter(|hex| is_lower_hex(hex, 8))
        .ok_or_else(|| Error::InvalidBundle(format!("hardware policy {label} is invalid")))?;
    u64::from_str_radix(hex, 16)
        .map_err(|_| Error::InvalidBundle(format!("hardware policy {label} is invalid")))
}

fn parse_and_verify_bundle_envelope(bundle_bytes: &[u8]) -> Result<BundleEnvelope, Error> {
    if bundle_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(bundle_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let body = serde_json::to_vec(
        value
            .get("body")
            .ok_or_else(|| Error::InvalidBundle("bundle body is absent".into()))?,
    )
    .map_err(|error| Error::InvalidBundle(error.to_string()))?;
    let envelope: BundleEnvelope =
        serde_json::from_value(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    validate_shape(&envelope)?;
    verify_envelope(&envelope, &body)?;
    Ok(envelope)
}

fn verify_bundle_approvals(
    body: &BundleBody,
    now_unix_ms: i64,
    verified_catalogs: &BTreeMap<ApprovalCacheKey, VerifiedCatalogRelease>,
    verified_releases: &BTreeMap<ApprovalCacheKey, VerifiedRelease>,
) -> Result<
    (
        Vec<VerifiedCatalogRelease>,
        Vec<VerifiedRelease>,
        VerificationCache,
    ),
    Error,
> {
    let mut catalog_cache = BTreeMap::new();
    let catalogs = body
        .catalogs
        .iter()
        .map(|catalog| {
            let key = approval_cache_key(catalog)?;
            let verified = verified_catalogs.get(&key).map_or_else(
                || verify_catalog(catalog, now_unix_ms),
                |catalog| Ok(catalog.clone()),
            )?;
            catalog_cache.insert(key, verified.clone());
            Ok(verified)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut release_cache = BTreeMap::new();
    let releases = body
        .allowed_igvms
        .iter()
        .map(|release| {
            let key = approval_cache_key(release)?;
            let verified = verified_releases.get(&key).map_or_else(
                || verify_release(release, now_unix_ms),
                |release| Ok(release.clone()),
            )?;
            release_cache.insert(key, verified.clone());
            Ok(verified)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((
        catalogs,
        releases,
        VerificationCache {
            catalogs: catalog_cache,
            releases: release_cache,
        },
    ))
}

fn verify_bundle_inner(
    bundle_bytes: &[u8],
    local_policy_bytes: Option<&[u8]>,
    now_unix_ms: i64,
    verified_catalogs: &BTreeMap<ApprovalCacheKey, VerifiedCatalogRelease>,
    verified_releases: &BTreeMap<ApprovalCacheKey, VerifiedRelease>,
) -> Result<(VerificationOutput, VerificationCache), Error> {
    let envelope = parse_and_verify_bundle_envelope(bundle_bytes)?;

    let hardware_policy = select_hardware_policy(
        &envelope.body.hardware_policy,
        local_policy_bytes,
        now_unix_ms,
    )?;
    let hardware_policy_map: BTreeMap<_, _> = hardware_policy
        .policy
        .policies
        .iter()
        .flat_map(|policy| {
            policy
                .chip_ids
                .iter()
                .map(move |chip_id| (chip_id.as_str(), policy))
        })
        .collect();

    let created_at = parse_time(&envelope.body.created_at)?;
    let expires_at = parse_time(&envelope.body.expires_at)?;
    validate_time(created_at, expires_at, now_unix_ms)?;

    let (catalogs, releases, next_cache) = verify_bundle_approvals(
        &envelope.body,
        now_unix_ms,
        verified_catalogs,
        verified_releases,
    )?;
    let release_manifests: BTreeMap<_, _> = envelope
        .body
        .allowed_igvms
        .iter()
        .map(|release| {
            (
                release.release_manifest.sev_snp.launch_measurement.as_str(),
                &release.release_manifest,
            )
        })
        .collect();
    let bundle_nodes = envelope
        .body
        .nodes
        .iter()
        .map(inspect_bundle_node)
        .collect::<Result<Vec<_>, Error>>()?;
    let amd_node_identities = bundle_nodes
        .iter()
        .map(|node| AmdNodeIdentity {
            chip_id: node.identity.chip_id.clone(),
            node_id: node.node.node_id.clone(),
            reported_tcb: node.identity.reported_tcb.clone(),
        })
        .collect::<Vec<_>>();
    let bundle_collateral = expand_bundle_vendor_collateral(&envelope.body.vendor_collateral)?;
    let amd_stacks = verified_amd_stacks(
        &bundle_collateral,
        &amd_node_identities,
        created_at,
        expires_at,
    )?;
    let verification_time = NodeVerificationTime {
        bundle_created_at: created_at,
        bundle_expires_at: expires_at,
        now_unix_ms,
    };
    let (nodes, excluded_nodes) = verify_and_partition_nodes(
        &bundle_nodes,
        verification_time,
        &release_manifests,
        &amd_stacks,
        &hardware_policy_map,
    )?;
    Ok((
        VerificationOutput {
            bundle: VerifiedBundle {
                catalogs,
                sequence: envelope.body.sequence,
                created_at_unix_ms: created_at,
                expires_at_unix_ms: expires_at,
                excluded_nodes,
                hardware_policy: hardware_policy.verified,
                releases,
                nodes,
                original: envelope.clone(),
            },
        },
        next_cache,
    ))
}

fn verify_and_partition_nodes(
    bundle_nodes: &[BundleNodeEvidence<'_>],
    verification_time: NodeVerificationTime,
    release_manifests: &BTreeMap<&str, &GatewayReleaseManifest>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    hardware_policies: &BTreeMap<&str, &AmdSevSnpPolicy>,
) -> Result<(Vec<VerifiedNode>, Vec<ExcludedNode>), Error> {
    let mut nodes = Vec::new();
    let mut excluded = Vec::new();
    for node in bundle_nodes {
        let hardware_policy = hardware_policies
            .get(node.identity.chip_id.as_str())
            .ok_or_else(|| {
                Error::Node(format!(
                    "{} chip id is absent from the verified hardware policy",
                    node.node.node_id
                ))
            })?;
        let verified = verify_bundle_node(
            node,
            verification_time,
            release_manifests,
            amd_stacks,
            hardware_policy,
        )?;
        if verified
            .drand_round_time_unix_ms
            .saturating_add(MAX_NODE_EVIDENCE_AGE_MS)
            < verification_time.bundle_created_at
        {
            excluded.push(ExcludedNode {
                drand_round: verified.drand_round,
                drand_round_time_unix_ms: verified.drand_round_time_unix_ms,
                evidence_age_ms: verified.evidence_age_ms,
                node_id: verified.node_id,
                reason: "attested node evidence was not fresh when the bundle was created".into(),
            });
        } else {
            nodes.push(verified);
        }
    }
    Ok((nodes, excluded))
}

fn approval_cache_key(approval: &impl serde::Serialize) -> Result<ApprovalCacheKey, Error> {
    let encoded =
        serde_json::to_vec(approval).map_err(|error| Error::Release(error.to_string()))?;
    Ok(Sha256::digest(encoded).into())
}

fn validate_shape(envelope: &BundleEnvelope) -> Result<(), Error> {
    if envelope.body.schema != "stogas.confidential-bundle.v1" {
        return Err(Error::InvalidBundle("unsupported schema".into()));
    }
    if envelope.body.allowed_igvms.len() > 2 {
        return Err(Error::InvalidBundle("invalid release count".into()));
    }
    if envelope.body.catalogs.len() > 2 {
        return Err(Error::InvalidBundle("invalid catalog release count".into()));
    }
    if envelope.body.nodes.len() > MAX_NODES
        || envelope.body.vendor_collateral.len() > MAX_VENDOR_COLLATERAL
    {
        return Err(Error::InvalidBundle("resource limit exceeded".into()));
    }
    let mut measurements = BTreeSet::new();
    for release in &envelope.body.allowed_igvms {
        validate_release_shape(release)?;
        if !measurements.insert(release.release_manifest.sev_snp.launch_measurement.clone()) {
            return Err(Error::InvalidBundle("duplicate release measurement".into()));
        }
    }
    let mut catalog_sequences = BTreeSet::new();
    for catalog in &envelope.body.catalogs {
        validate_catalog_shape(catalog)?;
        let manifest = &catalog.signed_release.manifest;
        if !catalog_sequences.insert(manifest.sequence) {
            return Err(Error::InvalidBundle("duplicate catalog sequence".into()));
        }
    }
    let hardware_chip_ids = envelope
        .body
        .hardware_policy
        .policy
        .policies
        .iter()
        .flat_map(|policy| policy.chip_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut node_ids = BTreeSet::new();
    let mut response_signing_keys = BTreeSet::new();
    let mut referenced_measurements = BTreeSet::new();
    let mut referenced_chip_ids = BTreeSet::new();
    for node in &envelope.body.nodes {
        let evidence = inspect_bundle_node(node)?;
        if !node_ids.insert(node.node_id.as_str()) {
            return Err(Error::InvalidBundle("duplicate node id".into()));
        }
        if !response_signing_keys.insert(node.report_data.ed25519_public_key.as_str()) {
            return Err(Error::InvalidBundle(
                "duplicate Ed25519 response signing key".into(),
            ));
        }
        referenced_measurements.insert(evidence.identity.release_measurement.clone());
        let release = envelope
            .body
            .allowed_igvms
            .iter()
            .find(|release| {
                release.release_manifest.sev_snp.launch_measurement
                    == evidence.identity.release_measurement
            })
            .ok_or_else(|| Error::InvalidBundle("node release evidence is absent".into()))?;
        compatible_launch_policy(
            &release.release_manifest.sev_snp.launch_policies,
            &evidence.identity.chip_id,
        )?;
        referenced_chip_ids.insert(evidence.identity.chip_id.clone());
    }
    if measurements != referenced_measurements || !referenced_chip_ids.is_subset(&hardware_chip_ids)
    {
        return Err(Error::InvalidBundle(
            "bundle release evidence must match its nodes and hardware evidence must cover them"
                .into(),
        ));
    }
    Ok(())
}

fn validate_catalog_shape(catalog: &AllowedCatalog) -> Result<(), Error> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    let release = &catalog.signed_release;
    let manifest = &release.manifest;
    if catalog.github_in_toto.len() != 1
        || release.schema != "stogas.catalog.signed.v1"
        || manifest.schema != "stogas.catalog.release.v1"
        || manifest.catalog_schema != 1
        || manifest.minimum_gateway_sequence == 0
        || manifest.minimum_gateway_sequence > MAX_SAFE_INTEGER
        || manifest.sequence == 0
        || manifest.sequence > MAX_SAFE_INTEGER
        || manifest.source.repository != "https://github.com/StogasAI/catalog"
        || manifest.source.tag != format!("catalog-v{}", manifest.sequence)
        || !is_lower_hex(&manifest.source.commit, 20)
        || !is_lower_hex(&manifest.source.tree, 20)
        || !is_sha256_identity(&manifest.runtime)
        || !is_sha256_identity(&manifest.public)
        || release.key_id.is_empty()
        || release.key_id.len() > 200
    {
        return Err(Error::InvalidBundle("invalid catalog release shape".into()));
    }
    Ok(())
}

fn is_sha256_identity(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 32))
}

fn validate_gateway_release_manifest(manifest: &GatewayReleaseManifest) -> Result<(), Error> {
    if !gateway_release_manifest_shape_is_valid(manifest) {
        return Err(Error::InvalidBundle(
            "invalid gateway release manifest shape".into(),
        ));
    }
    validate_gateway_release_build(&manifest.build)?;
    validate_gateway_launch_policies(&manifest.sev_snp.launch_policies)?;
    let launch_policies = canonical_json(
        &serde_json::to_value(&manifest.sev_snp.launch_policies).map_err(|error| {
            Error::InvalidBundle(format!("launch policy serialization: {error}"))
        })?,
    )?;
    let launch_policies_sha256 = hex::encode(Sha256::digest(launch_policies.as_bytes()));
    if launch_policies_sha256 != manifest.artifacts.snp_launch_policies.sha256
        || manifest
            .build
            .input_sha256
            .get("stogas/release/snp-launch-policies.json")
            != Some(&launch_policies_sha256)
    {
        return Err(Error::InvalidBundle(
            "gateway launch policy artifact does not match the release manifest".into(),
        ));
    }
    Ok(())
}

fn gateway_release_manifest_shape_is_valid(manifest: &GatewayReleaseManifest) -> bool {
    let sev_snp = &manifest.sev_snp;
    let build = &manifest.build;
    manifest.schema == "stogas.gateway.release.v1"
        && manifest.git.repository == "https://github.com/StogasAI/gateway"
        && gateway_release_sequence(&manifest.git.tag) == Some(manifest.sequence)
        && manifest.git.git_ref == format!("refs/tags/{}", manifest.git.tag)
        && manifest.git.tag.len() <= 100
        && is_lower_hex(&manifest.git.commit, 20)
        && is_lower_hex(&manifest.git.tree, 20)
        && is_lower_hex(&manifest.artifacts.gateway_igvm.sha256, 32)
        && manifest.artifacts.gateway_igvm.size_bytes > 0
        && manifest.artifacts.gateway_igvm.size_bytes <= 128 * 1024 * 1024
        && is_lower_hex(&manifest.artifacts.snp_launch_policies.sha256, 32)
        && manifest.artifacts.snp_launch_policies.size_bytes > 0
        && manifest.artifacts.snp_launch_policies.size_bytes <= 16 * 1024 * 1024
        && sev_snp.check_kvm
        && sev_snp.platform == "SEV_SNP"
        && sev_snp.vmm == "qemu-kvm"
        && sev_snp.measurement_command == "igvmmeasure --check-kvm gateway.igvm measure"
        && sev_snp.measurement_tool == "igvmmeasure"
        && !sev_snp.measurement_tool_version.is_empty()
        && sev_snp.measurement_tool_version.len() <= 100
        && is_lower_hex(&sev_snp.measurement_tool_sha256, 32)
        && is_lower_hex(&sev_snp.launch_measurement, 48)
        && sev_snp.vcpu_count > 0
        && sev_snp.vcpu_count <= 1024
        && build.environment.lc_all == "C"
        && build.environment.source_date_epoch == "1"
        && build.environment.tz == "UTC"
        && build.environment.umask == "022"
        && build.guest_ca_bundle_path == "/etc/ssl/certs/ca-certificates.crt"
        && is_lower_hex(&build.guix_channel_commit, 20)
        && !build.input_sha256.is_empty()
        && build.input_sha256.len() <= 256
        && !build.go_version.is_empty()
        && build.go_version.len() <= 200
        && !build.kernel_version.is_empty()
        && build.kernel_version.len() <= 100
}

fn validate_gateway_release_build(build: &GatewayReleaseBuild) -> Result<(), Error> {
    for digest in [
        &build.cmdline_sha256,
        &build.core_go_mod_sha256,
        &build.core_go_sum_sha256,
        &build.go_mod_sha256,
        &build.go_sum_sha256,
        &build.go_vendor_tree_sha256,
        &build.guest_ca_bundle_sha256,
        &build.kernel_config_sha256,
        &build.linux_bz_image_sha256,
        &build.os_release_sha256,
        &build.ovmf_sha256,
        &build.pins_lock_sha256,
        &build.systemd_stub_sha256,
        &build.uki_sha256,
    ] {
        if !is_lower_hex(digest, 32) {
            return Err(Error::InvalidBundle(
                "gateway release build digest is invalid".into(),
            ));
        }
    }
    if build
        .input_sha256
        .iter()
        .any(|(name, digest)| name.is_empty() || name.len() > 256 || !is_lower_hex(digest, 32))
    {
        return Err(Error::InvalidBundle(
            "gateway release build input is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_gateway_launch_policies(policies: &LaunchPolicies) -> Result<(), Error> {
    if policies.schema != "stogas.snp-launch-policies.v1"
        || policies.policies.is_empty()
        || policies.policies.len() > MAX_NODES
    {
        return Err(Error::InvalidBundle(
            "invalid gateway launch policies".into(),
        ));
    }
    let mut chip_ids = BTreeSet::new();
    let mut previous_group_first: Option<&str> = None;
    for policy in &policies.policies {
        if policy.chip_ids.is_empty() || policy.chip_ids.len() > MAX_NODES {
            return Err(Error::InvalidBundle(
                "invalid gateway launch-policy group".into(),
            ));
        }
        let mut previous_chip: Option<&str> = None;
        for chip_id in &policy.chip_ids {
            if !is_lower_hex(chip_id, 64)
                || previous_chip.is_some_and(|previous| previous >= chip_id.as_str())
                || !chip_ids.insert(chip_id.as_str())
            {
                return Err(Error::InvalidBundle(
                    "gateway launch policies contain an invalid, unsorted, or duplicate chip id"
                        .into(),
                ));
            }
            previous_chip = Some(chip_id);
        }
        let first = policy.chip_ids[0].as_str();
        if previous_group_first.is_some_and(|previous| previous >= first) {
            return Err(Error::InvalidBundle(
                "gateway launch-policy groups are not canonically ordered".into(),
            ));
        }
        previous_group_first = Some(first);
        validate_gateway_launch_policy(&policy.launch)?;
    }
    Ok(())
}

fn validate_gateway_launch_policy(launch: &LaunchValues) -> Result<(), Error> {
    if !is_lower_hex(&launch.family_id, 16)
        || !is_lower_hex(&launch.image_id, 16)
        || !is_lower_hex(&launch.host_data, 32)
        || !is_lower_hex(&launch.id_key_digest, 48)
        || !is_lower_hex(&launch.author_key_digest, 48)
        || launch.vmpl != 0
        || !is_prefixed_lower_hex(&launch.policy, 8)
    {
        return Err(Error::InvalidBundle("invalid gateway launch policy".into()));
    }
    let launch_policy = u64::from_str_radix(&launch.policy[2..], 16)
        .map_err(|_| Error::InvalidBundle("invalid SNP launch policy".into()))?;
    validate_snp_launch_policy(launch_policy, None)
        .map_err(|error| Error::InvalidBundle(format!("invalid gateway launch policy: {error}")))
}

fn compatible_launch_policy<'a>(
    policies: &'a LaunchPolicies,
    chip_id: &str,
) -> Result<&'a LaunchValues, Error> {
    policies
        .policies
        .iter()
        .find(|policy| {
            policy
                .chip_ids
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(chip_id))
        })
        .map(|policy| &policy.launch)
        .ok_or_else(|| Error::Node("chip id is absent from the release launch policies".into()))
}

fn validate_release_shape(release: &AllowedIgvm) -> Result<(), Error> {
    validate_gateway_release_manifest(&release.release_manifest)?;
    if release.github_in_toto.len() != 1 {
        return Err(Error::InvalidBundle(
            "a release must contain exactly one GitHub attestation".into(),
        ));
    }
    Ok(())
}

fn gateway_release_sequence(release_tag: &str) -> Option<u64> {
    const COMPONENT_BASE: u64 = 1_000_000;
    const MAJOR_BASE: u64 = COMPONENT_BASE * COMPONENT_BASE;
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    let mut parts = release_tag.strip_prefix('v')?.split('.');
    let parse = |part: &str| {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        part.parse::<u64>().ok()
    };
    let major = parse(parts.next()?)?;
    let minor = parse(parts.next()?)?;
    let patch = parse(parts.next()?)?;
    if parts.next().is_some() || minor >= COMPONENT_BASE || patch >= COMPONENT_BASE {
        return None;
    }
    let sequence = major
        .checked_mul(MAJOR_BASE)?
        .checked_add(minor.checked_mul(COMPONENT_BASE)?)?
        .checked_add(patch)?;
    (sequence > 0 && sequence <= MAX_SAFE_INTEGER).then_some(sequence)
}

fn validate_node_shape(node: &Node) -> Result<(), Error> {
    let checks = [
        (is_lower_hex(&node.node_id, 32), "node id"),
        (is_lower_hex(&node.chip_id, 64), "chip id"),
        (is_lower_hex(&node.reported_tcb, 8), "reported TCB"),
        (
            is_lower_hex(&node.release_measurement, 48),
            "release measurement",
        ),
        (
            is_lower_hex(&node.report_data_sha512, 64),
            "report-data digest",
        ),
        (!node.region.is_empty() && node.region.len() <= 64, "region"),
    ];
    if let Some((_, label)) = checks.into_iter().find(|(valid, _)| !valid) {
        return Err(Error::InvalidBundle(format!(
            "{} has an invalid {label}",
            node.node_id
        )));
    }
    validate_report_data_shape(&node.node_id, &node.report_data)
}

fn validate_bundle_node_shape(node: &BundleNode) -> Result<(), Error> {
    if !is_lower_hex(&node.node_id, 32) {
        return Err(Error::InvalidBundle(
            "bundle node has an invalid node id".into(),
        ));
    }
    validate_report_data_shape(&node.node_id, &node.report_data)
}

fn validate_report_data_shape(node_id: &str, report: &ReportData) -> Result<(), Error> {
    let checks = [
        (report.schema == "stogas.node-report.v1", "report schema"),
        (is_lower_hex(&report.tls_spki_sha256, 32), "TLS SPKI hash"),
        (
            report
                .accepted_cert_sha256
                .iter()
                .all(|hash| is_lower_hex(hash, 32)),
            "accepted certificate hash",
        ),
        (
            is_xwing_public_key_b64url(&report.hpke_public_key),
            "HPKE public key",
        ),
        (
            decode_b64url_len(&report.ed25519_public_key) == Some(32),
            "Ed25519 public key",
        ),
    ];
    if let Some((_, label)) = checks.into_iter().find(|(valid, _)| !valid) {
        return Err(Error::InvalidBundle(format!(
            "{node_id} has an invalid {label}"
        )));
    }
    let certs: BTreeSet<_> = report.accepted_cert_sha256.iter().collect();
    if certs.len() > 2 || certs.len() != report.accepted_cert_sha256.len() {
        return Err(Error::InvalidBundle(format!(
            "{node_id} has an invalid certificate rotation stack"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_prefixed_lower_hex(value: &str, bytes: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| is_lower_hex(hex, bytes))
}

fn decode_b64url_len(value: &str) -> Option<usize> {
    URL_SAFE_NO_PAD.decode(value).ok().map(|bytes| bytes.len())
}

fn is_xwing_public_key_b64url(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 1_216 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn verify_envelope(envelope: &BundleEnvelope, signed_body: &[u8]) -> Result<(), Error> {
    let actual = hex::encode(Sha256::digest(signed_body));
    if actual != envelope.body_sha256 {
        return Err(Error::BundleChecksum("body SHA-256 differs".into()));
    }
    Ok(())
}

fn verify_catalog(
    catalog: &AllowedCatalog,
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    let signed = &catalog.signed_release;
    let key = stogas_release_key(&signed.key_id)
        .ok_or_else(|| Error::Release("catalog signing key is not trusted".into()))?;
    verify_catalog_with_key(catalog, key, now_unix_ms)
}

fn verify_catalog_with_key(
    catalog: &AllowedCatalog,
    key: &str,
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    validate_catalog_shape(catalog)?;
    let signed = &catalog.signed_release;
    let manifest = &signed.manifest;
    let manifest_value =
        serde_json::to_value(manifest).map_err(|error| Error::Release(error.to_string()))?;
    let canonical = canonical_json(&manifest_value)?;
    let signed_canonical = canonical
        .strip_suffix('\n')
        .ok_or_else(|| Error::Release("catalog canonical manifest is invalid".into()))?;
    let manifest_digest = hex::encode(Sha256::digest(signed_canonical.as_bytes()));
    let mut payload = b"stogas catalog release v1\n".to_vec();
    payload.extend_from_slice(signed_canonical.as_bytes());
    verify_ed25519(key, &payload, &signed.signature).map_err(Error::Release)?;

    let attestation = catalog
        .github_in_toto
        .first()
        .ok_or_else(|| Error::Release("catalog GitHub attestation is absent".into()))?;
    let attestation_bytes =
        serde_json::to_vec(attestation).map_err(|error| Error::Release(error.to_string()))?;
    let (github_integrated_time_unix_ms, provenance) =
        verify_catalog_provenance(&attestation_bytes, manifest, &manifest_digest, now_unix_ms)?;

    Ok(VerifiedCatalogRelease {
        evidence: catalog.clone(),
        github_integrated_time_unix_ms,
        minimum_gateway_sequence: manifest.minimum_gateway_sequence,
        provenance,
        public_digest: manifest.public.clone(),
        runtime_digest: manifest.runtime.clone(),
        sequence: manifest.sequence,
        source_commit: manifest.source.commit.clone(),
        source_repository: manifest.source.repository.clone(),
        source_tag: manifest.source.tag.clone(),
        source_tree: manifest.source.tree.clone(),
        stogas_signing_key_id: signed.key_id.clone(),
    })
}

fn verify_catalog_provenance(
    attestation_bytes: &[u8],
    manifest: &CatalogReleaseManifest,
    manifest_digest: &str,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    #[cfg(feature = "staging")]
    if is_staging_development_provenance(
        attestation_bytes,
        &[("catalog-release.json", manifest_digest)],
    )? {
        return Ok((None, ReleaseProvenance::Staging));
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/catalog/.github/workflows/catalog-release.yml@refs/tags/{}",
        manifest.source.tag
    );
    verify_github_provenance(
        attestation_bytes,
        &[Subject {
            name: "catalog-release.json",
            sha256: manifest_digest,
        }],
        &GithubPolicy {
            repository: manifest.source.repository.clone(),
            workflow_identity,
            source_ref: format!("refs/tags/{}", manifest.source.tag),
            source_commit: manifest.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
        "catalog provenance",
    )
}

fn verify_release(release: &AllowedIgvm, now_unix_ms: i64) -> Result<VerifiedRelease, Error> {
    let signature = &release.stogas_signature;
    let key = stogas_release_key(&signature.key_id)
        .ok_or_else(|| Error::Release("release signing key is not trusted".into()))?;
    verify_release_with_key(release, key, now_unix_ms)
}

fn verify_release_with_key(
    release: &AllowedIgvm,
    key: &str,
    now_unix_ms: i64,
) -> Result<VerifiedRelease, Error> {
    validate_release_shape(release)?;
    let manifest = &release.release_manifest;
    let signature = &release.stogas_signature;
    if manifest.schema != "stogas.gateway.release.v1"
        || signature.schema != "stogas.gateway.counterbuild-signature.v1"
        || signature.algorithm != "Ed25519"
        || signature.signed != "release-manifest.json"
    {
        return Err(Error::Release(
            "unsupported release manifest or counterbuild signature".into(),
        ));
    }
    let manifest_value =
        serde_json::to_value(manifest).map_err(|error| Error::Release(error.to_string()))?;
    let canonical = canonical_json(&manifest_value)?;
    let mut payload = b"stogas gateway counterbuild v1\n".to_vec();
    payload.extend_from_slice(canonical.as_bytes());
    verify_ed25519(key, &payload, &signature.signature).map_err(Error::Release)?;

    let attestation_value = release
        .github_in_toto
        .first()
        .ok_or_else(|| Error::Release("GitHub attestation is absent".into()))?;
    let attestation_bytes =
        serde_json::to_vec(attestation_value).map_err(|error| Error::Release(error.to_string()))?;
    let manifest_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    let (github_integrated_time_unix_ms, provenance) =
        verify_release_provenance(&attestation_bytes, manifest, &manifest_digest, now_unix_ms)?;

    Ok(VerifiedRelease {
        evidence: release.clone(),
        github_integrated_time_unix_ms,
        igvm_sha256: manifest.artifacts.gateway_igvm.sha256.clone(),
        launch_policies: manifest.sev_snp.launch_policies.clone(),
        measurement: manifest.sev_snp.launch_measurement.clone(),
        provenance,
        release_manifest_sha256: manifest_digest,
        release_tag: manifest.git.tag.clone(),
        sequence: manifest.sequence,
        source_commit: manifest.git.commit.clone(),
        source_repository: manifest.git.repository.clone(),
        source_tree: manifest.git.tree.clone(),
        stogas_signing_key_id: signature.key_id.clone(),
        vcpu_count: manifest.sev_snp.vcpu_count,
    })
}

fn verify_release_provenance(
    attestation_bytes: &[u8],
    manifest: &GatewayReleaseManifest,
    manifest_digest: &str,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    #[cfg(feature = "staging")]
    if is_staging_development_provenance(
        attestation_bytes,
        &[("release-manifest.json", manifest_digest)],
    )? {
        return Ok((None, ReleaseProvenance::Staging));
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/{}",
        manifest.git.tag
    );
    verify_github_provenance(
        attestation_bytes,
        &[Subject {
            name: "release-manifest.json",
            sha256: manifest_digest,
        }],
        &GithubPolicy {
            repository: manifest.git.repository.clone(),
            workflow_identity,
            source_ref: manifest.git.git_ref.clone(),
            source_commit: manifest.git.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
        "gateway provenance",
    )
}

fn verify_github_provenance(
    attestation_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
    now_unix_ms: i64,
    context: &str,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    let verified =
        verify_github_attestation(attestation_bytes, expected_subjects, policy, now_unix_ms)
            .map_err(|error| Error::Release(format!("{context}: {error}")))?;
    let integrated_time = verified
        .integrated_time
        .checked_mul(1000)
        .ok_or_else(|| Error::Release(format!("{context} GitHub integration time overflows")))?;
    Ok((Some(integrated_time), ReleaseProvenance::Github))
}

#[cfg(feature = "staging")]
fn is_staging_development_provenance(
    bytes: &[u8],
    expected_subjects: &[(&str, &str)],
) -> Result<bool, Error> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| Error::Release(format!("invalid provenance JSON: {error}")))?;
    if value.get("predicateType").and_then(Value::as_str) != Some(STAGING_PROVENANCE_TYPE) {
        return Ok(false);
    }
    let statement: StagingDevelopmentProvenance =
        serde_json::from_value(value).map_err(|error| {
            Error::Release(format!("invalid staging development provenance: {error}"))
        })?;
    if statement.statement_type != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != STAGING_PROVENANCE_TYPE
        || statement.predicate.environment != "staging"
        || statement.subject.len() != expected_subjects.len()
    {
        return Err(Error::Release(
            "invalid staging development provenance policy".into(),
        ));
    }
    let expected = expected_subjects
        .iter()
        .map(|(name, digest)| ((*name).to_owned(), (*digest).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for subject in statement.subject {
        if subject.digest.len() != 1 {
            return Err(Error::Release(
                "staging development provenance subject digest is invalid".into(),
            ));
        }
        let Some(digest) = subject.digest.get("sha256") else {
            return Err(Error::Release(
                "staging development provenance requires SHA-256 subjects".into(),
            ));
        };
        if actual.insert(subject.name, digest.clone()).is_some() {
            return Err(Error::Release(
                "staging development provenance has duplicate subjects".into(),
            ));
        }
    }
    if actual != expected {
        return Err(Error::Release(
            "staging development provenance subjects differ".into(),
        ));
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct NodeVerificationTime {
    bundle_created_at: i64,
    bundle_expires_at: i64,
    now_unix_ms: i64,
}

impl NodeVerificationTime {
    const fn at(now_unix_ms: i64) -> Self {
        Self {
            bundle_created_at: now_unix_ms,
            bundle_expires_at: now_unix_ms,
            now_unix_ms,
        }
    }
}

struct AttestedNode<'a> {
    chip_id: &'a str,
    node_id: &'a str,
    quote: &'a str,
    release_measurement: &'a str,
    report_data: &'a ReportData,
    report_data_sha512: &'a str,
    reported_tcb: &'a str,
}

struct BundleNodeEvidence<'a> {
    identity: InspectedSnpQuote,
    node: &'a BundleNode,
    report_data_sha512: String,
}

fn inspect_bundle_node(node: &BundleNode) -> Result<BundleNodeEvidence<'_>, Error> {
    validate_bundle_node_shape(node)?;
    let identity = inspect_snp_quote(&node.quote)?;
    let canonical_report = canonical_report_data(&node.report_data)?;
    let report_data_sha512 = hex::encode(Sha512::digest(canonical_report.as_bytes()));
    verify_node_id(
        &node.node_id,
        &identity.chip_id,
        &node.report_data.tls_spki_sha256,
    )?;
    Ok(BundleNodeEvidence {
        identity,
        node,
        report_data_sha512,
    })
}

fn verify_node_id(node_id: &str, chip_id: &str, tls_spki_sha256: &str) -> Result<(), Error> {
    if derive_node_id(chip_id, tls_spki_sha256) != node_id {
        return Err(Error::Node(
            "node ID differs from its attested chip and TLS key".into(),
        ));
    }
    Ok(())
}

fn normalize_admission_node_id(
    supplied_node_id: &str,
    chip_id: &str,
    report_data: &ReportData,
) -> Result<String, Error> {
    let node_id = derive_node_id(chip_id, &report_data.tls_spki_sha256);
    let candidate_preimage = format!(
        "{{\"ed25519_public_key\":\"{}\",\"hpke_public_key\":\"{}\",\"tls_spki_sha256\":\"{}\"}}",
        report_data.ed25519_public_key, report_data.hpke_public_key, report_data.tls_spki_sha256
    );
    let candidate_node_id = hex::encode(Sha256::digest(candidate_preimage.as_bytes()));
    if supplied_node_id != node_id && supplied_node_id != candidate_node_id {
        return Err(Error::Node(
            "node ID differs from its attested generation identity".into(),
        ));
    }
    Ok(node_id)
}

fn derive_node_id(chip_id: &str, tls_spki_sha256: &str) -> String {
    let preimage =
        format!("{{\"chip_id\":\"{chip_id}\",\"tls_spki_sha256\":\"{tls_spki_sha256}\"}}");
    hex::encode(Sha256::digest(preimage.as_bytes()))
}

fn verify_bundle_node(
    node: &BundleNodeEvidence<'_>,
    verification_time: NodeVerificationTime,
    release_manifests: &BTreeMap<&str, &GatewayReleaseManifest>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    hardware_policy: &AmdSevSnpPolicy,
) -> Result<VerifiedNode, Error> {
    let evidence = AttestedNode {
        chip_id: &node.identity.chip_id,
        node_id: &node.node.node_id,
        quote: &node.node.quote,
        release_measurement: &node.identity.release_measurement,
        report_data: &node.node.report_data,
        report_data_sha512: &node.report_data_sha512,
        reported_tcb: &node.identity.reported_tcb,
    };
    verify_attested_node(
        &evidence,
        verification_time.bundle_created_at,
        verification_time,
        release_manifests,
        amd_stacks,
        hardware_policy,
    )
}

fn verify_node(
    node: &Node,
    verification_time: NodeVerificationTime,
    release_manifests: &BTreeMap<&str, &GatewayReleaseManifest>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    hardware_policy: &AmdSevSnpPolicy,
) -> Result<VerifiedNode, Error> {
    if parse_time(&node.cert_expires_at)? < verification_time.bundle_expires_at {
        return Err(Error::Node(format!(
            "bundle outlives {} certificate",
            node.node_id
        )));
    }
    let quote_verified_at = parse_time(&node.quote_verified_at)?;
    let evidence = AttestedNode {
        chip_id: &node.chip_id,
        node_id: &node.node_id,
        quote: &node.quote,
        release_measurement: &node.release_measurement,
        report_data: &node.report_data,
        report_data_sha512: &node.report_data_sha512,
        reported_tcb: &node.reported_tcb,
    };
    verify_node_id(
        &node.node_id,
        &node.chip_id,
        &node.report_data.tls_spki_sha256,
    )?;
    verify_attested_node(
        &evidence,
        quote_verified_at,
        verification_time,
        release_manifests,
        amd_stacks,
        hardware_policy,
    )
}

fn verify_attested_node(
    node: &AttestedNode<'_>,
    quote_verified_at: i64,
    verification_time: NodeVerificationTime,
    release_manifests: &BTreeMap<&str, &GatewayReleaseManifest>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    hardware_policy: &AmdSevSnpPolicy,
) -> Result<VerifiedNode, Error> {
    let release_manifest = release_manifests
        .get(node.release_measurement)
        .ok_or_else(|| {
            Error::Node(format!(
                "{} release measurement {} is absent from the verified release stack",
                node.node_id, node.release_measurement
            ))
        })?;
    let canonical_report = canonical_report_data(node.report_data)?;
    if hex::encode(Sha512::digest(canonical_report.as_bytes())) != node.report_data_sha512 {
        return Err(Error::Node(format!(
            "{} report-data hash differs",
            node.node_id
        )));
    }
    if node.report_data.drand.network != "quicknet"
        || node.report_data.drand.chain_hash != DRAND_CHAIN_HASH
    {
        return Err(Error::Node(format!(
            "{} uses the wrong drand chain",
            node.node_id
        )));
    }
    if quote_verified_at > verification_time.bundle_created_at {
        return Err(Error::Node(format!(
            "{} quote verification time is later than bundle creation",
            node.node_id
        )));
    }
    let drand_round_time_unix_ms = validate_node_evidence_time(
        node.node_id,
        node.report_data.drand.round,
        quote_verified_at,
        verification_time.now_unix_ms,
    )?;
    verify_quicknet(&node.report_data.drand)?;
    let amd_stack = amd_stacks
        .get(&amd_platform_key(node.chip_id, node.reported_tcb))
        .ok_or_else(|| Error::Node(format!("{} has no matching AMD evidence", node.node_id)))?;
    let launch = compatible_launch_policy(&release_manifest.sev_snp.launch_policies, node.chip_id)?;
    verify_snp_node(
        node,
        release_manifest,
        launch,
        verification_time.bundle_created_at,
        verification_time.bundle_expires_at,
        amd_stack,
        hardware_policy,
    )?;
    Ok(VerifiedNode {
        chip_id: node.chip_id.to_owned(),
        drand_round: node.report_data.drand.round,
        drand_round_time_unix_ms,
        evidence_age_ms: verification_time
            .bundle_created_at
            .saturating_sub(drand_round_time_unix_ms)
            .max(0),
        node_id: node.node_id.to_owned(),
        quote: node.quote.to_owned(),
        quote_verified_at_unix_ms: quote_verified_at,
        report_data: node.report_data.clone(),
        report_data_sha512: node.report_data_sha512.to_owned(),
        release_measurement: node.release_measurement.to_owned(),
        reported_tcb: node.reported_tcb.to_owned(),
    })
}

#[derive(Clone, Debug)]
struct AmdCollateralEntry {
    ca_product_name: String,
    collateral_type: String,
    der: Vec<u8>,
    sha256: String,
    chip_id: Option<String>,
    reported_tcb: Option<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    not(feature = "snp"),
    allow(
        dead_code,
        reason = "parsed AMD collateral is consumed only by the optional SNP verifier"
    )
)]
struct AmdCollateralStack {
    ark: Vec<u8>,
    ask: Vec<u8>,
    crl: Vec<u8>,
    vek: Vec<u8>,
}

struct AmdNodeIdentity {
    chip_id: String,
    node_id: String,
    reported_tcb: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AmdKdsPayload {
    ca_product_name: String,
    #[serde(default)]
    chip_id: Option<String>,
    collateral_type: String,
    der_base64url: String,
    fetched_at: String,
    #[serde(default)]
    hwid: Option<String>,
    product_name: String,
    #[serde(default)]
    reported_tcb: Option<String>,
    schema: String,
    sha256: String,
    source: String,
    source_url: String,
    #[serde(default)]
    tcb: Option<Value>,
}

fn expand_bundle_vendor_collateral(
    rows: &[BTreeMap<String, Value>],
) -> Result<Vec<VendorCollateral>, Error> {
    rows.iter()
        .map(|payload| {
            let parsed: AmdKdsPayload =
                serde_json::from_value(Value::Object(payload.clone().into_iter().collect()))
                    .map_err(|error| {
                        Error::InvalidBundle(format!("invalid AMD collateral: {error}"))
                    })?;
            Ok(VendorCollateral {
                chip_id: parsed.chip_id,
                collateral_type: parsed.collateral_type,
                fetched_at: parsed.fetched_at,
                payload: payload.clone(),
                sha256: parsed.sha256,
                source_url: parsed.source_url,
            })
        })
        .collect()
}

type AmdCommonCollateral = BTreeMap<(String, String), AmdCollateralEntry>;
type AmdVcekCollateral = BTreeMap<String, AmdCollateralEntry>;

fn verified_amd_stacks(
    rows: &[VendorCollateral],
    nodes: &[AmdNodeIdentity],
    bundle_created_at: i64,
    bundle_expires_at: i64,
) -> Result<BTreeMap<String, AmdCollateralStack>, Error> {
    let (common, vceks) = parse_amd_collateral(rows, bundle_created_at, bundle_expires_at)?;
    let mut used_hashes = BTreeSet::new();
    let mut stacks = BTreeMap::new();
    for node in nodes {
        let platform_key = amd_platform_key(&node.chip_id, &node.reported_tcb);
        let vek = vceks.get(&platform_key).ok_or_else(|| {
            Error::Node(format!("{} has no exact AMD VCEK evidence", node.node_id))
        })?;
        let get_common = |kind: &str| {
            common
                .get(&(vek.ca_product_name.clone(), kind.to_owned()))
                .ok_or_else(|| {
                    Error::Node(format!(
                        "{} has no matching AMD {kind} evidence",
                        node.node_id
                    ))
                })
        };
        let ark = get_common("ark")?;
        let ask = get_common("ask")?;
        let crl = get_common("crl")?;
        used_hashes.extend([
            vek.sha256.clone(),
            ark.sha256.clone(),
            ask.sha256.clone(),
            crl.sha256.clone(),
        ]);
        stacks.insert(
            platform_key,
            AmdCollateralStack {
                ark: ark.der.clone(),
                ask: ask.der.clone(),
                crl: crl.der.clone(),
                vek: vek.der.clone(),
            },
        );
    }
    if used_hashes.len() != rows.len() {
        return Err(Error::InvalidBundle(
            "bundle contains AMD evidence unused by its nodes".into(),
        ));
    }
    Ok(stacks)
}

fn exact_amd_stack(
    rows: &[VendorCollateral],
    chip_id: &str,
    reported_tcb: &str,
    valid_from: i64,
    valid_until: i64,
) -> Result<AmdCollateralStack, Error> {
    let (common, vceks) = parse_amd_collateral(rows, valid_from, valid_until)?;
    let platform_key = amd_platform_key(chip_id, reported_tcb);
    let vek = vceks
        .get(&platform_key)
        .ok_or_else(|| Error::Node("AMD collateral has no exact VCEK evidence".into()))?;
    let get_common = |kind: &str| {
        common
            .get(&(vek.ca_product_name.clone(), kind.to_owned()))
            .ok_or_else(|| Error::Node(format!("AMD collateral has no matching {kind} evidence")))
    };
    let ark = get_common("ark")?;
    let ask = get_common("ask")?;
    let crl = get_common("crl")?;
    let used = BTreeSet::from([
        vek.sha256.as_str(),
        ark.sha256.as_str(),
        ask.sha256.as_str(),
        crl.sha256.as_str(),
    ]);
    if used.len() != rows.len() {
        return Err(Error::InvalidBundle(
            "AMD collateral admission contains duplicate or unused evidence".into(),
        ));
    }
    Ok(AmdCollateralStack {
        ark: ark.der.clone(),
        ask: ask.der.clone(),
        crl: crl.der.clone(),
        vek: vek.der.clone(),
    })
}

fn parse_amd_collateral(
    rows: &[VendorCollateral],
    bundle_created_at: i64,
    bundle_expires_at: i64,
) -> Result<(AmdCommonCollateral, AmdVcekCollateral), Error> {
    let mut common = BTreeMap::<(String, String), AmdCollateralEntry>::new();
    let mut vceks = BTreeMap::<String, AmdCollateralEntry>::new();
    let mut hashes = BTreeSet::new();

    for row in rows {
        let payload: AmdKdsPayload = serde_json::from_value(
            serde_json::to_value(&row.payload)
                .map_err(|error| Error::InvalidBundle(error.to_string()))?,
        )
        .map_err(|error| Error::InvalidBundle(format!("invalid AMD collateral: {error}")))?;
        let _ = (&payload.hwid, &payload.product_name, &payload.tcb);
        if payload.schema != "stogas.amd-kds-collateral.v1"
            || payload.source != "amd-kds"
            || payload.collateral_type != row.collateral_type
            || payload.fetched_at != row.fetched_at
            || payload.sha256 != row.sha256
            || payload.source_url != row.source_url
            || payload.chip_id.as_deref() != row.chip_id.as_deref()
        {
            return Err(Error::InvalidBundle(
                "AMD collateral envelope and payload differ".into(),
            ));
        }
        if !matches!(row.collateral_type.as_str(), "ark" | "ask" | "crl" | "vcek") {
            return Err(Error::InvalidBundle(
                "unsupported AMD collateral type".into(),
            ));
        }
        let fetched_at = parse_time(&row.fetched_at)?;
        if fetched_at > bundle_created_at + MAX_CLOCK_SKEW_MS
            || fetched_at
                .checked_add(AMD_COLLATERAL_VALIDITY_MS)
                .is_none_or(|deadline| deadline < bundle_expires_at)
        {
            return Err(Error::InvalidBundle(
                "AMD collateral is future-dated or expires before the bundle".into(),
            ));
        }
        let der = URL_SAFE_NO_PAD
            .decode(&payload.der_base64url)
            .map_err(|_| Error::InvalidBundle("AMD collateral DER is not base64url".into()))?;
        if hex::encode(Sha256::digest(&der)) != row.sha256 || !hashes.insert(row.sha256.clone()) {
            return Err(Error::InvalidBundle(
                "AMD collateral digest differs or is duplicated".into(),
            ));
        }
        let entry = AmdCollateralEntry {
            ca_product_name: payload.ca_product_name,
            collateral_type: row.collateral_type.clone(),
            der,
            sha256: row.sha256.clone(),
            chip_id: row.chip_id.clone(),
            reported_tcb: payload.reported_tcb.map(|value| value.to_lowercase()),
        };
        if entry.collateral_type == "vcek" {
            let chip_id = entry
                .chip_id
                .as_deref()
                .ok_or_else(|| Error::InvalidBundle("AMD VCEK has no chip id".into()))?;
            let reported_tcb = entry
                .reported_tcb
                .as_deref()
                .ok_or_else(|| Error::InvalidBundle("AMD VCEK has no reported TCB".into()))?;
            if vceks
                .insert(amd_platform_key(chip_id, reported_tcb), entry)
                .is_some()
            {
                return Err(Error::InvalidBundle(
                    "duplicate AMD VCEK platform evidence".into(),
                ));
            }
        } else {
            if entry.chip_id.is_some() || entry.reported_tcb.is_some() {
                return Err(Error::InvalidBundle(
                    "product-scoped AMD evidence has node identity".into(),
                ));
            }
            let key = (entry.ca_product_name.clone(), entry.collateral_type.clone());
            if common.insert(key, entry).is_some() {
                return Err(Error::InvalidBundle(
                    "duplicate product-scoped AMD evidence".into(),
                ));
            }
        }
    }

    Ok((common, vceks))
}

fn amd_platform_key(chip_id: &str, reported_tcb: &str) -> String {
    format!(
        "{}:{}",
        chip_id.trim().to_lowercase(),
        reported_tcb.trim().to_lowercase()
    )
}

fn validate_node_evidence_time(
    node_id: &str,
    drand_round: u64,
    quote_verified_at: i64,
    now_unix_ms: i64,
) -> Result<i64, Error> {
    if quote_verified_at > now_unix_ms + MAX_CLOCK_SKEW_MS {
        return Err(Error::Node(format!(
            "{node_id} quote verification time is in the future"
        )));
    }
    let round_offset = i64::try_from(drand_round.saturating_sub(1))
        .map_err(|_| Error::Node("drand round is too large".into()))?;
    let round_time_ms = round_offset
        .checked_mul(DRAND_PERIOD_SECONDS)
        .and_then(|seconds| DRAND_GENESIS_SECONDS.checked_add(seconds))
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| Error::Node("drand round time overflows".into()))?;
    if round_time_ms > quote_verified_at + DRAND_PERIOD_SECONDS * 1000 {
        return Err(Error::Node(format!(
            "{node_id} drand round is later than quote verification"
        )));
    }
    if round_time_ms < quote_verified_at - DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS {
        return Err(Error::Node(format!(
            "{node_id} drand round was stale when the quote was verified"
        )));
    }
    Ok(round_time_ms)
}

fn verify_quicknet(beacon: &DrandBeacon) -> Result<(), Error> {
    let signature = hex::decode(&beacon.signature)
        .map_err(|_| Error::Node("drand signature is not hex".into()))?;
    let randomness = hex::encode(Sha256::digest(&signature));
    if randomness != beacon.randomness {
        return Err(Error::Node(
            "drand randomness does not match signature".into(),
        ));
    }
    // Signature verification uses drand-verify's Quicknet ciphersuite. This call is isolated so
    // chain constants and round encoding cannot drift between SDKs.
    verify_quicknet_signature(beacon, &signature)
}

fn verify_quicknet_signature(beacon: &DrandBeacon, signature: &[u8]) -> Result<(), Error> {
    use drand_verify::{G2PubkeyRfc, Pubkey};
    const PUBLIC_KEY_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    let public_key = hex::decode(PUBLIC_KEY_HEX)
        .map_err(|_| Error::Node("pinned Quicknet key is malformed".into()))?;
    let key = G2PubkeyRfc::from_variable(&public_key)
        .map_err(|error| Error::Node(format!("pinned Quicknet key is invalid: {error}")))?;
    let valid = key
        .verify(beacon.round, b"", signature)
        .map_err(|error| Error::Node(format!("Quicknet verification failed: {error}")))?;
    if !valid {
        return Err(Error::Node("Quicknet signature is invalid".into()));
    }
    Ok(())
}

fn decode_snp_report(quote_value: &str, node_id: &str) -> Result<Vec<u8>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct QuoteEnvelope {
        #[serde(default)]
        auxblob: Option<String>,
        #[serde(default)]
        manifestblob: Option<String>,
        provider: String,
        report: String,
        schema: String,
    }

    let quote_json = URL_SAFE_NO_PAD
        .decode(quote_value)
        .map_err(|_| Error::Node(format!("{node_id} quote encoding is invalid")))?;
    let quote: QuoteEnvelope = serde_json::from_slice(&quote_json)
        .map_err(|_| Error::Node(format!("{node_id} quote is not an AMD SEV-SNP quote")))?;
    if quote.schema != "stogas.sev-snp-quote-envelope.v1"
        || quote.provider != "sev_guest"
        || quote.manifestblob.is_some()
    {
        return Err(Error::Node(format!(
            "{node_id} quote envelope is unsupported"
        )));
    }
    let _ = quote.auxblob;
    let report = URL_SAFE_NO_PAD
        .decode(&quote.report)
        .map_err(|_| Error::Node(format!("{node_id} SNP report encoding is invalid")))?;
    if report.len() != 0x4a0 {
        return Err(Error::Node(format!(
            "{node_id} SNP report has the wrong size"
        )));
    }
    Ok(report)
}

#[cfg(feature = "snp")]
fn verify_snp_node(
    node: &AttestedNode<'_>,
    release_manifest: &GatewayReleaseManifest,
    launch: &LaunchValues,
    bundle_created_at: i64,
    bundle_expires_at: i64,
    collateral: &AmdCollateralStack,
    hardware_policy: &AmdSevSnpPolicy,
) -> Result<(), Error> {
    let report_bytes = decode_snp_report(node.quote, node.node_id)?;
    check_raw_report_bindings(
        node,
        release_manifest,
        launch,
        &report_bytes,
        Some(hardware_policy),
    )?;
    verify_amd_collateral_stack(
        collateral,
        node.chip_id,
        node.reported_tcb,
        bundle_created_at,
        bundle_expires_at,
    )?;
    let product = validate_report_product_binding(&collateral.vek, &report_bytes)?;
    let expected_policy = u64::from_str_radix(launch.policy.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Node("invalid launch policy value".into()))?;
    validate_snp_launch_policy(expected_policy, Some(product))?;
    verify_raw_snp_report_signature_with_vcek(&report_bytes, &collateral.vek, node.node_id)
}

#[cfg(not(feature = "snp"))]
fn verify_snp_node(
    _node: &AttestedNode<'_>,
    _release_manifest: &GatewayReleaseManifest,
    _launch: &LaunchValues,
    _bundle_created_at: i64,
    _bundle_expires_at: i64,
    _collateral: &AmdCollateralStack,
    _hardware_policy: &AmdSevSnpPolicy,
) -> Result<(), Error> {
    Err(Error::Node(
        "AMD SNP verification is unavailable in this build".into(),
    ))
}

#[cfg(feature = "snp")]
fn check_raw_report_bindings(
    node: &AttestedNode<'_>,
    release_manifest: &GatewayReleaseManifest,
    launch: &LaunchValues,
    report: &[u8],
    hardware_policy: Option<&AmdSevSnpPolicy>,
) -> Result<(), Error> {
    fn bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Error> {
        let decoded = hex::decode(value).map_err(|_| Error::Node(format!("invalid {label}")))?;
        decoded
            .try_into()
            .map_err(|_| Error::Node(format!("invalid {label} length")))
    }
    let u32_at = |offset: usize| {
        u32::from_le_bytes(report[offset..offset + 4].try_into().unwrap_or_default())
    };
    let u64_at = |offset: usize| {
        u64::from_le_bytes(report[offset..offset + 8].try_into().unwrap_or_default())
    };
    let expected_policy = u64::from_str_radix(launch.policy.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Node("invalid launch policy value".into()))?;
    validate_snp_launch_policy(expected_policy, None)?;
    let report_version = u32_at(0x00);
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node(format!(
            "{} SNP report version differs",
            node.node_id
        )));
    }
    let (_, _, _, report_product) = inspect_report_product(report, report_version)?;
    if let Some(product) = report_product {
        validate_snp_launch_policy(expected_policy, Some(product))?;
    }
    validate_raw_snp_report_encoding(report, report_version, report_product, node.node_id)?;
    let report_info = u32_at(0x48);
    let author_key_present = launch.author_key_digest.bytes().any(|byte| byte != b'0');
    let checks = [
        (
            report[0x10..0x20] == bytes::<16>(&launch.family_id, "family id")?,
            "family id",
        ),
        (
            report[0x20..0x30] == bytes::<16>(&launch.image_id, "image id")?,
            "image id",
        ),
        (
            report[0x50..0x90] == bytes::<64>(node.report_data_sha512, "report data")?,
            "report data",
        ),
        (
            report[0x90..0xc0]
                == bytes::<48>(&release_manifest.sev_snp.launch_measurement, "measurement")?,
            "measurement",
        ),
        (
            report[0xc0..0xe0] == bytes::<32>(&launch.host_data, "host data")?,
            "host data",
        ),
        (
            report[0xe0..0x110] == bytes::<48>(&launch.id_key_digest, "id key digest")?,
            "id key digest",
        ),
        (
            report[0x110..0x140] == bytes::<48>(&launch.author_key_digest, "author key digest")?,
            "author key digest",
        ),
        (
            report[0x180..0x188] == bytes::<8>(node.reported_tcb, "reported TCB")?,
            "reported TCB",
        ),
        (
            report[0x1a0..0x1e0] == bytes::<64>(node.chip_id, "chip id")?,
            "chip id",
        ),
        (u32_at(0x30) == u32::from(launch.vmpl), "VMPL"),
        (u64_at(0x08) == expected_policy, "guest policy"),
        (u32_at(0x34) == 1, "signature algorithm"),
        ((report_info & !1) == 0, "VCEK signing key information"),
        (
            (report_info & 1 != 0) == author_key_present,
            "author key flag",
        ),
        (
            expected_policy & SNP_POLICY_MIGRATE_MA != 0
                || is_absent_snp_migration_agent_id(&report[0x160..0x180]),
            "migration-agent report id",
        ),
    ];
    for (valid, label) in checks {
        if !valid {
            return Err(Error::Node(format!("{} SNP {label} differs", node.node_id)));
        }
    }
    if let Some(hardware_policy) = hardware_policy {
        appraise_snp_report(
            report,
            report_version,
            report_product,
            hardware_policy,
            node.node_id,
        )?;
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn is_absent_snp_migration_agent_id(value: &[u8]) -> bool {
    // The ABI specifies zero at launch. Milan firmware 1.58 uses all ones as its
    // absent-agent report sentinel. The signed policy bit remains authoritative.
    value.iter().all(|byte| *byte == 0) || value.iter().all(|byte| *byte == 0xff)
}

#[cfg(feature = "snp")]
fn validate_raw_snp_report_encoding(
    report: &[u8],
    report_version: u32,
    product: Option<&AmdProductProfile>,
    node_id: &str,
) -> Result<(), Error> {
    let zero_ranges: &[(usize, usize)] = if report_version == 5 {
        &[(0x4c, 0x50), (0x18b, 0x1a0), (0x208, 0x2a0)]
    } else {
        &[(0x4c, 0x50), (0x188, 0x1a0), (0x1f8, 0x2a0)]
    };
    if zero_ranges
        .iter()
        .any(|(start, end)| report[*start..*end].iter().any(|byte| *byte != 0))
        || report[0x1eb] != 0
        || report[0x1ef] != 0
    {
        return Err(Error::Node(format!(
            "{node_id} SNP report reserved bytes are nonzero"
        )));
    }
    let platform_info = u64::from_le_bytes(report[0x40..0x48].try_into().unwrap_or_default());
    if platform_info & !SNP_PLATFORM_INFO_KNOWN_MASK != 0 {
        return Err(Error::Node(format!(
            "{node_id} SNP platform information sets reserved bits"
        )));
    }
    if product.is_some_and(|profile| profile.tcb_layout == AmdTcbLayout::Family19h) {
        for (offset, label) in [
            (0x38, "current"),
            (0x180, "reported"),
            (0x1e0, "committed"),
            (0x1f0, "launch"),
        ] {
            if report[offset + 2..offset + 6].iter().any(|byte| *byte != 0) {
                return Err(Error::Node(format!(
                    "{node_id} SNP {label} TCB reserved bytes are nonzero"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn appraise_snp_report(
    report: &[u8],
    report_version: u32,
    product: Option<&AmdProductProfile>,
    profile: &AmdSevSnpPolicy,
    node_id: &str,
) -> Result<(), Error> {
    if report_version != 5 {
        return Err(Error::Node(format!(
            "{node_id} SNP report version is below hardware policy"
        )));
    }
    let family = report[0x188];
    let model = report[0x189];
    let stepping = report[0x18a];
    if profile.cpuid_family != family
        || profile.cpuid_model != model
        || profile.cpuid_stepping != stepping
    {
        return Err(Error::Node(format!(
            "{node_id} CPUID differs from hardware policy"
        )));
    }
    let policy_product = amd_product_from_cpuid(profile.cpuid_family, profile.cpuid_model);
    if policy_product != product {
        return Err(Error::Node(format!(
            "{node_id} SNP processor identity differs from hardware policy"
        )));
    }

    let current = family19h_tcb(&report[0x38..0x40]);
    let reported = family19h_tcb(&report[0x180..0x188]);
    let committed = family19h_tcb(&report[0x1e0..0x1e8]);
    let launch = family19h_tcb(&report[0x1f0..0x1f8]);
    for (label, actual) in [
        ("current", current),
        ("reported", reported),
        ("committed", committed),
        ("launch", launch),
    ] {
        if !tcb_at_least(actual, profile.minimum_tcb) {
            return Err(Error::Node(format!(
                "{node_id} SNP {label} TCB is below hardware policy"
            )));
        }
    }
    if !tcb_at_least(committed, reported) || !tcb_at_least(current, committed) {
        return Err(Error::Node(format!(
            "{node_id} SNP TCB fields have an invalid downgrade order"
        )));
    }

    let current_version = (report[0x1ea], report[0x1e9], report[0x1e8]);
    let committed_version = (report[0x1ee], report[0x1ed], report[0x1ec]);
    if committed_version > current_version {
        return Err(Error::Node(format!(
            "{node_id} SNP committed firmware version exceeds current version"
        )));
    }

    let platform_info = u64::from_le_bytes(report[0x40..0x48].try_into().unwrap_or_default());
    let required_platform = parse_u64_hex(
        &profile.required_platform_info_mask,
        "required platform-info mask",
    )?;
    let forbidden_platform = parse_u64_hex(
        &profile.forbidden_platform_info_mask,
        "forbidden platform-info mask",
    )?;
    if platform_info & required_platform != required_platform
        || platform_info & forbidden_platform != 0
    {
        return Err(Error::Node(format!(
            "{node_id} SNP platform information is below hardware policy"
        )));
    }

    let launch_mitigations =
        u64::from_le_bytes(report[0x1f8..0x200].try_into().unwrap_or_default());
    let current_mitigations =
        u64::from_le_bytes(report[0x200..0x208].try_into().unwrap_or_default());
    let required_launch = parse_u64_hex(
        &profile.required_launch_mitigation_mask,
        "required launch mitigation mask",
    )?;
    let required_current = parse_u64_hex(
        &profile.required_current_mitigation_mask,
        "required current mitigation mask",
    )?;
    if launch_mitigations & required_launch != required_launch {
        return Err(Error::Node(format!(
            "{node_id} SNP launch mitigations are below hardware policy"
        )));
    }
    if current_mitigations & required_current != required_current {
        return Err(Error::Node(format!(
            "{node_id} SNP current mitigations are below hardware policy"
        )));
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn appraise_stored_node_hardware(
    node: &BundleNodeEvidence<'_>,
    policy: &AmdSevSnpPolicy,
) -> Result<(), Error> {
    let report = decode_snp_report(&node.node.quote, &node.node.node_id)?;
    let expected_report_data = hex::decode(&node.report_data_sha512)
        .map_err(|_| Error::Node("report-data digest is invalid".into()))?;
    if report[0x50..0x90] != expected_report_data {
        return Err(Error::Node(format!(
            "{} SNP report data differs",
            node.node.node_id
        )));
    }
    let report_version = u32::from_le_bytes(report[0x00..0x04].try_into().unwrap_or_default());
    let (_, _, _, product) = inspect_report_product(&report, report_version)?;
    validate_raw_snp_report_encoding(&report, report_version, product, &node.node.node_id)?;
    appraise_snp_report(&report, report_version, product, policy, &node.node.node_id)
}

#[cfg(not(feature = "snp"))]
fn appraise_stored_node_hardware(
    _node: &BundleNodeEvidence<'_>,
    _policy: &AmdSevSnpPolicy,
) -> Result<(), Error> {
    Err(Error::Node(
        "AMD SNP verification is unavailable in this build".into(),
    ))
}

#[cfg(feature = "snp")]
fn family19h_tcb(bytes: &[u8]) -> AmdTcb {
    AmdTcb {
        bootloader: bytes[0],
        tee: bytes[1],
        snp: bytes[6],
        microcode: bytes[7],
    }
}

#[cfg(feature = "snp")]
const fn tcb_at_least(actual: AmdTcb, minimum: AmdTcb) -> bool {
    actual.bootloader >= minimum.bootloader
        && actual.tee >= minimum.tee
        && actual.snp >= minimum.snp
        && actual.microcode >= minimum.microcode
}

#[cfg(feature = "snp")]
#[allow(clippy::similar_names)]
fn validate_amd_x509(
    collateral: &AmdCollateralStack,
    chip_id: &str,
    reported_tcb: &str,
    bundle_created_at: i64,
    bundle_expires_at: i64,
) -> Result<(), Error> {
    use sha2::Sha384;
    use x509_parser::{parse_x509_certificate, parse_x509_crl};
    let (ark_remaining, ark) = parse_x509_certificate(&collateral.ark)
        .map_err(|error| Error::Node(format!("AMD ARK: {error}")))?;
    let (ask_remaining, ask) = parse_x509_certificate(&collateral.ask)
        .map_err(|error| Error::Node(format!("AMD ASK: {error}")))?;
    let (vek_remaining, vek) = parse_x509_certificate(&collateral.vek)
        .map_err(|error| Error::Node(format!("AMD VEK: {error}")))?;
    if !ark_remaining.is_empty() || !ask_remaining.is_empty() || !vek_remaining.is_empty() {
        return Err(Error::Node(
            "AMD certificate collateral contains trailing data".into(),
        ));
    }
    for (label, cert) in [("ARK", &ark), ("ASK", &ask), ("VEK", &vek)] {
        if cert.validity().not_before.timestamp() * 1000 > bundle_created_at
            || cert.validity().not_after.timestamp() * 1000 < bundle_expires_at
        {
            return Err(Error::Node(format!(
                "AMD {label} is not valid for the complete bundle interval"
            )));
        }
    }
    let product = validate_vcek_extensions(&vek, chip_id, reported_tcb)?;
    let root_hash = hex::encode(Sha384::digest(ark.public_key().raw));
    if root_hash != product.root_spki_sha384
        || ark.subject() != ark.issuer()
        || ask.issuer() != ark.subject()
        || vek.issuer() != ask.subject()
    {
        return Err(Error::Node("AMD certificate identity chain differs".into()));
    }
    let (crl_remaining, crl) = parse_x509_crl(&collateral.crl)
        .map_err(|error| Error::Node(format!("AMD CRL: {error}")))?;
    if !crl_remaining.is_empty() {
        return Err(Error::Node("AMD CRL contains trailing data".into()));
    }
    validate_amd_crl(&crl, &ark, &ask, bundle_created_at, bundle_expires_at)?;
    Ok(())
}

#[cfg(feature = "snp")]
fn validate_amd_crl(
    crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    ark: &x509_parser::certificate::X509Certificate<'_>,
    ask: &x509_parser::certificate::X509Certificate<'_>,
    bundle_created_at: i64,
    bundle_expires_at: i64,
) -> Result<(), Error> {
    if crl.tbs_cert_list.issuer != *ark.subject() {
        return Err(Error::Node("AMD CRL issuer differs from the ARK".into()));
    }
    verify_amd_crl_signature(crl, ark)?;
    if crl.tbs_cert_list.this_update.timestamp() * 1000 > bundle_created_at + MAX_CLOCK_SKEW_MS {
        return Err(Error::Node("AMD CRL is future-dated".into()));
    }
    if crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .is_none_or(|time| time.timestamp() * 1000 < bundle_expires_at)
    {
        return Err(Error::Node("AMD CRL expires before the bundle".into()));
    }
    if crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == ask.raw_serial())
    {
        return Err(Error::Node("AMD ASK is revoked".into()));
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn verify_amd_collateral_stack(
    collateral: &AmdCollateralStack,
    chip_id: &str,
    reported_tcb: &str,
    valid_from: i64,
    valid_until: i64,
) -> Result<(), Error> {
    use sev::certs::snp::{Chain, Verifiable};
    validate_amd_x509(collateral, chip_id, reported_tcb, valid_from, valid_until)?;
    let chain = Chain::from_der(&collateral.ark, &collateral.ask, &collateral.vek)
        .map_err(|error| Error::Node(format!("AMD chain: {error}")))?;
    (&chain)
        .verify()
        .map_err(|error| Error::Node(format!("AMD chain signature: {error}")))?;
    Ok(())
}

#[cfg(not(feature = "snp"))]
fn verify_amd_collateral_stack(
    _collateral: &AmdCollateralStack,
    _chip_id: &str,
    _reported_tcb: &str,
    _valid_from: i64,
    _valid_until: i64,
) -> Result<(), Error> {
    Err(Error::Node(
        "AMD SNP verification is unavailable in this build".into(),
    ))
}

#[cfg(feature = "snp")]
fn verify_amd_crl_signature(
    crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    signer: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), Error> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey as _, pss};
    use signature::Verifier as _;
    use x509_parser::signature_algorithm::SignatureAlgorithm;

    const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
    const MGF1_OID: &str = "1.2.840.113549.1.1.8";
    const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
    const SHA384_BYTES: u32 = 48;
    if crl.signature_algorithm != crl.tbs_cert_list.signature
        || crl.signature_algorithm.algorithm.to_id_string() != RSA_PSS_OID
    {
        return Err(Error::Node(
            "AMD CRL must use one matching RSA-PSS signature algorithm".into(),
        ));
    }
    let SignatureAlgorithm::RSASSA_PSS(parameters) =
        SignatureAlgorithm::try_from(&crl.signature_algorithm)
            .map_err(|_| Error::Node("AMD CRL has invalid RSA-PSS signature parameters".into()))?
    else {
        return Err(Error::Node("AMD CRL must use RSA-PSS with SHA-384".into()));
    };
    let mask = parameters
        .mask_gen_algorithm()
        .map_err(|_| Error::Node("AMD CRL has invalid RSA-PSS mask parameters".into()))?;
    if parameters.hash_algorithm_oid().to_id_string() != SHA384_OID
        || mask.mgf.to_id_string() != MGF1_OID
        || mask.hash.to_id_string() != SHA384_OID
        || parameters.salt_length() != SHA384_BYTES
        || parameters.trailer_field() != 1
    {
        return Err(Error::Node(
            "AMD CRL must use RSA-PSS with SHA-384, MGF1-SHA-384, and a 48-byte salt".into(),
        ));
    }
    let public_key = RsaPublicKey::from_public_key_der(signer.public_key().raw)
        .map_err(|error| Error::Node(format!("AMD CRL signer key: {error}")))?;
    let signature = pss::Signature::try_from(crl.signature_value.data.as_ref())
        .map_err(|error| Error::Node(format!("AMD CRL signature encoding: {error}")))?;
    pss::VerifyingKey::<sha2::Sha384>::new(public_key)
        .verify(crl.tbs_cert_list.as_ref(), &signature)
        .map_err(|error| Error::Node(format!("AMD CRL signature: {error}")))
}

#[cfg(feature = "snp")]
fn validate_vcek_extensions(
    vek: &x509_parser::certificate::X509Certificate<'_>,
    chip_id: &str,
    reported_tcb: &str,
) -> Result<&'static AmdProductProfile, Error> {
    let expected_tcb =
        hex::decode(reported_tcb).map_err(|_| Error::Node("reported TCB is invalid".into()))?;
    if expected_tcb.len() != 8 {
        return Err(Error::Node("reported TCB has the wrong length".into()));
    }

    let mut extensions = BTreeMap::new();
    for extension in vek.extensions().iter().filter(|extension| {
        extension
            .oid
            .to_id_string()
            .starts_with("1.3.6.1.4.1.3704.1.")
    }) {
        let oid = extension.oid.to_id_string();
        if extensions.insert(oid.clone(), extension.value).is_some() {
            return Err(Error::Node(format!(
                "AMD VCEK extension {oid} is duplicated"
            )));
        }
    }
    let required = |oid: &str| {
        extensions
            .get(oid)
            .copied()
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is absent")))
    };

    let struct_version_oid = "1.3.6.1.4.1.3704.1.1";
    let struct_version = parse_der_u8(required(struct_version_oid)?)
        .ok_or_else(|| Error::Node("AMD VCEK structVersion is malformed".into()))?;
    let product_name = parse_der_ia5_string(required("1.3.6.1.4.1.3704.1.2")?)
        .ok_or_else(|| Error::Node("AMD VCEK productName is malformed".into()))?;
    let profile = amd_product_from_vcek_name(product_name)
        .ok_or_else(|| Error::Node("AMD VCEK productName is unsupported".into()))?;
    if struct_version != profile.struct_version {
        return Err(Error::Node(format!(
            "AMD VCEK structVersion differs for {}",
            profile.product_name
        )));
    }

    let tcb_extensions: &[(&str, usize)] = match profile.tcb_layout {
        AmdTcbLayout::Family19h => &[
            ("1.3.6.1.4.1.3704.1.3.1", 0),
            ("1.3.6.1.4.1.3704.1.3.2", 1),
            ("1.3.6.1.4.1.3704.1.3.4", 2),
            ("1.3.6.1.4.1.3704.1.3.5", 3),
            ("1.3.6.1.4.1.3704.1.3.6", 4),
            ("1.3.6.1.4.1.3704.1.3.7", 5),
            ("1.3.6.1.4.1.3704.1.3.3", 6),
            ("1.3.6.1.4.1.3704.1.3.8", 7),
        ],
        AmdTcbLayout::Family1ah => &[
            ("1.3.6.1.4.1.3704.1.3.9", 0),
            ("1.3.6.1.4.1.3704.1.3.1", 1),
            ("1.3.6.1.4.1.3704.1.3.2", 2),
            ("1.3.6.1.4.1.3704.1.3.3", 3),
            ("1.3.6.1.4.1.3704.1.3.5", 4),
            ("1.3.6.1.4.1.3704.1.3.6", 5),
            ("1.3.6.1.4.1.3704.1.3.7", 6),
            ("1.3.6.1.4.1.3704.1.3.8", 7),
        ],
    };
    for &(oid, tcb_index) in tcb_extensions {
        let expected_value = expected_tcb[tcb_index];
        if tcb_index != 7 && expected_value > 127 {
            return Err(Error::Node(format!(
                "reported TCB byte {tcb_index} exceeds AMD KDS policy"
            )));
        }
        let value = parse_der_u8(required(oid)?)
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is malformed")))?;
        if value != expected_value {
            return Err(Error::Node(format!(
                "AMD VCEK extension {oid} differs: certificate={value:#04x}, report={expected_value:#04x}"
            )));
        }
    }
    let chip = hex::decode(chip_id).map_err(|_| Error::Node("chip id is invalid".into()))?;
    if chip.len() != 64 {
        return Err(Error::Node("chip id has the wrong length".into()));
    }
    let hwid = required("1.3.6.1.4.1.3704.1.4")?;
    let certificate_chip = parse_der_octet_string(hwid)
        .ok_or_else(|| Error::Node(format!("AMD VCEK chip id is malformed ({})", hwid.len())))?;
    let expected_hwid = match profile.tcb_layout {
        AmdTcbLayout::Family19h => chip.as_slice(),
        AmdTcbLayout::Family1ah => {
            if chip[8..].iter().any(|byte| *byte != 0) || chip[..8].iter().all(|byte| *byte == 0) {
                return Err(Error::Node(
                    "Family 1Ah report CHIP_ID is not an 8-byte PSN followed by zeros".into(),
                ));
            }
            &chip[..8]
        }
    };
    if certificate_chip != expected_hwid {
        return Err(Error::Node("AMD VCEK chip id differs".into()));
    }
    Ok(profile)
}

#[cfg(feature = "snp")]
fn amd_product_from_vcek_name(value: &str) -> Option<&'static AmdProductProfile> {
    AMD_PRODUCT_PROFILES.iter().find(|profile| {
        value == profile.product_name
            || value
                .strip_prefix(profile.product_name)
                .and_then(|suffix| suffix.strip_prefix('-'))
                .is_some_and(|stepping| {
                    !stepping.is_empty()
                        && stepping.len() <= 8
                        && stepping.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
    })
}

#[cfg(feature = "snp")]
fn validate_report_product_binding(
    vek_der: &[u8],
    report: &[u8],
) -> Result<&'static AmdProductProfile, Error> {
    use x509_parser::parse_x509_certificate;

    let (remaining, vek) = parse_x509_certificate(vek_der)
        .map_err(|error| Error::Node(format!("AMD VEK: {error}")))?;
    if !remaining.is_empty() {
        return Err(Error::Node("AMD VEK contains trailing data".into()));
    }
    let product_name = vek
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.3704.1.2")
        .and_then(|extension| parse_der_ia5_string(extension.value))
        .ok_or_else(|| Error::Node("AMD VCEK productName is malformed".into()))?;
    let certificate_product = amd_product_from_vcek_name(product_name)
        .ok_or_else(|| Error::Node("AMD VCEK productName is unsupported".into()))?;
    let report_version = u32::from_le_bytes(
        report[0x00..0x04]
            .try_into()
            .map_err(|_| Error::Node("SNP report version is absent".into()))?,
    );
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node("unsupported SNP report version".into()));
    }
    let (_, _, _, report_product) = inspect_report_product(report, report_version)?;
    match report_product {
        Some(report_product) if report_product == certificate_product => Ok(certificate_product),
        Some(_) => Err(Error::Node(
            "AMD VCEK product differs from the report CPUID".into(),
        )),
        None if certificate_product.tcb_layout == AmdTcbLayout::Family19h => {
            Ok(certificate_product)
        }
        None => Err(Error::Node(
            "Family 1Ah VCEK requires report CPUID fields".into(),
        )),
    }
}

#[cfg(feature = "snp")]
fn parse_der_u8(value: &[u8]) -> Option<u8> {
    match value {
        [0x02, 0x01, byte] if *byte < 0x80 => Some(*byte),
        [0x02, 0x02, 0x00, byte] if *byte >= 0x80 => Some(*byte),
        _ => None,
    }
}

#[cfg(feature = "snp")]
fn parse_der_ia5_string(value: &[u8]) -> Option<&str> {
    let [0x16, length, bytes @ ..] = value else {
        return None;
    };
    if usize::from(*length) != bytes.len() || *length >= 0x80 || !bytes.is_ascii() {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[cfg(feature = "snp")]
fn parse_der_octet_string(value: &[u8]) -> Option<&[u8]> {
    if matches!(value.len(), 8 | 64) {
        return Some(value);
    }
    match value {
        [0x04, length, bytes @ ..] if usize::from(*length) == bytes.len() && *length < 0x80 => {
            Some(bytes)
        }
        _ => None,
    }
}

fn validate_time(created: i64, expires: i64, now: i64) -> Result<(), Error> {
    if created > now + MAX_CLOCK_SKEW_MS {
        return Err(Error::InvalidBundle(
            "creation time is in the future".into(),
        ));
    }
    if created < now - MAX_BUNDLE_AGE_MS {
        return Err(Error::InvalidBundle(
            "bundle was created more than three minutes ago".into(),
        ));
    }
    if expires <= now || expires <= created {
        return Err(Error::InvalidBundle(
            "bundle is expired or has an invalid interval".into(),
        ));
    }
    let interval = expires - created;
    if interval > MAX_BUNDLE_VALIDITY_MS {
        return Err(Error::InvalidBundle(format!(
            "bundle validity ({interval} ms) exceeds the {MAX_BUNDLE_VALIDITY_MS} ms policy"
        )));
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<i64, Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc).timestamp_millis())
        .map_err(|_| Error::InvalidBundle(format!("invalid timestamp: {value}")))
}

fn verify_ed25519(
    public_der_b64: &str,
    payload: &[u8],
    signature_b64url: &str,
) -> Result<(), String> {
    use ed25519_dalek::Verifier as _;
    let der = STANDARD
        .decode(public_der_b64)
        .map_err(|error| error.to_string())?;
    let key = VerifyingKey::from_public_key_der(&der).map_err(|error| error.to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .map_err(|error| error.to_string())?;
    let signature =
        Ed25519Signature::from_slice(&signature_bytes).map_err(|error| error.to_string())?;
    key.verify(payload, &signature)
        .map_err(|error| error.to_string())
}

fn canonical_json(value: &Value) -> Result<String, Error> {
    fn write(value: &Value, output: &mut String) -> Result<(), Error> {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => {
                output.push_str(&serde_json::to_string(value).map_err(|error| {
                    Error::InvalidBundle(format!("serialize canonical JSON string: {error}"))
                })?);
            }
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(value, output)?;
                }
                output.push(']');
            }
            Value::Object(values) => {
                output.push('{');
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).map_err(|error| {
                        Error::InvalidBundle(format!("serialize canonical JSON key: {error}"))
                    })?);
                    output.push(':');
                    write(&values[key], output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }
    let mut output = String::new();
    write(value, &mut output)?;
    output.push('\n');
    Ok(output)
}

fn canonical_report_data(report: &ReportData) -> Result<String, Error> {
    let mut certs = report.accepted_cert_sha256.clone();
    certs.sort();
    certs.dedup();
    if certs.len() > 2 {
        return Err(Error::Node("invalid certificate rotation stack".into()));
    }
    let mut value = serde_json::Map::new();
    value.insert("schema".into(), Value::String(report.schema.clone()));
    value.insert(
        "tls_spki_sha256".into(),
        Value::String(report.tls_spki_sha256.clone()),
    );
    value.insert(
        "accepted_cert_sha256".into(),
        serde_json::to_value(certs).map_err(|error| {
            Error::InvalidBundle(format!("serialize accepted certificate hashes: {error}"))
        })?,
    );
    value.insert(
        "hpke_public_key".into(),
        Value::String(report.hpke_public_key.clone()),
    );
    value.insert(
        "ed25519_public_key".into(),
        Value::String(report.ed25519_public_key.clone()),
    );
    value.insert(
        "drand".into(),
        serde_json::json!({
            "network": report.drand.network,
            "chain_hash": report.drand.chain_hash,
            "round": report.drand.round,
            "randomness": report.drand.randomness,
            "signature": report.drand.signature,
        }),
    );
    serde_json::to_string(&Value::Object(value)).map_err(|error| Error::Node(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_certificate_history_fixture() -> (NodeEvidence, NodeCertificateHistory, i64) {
        let admitted_at = "2026-08-27T00:00:00.000Z";
        let leaf_der = STANDARD
            .decode(include_str!("../tests/fixtures/vcek-turin.der.base64").trim())
            .unwrap();
        let leaf_sha256 = hex::encode(Sha256::digest(&leaf_der));
        let node_id = "11".repeat(32);
        let evidence = serde_json::from_value(serde_json::json!({
            "admitted_at": admitted_at,
            "admission": {
                "cert_expires_at": "2026-11-27T00:00:00.000Z",
                "chip_id": "22".repeat(64),
                "endorsements": [],
                "quote": "AA",
                "quote_verified_at": admitted_at,
                "region": "us-east-va",
                "report_data": {
                    "accepted_cert_sha256": [leaf_sha256.clone()],
                    "drand": {
                        "chain_hash": DRAND_CHAIN_HASH,
                        "network": "quicknet",
                        "randomness": "33".repeat(32),
                        "round": 1,
                        "signature": URL_SAFE_NO_PAD.encode([4_u8; 96])
                    },
                    "ed25519_public_key": URL_SAFE_NO_PAD.encode([5_u8; 32]),
                    "hpke_public_key": URL_SAFE_NO_PAD.encode([6_u8; 1_216]),
                    "schema": "stogas.node-report.v1",
                    "tls_spki_sha256": "77".repeat(32)
                },
                "report_data_sha512": "88".repeat(64),
                "reported_tcb": "00".repeat(8)
            },
            "hardware_policy_sha256": "99".repeat(32),
            "node_id": node_id.clone(),
            "release_measurement": "aa".repeat(48),
            "schema": "stogas.node-evidence.v1"
        }))
        .unwrap();
        let history = NodeCertificateHistory {
            certificates: vec![NodeCertificateHistoryEntry {
                certificate_chain_pem: format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    STANDARD.encode(&leaf_der)
                ),
                first_observed_at: admitted_at.into(),
                leaf_der: URL_SAFE_NO_PAD.encode(leaf_der),
                sha256: leaf_sha256,
            }],
            node_id,
            schema: "stogas.node-certificate-history.v1".into(),
        };
        (evidence, history, parse_time(admitted_at).unwrap())
    }

    #[test]
    fn validates_exact_node_certificate_history_bytes() {
        let (evidence, history, admitted_at) = node_certificate_history_fixture();
        validate_node_certificate_history(&evidence, &history, admitted_at).unwrap();

        let mut wrong_hash = history.clone();
        wrong_hash.certificates[0].sha256 = "00".repeat(32);
        assert!(
            validate_node_certificate_history(&evidence, &wrong_hash, admitted_at)
                .unwrap_err()
                .to_string()
                .contains("leaf DER differs")
        );

        let mut wrong_node = history;
        wrong_node.node_id = "ff".repeat(32);
        assert!(
            validate_node_certificate_history(&evidence, &wrong_node, admitted_at)
                .unwrap_err()
                .to_string()
                .contains("unsupported or invalid")
        );
    }

    #[test]
    fn normalizes_only_the_quote_bound_boot_candidate_to_the_attested_node_id() {
        let report_data = ReportData {
            accepted_cert_sha256: Vec::new(),
            drand: DrandBeacon {
                chain_hash: DRAND_CHAIN_HASH.into(),
                network: "quicknet".into(),
                randomness: "3".repeat(64),
                round: 1,
                signature: "4".repeat(96),
            },
            ed25519_public_key: "ZWRrZXk".into(),
            hpke_public_key: "aHBrZQ".into(),
            schema: "stogas.node-report.v1".into(),
            tls_spki_sha256: "2".repeat(64),
        };
        let chip_id = "1".repeat(128);
        let candidate_node_id = "80278d7321aa5ea1320e9a566a0f8b5225f0143c4e3de27f6bb0b12ac14faf81";
        let expected_node_id = "9f4ad58f8fadbe44f05918b391bacd633d90bf828069037537c4cf4811c2d291";

        assert_eq!(
            normalize_admission_node_id(candidate_node_id, &chip_id, &report_data).unwrap(),
            expected_node_id
        );
        assert_eq!(
            normalize_admission_node_id(expected_node_id, &chip_id, &report_data).unwrap(),
            expected_node_id
        );
        assert!(normalize_admission_node_id(&"0".repeat(64), &chip_id, &report_data).is_err());

        assert_eq!(
            derive_node_id(&"f".repeat(128), &"c".repeat(64)),
            "886be0b5fac4ee4d04ae33c441632ce67645706809e958fd31836d5f82e67871"
        );
    }

    #[test]
    fn groups_exact_chip_ids_under_shared_hardware_requirements() {
        let policy: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        validate_hardware_policy(&policy).unwrap();
        let chip_id = &policy.policies[0].chip_ids[0];
        assert_eq!(
            compatible_hardware(&policy, chip_id).unwrap().chip_ids,
            vec![chip_id.clone()]
        );
        assert!(compatible_hardware(&policy, &"00".repeat(64)).is_err());
    }

    #[test]
    fn rejects_hardware_policy_without_a_valid_transparency_proof() {
        let signed: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        assert!(verify_signed_hardware_policy(&signed, 1_784_246_400_000).is_err());
    }

    #[test]
    fn converts_rekor_seconds_to_the_documented_milliseconds() {
        assert_eq!(
            rekor_seconds_to_millis(1_788_000_000).unwrap(),
            1_788_000_000_000
        );
        assert!(rekor_seconds_to_millis(i64::MAX).is_err());
    }

    #[cfg(feature = "snp")]
    fn appraisable_milan_report() -> (Vec<u8>, AmdSevSnpPolicy, &'static AmdProductProfile) {
        let policy: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        let profile = amd_product_from_cpuid(0x19, 0x01).unwrap();
        let mut report = vec![0_u8; 0x4a0];
        report[0x00..0x04].copy_from_slice(&5_u32.to_le_bytes());
        let tcb = [4, 0, 0, 0, 0, 0, 29, 222];
        for offset in [0x38, 0x180, 0x1e0, 0x1f0] {
            report[offset..offset + 8].copy_from_slice(&tcb);
        }
        report[0x40..0x48].copy_from_slice(&0x24_u64.to_le_bytes());
        report[0x188..0x18b].copy_from_slice(&[0x19, 0x01, 0x01]);
        report[0x1f8..0x200].copy_from_slice(&0x0b_u64.to_le_bytes());
        report[0x200..0x208].copy_from_slice(&0x0b_u64.to_le_bytes());
        (report, policy.policies[0].clone(), profile)
    }

    #[cfg(feature = "snp")]
    #[test]
    fn report_v5_appraisal_enforces_every_dynamic_amd_security_field() {
        let (report, policy, product) = appraisable_milan_report();
        appraise_snp_report(&report, 5, Some(product), &policy, "node").unwrap();

        for (label, offset, value) in [
            ("current TCB", 0x3e, 28_u8),
            ("reported TCB", 0x186, 28),
            ("committed TCB", 0x1e6, 28),
            ("launch TCB", 0x1f6, 28),
        ] {
            let mut invalid = report.clone();
            invalid[offset] = value;
            let error = appraise_snp_report(&invalid, 5, Some(product), &policy, "node")
                .unwrap_err()
                .to_string();
            assert!(error.contains("below hardware policy"), "{label}: {error}");
        }

        for (label, offset) in [("launch", 0x1f8), ("current", 0x200)] {
            let mut invalid = report.clone();
            invalid[offset..offset + 8].copy_from_slice(&0x12_u64.to_le_bytes());
            let error = appraise_snp_report(&invalid, 5, Some(product), &policy, "node")
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!("{label} mitigations")), "{error}");
        }

        let mut missing_alias_check = report.clone();
        missing_alias_check[0x40..0x48].copy_from_slice(&0_u64.to_le_bytes());
        assert!(
            appraise_snp_report(&missing_alias_check, 5, Some(product), &policy, "node")
                .unwrap_err()
                .to_string()
                .contains("platform information")
        );

        let mut smt_enabled = report.clone();
        smt_enabled[0x40..0x48].copy_from_slice(&0x25_u64.to_le_bytes());
        appraise_snp_report(&smt_enabled, 5, Some(product), &policy, "node").unwrap();

        assert!(
            appraise_snp_report(&report, 4, Some(product), &policy, "node")
                .unwrap_err()
                .to_string()
                .contains("report version")
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn report_v5_appraisal_rejects_tcb_and_firmware_downgrade_inconsistency() {
        let (mut report, mut policy, product) = appraisable_milan_report();
        policy.minimum_tcb = AmdTcb {
            bootloader: 0,
            microcode: 0,
            snp: 0,
            tee: 0,
        };
        report[0x187] = 3;
        report[0x1e7] = 2;
        let error = appraise_snp_report(&report, 5, Some(product), &policy, "node")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid downgrade order"));

        let (mut report, policy, product) = appraisable_milan_report();
        report[0x1e8..0x1eb].copy_from_slice(&[1, 0, 1]);
        report[0x1ec..0x1ef].copy_from_slice(&[2, 0, 1]);
        let error = appraise_snp_report(&report, 5, Some(product), &policy, "node")
            .unwrap_err()
            .to_string();
        assert!(error.contains("committed firmware version exceeds current"));
    }

    #[test]
    fn csr_submission_cannot_supply_its_own_node_identity() {
        let submission = serde_json::to_vec(&serde_json::json!({
            "csr_der": URL_SAFE_NO_PAD.encode([1_u8]),
            "node_id": "attacker-generation",
            "node_ed25519_public_key": URL_SAFE_NO_PAD.encode([1_u8; 32]),
            "order_id": "attacker-order",
            "signature": URL_SAFE_NO_PAD.encode([0_u8; 64]),
        }))
        .unwrap();
        let trusted = serde_json::to_vec(&serde_json::json!({
            "attested_node_ed25519_public_key": URL_SAFE_NO_PAD.encode([2_u8; 32]),
            "expected_common_name": null,
            "expected_dns_names": ["api.stogas.ai"],
            "expected_tls_spki_sha256": "00".repeat(32),
            "node_id": "trusted-generation",
            "order_id": "trusted-order",
        }))
        .unwrap();

        let error = verify_certificate_csr_submission(&submission, &trusted).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn csr_submission_must_match_the_trusted_order() {
        let submission = serde_json::to_vec(&serde_json::json!({
            "csr_der": URL_SAFE_NO_PAD.encode([1_u8]),
            "node_id": "attacker-generation",
            "order_id": "attacker-order",
            "signature": URL_SAFE_NO_PAD.encode([0_u8; 64]),
        }))
        .unwrap();
        let trusted = serde_json::to_vec(&serde_json::json!({
            "attested_node_ed25519_public_key": URL_SAFE_NO_PAD.encode([2_u8; 32]),
            "expected_common_name": null,
            "expected_dns_names": ["api.stogas.ai"],
            "expected_tls_spki_sha256": "00".repeat(32),
            "node_id": "trusted-generation",
            "order_id": "trusted-order",
        }))
        .unwrap();

        let error = verify_certificate_csr_submission(&submission, &trusted).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the trusted certificate order")
        );
    }

    #[test]
    fn csr_submission_rejects_a_self_authorized_signature() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let csr_der = [1_u8];
        let mut authorization = Vec::new();
        authorization.extend_from_slice(CSR_SIGNATURE_DOMAIN);
        for field in [
            b"trusted-generation".as_slice(),
            b"trusted-order".as_slice(),
            &Sha256::digest(csr_der)[..],
        ] {
            append_transcript_field(&mut authorization, field).unwrap();
        }
        let attacker_key = SigningKey::from_bytes(&[1_u8; 32]);
        let trusted_key = SigningKey::from_bytes(&[2_u8; 32]);
        let submission = serde_json::to_vec(&serde_json::json!({
            "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
            "node_id": "trusted-generation",
            "order_id": "trusted-order",
            "signature": URL_SAFE_NO_PAD.encode(attacker_key.sign(&authorization).to_bytes()),
        }))
        .unwrap();
        let trusted = serde_json::to_vec(&serde_json::json!({
            "attested_node_ed25519_public_key": URL_SAFE_NO_PAD.encode(trusted_key.verifying_key().as_bytes()),
            "expected_common_name": null,
            "expected_dns_names": ["api.stogas.ai"],
            "expected_tls_spki_sha256": "00".repeat(32),
            "node_id": "trusted-generation",
            "order_id": "trusted-order",
        }))
        .unwrap();

        let error = verify_certificate_csr_submission(&submission, &trusted).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("certificate CSR submission signature is invalid")
        );
    }

    fn quote_with_identity(chip: [u8; 64], measurement: [u8; 48], tcb: [u8; 8]) -> String {
        quote_with_product_identity(2, chip, measurement, tcb, None)
    }

    fn quote_with_product_identity(
        version: u32,
        chip: [u8; 64],
        measurement: [u8; 48],
        tcb: [u8; 8],
        cpuid: Option<(u8, u8, u8)>,
    ) -> String {
        let mut report = vec![0_u8; 0x4a0];
        report[0x00..0x04].copy_from_slice(&version.to_le_bytes());
        report[0x90..0xc0].copy_from_slice(&measurement);
        report[0x180..0x188].copy_from_slice(&tcb);
        if let Some((family, model, stepping)) = cpuid {
            report[0x188] = family;
            report[0x189] = model;
            report[0x18a] = stepping;
        }
        report[0x1a0..0x1e0].copy_from_slice(&chip);
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "provider": "sev_guest",
                "report": URL_SAFE_NO_PAD.encode(report),
                "schema": "stogas.sev-snp-quote-envelope.v1"
            }))
            .unwrap(),
        )
    }

    fn release_fixture() -> AllowedIgvm {
        let launch = serde_json::json!({
            "author_key_digest": "00".repeat(48),
            "family_id": "00".repeat(16),
            "host_data": "00".repeat(32),
            "id_key_digest": "00".repeat(48),
            "image_id": "00".repeat(16),
            "policy": "0x000000000213013a",
            "vmpl": 0
        });
        let launch_policies = serde_json::json!({
            "policies": [{
                "chip_ids": ["66".repeat(64)],
                "launch": launch
            }],
            "schema": "stogas.snp-launch-policies.v1"
        });
        let launch_policies_bytes = canonical_json(&launch_policies).unwrap();
        let launch_policies_sha256 = hex::encode(Sha256::digest(launch_policies_bytes.as_bytes()));
        serde_json::from_value(serde_json::json!({
            "github_in_toto": [{}],
            "release_manifest": {
                "artifacts": {
                    "gateway.igvm": { "sha256": "11".repeat(32), "sizeBytes": 1 },
                    "snp-launch-policies.json": {
                        "sha256": launch_policies_sha256,
                        "sizeBytes": launch_policies_bytes.len()
                    }
                },
                "build": {
                    "cmdlineSha256": "12".repeat(32),
                    "coreGoModSha256": "13".repeat(32),
                    "coreGoSumSha256": "14".repeat(32),
                    "environment": { "lcAll": "C", "sourceDateEpoch": "1", "tz": "UTC", "umask": "022" },
                    "goModSha256": "15".repeat(32),
                    "goSumSha256": "16".repeat(32),
                    "goVendorTreeSha256": "17".repeat(32),
                    "goVersion": "go1.25.0",
                    "guestCaBundlePath": "/etc/ssl/certs/ca-certificates.crt",
                    "guestCaBundleSha256": "18".repeat(32),
                    "guixChannelCommit": "19".repeat(20),
                    "inputSha256": {
                        "source": "20".repeat(32),
                        "stogas/release/snp-launch-policies.json": launch_policies_sha256
                    },
                    "kernelConfigSha256": "21".repeat(32),
                    "kernelVersion": "6.12.0",
                    "linuxBzImageSha256": "22".repeat(32),
                    "osReleaseSha256": "23".repeat(32),
                    "ovmfSha256": "24".repeat(32),
                    "pinsLockSha256": "25".repeat(32),
                    "systemdStubSha256": "26".repeat(32),
                    "ukiSha256": "27".repeat(32)
                },
                "git": {
                    "commit": "33".repeat(20),
                    "ref": "refs/tags/v0.0.1",
                    "repository": "https://github.com/StogasAI/gateway",
                    "tag": "v0.0.1",
                    "tree": "44".repeat(20)
                },
                "schema": "stogas.gateway.release.v1",
                "sequence": 1,
                "sevSnp": {
                    "checkKvm": true,
                    "launchMeasurement": "55".repeat(48),
                    "launchPolicies": launch_policies,
                    "measurementCommand": "igvmmeasure --check-kvm gateway.igvm measure",
                    "measurementTool": "igvmmeasure",
                    "measurementToolSha256": "66".repeat(32),
                    "measurementToolVersion": "0.3.1",
                    "platform": "SEV_SNP",
                    "vcpuCount": 4,
                    "vmm": "qemu-kvm"
                }
            },
            "stogas_signature": {
                "algorithm": "Ed25519",
                "key_id": STOGAS_RELEASE_KEY_ID,
                "schema": "stogas.gateway.counterbuild-signature.v1",
                "signature": URL_SAFE_NO_PAD.encode([0_u8; 64]),
                "signed": "release-manifest.json"
            }
        }))
        .unwrap()
    }

    fn catalog_fixture() -> AllowedCatalog {
        serde_json::from_value(serde_json::json!({
            "github_in_toto": [{}],
            "signed_release": {
                "keyId": "test",
                "manifest": {
                    "catalogSchema": 1,
                    "minimumGatewaySequence": 1,
                    "public": format!("sha256:{}", "11".repeat(32)),
                    "runtime": format!("sha256:{}", "22".repeat(32)),
                    "schema": "stogas.catalog.release.v1",
                    "sequence": 1,
                    "source": {
                        "commit": "33".repeat(20),
                        "repository": "https://github.com/StogasAI/catalog",
                        "tag": "catalog-v1",
                        "tree": "44".repeat(20)
                    }
                },
                "schema": "stogas.catalog.signed.v1",
                "signature": "test"
            }
        }))
        .unwrap()
    }

    #[test]
    fn bundle_sequence_is_not_a_trust_input() {
        let hardware_policy: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        let envelope = BundleEnvelope {
            body: BundleBody {
                catalogs: Vec::new(),
                allowed_igvms: Vec::new(),
                created_at: "2026-07-23T16:00:00.000Z".into(),
                expires_at: "2026-07-23T16:15:00.000Z".into(),
                hardware_policy,
                nodes: Vec::new(),
                schema: "stogas.confidential-bundle.v1".into(),
                sequence: 0,
                vendor_collateral: Vec::new(),
            },
            body_sha256: "00".repeat(32),
        };

        validate_shape(&envelope).unwrap();
    }

    #[test]
    fn bundle_shape_allows_catalog_preauthorization_and_unused_hardware_policies() {
        let policy: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        let mut envelope = BundleEnvelope {
            body: BundleBody {
                catalogs: Vec::new(),
                allowed_igvms: Vec::new(),
                created_at: "2026-07-23T16:00:00.000Z".into(),
                expires_at: "2026-07-23T16:15:00.000Z".into(),
                hardware_policy: policy.clone(),
                nodes: Vec::new(),
                schema: "stogas.confidential-bundle.v1".into(),
                sequence: 1,
                vendor_collateral: Vec::new(),
            },
            body_sha256: "00".repeat(32),
        };
        validate_shape(&envelope).unwrap();
        envelope.body.catalogs.push(catalog_fixture());
        validate_shape(&envelope).unwrap();

        let mut repeated_runtime = catalog_fixture();
        repeated_runtime.signed_release.manifest.sequence = 2;
        repeated_runtime.signed_release.manifest.source.tag = "catalog-v2".into();
        envelope.body.catalogs.push(repeated_runtime);
        validate_shape(&envelope).unwrap();

        envelope.body.catalogs[1].signed_release.manifest.sequence = 1;
        envelope.body.catalogs[1].signed_release.manifest.source.tag = "catalog-v1".into();
        assert!(
            validate_shape(&envelope)
                .unwrap_err()
                .to_string()
                .contains("duplicate catalog sequence")
        );
        envelope.body.catalogs.pop();

        envelope
            .body
            .hardware_policy
            .policy
            .policies
            .push(policy.policy.policies[0].clone());
        assert!(
            validate_hardware_policy(&envelope.body.hardware_policy.policy)
                .unwrap_err()
                .to_string()
                .contains("duplicate chip id")
        );
    }

    #[test]
    fn rejects_duplicate_node_ids_and_response_signing_keys_in_bundle() {
        let chip = [0x66; 64];
        let chip_id = hex::encode(chip);
        let measurement = [0x55; 48];
        let node = |tls_byte: u8, signing_key_byte: u8| {
            let tls_spki_sha256 = hex::encode([tls_byte; 32]);
            BundleNode {
                node_id: derive_node_id(&chip_id, &tls_spki_sha256),
                quote: quote_with_identity(chip, measurement, [0x33; 8]),
                report_data: ReportData {
                    accepted_cert_sha256: vec!["cc".repeat(32)],
                    drand: DrandBeacon {
                        chain_hash: DRAND_CHAIN_HASH.into(),
                        network: "quicknet".into(),
                        randomness: "dd".repeat(32),
                        round: 1,
                        signature: URL_SAFE_NO_PAD.encode([0_u8; 96]),
                    },
                    ed25519_public_key: URL_SAFE_NO_PAD.encode([signing_key_byte; 32]),
                    hpke_public_key: URL_SAFE_NO_PAD.encode([0xee; 1_216]),
                    schema: "stogas.node-report.v1".into(),
                    tls_spki_sha256,
                },
            }
        };
        let mut hardware_policy: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        hardware_policy.policy.policies[0].chip_ids = vec![chip_id.clone()];
        let mut envelope = BundleEnvelope {
            body: BundleBody {
                catalogs: Vec::new(),
                allowed_igvms: vec![release_fixture()],
                created_at: "2026-08-27T00:00:00.000Z".into(),
                expires_at: "2026-08-27T00:15:00.000Z".into(),
                hardware_policy,
                nodes: vec![node(0xaa, 1), node(0xbb, 2)],
                schema: "stogas.confidential-bundle.v1".into(),
                sequence: 1,
                vendor_collateral: Vec::new(),
            },
            body_sha256: "00".repeat(32),
        };
        validate_shape(&envelope).unwrap();

        let mut duplicate_node_id = envelope.clone();
        duplicate_node_id.body.nodes[1].report_data.tls_spki_sha256 = duplicate_node_id.body.nodes
            [0]
        .report_data
        .tls_spki_sha256
        .clone();
        duplicate_node_id.body.nodes[1].node_id = duplicate_node_id.body.nodes[0].node_id.clone();
        let error = validate_shape(&duplicate_node_id).unwrap_err();
        assert!(error.to_string().contains("duplicate node id"));

        let duplicate_key = envelope.body.nodes[0]
            .report_data
            .ed25519_public_key
            .clone();
        envelope.body.nodes[1].report_data.ed25519_public_key = duplicate_key;

        let error = validate_shape(&envelope).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate Ed25519 response signing key")
        );
    }

    #[test]
    fn inspects_only_raw_snp_identity_needed_for_collateral_selection() {
        let identity =
            inspect_snp_quote(&quote_with_identity([0x11; 64], [0x22; 48], [0x33; 8])).unwrap();
        assert_eq!(identity.chip_id, "11".repeat(64));
        assert_eq!(identity.cpuid_family, None);
        assert_eq!(identity.product_name, None);
        assert_eq!(identity.release_measurement, "22".repeat(48));
        assert_eq!(identity.report_version, 2);
        assert_eq!(identity.reported_tcb, "33".repeat(8));
    }

    #[test]
    fn maps_report_cpuid_to_milan_and_turin_without_guessing_future_products() {
        let milan = inspect_snp_quote(&quote_with_product_identity(
            5,
            [0x11; 64],
            [0x22; 48],
            [0x33; 8],
            Some((0x19, 0x0f, 0x2)),
        ))
        .unwrap();
        assert_eq!(milan.product_name.as_deref(), Some("Milan"));
        assert_eq!(milan.cpuid_family, Some(0x19));
        assert_eq!(milan.cpuid_model, Some(0x0f));
        assert_eq!(milan.cpuid_stepping, Some(0x2));

        let mut turin_chip = [0_u8; 64];
        turin_chip[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let turin = inspect_snp_quote(&quote_with_product_identity(
            5,
            turin_chip,
            [0x22; 48],
            [0x33; 8],
            Some((0x1a, 0x11, 0x0)),
        ))
        .unwrap();
        assert_eq!(turin.product_name.as_deref(), Some("Turin"));

        assert!(
            inspect_snp_quote(&quote_with_product_identity(
                5,
                [0x11; 64],
                [0x22; 48],
                [0x33; 8],
                Some((0x1a, 0x50, 0x0)),
            ))
            .is_err()
        );
        assert!(
            inspect_snp_quote(&quote_with_product_identity(
                2, turin_chip, [0x22; 48], [0x33; 8], None,
            ))
            .is_err()
        );
    }

    #[cfg(feature = "snp")]
    fn with_amd_crl_test_vector(
        crl_field: &str,
        test: impl FnOnce(
            &x509_parser::revocation_list::CertificateRevocationList<'_>,
            &x509_parser::certificate::X509Certificate<'_>,
            &x509_parser::certificate::X509Certificate<'_>,
            i64,
            i64,
        ),
    ) {
        use x509_parser::{parse_x509_certificate, parse_x509_crl};

        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/amd-crl-test-vectors.json"))
                .unwrap();
        assert_eq!(fixture["schema"], "stogas.amd-crl-test-vectors.v1");
        let decode = |field: &str| STANDARD.decode(fixture[field].as_str().unwrap()).unwrap();
        let root_der = decode("ark_der_base64");
        let intermediate_der = decode("ask_der_base64");
        let crl_der = decode(crl_field);
        let (root_remaining, ark) = parse_x509_certificate(&root_der).unwrap();
        let (intermediate_remaining, ask) = parse_x509_certificate(&intermediate_der).unwrap();
        let (crl_remaining, crl) = parse_x509_crl(&crl_der).unwrap();
        assert!(root_remaining.is_empty());
        assert!(intermediate_remaining.is_empty());
        assert!(crl_remaining.is_empty());
        assert_eq!(
            hex::encode(ask.raw_serial()),
            fixture["ask_serial_hex"].as_str().unwrap()
        );
        test(
            &crl,
            &ark,
            &ask,
            fixture["this_update_unix_ms"].as_i64().unwrap(),
            fixture["next_update_unix_ms"].as_i64().unwrap(),
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn accepts_an_ark_crl_that_does_not_revoke_the_ask() {
        with_amd_crl_test_vector(
            "clean_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                assert!(
                    crl.iter_revoked_certificates()
                        .any(|revoked| revoked.raw_serial() == [0])
                );
                assert_ne!(ask.raw_serial(), [0]);
                validate_amd_crl(crl, ark, ask, this_update, next_update).unwrap();
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn rejects_an_ark_crl_that_revokes_the_ask() {
        with_amd_crl_test_vector(
            "revoked_ask_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                let error = validate_amd_crl(crl, ark, ask, this_update, next_update).unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "node verification failed: AMD ASK is revoked"
                );
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn rejects_an_ask_signed_crl() {
        with_amd_crl_test_vector(
            "ask_signed_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                assert_eq!(crl.issuer(), ask.subject());
                let error = validate_amd_crl(crl, ark, ask, this_update, next_update).unwrap_err();
                assert!(error.to_string().contains("issuer differs from the ARK"));
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn rejects_an_amd_crl_signed_by_an_untrusted_ark() {
        with_amd_crl_test_vector(
            "wrong_ark_signed_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                assert_eq!(crl.issuer(), ark.subject());
                let error = validate_amd_crl(crl, ark, ask, this_update, next_update).unwrap_err();
                assert!(error.to_string().contains("AMD CRL signature"));
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn rejects_amd_crl_signature_algorithm_and_parameter_mismatches() {
        with_amd_crl_test_vector(
            "clean_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                let mut mismatched_algorithm = crl.clone();
                mismatched_algorithm.tbs_cert_list.signature.parameters = None;
                let error =
                    validate_amd_crl(&mismatched_algorithm, ark, ask, this_update, next_update)
                        .unwrap_err();
                assert!(error.to_string().contains("one matching RSA-PSS"));

                let mut missing_parameters = crl.clone();
                missing_parameters.signature_algorithm.parameters = None;
                missing_parameters.tbs_cert_list.signature.parameters = None;
                let error =
                    validate_amd_crl(&missing_parameters, ark, ask, this_update, next_update)
                        .unwrap_err();
                assert!(error.to_string().contains("invalid RSA-PSS"));
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn requires_the_crl_for_the_complete_bundle_interval() {
        with_amd_crl_test_vector(
            "clean_crl_der_base64",
            |crl, ark, ask, this_update, next_update| {
                let future = validate_amd_crl(
                    crl,
                    ark,
                    ask,
                    this_update - MAX_CLOCK_SKEW_MS - 1,
                    next_update,
                )
                .unwrap_err();
                assert!(future.to_string().contains("future-dated"));

                let expired =
                    validate_amd_crl(crl, ark, ask, this_update, next_update + 1).unwrap_err();
                assert!(expired.to_string().contains("expires before the bundle"));

                let mut missing_next_update = crl.clone();
                missing_next_update.tbs_cert_list.next_update = None;
                let missing =
                    validate_amd_crl(&missing_next_update, ark, ask, this_update, next_update)
                        .unwrap_err();
                assert!(missing.to_string().contains("expires before the bundle"));
            },
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn validates_turin_vcek_structure_tcb_and_psn_extensions() {
        use x509_parser::parse_x509_certificate;

        let der = STANDARD
            .decode(include_str!("../tests/fixtures/vcek-turin.der.base64").trim())
            .unwrap();
        let (_, vcek) = parse_x509_certificate(&der).unwrap();
        let chip_id = format!("{}{}", "1e550a8ee5cf9f4d", "00".repeat(56));
        let profile = validate_vcek_extensions(&vcek, &chip_id, "0000000000000009").unwrap();
        assert_eq!(profile.product_name, "Turin");
        assert_eq!(profile.struct_version, 1);
        assert_eq!(profile.tcb_layout, AmdTcbLayout::Family1ah);
        assert!(validate_vcek_extensions(&vcek, &chip_id, "0000000000000008").is_err());
        assert!(validate_vcek_extensions(&vcek, &"11".repeat(64), "0000000000000009").is_err());
    }

    #[test]
    fn quote_inspection_rejects_noncanonical_envelopes_and_sizes() {
        let extra_field = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "extra": true,
                "provider": "sev_guest",
                "report": URL_SAFE_NO_PAD.encode(vec![0_u8; 0x4a0]),
                "schema": "stogas.sev-snp-quote-envelope.v1"
            }))
            .unwrap(),
        );
        assert!(inspect_snp_quote(&extra_field).is_err());

        let short = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "provider": "sev_guest",
                "report": URL_SAFE_NO_PAD.encode(vec![0_u8; 0x49f]),
                "schema": "stogas.sev-snp-quote-envelope.v1"
            }))
            .unwrap(),
        );
        assert!(inspect_snp_quote(&short).is_err());
    }

    fn local_admission_fixture(now_unix_ms: i64) -> serde_json::Value {
        use ed25519_dalek::{Signer as _, SigningKey};

        let release_manifest = release_fixture().release_manifest;
        let heartbeat_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let report_data = ReportData {
            accepted_cert_sha256: vec!["11".repeat(32)],
            drand: DrandBeacon {
                chain_hash: DRAND_CHAIN_HASH.into(),
                network: "quicknet".into(),
                randomness: "33".repeat(32),
                round: 1,
                signature: "44".repeat(48),
            },
            ed25519_public_key: URL_SAFE_NO_PAD.encode(heartbeat_signing_key.verifying_key()),
            hpke_public_key: "local-hpke".into(),
            schema: "stogas.node-report.v1".into(),
            tls_spki_sha256: "55".repeat(32),
        };
        let report_data_sha512 = hex::encode(Sha512::digest(
            canonical_report_data(&report_data).unwrap().as_bytes(),
        ));
        let generated_at = DateTime::<Utc>::from_timestamp_millis(now_unix_ms)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let quote = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "attester_mode": "mock",
                "quote_generated_at": generated_at,
                "report_data_sha512": report_data_sha512,
                "schema": "stogas.local-mock-quote.v1"
            }))
            .unwrap(),
        );
        let mut request = serde_json::json!({
            "attester_mode": "mock",
            "heartbeat": {
                "active_cert_sha256": "11".repeat(32),
                "catalog": {
                    "digest": format!("sha256:{}", "22".repeat(32)),
                    "sequence": 7
                },
                "cert_expires_at": "2026-08-01T00:00:00.000Z",
                "health": { "ready": true, "secret_versions": {} },
                "node_id": "local-node",
                "observed_at": generated_at,
                "quote": quote,
                "quote_generated_at": generated_at,
                "report_data": report_data,
                "report_data_sha512": report_data_sha512,
                "signature": ""
            },
            "release_manifests": [release_manifest],
            "region": "local",
            "trusted_chip_ids": ["66".repeat(64)]
        });
        let heartbeat: HeartbeatCandidate =
            serde_json::from_value(request["heartbeat"].clone()).unwrap();
        let signature =
            heartbeat_signing_key.sign(&heartbeat_signature_transcript(&heartbeat).unwrap());
        request["heartbeat"]["signature"] =
            Value::String(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        request
    }

    #[cfg(feature = "snp")]
    #[test]
    fn raw_snp_binding_requires_the_hardened_launch_policy_baseline() {
        let now = 1_784_246_400_000;
        let request = local_admission_fixture(now);
        let heartbeat: HeartbeatCandidate =
            serde_json::from_value(request["heartbeat"].clone()).unwrap();
        let mut manifest = release_fixture().release_manifest;
        manifest.sev_snp.launch_policies.policies[0].launch.policy = "0x000000000013013a".into();
        let node = Node {
            cert_expires_at: heartbeat.cert_expires_at,
            chip_id: "00".repeat(64),
            health: heartbeat.health,
            node_id: heartbeat.node_id,
            quote: heartbeat.quote,
            quote_verified_at: heartbeat.observed_at,
            region: "test".into(),
            release_measurement: manifest.sev_snp.launch_measurement.clone(),
            reported_tcb: "00".repeat(8),
            report_data: heartbeat.report_data,
            report_data_sha512: heartbeat.report_data_sha512,
        };
        let report = vec![0_u8; 0x4a0];
        let evidence = AttestedNode {
            chip_id: &node.chip_id,
            node_id: &node.node_id,
            quote: &node.quote,
            release_measurement: &node.release_measurement,
            report_data: &node.report_data,
            report_data_sha512: &node.report_data_sha512,
            reported_tcb: &node.reported_tcb,
        };

        let error = check_raw_report_bindings(
            &evidence,
            &manifest,
            &manifest.sev_snp.launch_policies.policies[0].launch,
            &report,
            None,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("required admitted platform protections")
        );

        manifest.sev_snp.launch_policies.policies[0].launch.policy = "0x000000000213013a".into();
        let error = check_raw_report_bindings(
            &evidence,
            &manifest,
            &manifest.sev_snp.launch_policies.policies[0].launch,
            &report,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SNP report version differs"));
    }

    #[cfg(feature = "snp")]
    #[test]
    fn raw_snp_binding_accepts_only_absent_migration_agent_ids() {
        assert!(is_absent_snp_migration_agent_id(&[0; 32]));
        assert!(is_absent_snp_migration_agent_id(&[0xff; 32]));

        let mut migration_agent_id = [0; 32];
        migration_agent_id[31] = 1;
        assert!(!is_absent_snp_migration_agent_id(&migration_agent_id));
    }

    #[test]
    fn snp_policy_requirements_are_product_specific() {
        let milan = AMD_PRODUCT_PROFILES
            .iter()
            .find(|profile| profile.product_name == "Milan")
            .unwrap();
        let genoa = AMD_PRODUCT_PROFILES
            .iter()
            .find(|profile| profile.product_name == "Genoa")
            .unwrap();
        let milan_policy = 0x0000_0000_0213_013a;

        validate_snp_launch_policy(milan_policy, Some(milan)).unwrap();
        let error = validate_snp_launch_policy(milan_policy, Some(genoa)).unwrap_err();
        assert!(error.to_string().contains("required Genoa protections"));
        validate_snp_launch_policy(milan_policy | SNP_POLICY_MEM_AES_256_XTS, Some(genoa)).unwrap();
    }

    #[test]
    fn local_mock_admission_uses_the_rust_boundary_without_claiming_amd_trust() {
        let now = 1_784_246_400_000;
        let request = local_admission_fixture(now);
        let output =
            verify_local_heartbeat_admission(&serde_json::to_vec(&request).unwrap(), now).unwrap();
        assert_eq!(output.node.chip_id, "66".repeat(64));
        assert_eq!(output.node.reported_tcb, "00".repeat(8));
        assert_eq!(output.verified.evidence_age_ms, 0);
        assert_eq!(output.verified.quote, output.node.quote);

        for mutation in [
            "/heartbeat/report_data_sha512",
            "/heartbeat/quote_generated_at",
            "/heartbeat/observed_at",
        ] {
            let mut invalid = request.clone();
            *invalid.pointer_mut(mutation).unwrap() = Value::String("invalid".into());
            assert!(
                verify_local_heartbeat_admission(&serde_json::to_vec(&invalid).unwrap(), now)
                    .is_err(),
                "accepted mutated local admission field {mutation}"
            );
        }

        let mut legacy_verifier = request.clone();
        legacy_verifier["heartbeat"]["quote_verifier_jwt"] = Value::String("untrusted.jwt".into());
        assert!(
            verify_local_heartbeat_admission(&serde_json::to_vec(&legacy_verifier).unwrap(), now)
                .is_err(),
            "accepted retired verifier JWT metadata"
        );

        let mut ambiguous = request;
        ambiguous["trusted_chip_ids"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("77".repeat(64)));
        assert!(
            verify_local_heartbeat_admission(&serde_json::to_vec(&ambiguous).unwrap(), now)
                .unwrap_err()
                .to_string()
                .contains("exactly one chip")
        );
    }

    #[test]
    fn heartbeat_signature_binds_the_mutable_catalog_identity() {
        let now = 1_784_246_400_000;
        let request = local_admission_fixture(now);
        let heartbeat: HeartbeatCandidate =
            serde_json::from_value(request["heartbeat"].clone()).unwrap();
        let public_key = heartbeat.report_data.ed25519_public_key.clone();
        verify_recognized_heartbeat_signature(
            &serde_json::to_vec(&heartbeat).unwrap(),
            &public_key,
        )
        .unwrap();

        let mut changed_digest = heartbeat.clone();
        changed_digest.catalog.digest = format!("sha256:{}", "23".repeat(32));
        let error = verify_recognized_heartbeat_signature(
            &serde_json::to_vec(&changed_digest).unwrap(),
            &public_key,
        )
        .unwrap_err();
        assert!(error.to_string().contains("heartbeat signature is invalid"));

        let mut changed_sequence = heartbeat;
        changed_sequence.catalog.sequence += 1;
        let error = verify_recognized_heartbeat_signature(
            &serde_json::to_vec(&changed_sequence).unwrap(),
            &public_key,
        )
        .unwrap_err();
        assert!(error.to_string().contains("heartbeat signature is invalid"));
    }

    #[test]
    fn public_node_evidence_rejects_unattested_catalog_metadata() {
        let request = local_admission_fixture(1_784_246_400_000);
        let heartbeat: HeartbeatCandidate =
            serde_json::from_value(request["heartbeat"].clone()).unwrap();
        let catalog = serde_json::to_value(&heartbeat.catalog).unwrap();
        let node = BundleNode {
            node_id: heartbeat.node_id,
            quote: heartbeat.quote,
            report_data: heartbeat.report_data,
        };

        let mut node_value = serde_json::to_value(&node).unwrap();
        node_value["catalog"] = catalog.clone();
        assert!(serde_json::from_value::<BundleNode>(node_value).is_err());

        let mut report_value = serde_json::to_value(&node.report_data).unwrap();
        report_value["catalog"] = catalog;
        assert!(serde_json::from_value::<ReportData>(report_value).is_err());
    }

    #[cfg(feature = "snp")]
    #[test]
    fn local_software_snp_signature_path_rejects_report_and_reserved_byte_mutations() {
        use p384::{
            ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _},
            pkcs8::EncodePublicKey as _,
        };
        use sha2::Sha384;

        let signing_key = SigningKey::from_bytes((&[0x42_u8; 48]).into()).unwrap();
        let mut report = vec![0_u8; 0x4a0];
        let digest = Sha384::digest(&report[..0x2a0]);
        let signature: p384::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let raw = signature.to_bytes();
        for index in 0..48 {
            report[0x2a0 + index] = raw[47 - index];
            report[0x2a0 + 72 + index] = raw[95 - index];
        }
        let public_key = STANDARD.encode(
            signing_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        );

        verify_local_raw_report_signature(&report, Some(&public_key)).unwrap();
        let mut signed_mutation = report.clone();
        signed_mutation[0x50] ^= 1;
        assert!(verify_local_raw_report_signature(&signed_mutation, Some(&public_key)).is_err());
        let mut reserved_mutation = report;
        reserved_mutation[0x2a0 + 48] = 1;
        assert!(verify_local_raw_report_signature(&reserved_mutation, Some(&public_key)).is_err());
    }

    #[cfg(not(feature = "snp"))]
    #[test]
    fn local_software_snp_signature_path_is_unavailable_without_snp_support() {
        let error = verify_local_raw_report_signature(&[0_u8; 0x4a0], None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("local SNP signature verification is unavailable")
        );
    }

    #[test]
    fn pinned_quicknet_vector_rejects_round_randomness_and_signature_mutations() {
        let vector = DrandBeacon {
            chain_hash: DRAND_CHAIN_HASH.into(),
            network: "quicknet".into(),
            randomness: "b71151f3a4a15822dbe07915b282f5c90edd9da0e2cc410099d6fc392654f8dd"
                .into(),
            round: 30_051_238,
            signature: "b79a809ed952e5b7def6f8494b8a909728b80f8d17d6d47f05ab1d43e1cc5391d9ab9ce77b871dc69bc4523db77d2f5c".into(),
        };
        verify_quicknet(&vector).unwrap();

        let mut wrong_round = vector.clone();
        wrong_round.round += 1;
        assert!(verify_quicknet(&wrong_round).is_err());
        let mut wrong_randomness = vector.clone();
        wrong_randomness.randomness = "00".repeat(32);
        assert!(verify_quicknet(&wrong_randomness).is_err());
        let mut wrong_signature = vector;
        wrong_signature.signature.replace_range(..2, "00");
        assert!(verify_quicknet(&wrong_signature).is_err());
    }

    fn resign_release(release: &mut AllowedIgvm) -> String {
        use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let canonical =
            canonical_json(&serde_json::to_value(&release.release_manifest).unwrap()).unwrap();
        let mut payload = b"stogas gateway counterbuild v1\n".to_vec();
        payload.extend_from_slice(canonical.as_bytes());
        release.stogas_signature.key_id = "test-release-key".into();
        release.stogas_signature.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        STANDARD.encode(
            signing_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }

    fn resign_catalog(catalog: &mut AllowedCatalog) -> String {
        use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let canonical =
            canonical_json(&serde_json::to_value(&catalog.signed_release.manifest).unwrap())
                .unwrap();
        let canonical = canonical.strip_suffix('\n').unwrap();
        let mut payload = b"stogas catalog release v1\n".to_vec();
        payload.extend_from_slice(canonical.as_bytes());
        catalog.signed_release.key_id = "test-release-key".into();
        catalog.signed_release.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        STANDARD.encode(
            signing_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = strict_json::from_slice(br#"{"body":1,"body":2}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key"));
    }

    #[test]
    fn changing_a_release_manifest_requires_fresh_stogas_and_github_approval() {
        let release = release_fixture();
        let error = verify_release(&release, 1_784_246_400_000).unwrap_err();
        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn release_manifest_rejects_nonzero_vmpl() {
        let mut release = release_fixture();
        release.release_manifest.sev_snp.launch_policies.policies[0]
            .launch
            .vmpl = 1;
        let error = validate_release_shape(&release).unwrap_err();
        assert!(error.to_string().contains("invalid gateway launch policy"));
    }

    #[test]
    fn release_approval_boundary_rejects_duplicate_fields() {
        let duplicate = br#"{"github_in_toto":[],"github_in_toto":[]}"#;
        assert!(verify_release_approval(duplicate, 1_784_246_400_000).is_err());
    }

    #[test]
    fn staging_release_policy_is_fixed_by_the_compiled_artifact() {
        let mut release = release_fixture();
        let key = resign_release(&mut release);
        let canonical =
            canonical_json(&serde_json::to_value(&release.release_manifest).unwrap()).unwrap();
        let manifest_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        release.github_in_toto = vec![serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://stogas.ai/attestations/staging-development/v1",
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "release-manifest.json", "digest": { "sha256": manifest_digest } }
            ]
        })];

        #[cfg(feature = "staging")]
        {
            let verified = verify_release_with_key(&release, &key, 1_784_246_400_000).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            release.github_in_toto[0]["subject"][0]["digest"]["sha256"] =
                Value::String("00".repeat(32));
            assert!(verify_release_with_key(&release, &key, 1_784_246_400_000).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_release_with_key(&release, &key, 1_784_246_400_000).is_err());
    }

    #[test]
    fn staging_catalog_policy_is_fixed_by_the_compiled_artifact() {
        let mut catalog = catalog_fixture();
        let key = resign_catalog(&mut catalog);
        let canonical =
            canonical_json(&serde_json::to_value(&catalog.signed_release.manifest).unwrap())
                .unwrap();
        let manifest_digest = hex::encode(Sha256::digest(
            canonical.strip_suffix('\n').unwrap().as_bytes(),
        ));
        catalog.github_in_toto = vec![serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://stogas.ai/attestations/staging-development/v1",
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "catalog-release.json", "digest": { "sha256": manifest_digest } }
            ]
        })];

        #[cfg(feature = "staging")]
        {
            let verified = verify_catalog_with_key(&catalog, &key, 1_784_246_400_000).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            catalog.github_in_toto[0]["subject"][0]["digest"]["sha256"] =
                Value::String("00".repeat(32));
            assert!(verify_catalog_with_key(&catalog, &key, 1_784_246_400_000).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_catalog_with_key(&catalog, &key, 1_784_246_400_000).is_err());
    }

    #[cfg(feature = "staging")]
    #[test]
    fn changing_catalog_identity_requires_fresh_stogas_and_github_approval() {
        let now = 1_784_246_400_000;
        let mut catalog = catalog_fixture();
        let key = resign_catalog(&mut catalog);
        let canonical =
            canonical_json(&serde_json::to_value(&catalog.signed_release.manifest).unwrap())
                .unwrap();
        let manifest_digest = hex::encode(Sha256::digest(
            canonical.strip_suffix('\n').unwrap().as_bytes(),
        ));
        catalog.github_in_toto = vec![serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://stogas.ai/attestations/staging-development/v1",
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "catalog-release.json", "digest": { "sha256": manifest_digest } }
            ]
        })];
        verify_catalog_with_key(&catalog, &key, now).unwrap();

        catalog.signed_release.manifest.runtime = format!("sha256:{}", "99".repeat(32));
        assert!(verify_catalog_with_key(&catalog, &key, now).is_err());

        let key = resign_catalog(&mut catalog);
        let error = verify_catalog_with_key(&catalog, &key, now).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("staging development provenance subjects differ")
        );

        let canonical =
            canonical_json(&serde_json::to_value(&catalog.signed_release.manifest).unwrap())
                .unwrap();
        let manifest_digest = hex::encode(Sha256::digest(
            canonical.strip_suffix('\n').unwrap().as_bytes(),
        ));
        catalog.github_in_toto[0]["subject"][0]["digest"]["sha256"] =
            Value::String(manifest_digest);
        verify_catalog_with_key(&catalog, &key, now).unwrap();
    }

    #[test]
    fn approval_cache_key_is_the_complete_approval_sha256() {
        let release = release_fixture();
        let encoded = serde_json::to_vec(&release).unwrap();
        let original_key = approval_cache_key(&release).unwrap();
        let expected: ApprovalCacheKey = Sha256::digest(encoded).into();
        assert_eq!(original_key, expected);
        let mut changed = release;
        changed
            .github_in_toto
            .push(serde_json::json!({"different": true}));
        assert_ne!(original_key, approval_cache_key(&changed).unwrap());
    }

    #[test]
    fn rejects_invalid_stogas_release_signature_before_accepting_github_evidence() {
        let mut release = release_fixture();
        release.stogas_signature.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        let error = verify_release(&release, 1_784_246_400_000).unwrap_err();
        assert!(error.to_string().contains("release verification failed"));
    }

    #[test]
    fn rejects_resigned_manifest_when_github_did_not_attest_exact_bytes() {
        let mutations: [fn(&mut AllowedIgvm); 3] = [
            |release: &mut AllowedIgvm| {
                release
                    .release_manifest
                    .sev_snp
                    .launch_measurement
                    .replace_range(..2, "aa");
            },
            |release: &mut AllowedIgvm| {
                release
                    .release_manifest
                    .artifacts
                    .gateway_igvm
                    .sha256
                    .replace_range(..2, "aa");
            },
            |release: &mut AllowedIgvm| {
                release.release_manifest.git.tree.replace_range(..2, "aa");
            },
        ];
        for mutate in mutations {
            let mut release = release_fixture();
            mutate(&mut release);
            let key = resign_release(&mut release);
            let error = verify_release_with_key(&release, &key, 1_784_246_400_000).unwrap_err();
            assert!(error.to_string().contains("Sigstore"));
        }
    }

    #[test]
    fn release_manifest_canonicalization_sorts_recursively_and_ends_with_newline() {
        let value = serde_json::json!({"z": [2, {"b": true, "a": null}], "a": "x"});
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"a\":\"x\",\"z\":[2,{\"a\":null,\"b\":true}]}\n"
        );
    }

    #[test]
    fn accepts_a_historical_proof_that_was_fresh_when_control_admitted_it() {
        let round = 1_000_000_u64;
        let round_time = (DRAND_GENESIS_SECONDS
            + i64::try_from(round - 1).unwrap() * DRAND_PERIOD_SECONDS)
            * 1000;
        let quote_verified_at = round_time + DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS;
        let now = round_time + MAX_NODE_EVIDENCE_AGE_MS;

        assert_eq!(
            validate_node_evidence_time("node", round, quote_verified_at, now).unwrap(),
            round_time
        );
    }

    #[test]
    fn rejects_drand_that_was_already_stale_when_control_verified_quote() {
        let round = 1_000_000_u64;
        let round_time = (DRAND_GENESIS_SECONDS
            + i64::try_from(round - 1).unwrap() * DRAND_PERIOD_SECONDS)
            * 1000;
        let quote_verified_at = round_time + DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS + 1;
        let error =
            validate_node_evidence_time("node", round, quote_verified_at, quote_verified_at)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("stale when the quote was verified")
        );
    }
}
