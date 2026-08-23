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
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
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
const HARDWARE_POLICY_SIGNATURE_DOMAIN: &[u8] = b"stogas hardware policy v1\n";
const SNP_PLATFORM_INFO_KNOWN_MASK: u64 = 0xbf;

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

/// Runtime-independent trust configuration.
#[derive(Clone, Debug)]
pub struct Environment {
    /// Trusted Stogas release signing keys, keyed by key id, as base64 SPKI DER.
    pub release_keys: BTreeMap<String, String>,
    #[cfg(feature = "staging")]
    allow_staging_development_provenance: bool,
}

impl Environment {
    /// Standard Stogas trust roots and freshness policy.
    #[must_use]
    pub fn stogas() -> Self {
        let release_keys = BTreeMap::from([(
            STOGAS_RELEASE_KEY_ID.to_owned(),
            STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64.to_owned(),
        )]);
        Self {
            release_keys,
            #[cfg(feature = "staging")]
            allow_staging_development_provenance: false,
        }
    }

    #[cfg(feature = "staging")]
    #[doc(hidden)]
    #[must_use]
    pub fn staging() -> Self {
        Self {
            #[cfg(feature = "staging")]
            allow_staging_development_provenance: true,
            ..Self::stogas()
        }
    }
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

/// Verifier with a bounded in-memory cache for immutable release evidence.
///
/// The cache is only a performance optimization. It is deliberately ephemeral and cannot bypass
/// GitHub or Stogas signature verification for new release bytes.
#[derive(Debug, Default)]
pub struct Verifier {
    active_bundle: Option<VerificationOutput>,
    verified_catalogs: BTreeMap<String, VerifiedCatalogRelease>,
    verified_releases: BTreeMap<String, VerifiedRelease>,
}

struct VerificationCache {
    catalogs: BTreeMap<String, VerifiedCatalogRelease>,
    releases: BTreeMap<String, VerifiedRelease>,
}

/// Exact bytes and trust context required to verify one historical response receipt.
pub struct HistoricalResponseProofInput<'a> {
    /// Compact response receipt bytes.
    pub proof_bytes: &'a [u8],
    /// Exact plaintext request body.
    pub request_body: &'a [u8],
    /// Exact plaintext response body.
    pub response_body: &'a [u8],
    /// Expected E2EE transcript hash when application encryption was used.
    pub expected_e2ee_transcript_sha256: Option<&'a str>,
    /// One captured verification wall-clock value.
    pub now_unix_ms: i64,
    /// Immutable node-admission ledger bytes.
    pub ledger_bytes: &'a [u8],
    /// Immutable catalog approval bytes selected by the signed catalog sequence.
    pub catalog_approval_bytes: &'a [u8],
    /// Release and hardware trust policy.
    pub environment: &'a Environment,
}

/// Locally computed hashes and trust context for constant-memory historical verification.
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
    /// Release and hardware trust policy.
    pub environment: &'a Environment,
}

impl Verifier {
    /// Verify a bundle and retain only the release results referenced by that accepted bundle.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the release cache.
    pub fn verify_bundle(
        &mut self,
        bundle_bytes: &[u8],
        now_unix_ms: i64,
        environment: &Environment,
    ) -> Result<VerificationOutput, Error> {
        self.verify_bundle_using_policy(bundle_bytes, None, now_unix_ms, environment)
    }

    /// Verify a bundle while replacing only its mutable hardware appraisal rules.
    ///
    /// The bundled Stogas policy signature is still checked. The local policy cannot disable
    /// quote signatures, certificate chains, report bindings, launch policy, or freshness checks.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active bundle or release cache.
    pub fn verify_bundle_with_policy(
        &mut self,
        bundle_bytes: &[u8],
        local_policy_bytes: &[u8],
        now_unix_ms: i64,
        environment: &Environment,
    ) -> Result<VerificationOutput, Error> {
        self.verify_bundle_using_policy(
            bundle_bytes,
            Some(local_policy_bytes),
            now_unix_ms,
            environment,
        )
    }

    fn verify_bundle_using_policy(
        &mut self,
        bundle_bytes: &[u8],
        local_policy_bytes: Option<&[u8]>,
        now_unix_ms: i64,
        environment: &Environment,
    ) -> Result<VerificationOutput, Error> {
        let (output, next_cache) = verify_bundle_inner(
            bundle_bytes,
            local_policy_bytes,
            now_unix_ms,
            environment,
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
        proof_bytes: &[u8],
        request_body: &[u8],
        response_body: &[u8],
        expected_e2ee_transcript_sha256: Option<&str>,
        now_unix_ms: i64,
    ) -> Result<response_proof::VerifiedResponseProof, Error> {
        let bundle = self.active_bundle.as_ref().ok_or_else(|| {
            Error::ResponseProof("a bundle must be verified before a response proof".into())
        })?;
        response_proof::verify_with_bundle(
            proof_bytes,
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
        let ledger = verify_node_ledger_record(input.ledger_bytes, input.environment)?;
        let catalog = verify_catalog_approval_with_environment(
            input.catalog_approval_bytes,
            input.environment,
            input.now_unix_ms,
        )?;
        response_proof::verify_with_ledger(
            input.proof_bytes,
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
        let ledger = verify_node_ledger_record(input.ledger_bytes, input.environment)?;
        let catalog = verify_catalog_approval_with_environment(
            input.catalog_approval_bytes,
            input.environment,
            input.now_unix_ms,
        )?;
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
pub fn verify_bundle(
    bundle_bytes: &[u8],
    now_unix_ms: i64,
    environment: &Environment,
) -> Result<VerificationOutput, Error> {
    Verifier::default().verify_bundle(bundle_bytes, now_unix_ms, environment)
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
    environment: &Environment,
) -> Result<VerificationOutput, Error> {
    Verifier::default().verify_bundle_with_policy(
        bundle_bytes,
        local_policy_bytes,
        now_unix_ms,
        environment,
    )
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
    verify_release(&release, &Environment::stogas(), now_unix_ms)
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
    verify_catalog_approval_with_environment(approval_bytes, &Environment::stogas(), now_unix_ms)
}

#[cfg(feature = "staging")]
#[doc(hidden)]
pub fn verify_staging_catalog_approval(
    approval_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    verify_catalog_approval_with_environment(approval_bytes, &Environment::staging(), now_unix_ms)
}

fn verify_catalog_approval_with_environment(
    approval_bytes: &[u8],
    environment: &Environment,
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    if approval_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(approval_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let catalog: AllowedCatalog =
        serde_json::from_value(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    verify_catalog(&catalog, environment, now_unix_ms)
}

#[cfg(feature = "staging")]
#[doc(hidden)]
pub fn verify_staging_release_approval(
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
    verify_release(&release, &Environment::staging(), now_unix_ms)
}

/// Verify one immutable historical node-admission ledger record.
///
/// Verification is anchored to the recorded admission time, so an expired certificate or AMD
/// collateral does not invalidate evidence that was valid when Control admitted the node.
/// The node ID is independently re-derived from the quote-bound chip and TLS identities.
///
/// # Errors
///
/// Returns an error when the release provenance, SNP quote, AMD collateral, report data, drand
/// evidence, or node identity is invalid.
pub fn verify_node_ledger_record(
    record_bytes: &[u8],
    environment: &Environment,
) -> Result<VerifiedNodeLedgerRecord, Error> {
    if record_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(record_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let record: NodeLedgerRecord = serde_json::from_value(value)
        .map_err(|error| Error::InvalidBundle(format!("invalid node ledger record: {error}")))?;
    if record.schema != "stogas.node-ledger.v1" || !is_lower_hex(&record.node_id, 32) {
        return Err(Error::InvalidBundle(
            "unsupported or invalid node ledger record".into(),
        ));
    }
    if !is_lower_hex(&record.release_measurement, 32)
        && !is_lower_hex(&record.release_measurement, 48)
    {
        return Err(Error::InvalidBundle(
            "node ledger release measurement is invalid".into(),
        ));
    }
    if record.release_measurement != record.release.launch_policy.measurement {
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
    if record.certificate_history.is_empty() || record.certificate_history.len() > 64 {
        return Err(Error::InvalidBundle(
            "node ledger certificate history is empty or too large".into(),
        ));
    }
    validate_ledger_certificate_history(&record, admitted_at)?;
    let release = verify_release(&record.release, environment, admitted_at)?;
    let hardware_policy = verify_signed_hardware_policy(&record.hardware_policy, environment)?;
    let node = ledger_record_node(&record);
    if hardware_policy.policy.chip_id != node.chip_id {
        return Err(Error::InvalidBundle(
            "node ledger hardware policy is bound to a different chip id".into(),
        ));
    }
    validate_node_shape(&node)?;
    let node_preimage = format!(
        "{{\"chip_id\":\"{}\",\"tls_spki_sha256\":\"{}\"}}",
        node.chip_id, node.report_data.tls_spki_sha256
    );
    let derived_node_id = hex::encode(Sha256::digest(node_preimage.as_bytes()));
    if derived_node_id != record.node_id {
        return Err(Error::Node(
            "node ledger node ID differs from its attested identity".into(),
        ));
    }
    let launch_policies = BTreeMap::from([(
        record.release_measurement.as_str(),
        &record.release.launch_policy,
    )]);
    let amd_stacks = verified_amd_stacks(
        &record.admission.endorsements,
        std::slice::from_ref(&node),
        admitted_at,
        admitted_at,
    )?;
    let verified_node = verify_node(
        &node,
        NodeVerificationTime::at(admitted_at),
        &launch_policies,
        &amd_stacks,
        &hardware_policy.policy,
    )?;
    Ok(VerifiedNodeLedgerRecord {
        admitted_at_unix_ms: admitted_at,
        node_id: record.node_id,
        node: verified_node,
        release,
    })
}

fn validate_ledger_certificate_history(
    record: &NodeLedgerRecord,
    admitted_at: i64,
) -> Result<(), Error> {
    let mut certificate_hashes = BTreeSet::new();
    let mut previous_certificate = None;
    for certificate in &record.certificate_history {
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

fn ledger_record_node(record: &NodeLedgerRecord) -> Node {
    Node {
        cert_expires_at: record.admission.cert_expires_at.clone(),
        chip_id: record.admission.chip_id.clone(),
        health: NodeHealth {
            last_quote_error: None,
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
    let hardware_policy =
        verify_signed_hardware_policy(&request.hardware_policy, &Environment::stogas())?;
    if request.launch_policies.is_empty() || request.launch_policies.len() > 2 {
        return Err(Error::InvalidBundle(
            "admission requires one or two launch policies".into(),
        ));
    }
    if request.vendor_collateral.len() > MAX_VENDOR_COLLATERAL {
        return Err(Error::InvalidBundle(
            "admission contains too many collateral records".into(),
        ));
    }
    let heartbeat = &request.heartbeat;
    for (label, value) in [
        ("heartbeat observation", &heartbeat.observed_at),
        ("quote generation", &heartbeat.quote_generated_at),
    ] {
        if parse_time(value)? > now_unix_ms + MAX_CLOCK_SKEW_MS {
            return Err(Error::Node(format!("{label} time is in the future")));
        }
    }
    let identity = inspect_snp_quote(&heartbeat.quote)?;
    if hardware_policy.policy.chip_id != identity.chip_id {
        return Err(Error::Node(
            "SNP chip id differs from the signed hardware policy".into(),
        ));
    }
    if !request
        .trusted_chip_ids
        .iter()
        .any(|chip| chip.eq_ignore_ascii_case(&identity.chip_id))
    {
        return Err(Error::Node("unknown chip id".into()));
    }
    let mut policies = BTreeMap::new();
    for policy in &request.launch_policies {
        if policies
            .insert(policy.measurement.as_str(), policy)
            .is_some()
        {
            return Err(Error::InvalidBundle(
                "admission launch policies contain a duplicate measurement".into(),
            ));
        }
    }
    if !policies.contains_key(identity.release_measurement.as_str()) {
        return Err(Error::Node(
            "SNP measurement is absent from the authorized release stack".into(),
        ));
    }
    if parse_time(&heartbeat.cert_expires_at)? <= now_unix_ms {
        return Err(Error::Node("active certificate is expired".into()));
    }
    let node = Node {
        cert_expires_at: heartbeat.cert_expires_at.clone(),
        chip_id: identity.chip_id,
        health: heartbeat.health.clone(),
        node_id: heartbeat.node_id.clone(),
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
    let amd_stacks = verified_amd_stacks(
        &request.vendor_collateral,
        std::slice::from_ref(&node),
        now_unix_ms,
        now_unix_ms,
    )?;
    let verified = verify_node(
        &node,
        NodeVerificationTime::at(now_unix_ms),
        &policies,
        &amd_stacks,
        &hardware_policy.policy,
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
    let launch_policy = request
        .launch_policies
        .iter()
        .find(|policy| {
            policy
                .measurement
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
            check_raw_report_bindings(&node, launch_policy, report, None)?;
            verify_local_raw_report_signature(
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
        region: node.region.clone(),
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
    transcript.extend_from_slice(HEARTBEAT_SIGNATURE_DOMAIN);
    for field in [
        heartbeat.node_id.as_bytes(),
        heartbeat.cert_expires_at.as_bytes(),
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
            .last_quote_error
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
    if request.launch_policies.is_empty() || request.launch_policies.len() > 2 {
        return Err(Error::InvalidBundle(
            "local admission requires one or two launch policies".into(),
        ));
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
    if request.trusted_chip_ids.len() != 1 || request.launch_policies.len() != 1 {
        return Err(Error::Node(
            "local mock admission requires exactly one chip and release".into(),
        ));
    }
    Ok(LocalQuoteIdentity {
        chip_id: request.trusted_chip_ids[0].to_lowercase(),
        raw_report: None,
        release_measurement: request.launch_policies[0].measurement.to_lowercase(),
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

fn select_hardware_policies(
    signed: &[SignedHardwarePolicy],
    local_policy_bytes: Option<&[u8]>,
    environment: &Environment,
) -> Result<Vec<SelectedHardwarePolicy>, Error> {
    let mut selected = signed
        .iter()
        .map(|policy| verify_signed_hardware_policy(policy, environment))
        .collect::<Result<Vec<_>, _>>()?;
    let mut chip_ids = BTreeSet::new();
    if selected
        .iter()
        .any(|policy| !chip_ids.insert(policy.policy.chip_id.as_str()))
    {
        return Err(Error::InvalidBundle(
            "hardware policies contain a duplicate chip id".into(),
        ));
    }
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
    let local = SelectedHardwarePolicy {
        verified: VerifiedHardwarePolicy {
            chip_id: policy.chip_id.clone(),
            sequence: policy.sequence,
            sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
            source: HardwarePolicySource::Local,
            stogas_signing_key_id: None,
        },
        policy,
    };
    let index = selected
        .iter()
        .position(|candidate| candidate.policy.chip_id == local.policy.chip_id)
        .ok_or_else(|| {
            Error::InvalidBundle(
                "local hardware policy chip id is absent from the signed bundle policies".into(),
            )
        })?;
    selected[index] = local;
    Ok(selected)
}

fn verify_signed_hardware_policy(
    signed: &SignedHardwarePolicy,
    environment: &Environment,
) -> Result<SelectedHardwarePolicy, Error> {
    let signature = &signed.stogas_signature;
    if signature.schema != "stogas.hardware-policy.signature.v1"
        || signature.algorithm != "Ed25519"
        || signature.signed != "hardware-policy.json"
    {
        return Err(Error::InvalidBundle(
            "unsupported hardware policy signature".into(),
        ));
    }
    let key = environment
        .release_keys
        .get(&signature.key_id)
        .ok_or_else(|| Error::InvalidBundle("hardware policy signing key is not trusted".into()))?;
    let canonical = validate_hardware_policy(&signed.policy)?;
    let mut payload = HARDWARE_POLICY_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(canonical.as_bytes());
    verify_ed25519(key, &payload, &signature.signature)
        .map_err(|error| Error::InvalidBundle(format!("hardware policy signature: {error}")))?;
    Ok(SelectedHardwarePolicy {
        verified: VerifiedHardwarePolicy {
            chip_id: signed.policy.chip_id.clone(),
            sequence: signed.policy.sequence,
            sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
            source: HardwarePolicySource::StogasBundle,
            stogas_signing_key_id: Some(signature.key_id.clone()),
        },
        policy: signed.policy.clone(),
    })
}

fn validate_hardware_policy(policy: &HardwarePolicy) -> Result<String, Error> {
    if policy.schema != "stogas.hardware-policy.v1"
        || policy.sequence == 0
        || !is_lower_hex(&policy.chip_id, 64)
    {
        return Err(Error::InvalidBundle(
            "unsupported or invalid hardware policy".into(),
        ));
    }
    let profile = &policy.amd_sev_snp;
    if profile.report_version != 5 || profile.product.is_empty() || profile.product.len() > 32 {
        return Err(Error::InvalidBundle(
            "hardware policy has an invalid AMD profile".into(),
        ));
    }
    let built_in = amd_product_from_cpuid(profile.cpuid_family, profile.cpuid_model)
        .ok_or_else(|| Error::InvalidBundle("hardware policy has an unsupported CPUID".into()))?;
    if profile.product != built_in.product_name || built_in.tcb_layout != AmdTcbLayout::Family19h {
        return Err(Error::InvalidBundle(
            "hardware policy product differs from its CPUID or TCB layout".into(),
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
    let value = serde_json::to_value(policy)
        .map_err(|error| Error::InvalidBundle(format!("hardware policy: {error}")))?;
    canonical_json(&value)
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

fn verify_bundle_inner(
    bundle_bytes: &[u8],
    local_policy_bytes: Option<&[u8]>,
    now_unix_ms: i64,
    environment: &Environment,
    verified_catalogs: &BTreeMap<String, VerifiedCatalogRelease>,
    verified_releases: &BTreeMap<String, VerifiedRelease>,
) -> Result<(VerificationOutput, VerificationCache), Error> {
    let envelope = parse_and_verify_bundle_envelope(bundle_bytes)?;

    let hardware_policies = select_hardware_policies(
        &envelope.body.hardware_policies,
        local_policy_bytes,
        environment,
    )?;
    let hardware_policy_map: BTreeMap<_, _> = hardware_policies
        .iter()
        .map(|policy| (policy.policy.chip_id.as_str(), &policy.policy))
        .collect();

    let created_at = parse_time(&envelope.body.created_at)?;
    let expires_at = parse_time(&envelope.body.expires_at)?;
    validate_time(created_at, expires_at, envelope.body.ttl_ms, now_unix_ms)?;

    let mut next_catalog_cache = BTreeMap::new();
    let catalogs = envelope
        .body
        .allowed_catalogs
        .iter()
        .map(|catalog| {
            let key = catalog_cache_key(catalog, environment)?;
            let verified = verified_catalogs.get(&key).map_or_else(
                || verify_catalog(catalog, environment, now_unix_ms),
                |catalog| Ok(catalog.clone()),
            )?;
            next_catalog_cache.insert(key, verified.clone());
            Ok(verified)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut next_release_cache = BTreeMap::new();
    let releases = envelope
        .body
        .allowed_igvms
        .iter()
        .map(|release| {
            let key = release_cache_key(release, environment)?;
            let verified = verified_releases.get(&key).map_or_else(
                || verify_release(release, environment, now_unix_ms),
                |release| Ok(release.clone()),
            )?;
            next_release_cache.insert(key, verified.clone());
            Ok(verified)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let catalog_policies: BTreeMap<_, _> = catalogs
        .iter()
        .map(|catalog| (catalog.runtime_digest.as_str(), catalog.sequence))
        .collect();
    let launch_policies: BTreeMap<_, _> = envelope
        .body
        .allowed_igvms
        .iter()
        .map(|release| {
            (
                release.launch_policy.measurement.as_str(),
                &release.launch_policy,
            )
        })
        .collect();
    let amd_stacks = verified_amd_stacks(
        &envelope.body.vendor_collateral,
        &envelope.body.nodes,
        created_at,
        expires_at,
    )?;
    let verification_time = NodeVerificationTime {
        bundle_created_at: created_at,
        bundle_expires_at: expires_at,
        now_unix_ms,
    };
    let (nodes, excluded_nodes) = verify_and_partition_nodes(
        &envelope.body.nodes,
        verification_time,
        &launch_policies,
        &amd_stacks,
        &catalog_policies,
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
                hardware_policies: hardware_policies
                    .into_iter()
                    .map(|policy| policy.verified)
                    .collect(),
                releases,
                nodes,
                original: envelope.clone(),
            },
        },
        VerificationCache {
            catalogs: next_catalog_cache,
            releases: next_release_cache,
        },
    ))
}

fn verify_and_partition_nodes(
    bundle_nodes: &[Node],
    verification_time: NodeVerificationTime,
    launch_policies: &BTreeMap<&str, &LaunchPolicy>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    catalog_policies: &BTreeMap<&str, u64>,
    hardware_policies: &BTreeMap<&str, &HardwarePolicy>,
) -> Result<(Vec<VerifiedNode>, Vec<ExcludedNode>), Error> {
    let mut nodes = Vec::new();
    let mut excluded = Vec::new();
    for node in bundle_nodes {
        verify_node_catalog_policy(&node.node_id, &node.report_data.catalog, catalog_policies)?;
        let hardware_policy = hardware_policies
            .get(node.chip_id.as_str())
            .ok_or_else(|| {
                Error::Node(format!(
                    "{} chip id is absent from the verified hardware policy stack",
                    node.node_id
                ))
            })?;
        let verified = verify_node(
            node,
            verification_time,
            launch_policies,
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

fn verify_node_catalog_policy(
    node_id: &str,
    catalog: &CatalogIdentity,
    catalog_policies: &BTreeMap<&str, u64>,
) -> Result<(), Error> {
    if catalog_policies.get(catalog.digest.as_str()) != Some(&catalog.sequence) {
        return Err(Error::Node(format!(
            "{node_id} catalog identity is absent from the verified catalog stack"
        )));
    }
    Ok(())
}

fn release_cache_key(release: &AllowedIgvm, environment: &Environment) -> Result<String, Error> {
    let trusted_key = environment
        .release_keys
        .get(&release.stogas_signature.key_id)
        .ok_or_else(|| Error::Release("release signing key is not trusted".into()))?;
    let encoded = serde_json::to_vec(release).map_err(|error| Error::Release(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"stogas verified release cache v1\0");
    digest.update(trusted_key.as_bytes());
    digest.update([0]);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn catalog_cache_key(catalog: &AllowedCatalog, environment: &Environment) -> Result<String, Error> {
    let trusted_key = environment
        .release_keys
        .get(&catalog.signed_release.key_id)
        .ok_or_else(|| Error::Release("catalog signing key is not trusted".into()))?;
    let encoded = serde_json::to_vec(catalog).map_err(|error| Error::Release(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"stogas verified catalog cache v1\0");
    digest.update(trusted_key.as_bytes());
    digest.update([0]);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn validate_shape(envelope: &BundleEnvelope) -> Result<(), Error> {
    if envelope.body.schema != "stogas.confidential-bundle.v1" {
        return Err(Error::InvalidBundle("unsupported schema".into()));
    }
    if envelope.body.allowed_igvms.len() > 2 {
        return Err(Error::InvalidBundle("invalid release count".into()));
    }
    if envelope.body.allowed_catalogs.len() > 2 {
        return Err(Error::InvalidBundle("invalid catalog release count".into()));
    }
    if envelope.body.nodes.len() > MAX_NODES
        || envelope.body.hardware_policies.len() > MAX_NODES
        || envelope.body.vendor_collateral.len() > MAX_VENDOR_COLLATERAL
    {
        return Err(Error::InvalidBundle("resource limit exceeded".into()));
    }
    let mut measurements = BTreeSet::new();
    for release in &envelope.body.allowed_igvms {
        validate_release_shape(release)?;
        if !measurements.insert(release.launch_policy.measurement.as_str()) {
            return Err(Error::InvalidBundle("duplicate release measurement".into()));
        }
    }
    let mut catalog_digests = BTreeSet::new();
    let mut catalog_sequences = BTreeSet::new();
    for catalog in &envelope.body.allowed_catalogs {
        validate_catalog_shape(catalog)?;
        let manifest = &catalog.signed_release.manifest;
        if !catalog_digests.insert(manifest.runtime.as_str())
            || !catalog_sequences.insert(manifest.sequence)
        {
            return Err(Error::InvalidBundle(
                "duplicate catalog runtime digest or sequence".into(),
            ));
        }
    }
    let mut hardware_chip_ids = BTreeSet::new();
    for policy in &envelope.body.hardware_policies {
        if !hardware_chip_ids.insert(policy.policy.chip_id.as_str()) {
            return Err(Error::InvalidBundle(
                "duplicate hardware policy chip id".into(),
            ));
        }
    }
    let mut node_ids = BTreeSet::new();
    let mut referenced_measurements = BTreeSet::new();
    let mut referenced_catalogs = BTreeSet::new();
    let mut referenced_chip_ids = BTreeSet::new();
    for node in &envelope.body.nodes {
        validate_node_shape(node)?;
        if !node_ids.insert(node.node_id.as_str()) {
            return Err(Error::InvalidBundle("duplicate node id".into()));
        }
        referenced_measurements.insert(node.release_measurement.as_str());
        referenced_catalogs.insert((
            node.report_data.catalog.sequence,
            node.report_data.catalog.digest.as_str(),
        ));
        referenced_chip_ids.insert(node.chip_id.as_str());
    }
    let catalog_authorizations = envelope
        .body
        .allowed_catalogs
        .iter()
        .map(|catalog| {
            let manifest = &catalog.signed_release.manifest;
            (manifest.sequence, manifest.runtime.as_str())
        })
        .collect::<BTreeSet<_>>();
    if measurements != referenced_measurements
        || !referenced_catalogs.is_subset(&catalog_authorizations)
        || hardware_chip_ids != referenced_chip_ids
    {
        return Err(Error::InvalidBundle(
            "bundle release and hardware authorizations must match its nodes, and catalog authorizations must cover them".into(),
        ));
    }
    Ok(())
}

fn validate_catalog_shape(catalog: &AllowedCatalog) -> Result<(), Error> {
    let release = &catalog.signed_release;
    let manifest = &release.manifest;
    if catalog.github_in_toto.len() != 1
        || release.schema != "stogas.catalog.signed.v1"
        || manifest.schema != "stogas.catalog.release.v1"
        || manifest.catalog_schema != 1
        || manifest.sequence == 0
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

fn validate_release_shape(release: &AllowedIgvm) -> Result<(), Error> {
    let policy = &release.launch_policy;
    let launch = &policy.launch;
    if policy.source.repository != "https://github.com/StogasAI/gateway"
        || policy.sequence == 0
        || policy.vcpu_count == 0
        || policy.name.is_empty()
        || policy.name.len() > 128
        || !policy.release_tag.starts_with('v')
        || policy.release_tag.len() > 64
        || !is_lower_hex(&policy.igvm_sha256, 32)
        || !is_lower_hex(&policy.measurement, 48)
        || !is_lower_hex(&policy.source.commit, 20)
        || !is_lower_hex(&policy.source.tree, 20)
        || !is_lower_hex(&launch.family_id, 16)
        || !is_lower_hex(&launch.image_id, 16)
        || !is_lower_hex(&launch.host_data, 32)
        || !is_lower_hex(&launch.id_key_digest, 48)
        || !is_lower_hex(&launch.author_key_digest, 48)
        || launch.vmpl > 3
        || !is_prefixed_lower_hex(&launch.policy, 8)
    {
        return Err(Error::InvalidBundle("invalid launch policy shape".into()));
    }
    if release.github_in_toto.len() != 1 {
        return Err(Error::InvalidBundle(
            "a release must contain exactly one GitHub attestation".into(),
        ));
    }
    Ok(())
}

fn validate_node_shape(node: &Node) -> Result<(), Error> {
    let report = &node.report_data;
    let checks = [
        (report.schema == "stogas.node-report.v1", "report schema"),
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
        (is_lower_hex(&report.tls_spki_sha256, 32), "TLS SPKI hash"),
        (
            is_lower_hex(&report.active_cert_sha256, 32),
            "active certificate hash",
        ),
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
        (
            is_sha256_identity(&report.catalog.digest),
            "catalog identity",
        ),
        (!node.region.is_empty() && node.region.len() <= 64, "region"),
    ];
    if let Some((_, label)) = checks.into_iter().find(|(valid, _)| !valid) {
        return Err(Error::InvalidBundle(format!(
            "{} has an invalid {label}",
            node.node_id
        )));
    }
    let certs: BTreeSet<_> = report.accepted_cert_sha256.iter().collect();
    if !(1..=2).contains(&certs.len())
        || certs.len() != report.accepted_cert_sha256.len()
        || !certs.contains(&report.active_cert_sha256)
    {
        return Err(Error::InvalidBundle(format!(
            "{} has an invalid certificate rotation stack",
            node.node_id
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
    environment: &Environment,
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    validate_catalog_shape(catalog)?;
    let signed = &catalog.signed_release;
    let manifest = &signed.manifest;
    let key = environment
        .release_keys
        .get(&signed.key_id)
        .ok_or_else(|| Error::Release("catalog signing key is not trusted".into()))?;
    let manifest_value =
        serde_json::to_value(manifest).map_err(|error| Error::Release(error.to_string()))?;
    let canonical = canonical_json(&manifest_value)?;
    let canonical = canonical
        .strip_suffix('\n')
        .ok_or_else(|| Error::Release("catalog canonical manifest is invalid".into()))?;
    let mut payload = b"stogas catalog release v1\n".to_vec();
    payload.extend_from_slice(canonical.as_bytes());
    verify_ed25519(key, &payload, &signed.signature).map_err(Error::Release)?;

    let attestation = catalog
        .github_in_toto
        .first()
        .ok_or_else(|| Error::Release("catalog GitHub attestation is absent".into()))?;
    let attestation_bytes =
        serde_json::to_vec(attestation).map_err(|error| Error::Release(error.to_string()))?;
    let runtime_digest = manifest
        .runtime
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Release("catalog runtime digest is invalid".into()))?;
    let public_digest = manifest
        .public
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Release("catalog public digest is invalid".into()))?;
    #[cfg(feature = "staging")]
    let staging_development_provenance = environment.allow_staging_development_provenance
        && is_staging_development_provenance(
            &attestation_bytes,
            &[
                ("catalog.runtime.json", runtime_digest),
                ("catalog.public.json", public_digest),
            ],
        )?;
    #[cfg(not(feature = "staging"))]
    let staging_development_provenance = false;
    let (github_integrated_time_unix_ms, provenance) = verify_catalog_provenance(
        &attestation_bytes,
        manifest,
        runtime_digest,
        public_digest,
        staging_development_provenance,
        now_unix_ms,
    )?;

    Ok(VerifiedCatalogRelease {
        evidence: catalog.clone(),
        github_integrated_time_unix_ms,
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
    runtime_digest: &str,
    public_digest: &str,
    staging_development_provenance: bool,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    if let Some(provenance) = staging_provenance(staging_development_provenance) {
        return Ok(provenance);
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/catalog/.github/workflows/catalog-release.yml@refs/tags/{}",
        manifest.source.tag
    );
    verify_github_provenance(
        attestation_bytes,
        &[
            Subject {
                name: "catalog.runtime.json",
                sha256: runtime_digest,
            },
            Subject {
                name: "catalog.public.json",
                sha256: public_digest,
            },
        ],
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

fn verify_release(
    release: &AllowedIgvm,
    environment: &Environment,
    now_unix_ms: i64,
) -> Result<VerifiedRelease, Error> {
    let policy = &release.launch_policy;
    let signature = &release.stogas_signature;
    if policy.schema != "stogas.gateway.launch-policy.v1"
        || signature.schema != "stogas.gateway.signature.v1"
        || signature.algorithm != "Ed25519"
        || signature.signed != "gateway-launch-policy.json"
    {
        return Err(Error::Release(
            "unsupported launch policy or signature".into(),
        ));
    }
    let key = environment
        .release_keys
        .get(&signature.key_id)
        .ok_or_else(|| Error::Release("release signing key is not trusted".into()))?;
    let policy_value =
        serde_json::to_value(policy).map_err(|error| Error::Release(error.to_string()))?;
    let canonical = canonical_json(&policy_value)?;
    let mut payload = b"stogas gateway launch policy v1\n".to_vec();
    payload.extend_from_slice(canonical.as_bytes());
    verify_ed25519(key, &payload, &signature.signature).map_err(Error::Release)?;

    let attestation_value = release
        .github_in_toto
        .first()
        .ok_or_else(|| Error::Release("GitHub attestation is absent".into()))?;
    let attestation_bytes =
        serde_json::to_vec(attestation_value).map_err(|error| Error::Release(error.to_string()))?;
    let policy_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    #[cfg(feature = "staging")]
    let staging_development_provenance = environment.allow_staging_development_provenance
        && is_staging_development_provenance(
            &attestation_bytes,
            &[
                ("gateway.igvm", policy.igvm_sha256.as_str()),
                ("gateway-launch-policy.json", policy_digest.as_str()),
            ],
        )?;
    #[cfg(not(feature = "staging"))]
    let staging_development_provenance = false;
    let (github_integrated_time_unix_ms, provenance) = verify_release_provenance(
        &attestation_bytes,
        policy,
        &policy_digest,
        staging_development_provenance,
        now_unix_ms,
    )?;

    Ok(VerifiedRelease {
        evidence: release.clone(),
        github_integrated_time_unix_ms,
        igvm_sha256: policy.igvm_sha256.clone(),
        launch: policy.launch.clone(),
        launch_policy_sha256: policy_digest,
        measurement: policy.measurement.clone(),
        provenance,
        release_tag: policy.release_tag.clone(),
        sequence: policy.sequence,
        source_commit: policy.source.commit.clone(),
        source_repository: policy.source.repository.clone(),
        source_tree: policy.source.tree.clone(),
        stogas_signing_key_id: signature.key_id.clone(),
        vcpu_count: policy.vcpu_count,
    })
}

fn verify_release_provenance(
    attestation_bytes: &[u8],
    policy: &LaunchPolicy,
    policy_digest: &str,
    staging_development_provenance: bool,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    if let Some(provenance) = staging_provenance(staging_development_provenance) {
        return Ok(provenance);
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/{}",
        policy.release_tag
    );
    verify_github_provenance(
        attestation_bytes,
        &[
            Subject {
                name: "gateway.igvm",
                sha256: &policy.igvm_sha256,
            },
            Subject {
                name: "gateway-launch-policy.json",
                sha256: policy_digest,
            },
        ],
        &GithubPolicy {
            repository: policy.source.repository.clone(),
            workflow_identity,
            source_ref: format!("refs/tags/{}", policy.release_tag),
            source_commit: policy.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
        "gateway provenance",
    )
}

const fn staging_provenance(enabled: bool) -> Option<(Option<i64>, ReleaseProvenance)> {
    #[cfg(feature = "staging")]
    {
        if enabled {
            Some((None, ReleaseProvenance::Staging))
        } else {
            None
        }
    }
    #[cfg(not(feature = "staging"))]
    {
        let _ = enabled;
        None
    }
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

fn verify_node(
    node: &Node,
    verification_time: NodeVerificationTime,
    launch_policies: &BTreeMap<&str, &LaunchPolicy>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    hardware_policy: &HardwarePolicy,
) -> Result<VerifiedNode, Error> {
    if hardware_policy.chip_id != node.chip_id {
        return Err(Error::Node(format!(
            "{} chip id differs from its hardware policy",
            node.node_id
        )));
    }
    let launch_policy = launch_policies
        .get(node.release_measurement.as_str())
        .ok_or_else(|| {
            Error::Node(format!(
                "{} release measurement {} is absent from the verified release stack",
                node.node_id, node.release_measurement
            ))
        })?;
    if parse_time(&node.cert_expires_at)? < verification_time.bundle_expires_at {
        return Err(Error::Node(format!(
            "bundle outlives {} certificate",
            node.node_id
        )));
    }
    let canonical_report = canonical_report_data(&node.report_data)?;
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
    let quote_verified_at = parse_time(&node.quote_verified_at)?;
    if quote_verified_at > verification_time.bundle_created_at {
        return Err(Error::Node(format!(
            "{} quote verification time is later than bundle creation",
            node.node_id
        )));
    }
    let drand_round_time_unix_ms = validate_node_evidence_time(
        &node.node_id,
        node.report_data.drand.round,
        quote_verified_at,
        verification_time.now_unix_ms,
    )?;
    let round = node.report_data.drand.round;
    verify_quicknet(&node.report_data.drand)?;
    let amd_stack = amd_stacks
        .get(&amd_platform_key(&node.chip_id, &node.reported_tcb))
        .ok_or_else(|| Error::Node(format!("{} has no matching AMD evidence", node.node_id)))?;
    verify_snp_node(
        node,
        launch_policy,
        verification_time.bundle_created_at,
        verification_time.bundle_expires_at,
        amd_stack,
        hardware_policy,
    )?;
    Ok(VerifiedNode {
        chip_id: node.chip_id.clone(),
        drand_round: round,
        drand_round_time_unix_ms,
        evidence_age_ms: verification_time
            .bundle_created_at
            .saturating_sub(drand_round_time_unix_ms)
            .max(0),
        node_id: node.node_id.clone(),
        quote: node.quote.clone(),
        quote_verified_at_unix_ms: quote_verified_at,
        region: node.region.clone(),
        report_data: node.report_data.clone(),
        report_data_sha512: node.report_data_sha512.clone(),
        release_measurement: node.release_measurement.clone(),
        reported_tcb: node.reported_tcb.clone(),
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
struct AmdCollateralStack {
    ark: Vec<u8>,
    ask: Vec<u8>,
    crl: Vec<u8>,
    vek: Vec<u8>,
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

type AmdCommonCollateral = BTreeMap<(String, String), AmdCollateralEntry>;
type AmdVcekCollateral = BTreeMap<String, AmdCollateralEntry>;

fn verified_amd_stacks(
    rows: &[VendorCollateral],
    nodes: &[Node],
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
    node: &Node,
    policy: &LaunchPolicy,
    bundle_created_at: i64,
    bundle_expires_at: i64,
    collateral: &AmdCollateralStack,
    hardware_policy: &HardwarePolicy,
) -> Result<(), Error> {
    let report_bytes = decode_snp_report(&node.quote, &node.node_id)?;
    check_raw_report_bindings(node, policy, &report_bytes, Some(hardware_policy))?;
    verify_amd_collateral_stack(
        collateral,
        &node.chip_id,
        &node.reported_tcb,
        bundle_created_at,
        bundle_expires_at,
    )?;
    let product = validate_report_product_binding(&collateral.vek, &report_bytes)?;
    let expected_policy = u64::from_str_radix(policy.launch.policy.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Node("invalid launch policy value".into()))?;
    validate_snp_launch_policy(expected_policy, Some(product))?;
    verify_raw_snp_report_signature_with_vcek(&report_bytes, &collateral.vek, &node.node_id)
}

#[cfg(not(feature = "snp"))]
fn verify_snp_node(
    _node: &Node,
    _policy: &LaunchPolicy,
    _bundle_created_at: i64,
    _bundle_expires_at: i64,
    _collateral: &AmdCollateralStack,
    _hardware_policy: &HardwarePolicy,
) -> Result<(), Error> {
    Err(Error::Node(
        "AMD SNP verification is unavailable in this build".into(),
    ))
}

#[cfg(feature = "snp")]
fn check_raw_report_bindings(
    node: &Node,
    policy: &LaunchPolicy,
    report: &[u8],
    hardware_policy: Option<&HardwarePolicy>,
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
    let expected_policy = u64::from_str_radix(policy.launch.policy.trim_start_matches("0x"), 16)
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
    validate_raw_snp_report_encoding(report, report_version, report_product, &node.node_id)?;
    let report_info = u32_at(0x48);
    let author_key_present = policy
        .launch
        .author_key_digest
        .bytes()
        .any(|byte| byte != b'0');
    let checks = [
        (
            report[0x10..0x20] == bytes::<16>(&policy.launch.family_id, "family id")?,
            "family id",
        ),
        (
            report[0x20..0x30] == bytes::<16>(&policy.launch.image_id, "image id")?,
            "image id",
        ),
        (
            report[0x50..0x90] == bytes::<64>(&node.report_data_sha512, "report data")?,
            "report data",
        ),
        (
            report[0x90..0xc0] == bytes::<48>(&policy.measurement, "measurement")?,
            "measurement",
        ),
        (
            report[0xc0..0xe0] == bytes::<32>(&policy.launch.host_data, "host data")?,
            "host data",
        ),
        (
            report[0xe0..0x110] == bytes::<48>(&policy.launch.id_key_digest, "id key digest")?,
            "id key digest",
        ),
        (
            report[0x110..0x140]
                == bytes::<48>(&policy.launch.author_key_digest, "author key digest")?,
            "author key digest",
        ),
        (
            report[0x180..0x188] == bytes::<8>(&node.reported_tcb, "reported TCB")?,
            "reported TCB",
        ),
        (
            report[0x1a0..0x1e0] == bytes::<64>(&node.chip_id, "chip id")?,
            "chip id",
        ),
        (u32_at(0x30) == u32::from(policy.launch.vmpl), "VMPL"),
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
            &node.node_id,
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
    policy: &HardwarePolicy,
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
    let profile = &policy.amd_sev_snp;
    if profile.cpuid_family != family
        || profile.cpuid_model != model
        || profile.cpuid_stepping != stepping
    {
        return Err(Error::Node(format!(
            "{node_id} CPUID differs from hardware policy"
        )));
    }
    if profile.report_version != report_version
        || product.map(|product| product.product_name) != Some(profile.product.as_str())
    {
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
    if crl.tbs_cert_list.this_update.timestamp() * 1000 > bundle_created_at + MAX_CLOCK_SKEW_MS
        || crl
            .tbs_cert_list
            .next_update
            .as_ref()
            .is_none_or(|time| time.timestamp() * 1000 < bundle_expires_at)
        || crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == vek.raw_serial())
    {
        return Err(Error::Node(
            "AMD VEK is revoked or CRL expires before the bundle".into(),
        ));
    }
    let crl_signer = if crl.tbs_cert_list.issuer == *ask.subject() {
        &ask
    } else if crl.tbs_cert_list.issuer == *ark.subject() {
        &ark
    } else {
        return Err(Error::Node("AMD CRL issuer differs".into()));
    };
    verify_amd_crl_signature(&crl, crl_signer)?;
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

    const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
    if crl.signature_algorithm.algorithm.to_id_string() != RSA_PSS_OID
        || crl.tbs_cert_list.signature.algorithm.to_id_string() != RSA_PSS_OID
    {
        return Err(Error::Node(
            "AMD CRL must use RSA-PSS for both signature identifiers".into(),
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

fn validate_time(created: i64, expires: i64, ttl_ms: u64, now: i64) -> Result<(), Error> {
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
    let declared_ttl = i64::try_from(ttl_ms).unwrap_or(i64::MAX);
    if interval != declared_ttl {
        return Err(Error::InvalidBundle(format!(
            "bundle interval ({interval} ms) differs from ttl_ms ({declared_ttl} ms)"
        )));
    }
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
    if certs.is_empty() || certs.len() > 2 || !certs.contains(&report.active_cert_sha256) {
        return Err(Error::Node("invalid certificate rotation stack".into()));
    }
    let mut value = serde_json::Map::new();
    value.insert("schema".into(), Value::String(report.schema.clone()));
    value.insert(
        "catalog".into(),
        serde_json::json!({
            "digest": report.catalog.digest,
            "sequence": report.catalog.sequence,
        }),
    );
    value.insert(
        "tls_spki_sha256".into(),
        Value::String(report.tls_spki_sha256.clone()),
    );
    value.insert(
        "active_cert_sha256".into(),
        Value::String(report.active_cert_sha256.clone()),
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

    #[test]
    fn verifies_the_stogas_policy_signature_and_accepts_an_explicit_local_replacement() {
        let signed: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        let stogas =
            select_hardware_policies(std::slice::from_ref(&signed), None, &Environment::stogas())
                .unwrap();
        assert!(matches!(
            stogas[0].verified.source,
            HardwarePolicySource::StogasBundle
        ));
        assert_eq!(stogas[0].verified.sequence, 3);
        assert_eq!(
            stogas[0].verified.stogas_signing_key_id.as_deref(),
            Some(STOGAS_RELEASE_KEY_ID)
        );

        let mut local: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        local.sequence = 9;
        local.amd_sev_snp.minimum_tcb.snp = 30;
        let local = select_hardware_policies(
            std::slice::from_ref(&signed),
            Some(&serde_json::to_vec(&local).unwrap()),
            &Environment::stogas(),
        )
        .unwrap();
        assert!(matches!(
            local[0].verified.source,
            HardwarePolicySource::Local
        ));
        assert_eq!(local[0].verified.sequence, 9);
        assert_eq!(local[0].policy.amd_sev_snp.minimum_tcb.snp, 30);
        assert!(local[0].verified.stogas_signing_key_id.is_none());
    }

    #[test]
    fn rejects_tampered_stogas_hardware_policy() {
        let mut signed: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        signed.policy.amd_sev_snp.minimum_tcb.snp -= 1;
        assert!(verify_signed_hardware_policy(&signed, &Environment::stogas()).is_err());
    }

    #[cfg(feature = "snp")]
    fn appraisable_milan_report() -> (Vec<u8>, HardwarePolicy, &'static AmdProductProfile) {
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
        (report, policy, profile)
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
        policy.amd_sev_snp.minimum_tcb = AmdTcb {
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
        AllowedIgvm {
            github_in_toto: vec![
                serde_json::from_str(
                    include_str!("../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl").trim(),
                )
                .unwrap(),
            ],
            launch_policy: serde_json::from_str(include_str!(
                "../../../tests/fixtures/gateway-v0.0.1-launch-policy.json"
            ))
            .unwrap(),
            stogas_signature: serde_json::from_str(include_str!(
                "../../../tests/fixtures/gateway-v0.0.1-signature.json"
            ))
            .unwrap(),
        }
    }

    fn catalog_fixture() -> AllowedCatalog {
        serde_json::from_value(serde_json::json!({
            "github_in_toto": [{}],
            "signed_release": {
                "keyId": "test",
                "manifest": {
                    "catalogSchema": 1,
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
        let envelope = BundleEnvelope {
            body: BundleBody {
                allowed_catalogs: Vec::new(),
                allowed_igvms: Vec::new(),
                created_at: "2026-07-23T16:00:00.000Z".into(),
                expires_at: "2026-07-23T16:15:00.000Z".into(),
                hardware_policies: Vec::new(),
                nodes: Vec::new(),
                schema: "stogas.confidential-bundle.v1".into(),
                sequence: 0,
                ttl_ms: 900_000,
                vendor_collateral: Vec::new(),
            },
            body_sha256: "00".repeat(32),
        };

        validate_shape(&envelope).unwrap();
    }

    #[test]
    fn bundle_shape_allows_catalog_preauthorization_but_rejects_orphan_hardware_policies() {
        let policy: SignedHardwarePolicy = serde_json::from_str(include_str!(
            "../tests/fixtures/milan-hardware-policy.signed.json"
        ))
        .unwrap();
        let mut envelope = BundleEnvelope {
            body: BundleBody {
                allowed_catalogs: Vec::new(),
                allowed_igvms: Vec::new(),
                created_at: "2026-07-23T16:00:00.000Z".into(),
                expires_at: "2026-07-23T16:15:00.000Z".into(),
                hardware_policies: vec![policy.clone()],
                nodes: Vec::new(),
                schema: "stogas.confidential-bundle.v1".into(),
                sequence: 1,
                ttl_ms: 900_000,
                vendor_collateral: Vec::new(),
            },
            body_sha256: "00".repeat(32),
        };
        assert!(
            validate_shape(&envelope)
                .unwrap_err()
                .to_string()
                .contains("release and hardware authorizations must match its nodes")
        );

        envelope.body.hardware_policies.clear();
        envelope.body.allowed_catalogs.push(catalog_fixture());
        validate_shape(&envelope).unwrap();

        envelope.body.hardware_policies.push(policy);
        envelope
            .body
            .hardware_policies
            .push(envelope.body.hardware_policies[0].clone());
        assert!(
            validate_shape(&envelope)
                .unwrap_err()
                .to_string()
                .contains("duplicate hardware policy chip id")
        );
    }

    #[test]
    fn node_catalog_must_match_one_verified_catalog_policy() {
        let digest = format!("sha256:{}", "22".repeat(32));
        let catalog = CatalogIdentity {
            digest: digest.clone(),
            sequence: 7,
        };
        let policies = BTreeMap::from([(digest.as_str(), 7)]);

        verify_node_catalog_policy("node-a", &catalog, &policies).unwrap();
        let error = verify_node_catalog_policy(
            "node-a",
            &CatalogIdentity {
                digest: digest.clone(),
                sequence: 8,
            },
            &policies,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("catalog identity is absent from the verified catalog stack")
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

        let release = release_fixture().launch_policy;
        let heartbeat_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let report_data = ReportData {
            active_cert_sha256: "11".repeat(32),
            accepted_cert_sha256: vec!["11".repeat(32)],
            catalog: CatalogIdentity {
                digest: format!("sha256:{}", "22".repeat(32)),
                sequence: 7,
            },
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
            "launch_policies": [release],
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
        let mut policy = release_fixture().launch_policy;
        let node = Node {
            cert_expires_at: heartbeat.cert_expires_at,
            chip_id: "00".repeat(64),
            health: heartbeat.health,
            node_id: heartbeat.node_id,
            quote: heartbeat.quote,
            quote_verified_at: heartbeat.observed_at,
            region: "test".into(),
            release_measurement: policy.measurement.clone(),
            reported_tcb: "00".repeat(8),
            report_data: heartbeat.report_data,
            report_data_sha512: heartbeat.report_data_sha512,
        };
        let report = vec![0_u8; 0x4a0];

        let error = check_raw_report_bindings(&node, &policy, &report, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("required admitted platform protections")
        );

        policy.launch.policy = "0x000000000213013a".into();
        let error = check_raw_report_bindings(&node, &policy, &report, None).unwrap_err();
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

    fn resign_release(release: &mut AllowedIgvm) -> Environment {
        use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let canonical =
            canonical_json(&serde_json::to_value(&release.launch_policy).unwrap()).unwrap();
        let mut payload = b"stogas gateway launch policy v1\n".to_vec();
        payload.extend_from_slice(canonical.as_bytes());
        release.stogas_signature.key_id = "test-release-key".into();
        release.stogas_signature.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        Environment {
            release_keys: BTreeMap::from([(
                "test-release-key".into(),
                STANDARD.encode(
                    signing_key
                        .verifying_key()
                        .to_public_key_der()
                        .unwrap()
                        .as_bytes(),
                ),
            )]),
            #[cfg(feature = "staging")]
            allow_staging_development_provenance: false,
        }
    }

    #[cfg(feature = "staging")]
    fn resign_catalog(catalog: &mut AllowedCatalog) -> Environment {
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
        Environment {
            release_keys: BTreeMap::from([(
                "test-release-key".into(),
                STANDARD.encode(
                    signing_key
                        .verifying_key()
                        .to_public_key_der()
                        .unwrap()
                        .as_bytes(),
                ),
            )]),
            #[cfg(feature = "staging")]
            allow_staging_development_provenance: false,
        }
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = strict_json::from_slice(br#"{"body":1,"body":2}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key"));
    }

    #[test]
    fn verifies_real_release_only_when_stogas_and_github_bind_the_same_policy() {
        let release = release_fixture();
        let verified = verify_release(&release, &Environment::stogas(), 1_784_246_400_000).unwrap();
        assert_eq!(verified.igvm_sha256, release.launch_policy.igvm_sha256);
        assert_eq!(verified.measurement, release.launch_policy.measurement);
    }

    #[test]
    fn release_approval_boundary_is_strict_and_uses_the_complete_verifier() {
        let release = serde_json::to_vec(&release_fixture()).unwrap();
        let verified = verify_release_approval(&release, 1_784_246_400_000).unwrap();
        assert_eq!(verified.release_tag, "v0.0.1");

        let duplicate = br#"{"github_in_toto":[],"github_in_toto":[]}"#;
        assert!(verify_release_approval(duplicate, 1_784_246_400_000).is_err());
    }

    #[cfg(feature = "staging")]
    #[test]
    fn staging_development_provenance_is_exact_and_never_accepted_by_production() {
        let mut release = release_fixture();
        let mut environment = resign_release(&mut release);
        environment.allow_staging_development_provenance = true;
        let canonical =
            canonical_json(&serde_json::to_value(&release.launch_policy).unwrap()).unwrap();
        let policy_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        release.github_in_toto = vec![serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": STAGING_PROVENANCE_TYPE,
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "gateway.igvm", "digest": { "sha256": release.launch_policy.igvm_sha256 } },
                { "name": "gateway-launch-policy.json", "digest": { "sha256": policy_digest } }
            ]
        })];

        let verified = verify_release(&release, &environment, 1_784_246_400_000).unwrap();
        assert!(verified.github_integrated_time_unix_ms.is_none());
        assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

        environment.allow_staging_development_provenance = false;
        assert!(verify_release(&release, &environment, 1_784_246_400_000).is_err());

        environment.allow_staging_development_provenance = true;
        release.github_in_toto[0]["subject"][0]["digest"]["sha256"] =
            Value::String("00".repeat(32));
        assert!(verify_release(&release, &environment, 1_784_246_400_000).is_err());
    }

    #[cfg(feature = "staging")]
    #[test]
    fn staging_catalog_provenance_is_exact_and_never_accepted_by_production() {
        let mut catalog = catalog_fixture();
        let mut environment = resign_catalog(&mut catalog);
        environment.allow_staging_development_provenance = true;
        let runtime_digest = catalog
            .signed_release
            .manifest
            .runtime
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        let public_digest = catalog
            .signed_release
            .manifest
            .public
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        catalog.github_in_toto = vec![serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": STAGING_PROVENANCE_TYPE,
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "catalog.runtime.json", "digest": { "sha256": runtime_digest } },
                { "name": "catalog.public.json", "digest": { "sha256": public_digest } }
            ]
        })];

        let verified = verify_catalog(&catalog, &environment, 1_784_246_400_000).unwrap();
        assert!(verified.github_integrated_time_unix_ms.is_none());
        assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

        environment.allow_staging_development_provenance = false;
        assert!(verify_catalog(&catalog, &environment, 1_784_246_400_000).is_err());

        environment.allow_staging_development_provenance = true;
        catalog.github_in_toto[0]["subject"][1]["digest"]["sha256"] =
            Value::String("00".repeat(32));
        assert!(verify_catalog(&catalog, &environment, 1_784_246_400_000).is_err());
    }

    #[test]
    fn rejects_invalid_stogas_release_signature_before_accepting_github_evidence() {
        let mut release = release_fixture();
        release.stogas_signature.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        let error =
            verify_release(&release, &Environment::stogas(), 1_784_246_400_000).unwrap_err();
        assert!(error.to_string().contains("release verification failed"));
    }

    #[test]
    fn rejects_resigned_policy_when_github_did_not_attest_exact_bytes_and_igvm() {
        let mutations: [fn(&mut AllowedIgvm); 3] = [
            |release: &mut AllowedIgvm| release.launch_policy.measurement.replace_range(..2, "aa"),
            |release: &mut AllowedIgvm| release.launch_policy.igvm_sha256.replace_range(..2, "aa"),
            |release: &mut AllowedIgvm| release.launch_policy.source.tree.replace_range(..2, "aa"),
        ];
        for mutate in mutations {
            let mut release = release_fixture();
            mutate(&mut release);
            let environment = resign_release(&mut release);
            let error = verify_release(&release, &environment, 1_784_246_400_000).unwrap_err();
            assert!(error.to_string().contains("Sigstore"));
        }
    }

    #[test]
    fn launch_policy_canonicalization_sorts_recursively_and_ends_with_newline() {
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
