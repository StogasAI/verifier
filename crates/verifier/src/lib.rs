//! Deterministic, networkless verification for Stogas confidential bundles.

mod strict_json;
mod types;

pub use types::*;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey, pkcs8::DecodePublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
use thiserror::Error;

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
const STOGAS_RELEASE_KEY_ID: &str = "stogas-ed25519-stamp-v1";
const STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64: &str =
    "MCowBQYDK2VwAyEAByVn3LvWVbf3YkokMZPvir70vcDu0nNflgXoM0Y8aQU=";
const STAGING_PROVENANCE_TYPE: &str = "https://stogas.ai/attestations/staging-development/v1";

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentPredicate {
    environment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentSubject {
    digest: BTreeMap<String, String>,
    name: String,
}

/// Runtime-independent trust configuration.
#[derive(Clone, Debug)]
pub struct Environment {
    /// Trusted Stogas release signing keys, keyed by key id, as base64 SPKI DER.
    pub release_keys: BTreeMap<String, String>,
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
            allow_staging_development_provenance: false,
        }
    }

    /// Staging trust policy. This accepts the explicit Stogas development-provenance statement in
    /// place of GitHub provenance while retaining the signed launch-policy requirement.
    #[must_use]
    pub fn staging() -> Self {
        Self {
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
}

/// Verifier with a bounded in-memory cache for immutable release evidence.
///
/// The cache is only a performance optimization. It is deliberately ephemeral and cannot bypass
/// GitHub or Stogas signature verification for new release bytes.
#[derive(Debug, Default)]
pub struct Verifier {
    verified_releases: BTreeMap<String, VerifiedRelease>,
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
        let (output, next_cache) = verify_bundle_inner(
            bundle_bytes,
            now_unix_ms,
            environment,
            &self.verified_releases,
        )?;
        self.verified_releases = next_cache;
        Ok(output)
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

/// Verify one release authorization using the staging trust policy.
///
/// # Errors
///
/// Returns an error unless the release has a valid Stogas signature and either strict GitHub
/// provenance or the exact staging-only development-provenance statement.
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
    if !(2..=5).contains(&u32::from_le_bytes(
        report[0x00..0x04].try_into().unwrap_or_default(),
    )) {
        return Err(Error::Node("unsupported SNP report version".into()));
    }
    Ok(InspectedSnpQuote {
        chip_id: hex::encode(&report[0x1a0..0x1e0]),
        release_measurement: hex::encode(&report[0x90..0xc0]),
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
        now_unix_ms,
        now_unix_ms,
        now_unix_ms,
        &policies,
        &amd_stacks,
    )?;
    Ok(VerifiedAdmission { node, verified })
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
    if !request.trusted_platforms.iter().any(|platform| {
        platform.chip_id.eq_ignore_ascii_case(&identity.chip_id)
            && platform
                .reported_tcb
                .eq_ignore_ascii_case(&identity.reported_tcb)
    }) {
        return Err(Error::Node("unknown local chip id or reported TCB".into()));
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
            check_raw_report_bindings(&node, launch_policy, report)?;
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
        accepted_cert_sha256: node.report_data.accepted_cert_sha256.clone(),
        chip_id: node.chip_id.clone(),
        drand_round: node.report_data.drand.round,
        drand_round_time_unix_ms,
        evidence_age_ms,
        node_id: node.node_id.clone(),
        quote_verified_at_unix_ms: now_unix_ms,
        region: node.region.clone(),
        report_data: node.report_data.clone(),
        report_data_sha512: node.report_data_sha512.clone(),
        release_measurement: node.release_measurement.clone(),
        reported_tcb: node.reported_tcb.clone(),
        tls_spki_sha256: node.report_data.tls_spki_sha256.clone(),
    };
    Ok(VerifiedAdmission { node, verified })
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
    if request.trusted_platforms.is_empty() || request.trusted_platforms.len() > 16 {
        return Err(Error::InvalidBundle(
            "local admission requires one to sixteen trusted platforms".into(),
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
    if request.trusted_platforms.len() != 1 || request.launch_policies.len() != 1 {
        return Err(Error::Node(
            "local mock admission requires exactly one platform and release".into(),
        ));
    }
    let platform = &request.trusted_platforms[0];
    Ok(LocalQuoteIdentity {
        chip_id: platform.chip_id.to_lowercase(),
        raw_report: None,
        release_measurement: request.launch_policies[0].measurement.to_lowercase(),
        reported_tcb: platform.reported_tcb.to_lowercase(),
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
    use p384::{
        ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _},
        pkcs8::DecodePublicKey as _,
    };
    use sha2::Sha384;

    let public_key = public_key
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::Node("local AMD report signing key is not configured".into()))?;
    let der = decode_public_key_material(public_key)?;
    let key = VerifyingKey::from_public_key_der(&der)
        .map_err(|error| Error::Node(format!("local AMD report signing key: {error}")))?;
    let signature = &report[0x2a0..0x4a0];
    if signature[48..72].iter().any(|byte| *byte != 0)
        || signature[120..144].iter().any(|byte| *byte != 0)
        || signature[144..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Node(
            "local SNP signature reserved bytes are nonzero".into(),
        ));
    }
    let mut r = [0_u8; 48];
    let mut s = [0_u8; 48];
    for index in 0..48 {
        r[index] = signature[47 - index];
        s[index] = signature[72 + 47 - index];
    }
    let signature = Signature::from_scalars(r, s)
        .map_err(|error| Error::Node(format!("local SNP signature encoding: {error}")))?;
    let digest = Sha384::digest(&report[..0x2a0]);
    key.verify_prehash(&digest, &signature)
        .map_err(|error| Error::Node(format!("local SNP signature: {error}")))
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

fn verify_bundle_inner(
    bundle_bytes: &[u8],
    now_unix_ms: i64,
    environment: &Environment,
    verified_releases: &BTreeMap<String, VerifiedRelease>,
) -> Result<(VerificationOutput, BTreeMap<String, VerifiedRelease>), Error> {
    if bundle_bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let value = strict_json::from_slice(bundle_bytes)
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    let signed_body = serde_json::to_vec(
        value
            .get("body")
            .ok_or_else(|| Error::InvalidBundle("bundle body is absent".into()))?,
    )
    .map_err(|error| Error::InvalidBundle(error.to_string()))?;
    let envelope: BundleEnvelope =
        serde_json::from_value(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    validate_shape(&envelope)?;
    verify_envelope(&envelope, &signed_body)?;

    let created_at = parse_time(&envelope.body.created_at)?;
    let expires_at = parse_time(&envelope.body.expires_at)?;
    validate_time(created_at, expires_at, envelope.body.ttl_ms, now_unix_ms)?;

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
    let (nodes, excluded_nodes) = verify_and_partition_nodes(
        &envelope.body.nodes,
        created_at,
        expires_at,
        now_unix_ms,
        &launch_policies,
        &amd_stacks,
    )?;
    Ok((
        VerificationOutput {
            bundle: VerifiedBundle {
                sequence: envelope.body.sequence,
                created_at_unix_ms: created_at,
                expires_at_unix_ms: expires_at,
                excluded_nodes,
                releases,
                nodes,
                original: envelope.clone(),
            },
        },
        next_release_cache,
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_and_partition_nodes(
    bundle_nodes: &[Node],
    created_at: i64,
    expires_at: i64,
    now_unix_ms: i64,
    launch_policies: &BTreeMap<&str, &LaunchPolicy>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
) -> Result<(Vec<VerifiedNode>, Vec<ExcludedNode>), Error> {
    let mut nodes = Vec::new();
    let mut excluded = Vec::new();
    for node in bundle_nodes {
        let verified = verify_node(
            node,
            created_at,
            expires_at,
            now_unix_ms,
            launch_policies,
            amd_stacks,
        )?;
        if verified
            .drand_round_time_unix_ms
            .saturating_add(MAX_NODE_EVIDENCE_AGE_MS)
            < created_at
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

fn validate_shape(envelope: &BundleEnvelope) -> Result<(), Error> {
    if envelope.body.schema != "stogas.confidential-bundle.v1" {
        return Err(Error::InvalidBundle("unsupported schema".into()));
    }
    if envelope.body.sequence == 0 || !(1..=2).contains(&envelope.body.allowed_igvms.len()) {
        return Err(Error::InvalidBundle(
            "invalid sequence or release count".into(),
        ));
    }
    if envelope.body.nodes.len() > MAX_NODES
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
    let mut node_ids = BTreeSet::new();
    for node in &envelope.body.nodes {
        validate_node_shape(node)?;
        if !node_ids.insert(node.node_id.as_str()) {
            return Err(Error::InvalidBundle("duplicate node id".into()));
        }
    }
    Ok(())
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
        (is_lower_hex(&report.catalog_hash, 32), "catalog hash"),
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
            is_p256_uncompressed_b64url(&report.hpke_public_key),
            "HPKE public key",
        ),
        (
            decode_b64url_len(&report.ed25519_public_key) == Some(32),
            "Ed25519 public key",
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

fn is_p256_uncompressed_b64url(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 65 && bytes[0] == 0x04)
}

fn verify_envelope(envelope: &BundleEnvelope, signed_body: &[u8]) -> Result<(), Error> {
    let actual = hex::encode(Sha256::digest(signed_body));
    if actual != envelope.body_sha256 {
        return Err(Error::BundleChecksum("body SHA-256 differs".into()));
    }
    Ok(())
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
    let staging_development_provenance = environment.allow_staging_development_provenance
        && is_staging_development_provenance(
            &attestation_bytes,
            &policy.igvm_sha256,
            &policy_digest,
        )?;
    let github_integrated_time_unix_ms = if staging_development_provenance {
        None
    } else {
        let workflow_identity = format!(
            "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/{}",
            policy.release_tag
        );
        let verified_attestation = verify_github_attestation(
            &attestation_bytes,
            &[
                Subject {
                    name: "gateway.igvm",
                    sha256: &policy.igvm_sha256,
                },
                Subject {
                    name: "gateway-launch-policy.json",
                    sha256: &policy_digest,
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
        )
        .map_err(|error| Error::Release(error.to_string()))?;
        Some(
            verified_attestation
                .integrated_time
                .checked_mul(1000)
                .ok_or_else(|| Error::Release("GitHub integration time overflows".into()))?,
        )
    };

    Ok(VerifiedRelease {
        github_integrated_time_unix_ms,
        igvm_sha256: policy.igvm_sha256.clone(),
        launch: policy.launch.clone(),
        launch_policy_sha256: policy_digest,
        measurement: policy.measurement.clone(),
        provenance: if staging_development_provenance {
            ReleaseProvenance::Staging
        } else {
            ReleaseProvenance::Github
        },
        release_tag: policy.release_tag.clone(),
        sequence: policy.sequence,
        source_commit: policy.source.commit.clone(),
        source_repository: policy.source.repository.clone(),
        source_tree: policy.source.tree.clone(),
        stogas_signing_key_id: signature.key_id.clone(),
        vcpu_count: policy.vcpu_count,
    })
}

fn is_staging_development_provenance(
    bytes: &[u8],
    igvm_sha256: &str,
    launch_policy_sha256: &str,
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
        || statement.subject.len() != 2
    {
        return Err(Error::Release(
            "invalid staging development provenance policy".into(),
        ));
    }
    let expected = BTreeMap::from([
        ("gateway-launch-policy.json", launch_policy_sha256),
        ("gateway.igvm", igvm_sha256),
    ]);
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
    if actual
        != expected
            .into_iter()
            .map(|(name, digest)| (name.to_owned(), digest.to_owned()))
            .collect()
    {
        return Err(Error::Release(
            "staging development provenance subjects differ".into(),
        ));
    }
    Ok(true)
}

fn verify_node(
    node: &Node,
    bundle_created_at: i64,
    bundle_expires_at: i64,
    now_unix_ms: i64,
    launch_policies: &BTreeMap<&str, &LaunchPolicy>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
) -> Result<VerifiedNode, Error> {
    let launch_policy = launch_policies
        .get(node.release_measurement.as_str())
        .ok_or_else(|| {
            Error::Node(format!(
                "{} release measurement {} is absent from the verified release stack",
                node.node_id, node.release_measurement
            ))
        })?;
    if parse_time(&node.cert_expires_at)? < bundle_expires_at {
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
    if quote_verified_at > bundle_created_at {
        return Err(Error::Node(format!(
            "{} quote verification time is later than bundle creation",
            node.node_id
        )));
    }
    let drand_round_time_unix_ms = validate_node_evidence_time(
        &node.node_id,
        node.report_data.drand.round,
        quote_verified_at,
        now_unix_ms,
    )?;
    let round = node.report_data.drand.round;
    verify_quicknet(&node.report_data.drand)?;
    let amd_stack = amd_stacks
        .get(&amd_platform_key(&node.chip_id, &node.reported_tcb))
        .ok_or_else(|| Error::Node(format!("{} has no matching AMD evidence", node.node_id)))?;
    verify_snp_node(
        node,
        launch_policy,
        bundle_created_at,
        bundle_expires_at,
        amd_stack,
    )?;
    Ok(VerifiedNode {
        accepted_cert_sha256: node.report_data.accepted_cert_sha256.clone(),
        chip_id: node.chip_id.clone(),
        drand_round: round,
        drand_round_time_unix_ms,
        evidence_age_ms: now_unix_ms.saturating_sub(drand_round_time_unix_ms).max(0),
        node_id: node.node_id.clone(),
        quote_verified_at_unix_ms: quote_verified_at,
        region: node.region.clone(),
        report_data: node.report_data.clone(),
        report_data_sha512: node.report_data_sha512.clone(),
        release_measurement: node.release_measurement.clone(),
        reported_tcb: node.reported_tcb.clone(),
        tls_spki_sha256: node.report_data.tls_spki_sha256.clone(),
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
) -> Result<(), Error> {
    use sev::{
        certs::snp::{Chain, Verifiable},
        firmware::guest::AttestationReport,
        parser::ByteParser,
    };

    let report_bytes = decode_snp_report(&node.quote, &node.node_id)?;
    check_raw_report_bindings(node, policy, &report_bytes)?;
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|error| Error::Node(format!("{} SNP report: {error}", node.node_id)))?;
    verify_amd_collateral_stack(
        collateral,
        &node.chip_id,
        &node.reported_tcb,
        bundle_created_at,
        bundle_expires_at,
    )?;
    let chain = Chain::from_der(&collateral.ark, &collateral.ask, &collateral.vek)
        .map_err(|error| Error::Node(format!("{} AMD chain: {error}", node.node_id)))?;
    (&chain, &report)
        .verify()
        .map_err(|error| Error::Node(format!("{} SNP signature: {error}", node.node_id)))
}

#[cfg(not(feature = "snp"))]
fn verify_snp_node(
    _node: &Node,
    _policy: &LaunchPolicy,
    _bundle_created_at: i64,
    _bundle_expires_at: i64,
    _collateral: &AmdCollateralStack,
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
    let report_version = u32_at(0x00);
    let report_info = u32_at(0x48);
    let checks = [
        ((2..=5).contains(&report_version), "report version"),
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
        ((report_info & 0b10) == 0, "masked chip key flag"),
        ((report_info >> 2).trailing_zeros() >= 3, "VCEK signing key"),
    ];
    for (valid, label) in checks {
        if !valid {
            return Err(Error::Node(format!("{} SNP {label} differs", node.node_id)));
        }
    }
    Ok(())
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
    const ROOT_HASHES: [&str; 3] = [
        "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    ];
    let (_, ark) = parse_x509_certificate(&collateral.ark)
        .map_err(|error| Error::Node(format!("AMD ARK: {error}")))?;
    let (_, ask) = parse_x509_certificate(&collateral.ask)
        .map_err(|error| Error::Node(format!("AMD ASK: {error}")))?;
    let (_, vek) = parse_x509_certificate(&collateral.vek)
        .map_err(|error| Error::Node(format!("AMD VEK: {error}")))?;
    for (label, cert) in [("ARK", &ark), ("ASK", &ask), ("VEK", &vek)] {
        if cert.validity().not_before.timestamp() * 1000 > bundle_created_at
            || cert.validity().not_after.timestamp() * 1000 < bundle_expires_at
        {
            return Err(Error::Node(format!(
                "AMD {label} is not valid for the complete bundle interval"
            )));
        }
    }
    let root_hash = hex::encode(Sha384::digest(ark.public_key().raw));
    if !ROOT_HASHES.contains(&root_hash.as_str())
        || ark.subject() != ark.issuer()
        || ask.issuer() != ark.subject()
        || vek.issuer() != ask.subject()
    {
        return Err(Error::Node("AMD certificate identity chain differs".into()));
    }
    let (_, crl) = parse_x509_crl(&collateral.crl)
        .map_err(|error| Error::Node(format!("AMD CRL: {error}")))?;
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
    validate_vcek_extensions(&vek, chip_id, reported_tcb)
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
) -> Result<(), Error> {
    let expected_tcb =
        hex::decode(reported_tcb).map_err(|_| Error::Node("reported TCB is invalid".into()))?;
    let expected = [
        expected_tcb[0],
        expected_tcb[1],
        expected_tcb[6],
        expected_tcb[7],
    ];
    let oids = [
        "1.3.6.1.4.1.3704.1.3.1",
        "1.3.6.1.4.1.3704.1.3.2",
        "1.3.6.1.4.1.3704.1.3.3",
        "1.3.6.1.4.1.3704.1.3.8",
    ];
    for (oid, expected_value) in oids.into_iter().zip(expected) {
        let extension = vek
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == oid)
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is absent")))?;
        let value = parse_der_u8(extension.value)
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is malformed")))?;
        if value != expected_value {
            return Err(Error::Node(format!(
                "AMD VCEK extension {oid} differs: certificate={value:#04x}, report={expected_value:#04x}"
            )));
        }
    }
    let hwid = vek
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.3704.1.4")
        .ok_or_else(|| Error::Node("AMD VCEK chip-id extension is absent".into()))?;
    let chip = hex::decode(chip_id).map_err(|_| Error::Node("chip id is invalid".into()))?;
    let certificate_chip = parse_der_octet_string(hwid.value).ok_or_else(|| {
        Error::Node(format!(
            "AMD VCEK chip id is malformed ({})",
            hwid.value.len()
        ))
    })?;
    if certificate_chip != chip {
        return Err(Error::Node("AMD VCEK chip id differs".into()));
    }
    Ok(())
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
fn parse_der_octet_string(value: &[u8]) -> Option<&[u8]> {
    if value.len() == 64 {
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
                output.push_str(&serde_json::to_string(value).unwrap_or_default());
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
                    output.push_str(&serde_json::to_string(key).unwrap_or_default());
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
        "catalog_hash".into(),
        Value::String(report.catalog_hash.clone()),
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
        serde_json::to_value(certs).unwrap_or_default(),
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

    fn quote_with_identity(chip: [u8; 64], measurement: [u8; 48], tcb: [u8; 8]) -> String {
        let mut report = vec![0_u8; 0x4a0];
        report[0x00..0x04].copy_from_slice(&2_u32.to_le_bytes());
        report[0x90..0xc0].copy_from_slice(&measurement);
        report[0x180..0x188].copy_from_slice(&tcb);
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

    #[test]
    fn inspects_only_raw_snp_identity_needed_for_collateral_selection() {
        let identity =
            inspect_snp_quote(&quote_with_identity([0x11; 64], [0x22; 48], [0x33; 8])).unwrap();
        assert_eq!(identity.chip_id, "11".repeat(64));
        assert_eq!(identity.release_measurement, "22".repeat(48));
        assert_eq!(identity.reported_tcb, "33".repeat(8));
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
        let release = release_fixture().launch_policy;
        let report_data = ReportData {
            active_cert_sha256: "11".repeat(32),
            accepted_cert_sha256: vec!["11".repeat(32)],
            catalog_hash: "22".repeat(32),
            drand: DrandBeacon {
                chain_hash: DRAND_CHAIN_HASH.into(),
                network: "quicknet".into(),
                randomness: "33".repeat(32),
                round: 1,
                signature: "44".repeat(48),
            },
            ed25519_public_key: "local-ed25519".into(),
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
        serde_json::json!({
            "attester_mode": "mock",
            "heartbeat": {
                "cert_expires_at": "2026-08-01T00:00:00.000Z",
                "health": { "ready": true, "secret_versions": {} },
                "node_id": "local-node",
                "observed_at": generated_at,
                "quote": quote,
                "quote_generated_at": generated_at,
                "report_data": report_data,
                "report_data_sha512": report_data_sha512
            },
            "launch_policies": [release],
            "region": "local",
            "trusted_platforms": [{
                "chip_id": "66".repeat(64),
                "reported_tcb": "00".repeat(8)
            }]
        })
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
        ambiguous["trusted_platforms"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "chip_id": "77".repeat(64),
                "reported_tcb": "00".repeat(8)
            }));
        assert!(
            verify_local_heartbeat_admission(&serde_json::to_vec(&ambiguous).unwrap(), now)
                .unwrap_err()
                .to_string()
                .contains("exactly one platform")
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
