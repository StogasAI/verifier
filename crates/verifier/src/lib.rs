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
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};
use thiserror::Error;

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 1_024;
const MAX_VENDOR_COLLATERAL: usize = 4_096;
const MAX_BUNDLE_VALIDITY_MS: i64 = 10 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: i64 = 60_000;
const MAX_CLOCK_ROLLBACK_MS: i64 = 60_000;
const DRAND_CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const DRAND_GENESIS_SECONDS: i64 = 1_692_803_367;
const DRAND_PERIOD_SECONDS: i64 = 3;
const DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS: i64 = 10 * 60 * 1000;
const CLIENT_QUOTE_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
const AMD_COLLATERAL_VALIDITY_MS: i64 = 24 * 60 * 60 * 1000;
const STOGAS_RELEASE_KEY_ID: &str = "stogas-ed25519-stamp-v1";
const STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64: &str =
    "MCowBQYDK2VwAyEAByVn3LvWVbf3YkokMZPvir70vcDu0nNflgXoM0Y8aQU=";

/// Runtime-independent trust configuration.
#[derive(Clone, Debug)]
pub struct Environment {
    /// Environment label included in diagnostics.
    pub name: String,
    /// Trusted fleet bundle signing keys, keyed by key id, as base64 SPKI DER.
    pub fleet_keys: BTreeMap<String, String>,
    /// Trusted Stogas release signing keys, keyed by key id, as base64 SPKI DER.
    pub release_keys: BTreeMap<String, String>,
    /// Reject an empty production trust set.
    pub require_nodes: bool,
}

impl Environment {
    /// Temporary staging policy matching bundles created before the dedicated fleet key rollout.
    #[must_use]
    pub fn staging_legacy() -> Self {
        let release_keys = BTreeMap::from([(
            STOGAS_RELEASE_KEY_ID.to_owned(),
            STOGAS_RELEASE_PUBLIC_KEY_DER_BASE64.to_owned(),
        )]);
        Self {
            name: "staging".into(),
            fleet_keys: release_keys.clone(),
            release_keys,
            require_nodes: false,
        }
    }
}

/// Complete verification failure. No state may be persisted after this error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("bundle exceeds {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,
    #[error("invalid bundle JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported or invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("bundle signature failed: {0}")]
    BundleSignature(String),
    #[error("release verification failed: {0}")]
    Release(String),
    #[error("node verification failed: {0}")]
    Node(String),
    #[error("rollback protection failed: {0}")]
    Rollback(String),
}

/// Verify a bundle using one captured wall-clock time and optional prior rollback state.
///
/// # Errors
///
/// Returns an error without a state update if any parsing, cryptographic, policy, freshness, or
/// rollback check fails.
pub fn verify_bundle(
    bundle_bytes: &[u8],
    now_unix_ms: i64,
    environment: &Environment,
    prior_state: Option<&VerifierState>,
) -> Result<VerificationOutput, Error> {
    if bundle_bytes.len() > MAX_BUNDLE_BYTES {
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
    verify_envelope(&envelope, &signed_body, environment)?;

    let created_at = parse_time(&envelope.body.created_at)?;
    let expires_at = parse_time(&envelope.body.expires_at)?;
    validate_time(created_at, expires_at, envelope.body.ttl_ms, now_unix_ms)?;
    validate_prior_state(&envelope, now_unix_ms, prior_state)?;

    let releases = envelope
        .body
        .allowed_igvms
        .iter()
        .map(|release| verify_release(release, environment))
        .collect::<Result<Vec<_>, _>>()?;
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
    let mut rounds = prior_state
        .map(|state| state.highest_drand_round_by_node.clone())
        .unwrap_or_default();
    let nodes = envelope
        .body
        .nodes
        .iter()
        .map(|node| {
            verify_node(
                node,
                created_at,
                expires_at,
                now_unix_ms,
                &launch_policies,
                &amd_stacks,
                &mut rounds,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if environment.require_nodes && nodes.is_empty() {
        return Err(Error::InvalidBundle("production trust set is empty".into()));
    }

    Ok(VerificationOutput {
        bundle: VerifiedBundle {
            sequence: envelope.body.sequence,
            created_at_unix_ms: created_at,
            expires_at_unix_ms: expires_at,
            releases,
            nodes,
            original: envelope.clone(),
        },
        next_state: VerifierState {
            version: 1,
            highest_bundle_sequence: envelope.body.sequence,
            highest_observed_time_unix_ms: prior_state.map_or(now_unix_ms, |state| {
                state.highest_observed_time_unix_ms.max(now_unix_ms)
            }),
            highest_drand_round_by_node: rounds,
        },
    })
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

fn verify_envelope(
    envelope: &BundleEnvelope,
    signed_body: &[u8],
    environment: &Environment,
) -> Result<(), Error> {
    if envelope.signature.algorithm != "Ed25519" {
        return Err(Error::BundleSignature("unsupported algorithm".into()));
    }
    let actual = hex::encode(Sha256::digest(signed_body));
    if actual != envelope.body_sha256 {
        return Err(Error::BundleSignature("body SHA-256 differs".into()));
    }
    let key = environment
        .fleet_keys
        .get(&envelope.signature.key_id)
        .ok_or_else(|| Error::BundleSignature("fleet signing key is not trusted".into()))?;
    verify_ed25519(key, signed_body, &envelope.signature.signature).map_err(Error::BundleSignature)
}

fn verify_release(
    release: &AllowedIgvm,
    environment: &Environment,
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

    let attestation = release
        .github_in_toto
        .first()
        .ok_or_else(|| Error::Release("GitHub attestation is absent".into()))?;
    let attestation_bytes =
        serde_json::to_vec(attestation).map_err(|error| Error::Release(error.to_string()))?;
    let policy_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    let workflow_identity = format!(
        "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/{}",
        policy.release_tag
    );
    verify_github_attestation(
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
    )
    .map_err(|error| Error::Release(error.to_string()))?;

    Ok(VerifiedRelease {
        igvm_sha256: policy.igvm_sha256.clone(),
        measurement: policy.measurement.clone(),
        release_tag: policy.release_tag.clone(),
        source_commit: policy.source.commit.clone(),
    })
}

fn verify_node(
    node: &Node,
    bundle_created_at: i64,
    bundle_expires_at: i64,
    now_unix_ms: i64,
    launch_policies: &BTreeMap<&str, &LaunchPolicy>,
    amd_stacks: &BTreeMap<String, AmdCollateralStack>,
    rounds: &mut BTreeMap<String, u64>,
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
    validate_node_evidence_time(
        &node.node_id,
        node.report_data.drand.round,
        quote_verified_at,
        bundle_expires_at,
        now_unix_ms,
    )?;
    let round = node.report_data.drand.round;
    if rounds
        .get(&node.node_id)
        .is_some_and(|prior| round < *prior)
    {
        return Err(Error::Rollback(format!(
            "{} drand round regressed",
            node.node_id
        )));
    }
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
    rounds.insert(node.node_id.clone(), round);
    Ok(VerifiedNode {
        accepted_cert_sha256: node.report_data.accepted_cert_sha256.clone(),
        node_id: node.node_id.clone(),
        region: node.region.clone(),
        release_measurement: node.release_measurement.clone(),
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
    bundle_expires_at: i64,
    now_unix_ms: i64,
) -> Result<(), Error> {
    if quote_verified_at > now_unix_ms + MAX_CLOCK_SKEW_MS {
        return Err(Error::Node(format!(
            "{node_id} quote verification time is in the future"
        )));
    }
    let identity_deadline = quote_verified_at
        .checked_add(CLIENT_QUOTE_WINDOW_MS)
        .ok_or_else(|| Error::Node(format!("{node_id} quote deadline overflows")))?;
    if bundle_expires_at > identity_deadline {
        return Err(Error::Node(format!(
            "bundle outlives {node_id} verified identity"
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
    Ok(())
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
        .decode(&node.quote)
        .map_err(|_| Error::Node(format!("{} quote encoding is invalid", node.node_id)))?;
    let quote: QuoteEnvelope = serde_json::from_slice(&quote_json)
        .map_err(|error| Error::Node(format!("{} quote envelope: {error}", node.node_id)))?;
    if quote.schema != "stogas.sev-snp-quote-envelope.v1"
        || quote.provider != "sev_guest"
        || quote.manifestblob.is_some()
    {
        return Err(Error::Node(format!(
            "{} quote envelope is unsupported",
            node.node_id
        )));
    }
    let report_bytes = URL_SAFE_NO_PAD
        .decode(&quote.report)
        .map_err(|_| Error::Node(format!("{} SNP report encoding is invalid", node.node_id)))?;
    if report_bytes.len() != 0x4a0 {
        return Err(Error::Node(format!(
            "{} SNP report has the wrong size",
            node.node_id
        )));
    }
    check_raw_report_bindings(node, policy, &report_bytes)?;
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|error| Error::Node(format!("{} SNP report: {error}", node.node_id)))?;

    let _ = &quote.auxblob;
    validate_amd_x509(
        &collateral.ark,
        &collateral.ask,
        &collateral.vek,
        &collateral.crl,
        node,
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
    ark_der: &[u8],
    ask_der: &[u8],
    vek_der: &[u8],
    crl_der: &[u8],
    node: &Node,
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
    let (_, ark) = parse_x509_certificate(ark_der)
        .map_err(|error| Error::Node(format!("AMD ARK: {error}")))?;
    let (_, ask) = parse_x509_certificate(ask_der)
        .map_err(|error| Error::Node(format!("AMD ASK: {error}")))?;
    let (_, vek) = parse_x509_certificate(vek_der)
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
    let (_, crl) =
        parse_x509_crl(crl_der).map_err(|error| Error::Node(format!("AMD CRL: {error}")))?;
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
    validate_vcek_extensions(&vek, node)
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
    node: &Node,
) -> Result<(), Error> {
    let expected_tcb = hex::decode(&node.reported_tcb)
        .map_err(|_| Error::Node("reported TCB is invalid".into()))?;
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
    let chip = hex::decode(&node.chip_id).map_err(|_| Error::Node("chip id is invalid".into()))?;
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
    if expires <= now || expires <= created {
        return Err(Error::InvalidBundle(
            "bundle is expired or has an invalid interval".into(),
        ));
    }
    let interval = expires - created;
    let declared_ttl = i64::try_from(ttl_ms).unwrap_or(i64::MAX);
    if interval != declared_ttl {
        return Err(Error::InvalidBundle(format!(
            "bundle interval ({interval} ms) differs from signed ttl_ms ({declared_ttl} ms)"
        )));
    }
    if interval > MAX_BUNDLE_VALIDITY_MS {
        return Err(Error::InvalidBundle(format!(
            "bundle validity ({interval} ms) exceeds the {MAX_BUNDLE_VALIDITY_MS} ms policy"
        )));
    }
    Ok(())
}

fn validate_prior_state(
    envelope: &BundleEnvelope,
    now: i64,
    prior: Option<&VerifierState>,
) -> Result<(), Error> {
    let Some(prior) = prior else {
        return Ok(());
    };
    if prior.version != 1 {
        return Err(Error::Rollback("unsupported state version".into()));
    }
    if envelope.body.sequence < prior.highest_bundle_sequence {
        return Err(Error::Rollback("bundle sequence regressed".into()));
    }
    if now + MAX_CLOCK_ROLLBACK_MS < prior.highest_observed_time_unix_ms {
        return Err(Error::Rollback("wall clock moved backwards".into()));
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
            name: "test".into(),
            fleet_keys: BTreeMap::new(),
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
            require_nodes: false,
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
        let verified = verify_release(&release, &Environment::staging_legacy()).unwrap();
        assert_eq!(verified.igvm_sha256, release.launch_policy.igvm_sha256);
        assert_eq!(verified.measurement, release.launch_policy.measurement);
    }

    #[test]
    fn rejects_invalid_stogas_release_signature_before_accepting_github_evidence() {
        let mut release = release_fixture();
        release.stogas_signature.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        let error = verify_release(&release, &Environment::staging_legacy()).unwrap_err();
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
            let error = verify_release(&release, &environment).unwrap_err();
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
    fn retained_quote_uses_original_drand_freshness_and_forward_identity_deadline() {
        let round = 1_000_000_u64;
        let round_time = (DRAND_GENESIS_SECONDS
            + i64::try_from(round - 1).unwrap() * DRAND_PERIOD_SECONDS)
            * 1000;
        let quote_verified_at = round_time + DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS;
        let now = quote_verified_at + 23 * 60 * 60 * 1000;
        let expires = quote_verified_at + CLIENT_QUOTE_WINDOW_MS;

        validate_node_evidence_time("node", round, quote_verified_at, expires, now).unwrap();
    }

    #[test]
    fn rejects_drand_that_was_already_stale_when_control_verified_quote() {
        let round = 1_000_000_u64;
        let round_time = (DRAND_GENESIS_SECONDS
            + i64::try_from(round - 1).unwrap() * DRAND_PERIOD_SECONDS)
            * 1000;
        let quote_verified_at = round_time + DRAND_MAX_AGE_AT_QUOTE_VERIFICATION_MS + 1;
        let error = validate_node_evidence_time(
            "node",
            round,
            quote_verified_at,
            quote_verified_at + MAX_BUNDLE_VALIDITY_MS,
            quote_verified_at,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("stale when the quote was verified")
        );
    }

    #[test]
    fn rejects_bundle_past_verified_identity_deadline() {
        let round = 1_000_000_u64;
        let round_time = (DRAND_GENESIS_SECONDS
            + i64::try_from(round - 1).unwrap() * DRAND_PERIOD_SECONDS)
            * 1000;
        let error = validate_node_evidence_time(
            "node",
            round,
            round_time,
            round_time + CLIENT_QUOTE_WINDOW_MS + 1,
            round_time + CLIENT_QUOTE_WINDOW_MS - 1,
        )
        .unwrap_err();
        assert!(error.to_string().contains("verified identity"));
    }
}
