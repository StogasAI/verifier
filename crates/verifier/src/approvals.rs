//! Offline authorization of current evidence. Delivery and evidence appraisal remain separate.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AllowedCatalog, AllowedIgvm, MAX_INPUT_BYTES, STOGAS_SIGNATURE_DOMAIN, SignedHardwarePolicy,
    StogasSignature, VerifiedCatalogRelease, VerifiedHardwarePolicy, VerifiedRelease,
    canonical_json, strict_json,
};

pub const KEY_MANIFEST_SCHEMA: &str = "stogas.keys.v1";
pub const KEY_MANIFEST_PAYLOAD_TYPE: &str = "application/vnd.stogas.keys.v1+json";
pub const APPROVAL_MANIFEST_SCHEMA: &str = "stogas.approvals.v1";
const MAX_REVISION: u64 = (1 << 53) - 1;

mod keys;
pub(crate) use keys::KeyState;
use keys::VerifiedKeys;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Environment {
    #[serde(rename = "prod")]
    Production,
    #[cfg(feature = "staging")]
    #[serde(rename = "staging")]
    Staging,
}

impl Environment {
    /// Fixed evidence origins in delivery preference order.
    #[must_use]
    pub const fn evidence_origins(self) -> [&'static str; 2] {
        match self {
            Self::Production => [
                "https://evidence.stogas.ai/bundles/latest.json",
                "https://evidence2.stogas.ai/bundles/latest.json",
            ],
            #[cfg(feature = "staging")]
            Self::Staging => [
                "https://evidence-staging.stogas.ai/bundles/latest.json",
                "https://evidence2-staging.stogas.ai/bundles/latest.json",
            ],
        }
    }

    #[must_use]
    pub const fn api_origin(self) -> &'static str {
        match self {
            Self::Production => "https://api.stogas.ai",
            #[cfg(feature = "staging")]
            Self::Staging => "https://api-staging.stogas.ai",
        }
    }

    #[must_use]
    pub const fn e2ee_origin(self) -> &'static str {
        match self {
            Self::Production => "https://e2ee.stogas.ai",
            #[cfg(feature = "staging")]
            Self::Staging => "https://e2ee-staging.stogas.ai",
        }
    }

    /// Compiled Stogas trust seed; evidence cannot select or replace this authority.
    ///
    /// # Errors
    /// Production remains unavailable until its independent offline root is provisioned.
    pub fn stogas_root(self) -> Result<OnlineKey, Error> {
        match self {
            Self::Production => Err(invalid("production evidence root is not provisioned")),
            #[cfg(feature = "staging")]
            Self::Staging => Ok(OnlineKey {
                key_id: "stogas-root-staging-v1".into(),
                public_key: "MCowBQYDK2VwAyEAzLbKFJboWdiCQt4n8Zj50x+pg22KIq7vpD4UhWXiHks=".into(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OnlineKey {
    pub key_id: String,
    /// Canonical standard-base64 Ed25519 `SubjectPublicKeyInfo` DER.
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyManifest {
    pub schema: String,
    pub environment: Environment,
    pub generation: u64,
    pub active_key: OnlineKey,
    pub retired_keys: Vec<OnlineKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyManifest {
    pub manifest: KeyManifest,
    /// Root-signed DSSE and its verified Rekor inclusion, using the existing Sigstore format.
    pub sigstore: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalManifest {
    pub schema: String,
    pub environment: Environment,
    pub revision: u64,
    pub key_manifest_sha256: String,
    /// Sorted SHA-256 digests of canonical unsigned release manifests, without a newline.
    pub gateways: Vec<String>,
    pub catalogs: Vec<String>,
    pub hardware_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalManifest {
    pub manifest: ApprovalManifest,
    pub signature: StogasSignature,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("approval evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid approval evidence: {0}")]
    Invalid(String),
    #[error("approval evidence belongs to another authority or environment")]
    Authority,
    #[error("key manifest transparency verification failed: {0}")]
    Transparency(String),
    #[error("approval signing key is not active")]
    InactiveKey,
    #[error("approval signature is invalid")]
    Signature,
    #[error("approval evidence rolls back an accepted decision")]
    Rollback,
    #[error("different signed decisions use the same revision")]
    Equivocation,
    #[error("key manifest restores or changes a retired key")]
    RetiredKey,
    #[error("{0} is not in the signed approval set")]
    NotApproved(&'static str),
    #[error("approved evidence failed verification: {0}")]
    Evidence(String),
}

/// Holds only authenticated decisions, never CRLs, checkpoints, compression or HTTP `ETags`.
#[derive(Clone, Debug)]
pub struct VerifiedApprovals {
    authority: [u8; 32],
    keys: KeyManifest,
    approvals: ApprovalManifest,
    keys_digest: String,
    approvals_digest: String,
}

impl VerifiedApprovals {
    #[must_use]
    pub const fn keys(&self) -> &KeyManifest {
        &self.keys
    }

    #[must_use]
    pub const fn manifest(&self) -> &ApprovalManifest {
        &self.approvals
    }

    #[must_use]
    pub fn allows_gateway(&self, release_id: &str) -> bool {
        self.approvals
            .gateways
            .binary_search_by(|id| id.as_str().cmp(release_id))
            .is_ok()
    }

    #[must_use]
    pub fn allows_catalog(&self, release_id: &str) -> bool {
        self.approvals
            .catalogs
            .binary_search_by(|id| id.as_str().cmp(release_id))
            .is_ok()
    }

    /// Verify current approval, the exact release signature and its independent build evidence.
    ///
    /// # Errors
    /// Rejects an unlisted release, retired signer, invalid launch manifest or build proof.
    pub fn verify_gateway(
        &self,
        release: &AllowedIgvm,
        now_unix_ms: i64,
    ) -> Result<VerifiedRelease, Error> {
        if !self.allows_gateway(&payload_sha256(&release.manifest)?) {
            return Err(Error::NotApproved("gateway"));
        }
        self.require_active_key(&release.signature.key_id)?;
        let verified =
            crate::verify_release_with_key(release, &self.keys.active_key.public_key, now_unix_ms)
                .map_err(|error| Error::Evidence(error.to_string()))?;
        if !self.accepts_provenance(&verified.provenance) {
            return Err(Error::Authority);
        }
        Ok(verified)
    }

    /// Verify current approval, the catalog signature and independent artifact build evidence.
    ///
    /// # Errors
    /// Rejects an unlisted catalog, retired signer or invalid release/build evidence.
    pub fn verify_catalog(
        &self,
        catalog: &AllowedCatalog,
        now_unix_ms: i64,
    ) -> Result<VerifiedCatalogRelease, Error> {
        if !self.allows_catalog(&payload_sha256(&catalog.manifest)?) {
            return Err(Error::NotApproved("catalog"));
        }
        self.require_active_key(&catalog.signature.key_id)?;
        let verified =
            crate::verify_catalog_with_key(catalog, &self.keys.active_key.public_key, now_unix_ms)
                .map_err(|error| Error::Evidence(error.to_string()))?;
        if !self.accepts_provenance(&verified.provenance) {
            return Err(Error::Authority);
        }
        Ok(verified)
    }

    /// Verify the selected hardware policy, its active-key DSSE signature and Rekor inclusion.
    ///
    /// # Errors
    /// Rejects a different policy, invalid hardware rules, untrusted signer or invalid log proof.
    pub fn verify_hardware_policy(
        &self,
        signed: &SignedHardwarePolicy,
        now_unix_ms: i64,
    ) -> Result<VerifiedHardwarePolicy, Error> {
        if payload_sha256(&signed.policy)? != self.approvals.hardware_policy_sha256 {
            return Err(Error::NotApproved("hardware policy"));
        }
        crate::verify_signed_hardware_policy_with_key(
            signed,
            &self.keys.active_key.key_id,
            &self.keys.active_key.public_key,
            now_unix_ms,
        )
        .map_err(|error| Error::Evidence(error.to_string()))
    }

    fn require_active_key(&self, key_id: &str) -> Result<(), Error> {
        if key_id != self.keys.active_key.key_id {
            return Err(Error::InactiveKey);
        }
        Ok(())
    }

    // A staging-capable binary must still reject placeholders when its selected context is production.
    const fn accepts_provenance(&self, provenance: &crate::ReleaseProvenance) -> bool {
        match (self.keys.environment, provenance) {
            (Environment::Production, crate::ReleaseProvenance::Github) => true,
            #[cfg(feature = "staging")]
            (Environment::Staging, _) => true,
            #[cfg(feature = "staging")]
            (Environment::Production, crate::ReleaseProvenance::Staging) => false,
        }
    }
}

/// The caller selects this root from its trusted environment configuration, never the bundle.
/// A candidate does not replace learned decisions until every referenced evidence object passes.
pub struct ApprovalVerifier {
    environment: Environment,
    root: OnlineKey,
    root_der: Vec<u8>,
    authority: [u8; 32],
    accepted: Option<VerifiedApprovals>,
    key_state: Arc<KeyState>,
}

impl ApprovalVerifier {
    /// Separate historical appraisal from all learned current decisions.
    #[cfg(feature = "snp")]
    pub(crate) fn historical_authority(&self) -> Result<Self, Error> {
        Self::new(self.environment, self.root.clone())
    }

    /// Verify and retain a root decision independently of approval/artifact delivery.
    ///
    /// # Errors
    /// Rejects invalid inclusion, signatures, environments, conflicts or retired-key restoration.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<KeyManifest, Error> {
        Ok(self.observe_keys(bytes, now_unix_ms)?.manifest)
    }

    /// # Errors
    /// Rejects malformed or weak root keys and ambiguous key identifiers.
    pub fn new(environment: Environment, root: OnlineKey) -> Result<Self, Error> {
        let root_der = decode_key(&root)?;
        let authority = Sha256::digest(&root_der).into();
        Ok(Self {
            environment,
            root,
            root_der,
            authority,
            accepted: None,
            key_state: Arc::default(),
        })
    }

    /// Verify root authorization, public logging and the complete signed approval decision.
    /// This does not verify the artifacts named in the decision or install a new snapshot.
    ///
    /// # Errors
    /// Rejects malformed, untrusted, conflicting or superseded decisions without changing state.
    pub fn verify_candidate(
        &self,
        keys_bytes: &[u8],
        approvals_bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedApprovals, Error> {
        if keys_bytes.len().saturating_add(approvals_bytes.len()) > MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let keys = self.verify_keys(keys_bytes, now_unix_ms)?;
        self.verify_with_keys(keys, approvals_bytes)
    }

    fn verify_keys(&self, bytes: &[u8], now_unix_ms: i64) -> Result<VerifiedKeys, Error> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let keys: SignedKeyManifest = parse(bytes)?;
        validate_keys(&keys.manifest, self.environment, &self.root)?;
        let canonical = canonical_json(&serde_json::to_value(&keys.manifest).map_err(invalid)?)
            .map_err(invalid)?;
        stogas_offline_sigstore::verify_keyed_dsse(
            &keys.sigstore,
            canonical.as_bytes(),
            KEY_MANIFEST_PAYLOAD_TYPE,
            &self.root.key_id,
            &self.root_der,
            now_unix_ms,
        )
        .map_err(|error| Error::Transparency(error.to_string()))?;
        Ok(VerifiedKeys {
            digest: payload_sha256(&keys.manifest)?,
            manifest: keys.manifest,
        })
    }

    pub(crate) fn observe_keys(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedKeys, Error> {
        let keys = self.verify_keys(bytes, now_unix_ms)?;
        self.key_state.learn(keys.clone())?;
        Ok(keys)
    }

    pub(crate) fn key_state(&self) -> Arc<KeyState> {
        Arc::clone(&self.key_state)
    }

    pub(crate) fn verify_with_keys(
        &self,
        keys: VerifiedKeys,
        approvals_bytes: &[u8],
    ) -> Result<VerifiedApprovals, Error> {
        if approvals_bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let approvals: SignedApprovalManifest = parse(approvals_bytes)?;
        let candidate = verify_online_approval(self.authority, keys.manifest, approvals)?;
        self.check_update(&candidate)?;
        Ok(candidate)
    }

    /// Call only after the complete candidate bundle passes artifact and collateral checks.
    /// Rechecks ordering so overlapping acquisitions cannot undo a newer accepted decision.
    ///
    /// # Errors
    /// Rejects a candidate from another authority, rollback, equivocation or restored retired keys.
    pub fn accept(&mut self, candidate: VerifiedApprovals) -> Result<(), Error> {
        self.check_update(&candidate)?;
        self.key_state.learn(VerifiedKeys {
            manifest: candidate.keys.clone(),
            digest: candidate.keys_digest.clone(),
        })?;
        self.accepted = Some(candidate);
        Ok(())
    }

    #[must_use]
    pub const fn accepted(&self) -> Option<&VerifiedApprovals> {
        self.accepted.as_ref()
    }

    fn check_update(&self, candidate: &VerifiedApprovals) -> Result<(), Error> {
        if candidate.authority != self.authority || candidate.keys.environment != self.environment {
            return Err(Error::Authority);
        }
        self.key_state
            .check(&candidate.keys, &candidate.keys_digest)?;
        let Some(previous) = &self.accepted else {
            return Ok(());
        };
        if candidate.keys.generation < previous.keys.generation {
            return Err(Error::Rollback);
        }
        if candidate.keys.generation == previous.keys.generation {
            if candidate.keys_digest != previous.keys_digest {
                return Err(Error::Equivocation);
            }
            if candidate.approvals.revision < previous.approvals.revision {
                return Err(Error::Rollback);
            }
            if candidate.approvals.revision == previous.approvals.revision
                && candidate.approvals_digest != previous.approvals_digest
            {
                return Err(Error::Equivocation);
            }
        }
        Ok(())
    }
}

/// Stable payload identity. Approval signatures and supporting evidence are not part of it.
///
/// # Errors
/// Returns an error if the payload cannot be serialized as canonical JSON.
pub fn payload_sha256(payload: &impl Serialize) -> Result<String, Error> {
    let value = serde_json::to_value(payload).map_err(invalid)?;
    Ok(hex::encode(Sha256::digest(canonical_payload(&value)?)))
}

fn verify_online_approval(
    authority: [u8; 32],
    keys: KeyManifest,
    signed: SignedApprovalManifest,
) -> Result<VerifiedApprovals, Error> {
    let approvals = signed.manifest;
    if approvals.schema != APPROVAL_MANIFEST_SCHEMA || !valid_revision(approvals.revision) {
        return Err(Error::Invalid("approval schema or revision".into()));
    }
    if approvals.environment != keys.environment {
        return Err(Error::Authority);
    }
    let keys_digest = payload_sha256(&keys)?;
    if approvals.key_manifest_sha256 != keys_digest {
        return Err(Error::Invalid("key manifest digest mismatch".into()));
    }
    if !is_digest(&approvals.hardware_policy_sha256)
        || !sorted_digests(&approvals.gateways)
        || !sorted_digests(&approvals.catalogs)
    {
        return Err(Error::Invalid(
            "approval digests must be sorted and unique".into(),
        ));
    }
    verify_signature(
        &serde_json::to_value(&approvals).map_err(invalid)?,
        &signed.signature,
        &keys.active_key,
    )?;
    let approvals_digest = payload_sha256(&approvals)?;
    Ok(VerifiedApprovals {
        authority,
        keys,
        approvals,
        keys_digest,
        approvals_digest,
    })
}

fn validate_keys(
    keys: &KeyManifest,
    environment: Environment,
    root: &OnlineKey,
) -> Result<(), Error> {
    if keys.schema != KEY_MANIFEST_SCHEMA || !valid_revision(keys.generation) {
        return Err(Error::Invalid("key manifest schema or generation".into()));
    }
    if keys.environment != environment {
        return Err(Error::Authority);
    }
    if keys
        .retired_keys
        .windows(2)
        .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        return Err(Error::Invalid(
            "retired keys must be sorted and unique".into(),
        ));
    }
    let mut ids = BTreeSet::from([root.key_id.as_str()]);
    let mut public_keys = BTreeSet::from([root.public_key.as_str()]);
    for key in std::iter::once(&keys.active_key).chain(&keys.retired_keys) {
        decode_key(key)?;
        if !ids.insert(&key.key_id) || !public_keys.insert(&key.public_key) {
            return Err(Error::Invalid("duplicate or root operational key".into()));
        }
    }
    Ok(())
}

fn verify_signature(
    document: &Value,
    signature: &StogasSignature,
    key: &OnlineKey,
) -> Result<(), Error> {
    if signature.key_id != key.key_id {
        return Err(Error::InactiveKey);
    }
    let public = VerifyingKey::from_public_key_der(&decode_key(key)?).map_err(invalid)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .map_err(|_| Error::Signature)?;
    if bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&bytes) != signature.signature {
        return Err(Error::Signature);
    }
    let signature = Signature::from_slice(&bytes).map_err(|_| Error::Signature)?;
    let mut payload = STOGAS_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&canonical_payload(document)?);
    public
        .verify_strict(&payload, &signature)
        .map_err(|_| Error::Signature)
}

fn decode_key(key: &OnlineKey) -> Result<Vec<u8>, Error> {
    if key.key_id.is_empty()
        || key.key_id.len() > 128
        || !key
            .key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Invalid("key identifier".into()));
    }
    let bytes = STANDARD.decode(&key.public_key).map_err(invalid)?;
    if bytes.len() != 44 || STANDARD.encode(&bytes) != key.public_key {
        return Err(Error::Invalid("public key encoding".into()));
    }
    let public = VerifyingKey::from_public_key_der(&bytes).map_err(invalid)?;
    if public.is_weak() {
        return Err(Error::Invalid("weak public key".into()));
    }
    Ok(bytes)
}

fn canonical_payload(value: &Value) -> Result<Vec<u8>, Error> {
    let mut canonical = canonical_json(value).map_err(invalid)?;
    canonical.pop(); // The document-file newline is not signed or hashed as a payload.
    Ok(canonical.into_bytes())
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    serde_json::from_value(strict_json::from_slice(bytes).map_err(invalid)?).map_err(invalid)
}

const fn valid_revision(revision: u64) -> bool {
    revision > 0 && revision <= MAX_REVISION
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sorted_digests(values: &[String]) -> bool {
    values.iter().all(|v| is_digest(v)) && values.windows(2).all(|pair| pair[0] < pair[1])
}
fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
