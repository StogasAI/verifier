//! Complete current evidence, independent of fleet membership and connection lifetime.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AllowedCatalog, AllowedIgvm, HardwarePolicy, SignedHardwarePolicy, VerifiedCatalogRelease,
    VerifiedHardwarePolicy, VerifiedRelease,
    approvals::{
        self, ApprovalVerifier, Environment, OnlineKey, SignedApprovalManifest, SignedKeyManifest,
        VerifiedApprovals, payload_sha256,
    },
};

#[cfg(feature = "snp")]
pub mod boot;
mod collateral;
#[cfg(feature = "snp")]
mod history;
#[cfg(feature = "snp")]
mod session;
#[cfg(feature = "snp")]
mod snp;

pub use collateral::Validity;
#[cfg(feature = "snp")]
pub use history::MAX_ARCHIVE_BYTES;
#[cfg(feature = "snp")]
pub use session::VerifiedSession;
#[cfg(feature = "snp")]
pub use snp::VerifiedSnpReport;

/// The replacement body of `bundles/latest.json`. Boot records travel with session evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: String,
    pub keys: SignedKeyManifest,
    pub approvals: SignedApprovalManifest,
    pub allowed_igvms: Vec<AllowedIgvm>,
    pub catalogs: Vec<AllowedCatalog>,
    pub hardware_policy: SignedHardwarePolicy,
    pub vendor_collateral: Vec<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: String,
    pub body_sha256: String,
    pub body: Bundle,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("current evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid current evidence: {0}")]
    Invalid(String),
    #[error(transparent)]
    Approval(#[from] approvals::Error),
    #[error("the bundle does not contain the complete signed {0} set")]
    Incomplete(&'static str),
    #[error("invalid vendor collateral: {0}")]
    Collateral(String),
    #[error("the required vendor collateral is absent")]
    MissingCollateral,
    #[error("the required vendor collateral is outside its validity interval")]
    CollateralExpired,
    #[error("the required vendor certificate is revoked")]
    Revoked,
    #[error("vendor revocation evidence rolls back or conflicts with an authenticated CRL")]
    CrlOrder,
    #[error("invalid hardware attestation: {0}")]
    Attestation(String),
}

impl Error {
    /// Stable reason for bindings; callers never classify failures by parsing display text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge | Self::Approval(approvals::Error::TooLarge) => "evidence_too_large",
            Self::Incomplete(_) => "incomplete_evidence",
            Self::MissingCollateral => "missing_collateral",
            Self::CollateralExpired => "expired_collateral",
            Self::Revoked => "revoked",
            Self::CrlOrder => "crl_order",
            Self::Approval(approvals::Error::Rollback) => "rollback",
            Self::Approval(approvals::Error::Equivocation) => "conflicting_approval",
            Self::Approval(approvals::Error::NotApproved(_)) => "not_approved",
            Self::Approval(approvals::Error::InactiveKey | approvals::Error::RetiredKey) => {
                "key_rejected"
            }
            Self::Approval(approvals::Error::Authority) => "wrong_authority",
            Self::Attestation(_) => "invalid_attestation",
            Self::Invalid(_)
            | Self::Collateral(_)
            | Self::Approval(
                approvals::Error::Invalid(_)
                | approvals::Error::Transparency(_)
                | approvals::Error::Signature
                | approvals::Error::Evidence(_),
            ) => "invalid_evidence",
        }
    }
}

#[derive(Debug)]
struct Cached<T> {
    digest: String,
    verified_at: i64,
    value: Arc<T>,
}

/// Only a complete, authenticated candidate can become a snapshot. Immutable results are shared
/// with active users; each new connection still checks current authorization and vendor validity.
#[derive(Debug)]
pub struct Snapshot {
    body_sha256: String,
    #[cfg(feature = "snp")]
    identity: Arc<()>,
    approvals: VerifiedApprovals,
    key_state: Arc<approvals::KeyState>,
    gateways: BTreeMap<String, Cached<VerifiedRelease>>,
    catalogs: BTreeMap<String, Cached<VerifiedCatalogRelease>>,
    hardware: Cached<VerifiedHardwarePolicy>,
    policy: HardwarePolicy,
    hardware_sigstore: Value,
    collateral: collateral::Store,
}

impl Snapshot {
    /// Current vendor validity for monitoring. This does not appraise a node or authorize a session.
    #[must_use]
    pub fn collateral_summary(&self, now_unix_ms: i64) -> Vec<Value> {
        self.collateral.summary(now_unix_ms)
    }

    /// Identity of the complete verified evidence contents, including collateral.
    #[must_use]
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// Verified public configuration for bindings. This does not appraise a live node.
    #[must_use]
    pub fn summary(&self) -> Value {
        let gateways: Vec<_> = self
            .approvals
            .manifest()
            .gateways
            .iter()
            .map(|id| serde_json::json!({"release_id": id, "release": self.gateway(id)}))
            .collect();
        let catalogs: Vec<_> = self
            .approvals
            .manifest()
            .catalogs
            .iter()
            .map(|id| serde_json::json!({"release_id": id, "release": self.catalog(id)}))
            .collect();
        serde_json::json!({
            "keys": self.approvals.keys(), "approvals": self.approvals.manifest(),
            "gateways": gateways, "catalogs": catalogs, "hardware_policy": self.hardware_policy(),
            "hardware_policy_evidence": {"policy": self.policy, "sigstore": self.hardware_sigstore}
        })
    }

    /// Check learned root retirement before starting new work. Retained request snapshots
    /// remain available for content/receipt verification after an update.
    ///
    /// # Errors
    /// Rejects an older root generation or an authenticated conflicting root decision.
    pub fn require_current_keys(&self) -> Result<(), Error> {
        self.key_state
            .require_current(self.approvals.keys())
            .map_err(Error::from)
    }
    #[must_use]
    pub const fn approvals(&self) -> &VerifiedApprovals {
        &self.approvals
    }

    #[must_use]
    pub fn gateway(&self, release_id: &str) -> Option<&VerifiedRelease> {
        self.gateways
            .get(release_id)
            .map(|entry| entry.value.as_ref())
    }

    #[must_use]
    pub fn catalog(&self, release_id: &str) -> Option<&VerifiedCatalogRelease> {
        self.catalogs
            .get(release_id)
            .map(|entry| entry.value.as_ref())
    }

    /// Select the highest approved catalog compatible with this approved gateway release.
    #[must_use]
    pub fn compatible_catalog(&self, gateway_id: &str) -> Option<(&str, &VerifiedCatalogRelease)> {
        self.require_current_keys().ok()?;
        let gateway = self.gateway(gateway_id)?;
        self.catalogs
            .iter()
            .filter(|(_, entry)| entry.value.minimum_gateway_sequence <= gateway.sequence)
            .max_by_key(|(_, entry)| entry.value.sequence)
            .map(|(id, entry)| (id.as_str(), entry.value.as_ref()))
    }

    #[must_use]
    pub fn hardware_policy(&self) -> &VerifiedHardwarePolicy {
        &self.hardware.value
    }

    #[must_use]
    pub const fn hardware_rules(&self) -> &HardwarePolicy {
        &self.policy
    }

    /// The actual vendor-signed interval for one chip/TCB, independent of fetch timestamps.
    ///
    /// # Errors
    /// Missing or expired material blocks only operations requiring that platform.
    #[cfg_attr(
        not(feature = "snp"),
        expect(
            clippy::missing_const_for_fn,
            reason = "The SNP implementation reads shared revocation state."
        )
    )]
    pub fn collateral_validity(
        &self,
        chip_id: &str,
        reported_tcb: &str,
        now_unix_ms: i64,
    ) -> Result<Validity, Error> {
        #[cfg(feature = "snp")]
        {
            self.collateral.validity(chip_id, reported_tcb, now_unix_ms)
        }
        #[cfg(not(feature = "snp"))]
        {
            let _ = (chip_id, reported_tcb, now_unix_ms);
            Err(Error::MissingCollateral)
        }
    }
}

/// Networkless verifier. The connector owns fetching, origin-specific `ETags` and acquisition bounds.
pub struct Verifier {
    approvals: ApprovalVerifier,
    current: Option<Arc<Snapshot>>,
    revocations: Arc<collateral::Revocations>,
}

impl Verifier {
    /// # Errors
    /// Rejects an environment whose Stogas trust seed has not been provisioned.
    pub fn stogas(environment: Environment) -> Result<Self, Error> {
        Self::new(environment, environment.stogas_root()?)
    }

    /// Learn a root-signed key manifest without requiring the rest of the bundle.
    ///
    /// # Errors
    /// Rejects unauthenticated or conflicting root decisions.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<crate::approvals::KeyManifest, Error> {
        Ok(self.approvals.verify_key_manifest(bytes, now_unix_ms)?)
    }

    /// # Errors
    /// Rejects an invalid locally configured trust root.
    pub fn new(environment: Environment, root: OnlineKey) -> Result<Self, Error> {
        Ok(Self {
            approvals: ApprovalVerifier::new(environment, root)?,
            current: None,
            revocations: Arc::default(),
        })
    }

    #[must_use]
    pub const fn current(&self) -> Option<&Arc<Snapshot>> {
        self.current.as_ref()
    }

    /// Verify the complete candidate before installing a snapshot. Authenticated vendor
    /// revocation is retained independently, including when another candidate object fails.
    ///
    /// # Errors
    /// Rejects invalid, incomplete, conflicting or superseded evidence without losing current
    /// artifacts. Previously learned vendor revocation still constrains their use.
    pub fn refresh(&mut self, bytes: &[u8], now_unix_ms: i64) -> Result<Arc<Snapshot>, Error> {
        let value = parse_json(bytes)?;
        // Vendor revocation is an independent signed decision. Retain it even if a missing
        // release, altered approval or other malformed object prevents snapshot installation.
        let keys = self.approvals.observe_keys(
            &serde_json::to_vec(&value["body"]["keys"]).map_err(invalid)?,
            now_unix_ms,
        );
        #[cfg(feature = "snp")]
        let vendor = self.revocations.observe(&value["body"], now_unix_ms);
        // Process both independent authorities before returning either delivery failure.
        let keys = keys?;
        #[cfg(feature = "snp")]
        vendor?;
        let envelope = parse_envelope(value)?;
        let body = envelope.body;
        let approvals = self
            .approvals
            .verify_with_keys(keys, &serde_json::to_vec(&body.approvals).map_err(invalid)?)?;
        // Exact evidence bytes alone are not a trust-cache key after a signing-key change.
        let reusable = self
            .current
            .as_deref()
            .filter(|snapshot| snapshot.approvals.keys().active_key == approvals.keys().active_key);
        let mut gateways = BTreeMap::new();
        for gateway in body.allowed_igvms {
            let id = payload_sha256(&gateway.manifest)?;
            if !approvals.allows_gateway(&id) || gateways.contains_key(&id) {
                return Err(Error::Incomplete("gateway"));
            }
            let digest = payload_sha256(&gateway)?;
            let entry = cached(
                reusable.and_then(|snapshot| snapshot.gateways.get(&id)),
                digest,
                now_unix_ms,
                || approvals.verify_gateway(&gateway, now_unix_ms),
            )?;
            gateways.insert(id, entry);
        }
        if gateways.len() != approvals.manifest().gateways.len() {
            return Err(Error::Incomplete("gateway"));
        }
        let mut catalogs = BTreeMap::new();
        let mut sequences = std::collections::BTreeSet::new();
        for catalog in body.catalogs {
            let id = payload_sha256(&catalog.manifest)?;
            if !approvals.allows_catalog(&id)
                || catalogs.contains_key(&id)
                || !sequences.insert(catalog.manifest.sequence)
            {
                return Err(Error::Incomplete("catalog"));
            }
            let digest = payload_sha256(&catalog)?;
            let entry = cached(
                reusable.and_then(|snapshot| snapshot.catalogs.get(&id)),
                digest,
                now_unix_ms,
                || approvals.verify_catalog(&catalog, now_unix_ms),
            )?;
            catalogs.insert(id, entry);
        }
        if catalogs.len() != approvals.manifest().catalogs.len() {
            return Err(Error::Incomplete("catalog"));
        }
        // Recheck selection even on a cache hit: unchanged bytes may have been withdrawn.
        if payload_sha256(&body.hardware_policy.policy)?
            != approvals.manifest().hardware_policy_sha256
        {
            return Err(Error::Incomplete("hardware policy"));
        }
        let hardware = cached(
            reusable.map(|snapshot| &snapshot.hardware),
            payload_sha256(&body.hardware_policy)?,
            now_unix_ms,
            || approvals.verify_hardware_policy(&body.hardware_policy, now_unix_ms),
        )?;
        let collateral = collateral::Store::verify(
            &body.vendor_collateral,
            self.current.as_deref().map(|snapshot| &snapshot.collateral),
            Arc::clone(&self.revocations),
        )?;
        let snapshot = Arc::new(Snapshot {
            body_sha256: envelope.body_sha256,
            #[cfg(feature = "snp")]
            identity: Arc::new(()),
            approvals,
            key_state: self.approvals.key_state(),
            gateways,
            catalogs,
            hardware,
            policy: body.hardware_policy.policy,
            hardware_sigstore: body.hardware_policy.sigstore,
            collateral,
        });
        self.approvals.accept(snapshot.approvals.clone())?;
        self.current = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }
}

fn cached<T>(
    prior: Option<&Cached<T>>,
    digest: String,
    now_unix_ms: i64,
    verify: impl FnOnce() -> Result<T, approvals::Error>,
) -> Result<Cached<T>, Error> {
    let (value, verified_at) =
        match prior.filter(|entry| entry.digest == digest && now_unix_ms >= entry.verified_at) {
            Some(entry) => (Arc::clone(&entry.value), entry.verified_at),
            None => (Arc::new(verify()?), now_unix_ms),
        };
    Ok(Cached {
        digest,
        verified_at,
        value,
    })
}

fn parse_json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    crate::strict_json::from_slice(bytes).map_err(invalid)
}

fn parse_envelope(value: Value) -> Result<Envelope, Error> {
    let digest = payload_sha256(&value["body"])?;
    let envelope: Envelope = serde_json::from_value(value).map_err(invalid)?;
    if envelope.schema != crate::BUNDLE_ENVELOPE_SCHEMA
        || envelope.body.schema != "stogas.confidential-bundle.v1"
    {
        return Err(Error::Invalid("unsupported bundle schema".into()));
    }
    if digest != envelope.body_sha256 {
        return Err(Error::Invalid("bundle body checksum differs".into()));
    }
    Ok(envelope)
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
