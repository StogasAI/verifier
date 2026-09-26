use super::Error;

/// Intersection of the required vendor-signed certificate and revocation validity intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before_unix_ms: i64,
    pub not_after_unix_ms: i64,
}

#[cfg(feature = "snp")]
impl Validity {
    pub(super) const fn at(self, now_unix_ms: i64) -> Result<Self, Error> {
        if now_unix_ms < self.not_before_unix_ms || now_unix_ms >= self.not_after_unix_ms {
            return Err(Error::CollateralExpired);
        }
        Ok(self)
    }

    pub(super) fn intersect(self, other: Self) -> Self {
        Self {
            not_before_unix_ms: self.not_before_unix_ms.max(other.not_before_unix_ms),
            not_after_unix_ms: self.not_after_unix_ms.min(other.not_after_unix_ms),
        }
    }
}

#[cfg(feature = "snp")]
#[path = "amd.rs"]
mod amd;
#[cfg(feature = "snp")]
pub(super) use amd::{Revocations, Store};

#[cfg(not(feature = "snp"))]
#[derive(Debug, Default)]
pub(super) struct Revocations;

#[cfg(not(feature = "snp"))]
#[derive(Debug)]
pub(super) struct Store;
#[cfg(not(feature = "snp"))]
impl Store {
    #[expect(
        clippy::unused_self,
        clippy::missing_const_for_fn,
        reason = "Matches the enabled collateral backend API."
    )]
    pub(super) fn summary(&self, _now: i64) -> Vec<serde_json::Value> {
        Vec::new()
    }

    pub(super) fn verify(
        rows: &[std::collections::BTreeMap<String, serde_json::Value>],
        _prior: Option<&Self>,
        _revocations: std::sync::Arc<Revocations>,
    ) -> Result<Self, Error> {
        if !rows.is_empty() {
            return Err(Error::Collateral(
                "AMD SNP verification is unavailable".into(),
            ));
        }
        Ok(Self)
    }
}
