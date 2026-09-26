use super::{Error, KeyManifest, invalid};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct VerifiedKeys {
    pub(super) manifest: KeyManifest,
    pub(super) digest: String,
}

#[derive(Debug)]
struct Learned {
    keys: VerifiedKeys,
    conflicting: bool,
}

/// Root decisions remain authoritative even when unrelated delivery is incomplete.
#[derive(Debug, Default)]
pub struct KeyState(Mutex<Option<Learned>>);

impl KeyState {
    pub(super) fn learn(&self, keys: VerifiedKeys) -> Result<(), Error> {
        let mut state = self.0.lock().map_err(invalid)?;
        if let Some(previous) = state.as_mut() {
            if keys.manifest.generation == previous.keys.manifest.generation
                && keys.digest != previous.keys.digest
            {
                previous.conflicting = true;
                return Err(Error::Equivocation);
            }
            check(previous, &keys.manifest, &keys.digest)?;
        }
        *state = Some(Learned {
            keys,
            conflicting: false,
        });
        drop(state);
        Ok(())
    }

    pub(super) fn check(&self, keys: &KeyManifest, digest: &str) -> Result<(), Error> {
        if let Some(previous) = self.0.lock().map_err(invalid)?.as_ref() {
            check(previous, keys, digest)?;
        }
        Ok(())
    }

    pub(crate) fn require_current(&self, keys: &KeyManifest) -> Result<(), Error> {
        let state = self.0.lock().map_err(invalid)?;
        let learned = state.as_ref().ok_or(Error::InactiveKey)?;
        if learned.conflicting {
            return Err(Error::Equivocation);
        }
        if keys.generation != learned.keys.manifest.generation {
            let current = &learned.keys.manifest;
            // A root renewal with unchanged keys may arrive before its complete
            // approval package. Keep existing work eligible until its original
            // deadline; never accept the older manifest as a new candidate.
            if keys.generation > current.generation
                || keys.active_key != current.active_key
                || keys.retired_keys != current.retired_keys
                || keys.expires_at >= current.expires_at
            {
                return Err(Error::Rollback);
            }
        }
        drop(state);
        Ok(())
    }
}

fn check(previous: &Learned, keys: &KeyManifest, digest: &str) -> Result<(), Error> {
    let old = &previous.keys.manifest;
    if keys.generation < old.generation {
        return Err(Error::Rollback);
    }
    if keys.generation == old.generation {
        if previous.conflicting || digest != previous.keys.digest {
            return Err(Error::Equivocation);
        }
    } else {
        for retired in &old.retired_keys {
            if !keys.retired_keys.contains(retired) {
                return Err(Error::RetiredKey);
            }
        }
        if keys.active_key != old.active_key && !keys.retired_keys.contains(&old.active_key) {
            return Err(Error::RetiredKey);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_keeps_old_snapshots_usable_but_cannot_restore_them_as_current() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/approval-decisions.json"
        ))
        .unwrap();
        let original = VerifiedKeys {
            manifest: serde_json::from_value(vector["key_manifest"].clone()).unwrap(),
            digest: vector["key_manifest_sha256"].as_str().unwrap().into(),
        };
        let state = KeyState::default();
        state.learn(original.clone()).unwrap();
        let mut renewal = original.clone();
        renewal.manifest.generation += 1;
        renewal.manifest.expires_at = "2100-02-01T00:00:00Z".into();
        renewal.digest = "authenticated renewal".into();
        state.learn(renewal.clone()).unwrap();
        state.require_current(&original.manifest).unwrap();
        assert_eq!(state.learn(original.clone()).unwrap_err(), Error::Rollback);

        let mut shortened = renewal;
        shortened.manifest.generation += 1;
        shortened.manifest.expires_at = "2099-12-31T00:00:00Z".into();
        shortened.digest = "authenticated earlier deadline".into();
        state.learn(shortened).unwrap();
        assert_eq!(
            state.require_current(&original.manifest).unwrap_err(),
            Error::Rollback
        );
    }

    #[test]
    fn authenticated_conflict_blocks_old_snapshots_until_a_later_root_decision() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/approval-decisions.json"
        ))
        .unwrap();
        let manifest: KeyManifest = serde_json::from_value(vector["key_manifest"].clone()).unwrap();
        let original = VerifiedKeys {
            manifest,
            digest: vector["key_manifest_sha256"].as_str().unwrap().into(),
        };
        let state = KeyState::default();
        state.learn(original.clone()).unwrap();
        let mut conflicting = original.clone();
        conflicting.digest = "different authenticated decision".into();
        assert_eq!(state.learn(conflicting).unwrap_err(), Error::Equivocation);
        assert_eq!(
            state.require_current(&original.manifest).unwrap_err(),
            Error::Equivocation
        );
        assert_eq!(
            state.learn(original.clone()).unwrap_err(),
            Error::Equivocation
        );
        let mut recovery = original.clone();
        recovery.manifest.generation += 1;
        recovery.digest = "later authenticated root decision".into();
        state.learn(recovery.clone()).unwrap();
        state.require_current(&recovery.manifest).unwrap();
        assert_eq!(
            state.require_current(&original.manifest).unwrap_err(),
            Error::Rollback
        );
        assert_eq!(state.learn(original).unwrap_err(), Error::Rollback);
    }
}
