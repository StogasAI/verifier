use super::*;
use crate::signing::SigningKey;
use serde_json::json;

fn key(seed: u8) -> (OnlineKey, SigningKey) {
    let signer = SigningKey::from_seed(&[seed; 32]);
    (
        OnlineKey {
            key_id: format!("key-{seed}"),
            public_key: STANDARD.encode(signer.public_key_spki().unwrap()),
            rekor_public_key: STANDARD.encode(signer.rekor_public_key_spki().unwrap()),
        },
        signer,
    )
}

fn root(seed: u8) -> RootKey {
    let key = key(seed).0;
    RootKey {
        key_id: key.key_id,
        public_key: key.public_key,
    }
}

fn keys(generation: u64, seed: u8, retired: &[u8]) -> KeyManifest {
    let mut retired_keys: Vec<_> = retired.iter().map(|seed| key(*seed).0).collect();
    retired_keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    KeyManifest {
        schema: KEY_MANIFEST_SCHEMA.into(),
        environment: Environment::Production,
        generation,
        expires_at: "2100-01-01T00:00:00Z".into(),
        active_key: key(seed).0,
        retired_keys,
    }
}

fn signed(keys: &KeyManifest, revision: u64, seed: u8) -> SignedApprovalManifest {
    let manifest = ApprovalManifest {
        schema: APPROVAL_MANIFEST_SCHEMA.into(),
        environment: keys.environment,
        revision,
        key_manifest_sha256: payload_sha256(keys).unwrap(),
        gateways: vec!["1".repeat(64)],
        catalogs: vec!["2".repeat(64)],
        hardware_policy_sha256: "3".repeat(64),
    };
    let signature = sign(&serde_json::to_value(&manifest).unwrap(), seed);
    SignedApprovalManifest {
        manifest,
        signature,
        inclusion: Value::Null,
    }
}

fn sign(document: &Value, seed: u8) -> StogasSignature {
    let (key, signer) = key(seed);
    let mut payload = STOGAS_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&canonical_payload(document).unwrap());
    StogasSignature {
        key_id: key.key_id,
        signature: URL_SAFE_NO_PAD.encode(signer.sign(&payload, &[]).unwrap()),
    }
}

// Exercises decision installation independently of Rekor's existing cryptographic test suite.
// Production candidates can only be constructed after verify_candidate checks root ML-DSA signature + inclusion.
fn candidate(
    verifier: &ApprovalVerifier,
    generation: u64,
    revision: u64,
    seed: u8,
    retired: &[u8],
) -> VerifiedApprovals {
    let keys = keys(generation, seed, retired);
    validate_keys(&keys, verifier.environment, &verifier.root).unwrap();
    let signed = signed(&keys, revision, seed);
    verify_online_approval(verifier.authority, keys, signed).unwrap()
}

fn verifier() -> ApprovalVerifier {
    ApprovalVerifier::new(Environment::Production, root(1)).unwrap()
}

#[cfg(feature = "staging")]
#[test]
fn actual_logged_root_manifest_verifies_and_rejects_substituted_material() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/logged-key-manifest.json"
    ))
    .unwrap();
    let root: RootKey = serde_json::from_value(vector["root"].clone()).unwrap();
    let mut verifier = ApprovalVerifier::new(Environment::Staging, root).unwrap();
    let now = vector["verified_at_ms"].as_i64().unwrap();
    let keys = serde_json::to_vec(&vector["keys"]).unwrap();
    let approvals = serde_json::to_vec(&vector["approvals"]).unwrap();
    let candidate = verifier.verify_candidate(&keys, &approvals, now).unwrap();
    assert_eq!(candidate.keys().generation, 1);
    verifier.accept(candidate).unwrap();
    for pointer in [
        "/manifest/active_key/public_key",
        "/manifest/active_key/rekor_public_key",
        "/signature/signature",
        "/inclusion/verificationMaterial/publicKey/hint",
        "/inclusion/verificationMaterial/tlogEntries/0/canonicalizedBody",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
    ] {
        let mut changed = vector["keys"].clone();
        *changed.pointer_mut(pointer).unwrap() = Value::String("invalid".into());
        assert!(
            verifier
                .verify_candidate(&serde_json::to_vec(&changed).unwrap(), &approvals, now)
                .is_err(),
            "accepted {pointer}"
        );
        assert_eq!(verifier.accepted().unwrap().keys().generation, 1);
    }
}

#[test]
fn typescript_publisher_vector_verifies_without_representation_changes() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/approval-decisions.json"
    ))
    .unwrap();
    let keys: KeyManifest = serde_json::from_value(vector["key_manifest"].clone()).unwrap();
    let approval: SignedApprovalManifest =
        serde_json::from_value(vector["approval"].clone()).unwrap();
    validate_keys(&keys, Environment::Production, &root(1)).unwrap();
    assert_eq!(
        payload_sha256(&keys).unwrap(),
        vector["key_manifest_sha256"]
    );
    assert_eq!(
        payload_sha256(&vector["unsigned_release"]).unwrap(),
        vector["release_id"]
    );
    assert_eq!(
        payload_sha256(&vector["unicode_payload"]).unwrap(),
        vector["unicode_payload_sha256"]
    );
    let result = verify_online_approval([0; 32], keys, approval).unwrap();
    assert!(result.allows_gateway(vector["release_id"].as_str().unwrap()));
}

#[test]
fn unsigned_payload_identity_ignores_wrapping_signatures_and_key_order() {
    let payload = json!({"schema":"stogas.gateway.release.v1", "build":{"z":2,"a":1}});
    let reordered = json!({"build":{"a":1,"z":2}, "schema":"stogas.gateway.release.v1"});
    assert_eq!(
        payload_sha256(&payload).unwrap(),
        payload_sha256(&reordered).unwrap()
    );
    assert_eq!(
        payload_sha256(&payload).unwrap(),
        hex::encode(Sha256::digest(
            br#"{"build":{"a":1,"z":2},"schema":"stogas.gateway.release.v1"}"#
        ))
    );
    assert_ne!(sign(&payload, 2).signature, sign(&payload, 3).signature);
}

#[test]
fn rotations_keep_current_releases_and_supersede_compromised_max_revision() {
    let mut verifier = verifier();
    let original = candidate(&verifier, 1, MAX_REVISION, 2, &[]);
    verifier.accept(original.clone()).unwrap();
    let rotated = candidate(&verifier, 2, 1, 3, &[2]);
    assert!(rotated.allows_gateway(&"1".repeat(64)));
    assert!(rotated.allows_catalog(&"2".repeat(64)));
    assert!(!rotated.allows_gateway(&"2".repeat(64)));
    verifier.accept(rotated).unwrap();
    assert_eq!(verifier.accept(original).unwrap_err(), Error::Rollback);
    assert_eq!(verifier.accepted().unwrap().keys().generation, 2);
}

#[test]
fn root_expiry_bounds_online_updates_and_renewal_preserves_the_same_signer() {
    let mut verifier = verifier();
    let original = candidate(&verifier, 1, 1, 2, &[]);
    let deadline = original.keys.expiry_unix_ms().unwrap();
    assert_eq!(original.valid_until(deadline - 1).unwrap(), deadline);
    assert_eq!(original.valid_until(deadline), Err(Error::Expired));
    assert_eq!(original.valid_until(deadline + 1), Err(Error::Expired));
    let online_update = candidate(&verifier, 1, MAX_REVISION, 2, &[]);
    assert_eq!(online_update.valid_until(deadline), Err(Error::Expired));
    verifier.accept(original.clone()).unwrap();

    let mut renewed_keys = original.keys.clone();
    renewed_keys.expires_at = "2100-02-01T00:00:00Z".into();
    let approval = signed(&renewed_keys, 1, 2);
    let conflict =
        verify_online_approval(verifier.authority, renewed_keys.clone(), approval).unwrap();
    assert_eq!(verifier.accept(conflict).unwrap_err(), Error::Equivocation);

    renewed_keys.generation += 1;
    let approval = signed(&renewed_keys, 1, 2);
    let renewed = verify_online_approval(verifier.authority, renewed_keys, approval).unwrap();
    renewed.valid_until(deadline).unwrap();
    assert_eq!(renewed.keys.active_key, original.keys.active_key);
    assert_eq!(renewed.approvals.gateways, original.approvals.gateways);
    verifier.accept(renewed).unwrap();
    assert_eq!(verifier.accept(original).unwrap_err(), Error::Rollback);
}

#[test]
fn root_expiry_has_one_unambiguous_timestamp_representation() {
    let root = root(1);
    for expiry in [
        "",
        "2100-01-01",
        "2100-01-01T00:00:00.000Z",
        "2100-01-01T00:00:00+00:00",
        "2100-01-01T00:00:00+01:00",
        "2100-02-30T00:00:00Z",
        "2100-01-01T00:00:60Z",
    ] {
        let mut manifest = keys(1, 2, &[]);
        manifest.expires_at = expiry.into();
        assert!(
            validate_keys(&manifest, Environment::Production, &root).is_err(),
            "{expiry}"
        );
    }
}

#[test]
fn revisions_detect_only_conflicting_decisions_and_reject_stale_concurrent_candidates() {
    let mut verifier = verifier();
    let first = candidate(&verifier, 1, 1, 2, &[]);
    verifier.accept(first.clone()).unwrap();
    verifier.accept(first.clone()).unwrap();
    let mut conflict = signed(first.keys(), 1, 2);
    conflict.manifest.gateways.clear();
    conflict.signature = sign(&serde_json::to_value(&conflict.manifest).unwrap(), 2);
    let conflicting =
        verify_online_approval(verifier.authority, first.keys.clone(), conflict).unwrap();
    assert_eq!(
        verifier.accept(conflicting).unwrap_err(),
        Error::Equivocation
    );
    let same_generation_other_key = candidate(&verifier, 1, 2, 3, &[2]);
    assert_eq!(
        verifier.accept(same_generation_other_key).unwrap_err(),
        Error::Equivocation
    );
    verifier.accept(candidate(&verifier, 1, 2, 2, &[])).unwrap();
    assert_eq!(verifier.accept(first).unwrap_err(), Error::Rollback);
    assert_eq!(verifier.accepted().unwrap().manifest().revision, 2);
}

#[test]
fn rotation_cannot_forget_retirement_or_reuse_keys() {
    let mut verifier = verifier();
    verifier.accept(candidate(&verifier, 1, 1, 2, &[])).unwrap();
    assert_eq!(
        verifier
            .accept(candidate(&verifier, 2, 1, 3, &[]))
            .unwrap_err(),
        Error::RetiredKey
    );
    verifier
        .accept(candidate(&verifier, 2, 1, 3, &[2]))
        .unwrap();
    assert_eq!(
        verifier
            .accept(candidate(&verifier, 3, 1, 2, &[3]))
            .unwrap_err(),
        Error::RetiredKey
    );
    assert_eq!(
        verifier
            .accept(candidate(&verifier, 3, 1, 4, &[3]))
            .unwrap_err(),
        Error::RetiredKey
    );
    verifier
        .accept(candidate(&verifier, 3, 1, 4, &[2, 3]))
        .unwrap();
}

#[test]
fn signatures_are_bound_to_active_key_payload_purpose_and_delegation() {
    let keys = keys(2, 3, &[2]);
    let valid = signed(&keys, 1, 3);
    assert!(verify_online_approval([0; 32], keys.clone(), valid.clone()).is_ok());
    for seed in [1, 2, 4] {
        assert_eq!(
            verify_online_approval([0; 32], keys.clone(), signed(&keys, 1, seed)).unwrap_err(),
            Error::InactiveKey
        );
    }
    let mut invalid_signature = valid.clone();
    invalid_signature.signature.signature =
        sign(&serde_json::to_value(&valid.manifest).unwrap(), 4).signature;
    assert_eq!(
        verify_online_approval([0; 32], keys.clone(), invalid_signature).unwrap_err(),
        Error::Signature
    );
    for mutation in ["revision", "hardware", "delegation", "purpose", "gateway"] {
        let mut tampered = valid.clone();
        match mutation {
            "revision" => tampered.manifest.revision += 1,
            "hardware" => tampered.manifest.hardware_policy_sha256 = "4".repeat(64),
            "delegation" => tampered.manifest.key_manifest_sha256 = "4".repeat(64),
            "purpose" => tampered.manifest.schema = KEY_MANIFEST_SCHEMA.into(),
            _ => tampered.manifest.gateways.clear(),
        }
        assert!(
            verify_online_approval([0; 32], keys.clone(), tampered).is_err(),
            "{mutation}"
        );
    }
    let mut wrong_purpose = valid.clone();
    wrong_purpose.signature.signature = URL_SAFE_NO_PAD.encode(
        key(3)
            .1
            .sign(
                &canonical_payload(&serde_json::to_value(&valid.manifest).unwrap()).unwrap(),
                &[],
            )
            .unwrap(),
    );
    assert_eq!(
        verify_online_approval([0; 32], keys, wrong_purpose).unwrap_err(),
        Error::Signature
    );
}

#[test]
fn manifests_reject_ambiguous_ids_keys_versions_and_counters() {
    let root = root(1);
    for generation in [0, MAX_REVISION + 1, u64::MAX] {
        assert!(validate_keys(&keys(generation, 2, &[]), Environment::Production, &root).is_err());
    }
    for invalid in [keys(1, 1, &[]), keys(1, 2, &[2]), keys(1, 2, &[3, 3])] {
        assert!(validate_keys(&invalid, Environment::Production, &root).is_err());
    }
    let mut duplicate_public_key = keys(1, 2, &[3]);
    duplicate_public_key.retired_keys[0].public_key =
        duplicate_public_key.active_key.public_key.clone();
    assert!(validate_keys(&duplicate_public_key, Environment::Production, &root).is_err());
    let mut unordered = keys(1, 2, &[3, 4]);
    unordered.retired_keys.reverse();
    assert!(validate_keys(&unordered, Environment::Production, &root).is_err());
    let mut unknown_version = keys(1, 2, &[]);
    unknown_version.schema = "stogas.keys.v2".into();
    assert!(validate_keys(&unknown_version, Environment::Production, &root).is_err());
    for id in ["", "a b", "../key", "é", &"a".repeat(129)] {
        let mut invalid_key = key(2).0;
        invalid_key.key_id = id.into();
        assert!(decode_key(&invalid_key.key_id, &invalid_key.public_key).is_err());
    }
    let keys = keys(1, 2, &[]);
    for revision in [0, MAX_REVISION + 1, u64::MAX] {
        assert!(verify_online_approval([0; 32], keys.clone(), signed(&keys, revision, 2)).is_err());
    }
    for digests in [
        vec!["1".repeat(64); 2],
        vec!["2".repeat(64), "1".repeat(64)],
        vec!["A".repeat(64)],
        vec!["1".repeat(63)],
    ] {
        let mut invalid = signed(&keys, 1, 2);
        invalid.manifest.gateways = digests;
        invalid.signature = sign(&serde_json::to_value(&invalid.manifest).unwrap(), 2);
        assert!(verify_online_approval([0; 32], keys.clone(), invalid).is_err());
    }
}

#[test]
fn root_inclusion_is_mandatory_and_failure_never_advances_state() {
    let mut verifier = verifier();
    verifier.accept(candidate(&verifier, 1, 1, 2, &[])).unwrap();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(2, 3, &[2])).unwrap(), 1),
        manifest: keys(2, 3, &[2]),
        inclusion: json!({}),
    };
    let signed = signed(&keys.manifest, 1, 3);
    let error = verifier
        .verify_candidate(
            &serde_json::to_vec(&keys).unwrap(),
            &serde_json::to_vec(&signed).unwrap(),
            1_789_900_000_000,
        )
        .unwrap_err();
    assert!(matches!(error, Error::Transparency(_)));
    assert_eq!(verifier.accepted().unwrap().keys().generation, 1);
}

#[test]
fn strict_boundary_rejects_unknown_duplicate_trailing_and_oversized_inputs() {
    let verifier = verifier();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(1, 2, &[])).unwrap(), 1),
        manifest: keys(1, 2, &[]),
        inclusion: json!({}),
    };
    let signed = signed(&keys.manifest, 1, 2);
    let valid = serde_json::to_string(&keys).unwrap();
    let approvals = serde_json::to_vec(&signed).unwrap();
    for input in [
        format!("{valid}{{}}"),
        valid.replacen("\"generation\":1", "\"generation\":1,\"generation\":2", 1),
        valid.replacen("\"generation\":1", "\"generation\":1,\"extra\":true", 1),
    ] {
        assert!(matches!(
            verifier.verify_candidate(input.as_bytes(), &approvals, 0),
            Err(Error::Invalid(_))
        ));
    }
    assert_eq!(
        verifier
            .verify_candidate(&vec![b' '; MAX_INPUT_BYTES], &approvals, 0)
            .unwrap_err(),
        Error::TooLarge
    );
    assert!(verifier.accepted().is_none());
}

#[test]
fn a_candidate_from_another_root_cannot_be_installed() {
    let mut verifier = verifier();
    let other = ApprovalVerifier::new(Environment::Production, root(5)).unwrap();
    assert_eq!(
        verifier
            .accept(candidate(&other, 1, 1, 2, &[]))
            .unwrap_err(),
        Error::Authority
    );
}

#[cfg(feature = "staging")]
fn approved_artifacts(
    seed: u8,
    generation: u64,
    environment: Environment,
) -> (VerifiedApprovals, AllowedIgvm, AllowedCatalog) {
    let mut gateway = crate::tests::release_fixture();
    let mut catalog = crate::tests::catalog_fixture();
    let gateway_file_hash = hex::encode(Sha256::digest(
        canonical_json(&serde_json::to_value(&gateway.manifest).unwrap()).unwrap(),
    ));
    let catalog_file_hash = hex::encode(Sha256::digest(
        canonical_json(&serde_json::to_value(&catalog.manifest).unwrap()).unwrap(),
    ));
    gateway.attested_builds = vec![json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://stogas.ai/attestations/staging-development/v1",
        "predicate": { "environment": "staging" },
        "subject": [
            { "name": "release-manifest.json", "digest": { "sha256": gateway_file_hash } },
            { "name": "gateway.igvm", "digest": { "sha256": gateway.manifest.artifacts.gateway_igvm.sha256 } }
        ]
    })];
    catalog.attested_builds = vec![json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://stogas.ai/attestations/staging-development/v1",
        "predicate": { "environment": "staging" },
        "subject": [
            { "name": "catalog-release.json", "digest": { "sha256": catalog_file_hash } },
            { "name": "catalog.runtime.json", "digest": { "sha256": &catalog.manifest.runtime[7..] } },
            { "name": "catalog.public.json", "digest": { "sha256": &catalog.manifest.public[7..] } }
        ]
    })];
    gateway.signature = sign(&serde_json::to_value(&gateway.manifest).unwrap(), seed);
    catalog.signature = sign(&serde_json::to_value(&catalog.manifest).unwrap(), seed);
    let mut keys = keys(generation, seed, if generation > 1 { &[2] } else { &[] });
    keys.environment = environment;
    let mut approval = signed(&keys, 1, seed);
    approval.manifest.gateways = vec![payload_sha256(&gateway.manifest).unwrap()];
    approval.manifest.catalogs = vec![payload_sha256(&catalog.manifest).unwrap()];
    approval.signature = sign(&serde_json::to_value(&approval.manifest).unwrap(), seed);
    let authority = ApprovalVerifier::new(environment, root(1)).unwrap();
    let verified = verify_online_approval(authority.authority, keys, approval).unwrap();
    (verified, gateway, catalog)
}

#[cfg(feature = "staging")]
#[test]
fn current_artifacts_survive_resigning_without_authorizing_retired_signatures() {
    let (before, gateway_a, catalog_a) = approved_artifacts(2, 1, Environment::Staging);
    let (after, gateway_b, catalog_b) = approved_artifacts(3, 2, Environment::Staging);
    let now = 1_789_900_000_000;
    assert_eq!(before.manifest().gateways, after.manifest().gateways);
    assert_eq!(before.manifest().catalogs, after.manifest().catalogs);
    assert_ne!(
        payload_sha256(&gateway_a).unwrap(),
        payload_sha256(&gateway_b).unwrap()
    );
    assert_ne!(
        payload_sha256(&catalog_a).unwrap(),
        payload_sha256(&catalog_b).unwrap()
    );
    assert!(before.verify_gateway(&gateway_a, now).is_ok());
    assert!(before.verify_catalog(&catalog_a, now).is_ok());
    assert!(after.verify_gateway(&gateway_b, now).is_ok());
    assert!(after.verify_catalog(&catalog_b, now).is_ok());
    assert_eq!(
        after.verify_gateway(&gateway_a, now).unwrap_err(),
        Error::InactiveKey
    );
    assert_eq!(
        after.verify_catalog(&catalog_a, now).unwrap_err(),
        Error::InactiveKey
    );
    let mut changed = gateway_b.clone();
    changed.manifest.sev_snp.vcpu_count += 1;
    assert_eq!(
        after.verify_gateway(&changed, now).unwrap_err(),
        Error::NotApproved("gateway")
    );
    let mut changed = catalog_b.clone();
    changed.manifest.minimum_gateway_sequence += 1;
    assert_eq!(
        after.verify_catalog(&changed, now).unwrap_err(),
        Error::NotApproved("catalog")
    );
    let mut changed = gateway_b;
    changed.attested_builds[0]["subject"][0]["digest"]["sha256"] = json!("0".repeat(64));
    assert!(matches!(
        after.verify_gateway(&changed, now),
        Err(Error::Evidence(_))
    ));
    let mut changed = catalog_b;
    changed.attested_builds[0]["subject"][1]["digest"]["sha256"] = json!("0".repeat(64));
    assert!(matches!(
        after.verify_catalog(&changed, now),
        Err(Error::Evidence(_))
    ));
}

#[cfg(feature = "staging")]
#[test]
fn staging_capable_verifier_rejects_placeholders_in_a_production_context() {
    let (approvals, gateway, catalog) = approved_artifacts(2, 1, Environment::Production);
    assert_eq!(
        approvals
            .verify_gateway(&gateway, 1_789_900_000_000)
            .unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        approvals
            .verify_catalog(&catalog, 1_789_900_000_000)
            .unwrap_err(),
        Error::Authority
    );
}

#[test]
fn hardware_membership_does_not_replace_signature_and_inclusion_checks() {
    let verifier = verifier();
    let mut approvals = candidate(&verifier, 1, 1, 2, &[]);
    let hardware: SignedHardwarePolicy = serde_json::from_str(include_str!(
        "../../tests/fixtures/milan-hardware-policy.signed.json"
    ))
    .unwrap();
    assert_eq!(
        approvals
            .verify_hardware_policy(&hardware, 1_789_900_000_000)
            .unwrap_err(),
        Error::NotApproved("hardware policy")
    );
    approvals.approvals.hardware_policy_sha256 = payload_sha256(&hardware.policy).unwrap();
    assert!(matches!(
        approvals.verify_hardware_policy(&hardware, 1_789_900_000_000),
        Err(Error::Evidence(_))
    ));
}

#[cfg(feature = "staging")]
#[test]
fn environments_are_signed_and_cannot_share_candidates() {
    let verifier = verifier();
    let mut manifest = keys(1, 2, &[]);
    manifest.environment = Environment::Staging;
    assert_eq!(
        validate_keys(&manifest, verifier.environment, &verifier.root).unwrap_err(),
        Error::Authority
    );
    let mut signed = signed(&manifest, 1, 2);
    signed.manifest.environment = Environment::Production;
    signed.signature = sign(&serde_json::to_value(&signed.manifest).unwrap(), 2);
    assert_eq!(
        verify_online_approval(verifier.authority, manifest, signed).unwrap_err(),
        Error::Authority
    );
    let mut staging = ApprovalVerifier::new(Environment::Staging, root(1)).unwrap();
    assert_eq!(
        staging
            .accept(candidate(&verifier, 1, 1, 2, &[]))
            .unwrap_err(),
        Error::Authority
    );
}

#[cfg(not(feature = "staging"))]
#[test]
fn production_build_cannot_parse_staging_authorization() {
    assert!(serde_json::from_value::<Environment>(json!("staging")).is_err());
}

#[cfg(feature = "staging")]
#[test]
fn compiled_staging_root_verifies_actual_logged_operational_delegation() {
    let bytes = include_bytes!("../../../../tests/fixtures/staging-key-manifest.json");
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let now = value["inclusion"]["verificationMaterial"]["tlogEntries"][0]["integratedTime"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap()
        * 1000
        + 1000;
    let verifier = crate::evidence::Verifier::stogas(Environment::Staging).unwrap();
    let keys = verifier.verify_key_manifest(bytes, now).unwrap();
    assert_eq!(keys.active_key.key_id, "staging-stogas-online-2026-09-26-01");
    assert_eq!(keys.generation, 1);
    assert!(keys.retired_keys.is_empty());
    let mut changed = value;
    changed["manifest"]["generation"] = json!(2);
    assert!(
        verifier
            .verify_key_manifest(&serde_json::to_vec(&changed).unwrap(), now)
            .is_err()
    );
    assert!(crate::evidence::Verifier::stogas(Environment::Production).is_err());
}
