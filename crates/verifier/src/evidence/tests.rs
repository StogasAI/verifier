use super::*;

#[test]
fn strict_delivery_boundary_rejects_legacy_unknown_duplicate_and_oversized_inputs() {
    assert!(matches!(
        parse_json(&vec![b' '; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
    for bytes in [
        br#"{"body":{},"body":{}}"#.as_slice(),
        b"{}{}",
        b"null trailing",
    ] {
        assert!(parse_json(bytes).is_err());
    }
    let legacy: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/staging-bundle-sequence-1927.json"
    ))
    .unwrap();
    assert!(parse_envelope(legacy).is_err());
}

#[cfg(feature = "staging")]
mod staging {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn encode(body: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema": crate::BUNDLE_ENVELOPE_SCHEMA,
            "body":body, "body_sha256":payload_sha256(body).unwrap()}))
        .unwrap()
    }

    fn signature(value: &Value) -> Value {
        signature_for(value, 242, "stogas-fixture-online-20260920")
    }

    fn signature_for(value: &Value, seed: u8, key_id: &str) -> Value {
        let mut signed = crate::STOGAS_SIGNATURE_DOMAIN.to_vec();
        let canonical = crate::canonical_json(value).unwrap();
        signed.extend_from_slice(canonical.strip_suffix('\n').unwrap().as_bytes());
        json!({"key_id":key_id, "signature":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[seed;32]).sign(&signed).to_bytes())})
    }

    fn placeholder(subjects: Vec<(&str, String)>) -> Value {
        json!({"_type":"https://in-toto.io/Statement/v1", "predicateType":"https://stogas.ai/attestations/staging-development/v1", "predicate":{"environment":"staging"},
            "subject":subjects.into_iter().map(|(name,digest)|json!({"name":name,"digest":{"sha256":digest}})).collect::<Vec<_>>()})
    }

    fn sign_gateway(gateway: &mut Value) {
        gateway["attested_builds"] = json!([placeholder(vec![
            (
                "release-manifest.json",
                hex::encode(Sha256::digest(
                    crate::canonical_json(&gateway["manifest"]).unwrap()
                ))
            ),
            (
                "gateway.igvm",
                gateway["manifest"]["artifacts"]["gateway.igvm"]["sha256"]
                    .as_str()
                    .unwrap()
                    .into()
            )
        ])]);
        gateway["signature"] = signature(&gateway["manifest"]);
    }

    fn fixture() -> (Verifier, Value, i64) {
        let keys: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/logged-key-manifest.json"
        ))
        .unwrap();
        let hardware: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/logged-hardware-policy.json"
        ))
        .unwrap();
        let mut gateway = serde_json::to_value(crate::tests::release_fixture()).unwrap();
        let mut catalog = serde_json::to_value(crate::tests::catalog_fixture()).unwrap();
        let file_digest =
            |value: &Value| hex::encode(Sha256::digest(crate::canonical_json(value).unwrap()));
        sign_gateway(&mut gateway);
        catalog["attested_builds"] = json!([placeholder(vec![
            ("catalog-release.json", file_digest(&catalog["manifest"])),
            (
                "catalog.runtime.json",
                catalog["manifest"]["runtime"].as_str().unwrap()[7..].into()
            ),
            (
                "catalog.public.json",
                catalog["manifest"]["public"].as_str().unwrap()[7..].into()
            )
        ])]);
        catalog["signature"] = signature(&catalog["manifest"]);
        let mut approvals = keys["approvals"].clone();
        approvals["manifest"]["gateways"] = json!([payload_sha256(&gateway["manifest"]).unwrap()]);
        approvals["manifest"]["catalogs"] = json!([payload_sha256(&catalog["manifest"]).unwrap()]);
        approvals["manifest"]["hardware_policy_sha256"] =
            json!(payload_sha256(&hardware["policy"]).unwrap());
        approvals["signature"] = signature(&approvals["manifest"]);
        let now = hardware["sigstore"]["verificationMaterial"]["tlogEntries"][0]["integratedTime"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            * 1000
            + 1000;
        let body = json!({"schema":"stogas.confidential-bundle.v1","keys":keys["keys"],"approvals":approvals,"allowed_igvms":[gateway],"catalogs":[catalog],"hardware_policy":hardware,"vendor_collateral":[]});
        (
            Verifier::new(
                Environment::Staging,
                serde_json::from_value(keys["root"].clone()).unwrap(),
            )
            .unwrap(),
            body,
            now,
        )
    }

    #[test]
    fn complete_logged_bundle_installs_and_reuses_unchanged_approvals() {
        let (mut verifier, body, now) = fixture();
        let first = verifier.refresh(&encode(&body), now).unwrap();
        let summary = first.summary();
        assert_eq!(summary["keys_evidence"], body["keys"]);
        assert_eq!(summary["approvals_evidence"], body["approvals"]);
        let second = verifier.refresh(&encode(&body), now + 1000).unwrap();
        assert!(Arc::ptr_eq(&first.hardware.value, &second.hardware.value));
        let gateway_id = &first.approvals.manifest().gateways[0];
        assert!(Arc::ptr_eq(
            &first.gateways[gateway_id].value,
            &second.gateways[gateway_id].value
        ));
        assert!(second.compatible_catalog(gateway_id).is_some());
        assert!(second.compatible_catalog(&"0".repeat(64)).is_none());
        assert_eq!(second.hardware_policy().policy_count, 1);
    }

    #[test]
    fn typescript_current_bundle_verifies_and_synthetic_boots_never_gain_hardware_trust() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/current-evidence-v1.json"
        ))
        .unwrap();
        let now = fixture["verified_at_ms"].as_i64().unwrap();
        let mut verifier = Verifier::new(
            Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap();
        let snapshot = verifier
            .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
            .unwrap();
        assert_eq!(snapshot.gateways.len(), 1);
        assert_eq!(snapshot.catalogs.len(), 2);

        let synthetic: Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/node-boot-v1.json"))
                .unwrap();
        let mut record = synthetic["record"].clone();
        record["gateway_release_id"] = json!(snapshot.approvals.manifest().gateways[0]);
        record["hardware_policy_sha256"] =
            json!(snapshot.approvals.manifest().hardware_policy_sha256);
        record["report_data"]["environment"] = json!("staging");
        let challenge: [u8; 32] = hex::decode(
            record["report_data"]["registration_challenge"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let document = crate::canonical_json(&record).unwrap();
        assert!(matches!(
            snapshot.verify_registration(document.as_bytes(), &challenge, now),
            Err(Error::Attestation(_) | Error::MissingCollateral)
        ));
        assert!(
            snapshot
                .verify_logged_boot(document.as_bytes(), b"{}", now)
                .is_err()
        );
        let certificate: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/native-certificate-v1.json"
        ))
        .unwrap();
        let der = URL_SAFE_NO_PAD
            .decode(certificate["certificate"].as_str().unwrap())
            .unwrap();
        assert!(
            snapshot
                .verify_native_certificate(&der, challenge, now)
                .is_err()
        );
    }

    #[test]
    fn incomplete_or_altered_candidate_never_replaces_an_accepted_snapshot() {
        let (mut verifier, body, now) = fixture();
        let first = verifier.refresh(&encode(&body), now).unwrap();
        for pointer in [
            "/allowed_igvms",
            "/catalogs",
            "/keys/sigstore",
            "/hardware_policy/sigstore",
            "/approvals/signature",
            "/allowed_igvms/0/attested_builds",
        ] {
            let mut bad = body.clone();
            *bad.pointer_mut(pointer).unwrap() = json!([]);
            assert!(
                verifier.refresh(&encode(&bad), now).is_err(),
                "accepted {pointer}"
            );
            assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        }
        let mut omitted = body.clone();
        omitted["approvals"]["manifest"]["revision"] = json!(2);
        omitted["approvals"]["manifest"]["gateways"] = json!([]);
        omitted["approvals"]["signature"] = signature(&omitted["approvals"]["manifest"]);
        assert!(matches!(
            verifier.refresh(&encode(&omitted), now),
            Err(Error::Incomplete("gateway"))
        ));
        omitted["allowed_igvms"] = json!([]);
        let withdrawal = verifier.refresh(&encode(&omitted), now).unwrap();
        assert!(withdrawal.gateways.is_empty());
        assert!(matches!(
            verifier.refresh(&encode(&body), now),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        // The request's retained immutable context remains available after a live withdrawal.
        assert_eq!(first.gateways.len(), 1);
    }

    #[test]
    fn delivery_checksum_and_extensions_do_not_grant_authority() {
        let (mut verifier, body, now) = fixture();
        for pointer in [
            "/allowed_igvms/0/manifest/sequence",
            "/hardware_policy/policy/policies/0/cpuid_family",
            "/approvals/manifest/revision",
        ] {
            let mut bad = body.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(99);
            assert!(verifier.refresh(&encode(&bad), now).is_err());
        }
        let mut bad = body.clone();
        bad["nodes"] = json!([]);
        assert!(verifier.refresh(&encode(&bad), now).is_err());
        let mut envelope: Value = serde_json::from_slice(&encode(&body)).unwrap();
        envelope["body_sha256"] = json!("0".repeat(64));
        assert!(
            verifier
                .refresh(&serde_json::to_vec(&envelope).unwrap(), now)
                .is_err()
        );
        assert!(verifier.current().is_none());
    }

    #[test]
    fn logged_root_retirement_survives_partial_delivery_and_rotation_preserves_release_identity() {
        let (mut verifier, body, now) = fixture();
        let first = verifier.refresh(&encode(&body), now).unwrap();
        let rotation: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/logged-key-rotation.json"
        ))
        .unwrap();
        let now = rotation["verified_at_ms"].as_i64().unwrap();
        let mut next = body.clone();
        next["keys"] = rotation["keys"].clone();
        next["hardware_policy"] = rotation["hardware_policy"].clone();
        next["approvals"]["manifest"]["key_manifest_sha256"] =
            json!(payload_sha256(&next["keys"]["manifest"]).unwrap());
        let sign = |value: &Value| signature_for(value, 243, "stogas-fixture-online-20260921");
        next["approvals"]["signature"] = sign(&next["approvals"]["manifest"]);
        next["allowed_igvms"][0]["signature"] = sign(&next["allowed_igvms"][0]["manifest"]);
        next["catalogs"][0]["signature"] = sign(&next["catalogs"][0]["manifest"]);
        let mut partial = next.clone();
        partial["allowed_igvms"] = json!([]);
        partial["vendor_collateral"] = json!([{"collateral_type":"crl","der_base64url":"bad"}]);
        assert!(verifier.refresh(&encode(&partial), now).is_err());
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        assert!(matches!(
            first.require_current_keys(),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        assert!(matches!(
            verifier.refresh(&encode(&body), now),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        let second = verifier.refresh(&encode(&next), now).unwrap();
        second.require_current_keys().unwrap();
        assert_eq!(
            first.approvals.manifest().gateways,
            second.approvals.manifest().gateways
        );
        assert_eq!(
            first.approvals.manifest().catalogs,
            second.approvals.manifest().catalogs
        );
        assert_eq!(
            first.hardware_policy().sha256,
            second.hardware_policy().sha256
        );
        let id = &second.approvals.manifest().gateways[0];
        assert!(second.compatible_catalog(id).is_some());
        assert_eq!(
            first.gateway(id).unwrap().measurement,
            second.gateway(id).unwrap().measurement
        );
        // Already-running requests retain their original evidence; new work uses the current set.
        assert_eq!(
            first.approvals.keys().active_key.key_id,
            "stogas-fixture-online-20260920"
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn expired_collateral_remains_a_local_platform_failure_not_a_manifest_withdrawal() {
        let (mut verifier, mut body, now) = fixture();
        let archived: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/staging-bundle-sequence-1927.json"
        ))
        .unwrap();
        body["vendor_collateral"] = Value::Array(
            archived["body"]["vendor_collateral"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["payload"].clone())
                .collect(),
        );
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
        let chip = archived["body"]["nodes"][0]["chip_id"].as_str().unwrap();
        let tcb = archived["body"]["nodes"][0]["reported_tcb"]
            .as_str()
            .unwrap();
        assert!(matches!(
            snapshot.collateral_validity(chip, tcb, now),
            Err(Error::CollateralExpired)
        ));
        let before_expiry = crate::parse_time("2026-07-20T00:00:00Z").unwrap();
        assert!(
            snapshot
                .collateral_validity(chip, tcb, before_expiry)
                .is_ok()
        );
        let summaries = snapshot.collateral_summary(before_expiry);
        assert!(!summaries.is_empty());
        assert!(summaries.iter().all(|row| row["error"].is_null()
            && row["not_before_unix_ms"].as_i64().unwrap() <= before_expiry
            && row["not_after_unix_ms"].as_i64().unwrap() > before_expiry));
        assert!(
            snapshot
                .collateral_summary(now)
                .iter()
                .all(|row| row["error"] == "expired_collateral"
                    && row.get("not_after_unix_ms").is_none())
        );
        // Delivery timestamps cannot extend the vendor's signed nextUpdate.
        for row in body["vendor_collateral"].as_array_mut().unwrap() {
            row["fetched_at"] = json!("2026-09-20T00:00:00Z");
        }
        let refreshed = verifier.refresh(&encode(&body), now).unwrap();
        assert!(matches!(
            refreshed.collateral_validity(chip, tcb, now),
            Err(Error::CollateralExpired)
        ));
        assert_eq!(
            refreshed.approvals.manifest().revision,
            snapshot.approvals.manifest().revision
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn genuine_snp_report_requires_current_approval_binding_and_complete_hardware_appraisal() {
        let (mut verifier, mut body, _) = fixture();
        let real: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/snp-report-v5.json")).unwrap();
        let now = crate::parse_time(real["captured_at"].as_str().unwrap()).unwrap();
        let report = URL_SAFE_NO_PAD
            .decode(real["report"].as_str().unwrap())
            .unwrap();
        let expected: [u8; 64] = report[0x50..0x90].try_into().unwrap();
        body["allowed_igvms"][0]["manifest"] = real["manifest"].clone();
        sign_gateway(&mut body["allowed_igvms"][0]);
        let release_id = payload_sha256(&real["manifest"]).unwrap();
        body["approvals"]["manifest"]["gateways"] = json!([release_id]);
        body["approvals"]["signature"] = signature(&body["approvals"]["manifest"]);
        body["vendor_collateral"] = real["vendor_collateral"].clone();
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
        // Historical report appraisal, not a claim that this fixture establishes a fresh session.
        let session = snapshot
            .verify_snp_report(&report, &expected, &release_id, now)
            .unwrap();
        assert_eq!(session.report_id().as_slice(), &report[0x140..0x160]);
        assert_eq!(
            session.node_id(),
            crate::attestation::snp_node_id(session.report_id())
        );
        assert_eq!(session.chip_id(), hex::encode(&report[0x1a0..0x1e0]));
        assert_eq!(session.reported_tcb(), hex::encode(&report[0x180..0x188]));
        assert!(matches!(
            snapshot.verify_snp_report(
                &report,
                &expected,
                &release_id,
                session.validity().not_after_unix_ms
            ),
            Err(Error::CollateralExpired)
        ));
        assert!(matches!(
            snapshot.verify_snp_report(&report, &expected, &"ff".repeat(32), now),
            Err(Error::Approval(crate::approvals::Error::NotApproved(
                "gateway"
            )))
        ));
        let mut wrong_binding = expected;
        wrong_binding[0] ^= 1;
        assert!(
            snapshot
                .verify_snp_report(&report, &wrong_binding, &release_id, now)
                .is_err()
        );
        for vmpl in [1_u32, 2, 3, u32::MAX] {
            let mut altered = report.clone();
            altered[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err(),
                "accepted VMPL {vmpl}"
            );
        }
        // Measurement, launch flags, instance ID, chip/TCB, mitigations, reserved bytes and
        // signature must all remain authenticated, including fields outside report_data.
        for offset in [
            0, 8, 0x10, 0x20, 0x34, 0x38, 0x40, 0x48, 0x4c, 0x50, 0x90, 0xc0, 0xe0, 0x110, 0x140,
            0x160, 0x180, 0x188, 0x1a0, 0x1e0, 0x1f0, 0x1f8, 0x200, 0x208, 0x2a0, 0x2d0, 0x2e8,
            0x318, 0x330,
        ] {
            let mut altered = report.clone();
            altered[offset] ^= 1;
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err(),
                "accepted report mutation at {offset:x}"
            );
        }
        for size in [0, 0x140, 0x49f, 0x4a1] {
            let mut altered = report.clone();
            altered.resize(size, 0);
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err()
            );
        }
        body["approvals"]["manifest"]["revision"] = json!(2);
        body["approvals"]["manifest"]["gateways"] = json!([]);
        body["approvals"]["signature"] = signature(&body["approvals"]["manifest"]);
        body["allowed_igvms"] = json!([]);
        let withdrawn = verifier.refresh(&encode(&body), now).unwrap();
        assert!(matches!(
            withdrawn.verify_snp_report(&report, &expected, &release_id, now),
            Err(Error::Approval(crate::approvals::Error::NotApproved(
                "gateway"
            )))
        ));
    }
}
