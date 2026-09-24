use super::*;
use base64::engine::general_purpose::STANDARD;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/amd-crl-transition-vectors.json"
    ))
    .unwrap()
}

fn der(value: &Value, field: &str) -> Vec<u8> {
    STANDARD.decode(value[field].as_str().unwrap()).unwrap()
}

fn row(der: &[u8], kind: &str) -> Value {
    serde_json::json!({"collateral_type":kind,"der_base64url":URL_SAFE_NO_PAD.encode(der),"sha256":hex::encode(Sha256::digest(der))})
}

fn trusted_fixture() -> (Value, IssuerId, Revocations) {
    let value = fixture();
    let ark = der(&value, "ark");
    let (_, certificate) = parse_x509_certificate(&ark).unwrap();
    let id = Sha384::digest(certificate.public_key().raw).into();
    let state = Revocations::default();
    // Only this private test helper trusts the fixture CA. observe() cannot learn it from delivery.
    state.issuers.lock().unwrap().insert(
        id,
        Issuer {
            certificate: ark.into(),
            latest: None,
            conflicting: false,
        },
    );
    (value, id, state)
}

#[test]
fn forged_root_metadata_cannot_poison_later_authentic_crl_delivery() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/current-evidence-v1.json"
    ))
    .unwrap();
    let rows = fixture["bundle"]["body"]["vendor_collateral"]
        .as_array()
        .unwrap();
    let original = rows
        .iter()
        .find(|row| row["collateral_type"] == "ark")
        .unwrap();
    let crl = rows
        .iter()
        .find(|row| row["collateral_type"] == "crl")
        .unwrap();
    let bytes = row_der(original).unwrap();
    let mut forged_name = bytes.clone();
    let name = b"ARK-Milan";
    let offsets: Vec<_> = forged_name
        .windows(name.len())
        .enumerate()
        .filter_map(|(offset, value)| (value == name).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 2); // Replace both issuer and subject; leave the pinned SPKI intact.
    for offset in offsets {
        forged_name[offset] = b'B';
    }
    let mut forged_signature = bytes;
    *forged_signature.last_mut().unwrap() ^= 1;
    for forged in [forged_name, forged_signature] {
        let state = Revocations::default();
        let now = fixture["verified_at_ms"].as_i64().unwrap();
        state
            .observe(
                &serde_json::json!({"vendor_collateral":[row(&forged, "ark")]}),
                now,
            )
            .unwrap();
        assert!(
            state.issuers.lock().unwrap().is_empty(),
            "cached unauthenticated root metadata"
        );
        state
            .observe(
                &serde_json::json!({"vendor_collateral":[original, crl]}),
                now,
            )
            .unwrap();
        let issuers = state.issuers.lock().unwrap();
        assert_eq!(issuers.len(), 1);
        assert!(issuers.values().next().unwrap().latest.is_some());
        drop(issuers);
    }
}

#[test]
fn authenticated_revocation_survives_expiry_and_stale_replica() {
    let (value, id, state) = trusted_fixture();
    let now = value["now"].as_i64().unwrap();
    let validity = Validity {
        not_before_unix_ms: 0,
        not_after_unix_ms: i64::MAX,
    };
    let body = |name| serde_json::json!({"vendor_collateral":[row(&der(&value,name),"crl")]});
    state.observe(&body("clean"), now).unwrap();
    assert!(state.validity(&id, &[2, 0, 1], validity, now).is_ok());
    state.observe(&body("revoked"), now).unwrap();
    assert!(matches!(
        state.validity(&id, &[2, 0, 1], validity, now),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        state.observe(&body("clean"), now),
        Err(Error::CrlOrder)
    ));
    state.observe(&body("expired"), now).unwrap();
    assert!(matches!(
        state.validity(&id, &[2, 0, 1], validity, now),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        state.validity(&id, &[2, 0, 9], validity, now),
        Err(Error::CollateralExpired)
    ));
}

#[test]
fn same_number_conflict_blocks_the_scope_and_large_numbers_are_supported() {
    let (value, id, state) = trusted_fixture();
    let now = value["now"].as_i64().unwrap();
    let body = |name| serde_json::json!({"vendor_collateral":[row(&der(&value,name),"crl")]});
    state.observe(&body("revoked"), now).unwrap();
    state.observe(&body("revoked"), now).unwrap();
    assert!(matches!(
        state.observe(&body("conflict"), now),
        Err(Error::CrlOrder)
    ));
    assert!(matches!(
        state.observe(&body("revoked"), now),
        Err(Error::CrlOrder)
    ));
    state.observe(&body("large_number"), now).unwrap();
    assert!(!state.issuers.lock().unwrap()[&id].conflicting);
    assert_eq!(
        state.issuers.lock().unwrap()[&id]
            .latest
            .as_ref()
            .unwrap()
            .number[0],
        128
    );
}

#[test]
fn forged_future_scoped_or_untrusted_crls_cannot_advance_state() {
    let (value, id, state) = trusted_fixture();
    let now = value["now"].as_i64().unwrap();
    let body = |bytes: Vec<u8>| serde_json::json!({"vendor_collateral":[row(&bytes,"crl")]});
    state.observe(&body(der(&value, "clean")), now).unwrap();
    for kind in ["future", "scoped"] {
        assert!(state.observe(&body(der(&value, kind)), now).is_err());
    }
    let mut forged = der(&value, "large_number");
    *forged.last_mut().unwrap() ^= 1;
    assert!(state.observe(&body(forged), now).is_err());
    assert_eq!(
        state.issuers.lock().unwrap()[&id]
            .latest
            .as_ref()
            .unwrap()
            .number[19],
        1
    );
    let untrusted = Revocations::default();
    assert!(untrusted.observe(&serde_json::json!({"vendor_collateral":[row(&der(&value,"ark"),"ark"),row(&der(&value,"revoked"),"crl")]}),now).is_err());
    assert!(untrusted.issuers.lock().unwrap().is_empty());
}

#[test]
fn malformed_neighbor_does_not_discard_authentic_revocation() {
    let (value, id, state) = trusted_fixture();
    let now = value["now"].as_i64().unwrap();
    let invalid = serde_json::json!({"collateral_type":"crl","der_base64url":"bad","sha256":"bad"});
    for rows in [
        vec![invalid.clone(), row(&der(&value, "revoked"), "crl")],
        vec![row(&der(&value, "revoked"), "crl"), invalid],
    ] {
        assert!(
            state
                .observe(&serde_json::json!({"vendor_collateral":rows}), now)
                .is_err()
        );
        assert!(matches!(
            state.validity(
                &id,
                &[2, 0, 1],
                Validity {
                    not_before_unix_ms: 0,
                    not_after_unix_ms: i64::MAX
                },
                now
            ),
            Err(Error::Revoked)
        ));
    }
}

#[test]
fn signed_crl_extensions_and_entries_enforce_the_supported_scope() {
    let vectors = fixture()["extension_vectors"].clone();
    let ark = der(&vectors, "ark");
    let now = vectors["now"].as_i64().unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            authenticate_crl(&ark, &der(case, "der"), now).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    let original = der(&vectors["cases"][0], "der");
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(authenticate_crl(&ark, &trailing, now).is_err());

    let mut issuer = Issuer {
        certificate: ark.clone().into(),
        latest: None,
        conflicting: false,
    };
    issuer
        .learn(authenticate_crl(&ark, &original, now).unwrap())
        .unwrap();
    // A new randomized signature over the same signed contents is not equivocation.
    let resigned = der(&vectors, "resigned_same_contents");
    assert_ne!(original, resigned);
    issuer
        .learn(authenticate_crl(&ark, &resigned, now).unwrap())
        .unwrap();
    assert!(matches!(
        issuer.learn(authenticate_crl(&ark, &der(&vectors, "older_higher_number"), now).unwrap()),
        Err(Error::CrlOrder)
    ));
}

#[cfg(feature = "staging")]
#[test]
fn incomplete_bundle_cannot_hide_authenticated_negative_appraisal() {
    use crate::{approvals::Environment, evidence::Verifier};
    let (value, id, state) = trusted_fixture();
    let now = value["now"].as_i64().unwrap();
    let roots: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/logged-key-manifest.json"
    ))
    .unwrap();
    let mut verifier = Verifier::new(
        Environment::Staging,
        serde_json::from_value(roots["root"].clone()).unwrap(),
    )
    .unwrap();
    verifier.revocations = Arc::new(state);
    let body =
        serde_json::json!({"body":{"vendor_collateral":[row(&der(&value,"revoked"),"crl")]}});
    assert!(
        verifier
            .refresh(&serde_json::to_vec(&body).unwrap(), now)
            .is_err()
    );
    assert!(verifier.current().is_none());
    assert!(matches!(
        verifier.revocations.validity(
            &id,
            &[2, 0, 1],
            Validity {
                not_before_unix_ms: 0,
                not_after_unix_ms: i64::MAX
            },
            now
        ),
        Err(Error::Revoked)
    ));
}
