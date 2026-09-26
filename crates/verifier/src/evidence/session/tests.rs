use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::Digest as _;

fn fixture() -> (super::super::Verifier, Value, Vec<u8>, [u8; 32], i64) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let verifier = super::super::Verifier::new(
        crate::approvals::Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let challenge = hex::decode(fixture["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    (
        verifier,
        fixture["bundle"].clone(),
        certificate,
        challenge,
        now,
    )
}

#[test]
fn genuine_registration_binds_csr_possession_to_the_quoted_key() {
    let (mut verifier, bundle, _, _, _) = fixture();
    let registration: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-registration-v1.json"
    ))
    .unwrap();
    let now = registration["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    let document = crate::canonical_json(&registration["boot"]).unwrap();
    let challenge = hex::decode(
        registration["boot"]["report_data"]["registration_challenge"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let boot = snapshot
        .verify_registration(document.as_bytes(), &challenge, now)
        .unwrap();
    let csr = URL_SAFE_NO_PAD
        .decode(registration["csr_der"].as_str().unwrap())
        .unwrap();
    boot.verify_csr(&csr).unwrap();
    let mut corrupted = csr;
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(boot.verify_csr(&corrupted).is_err());
    let csr_vectors: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/boot-csr-v1.json"
    ))
    .unwrap();
    for name in ["prod", "extra_san", "extra_subject"] {
        let other = URL_SAFE_NO_PAD
            .decode(csr_vectors["requests"][name].as_str().unwrap())
            .unwrap();
        assert!(boot.verify_csr(&other).is_err());
    }
}

#[test]
fn registered_boot_reappraisal_preserves_history_without_reopening_registration() {
    use sha2::{Digest as _, Sha256};
    let (mut verifier, bundle, _, _, _) = fixture();
    let registration: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-registration-v1.json"
    ))
    .unwrap();
    let now = registration["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    // The original policy reference is historical. The genuine SNP report must still
    // satisfy today's policy, and its registered document cannot change.
    let mut historical = registration["boot"].clone();
    historical["hardware_policy_sha256"] = serde_json::json!("ab".repeat(32));
    let document = crate::canonical_json(&historical).unwrap();
    let registered_digest = Sha256::digest(document.as_bytes()).into();
    let challenge = hex::decode(
        historical["report_data"]["registration_challenge"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    snapshot
        .verify_registration(document.as_bytes(), &challenge, now)
        .unwrap();
    let retained = snapshot
        .verify_registered_boot(document.as_bytes(), &registered_digest, now)
        .unwrap();
    retained
        .verify_csr(
            &URL_SAFE_NO_PAD
                .decode(registration["csr_der"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    assert!(
        snapshot
            .verify_registered_boot(document.as_bytes(), &[0; 32], now)
            .is_err()
    );
    assert!(matches!(
        snapshot.verify_registered_boot(
            document.as_bytes(),
            &registered_digest,
            retained.hardware().validity().not_after_unix_ms
        ),
        Err(Error::CollateralExpired)
    ));
    historical["gateway_release_id"] = serde_json::json!("cd".repeat(32));
    let unapproved = crate::canonical_json(&historical).unwrap();
    assert!(
        snapshot
            .verify_registration(unapproved.as_bytes(), &challenge, now)
            .is_err()
    );
    assert!(
        snapshot
            .verify_registered_boot(
                unapproved.as_bytes(),
                &Sha256::digest(unapproved.as_bytes()).into(),
                now
            )
            .is_err()
    );
}

#[test]
fn genuine_hardware_boot_and_fresh_native_evidence_verify_as_one_guest() {
    let (mut verifier, bundle, certificate, challenge, now) = fixture();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    let peer = snapshot
        .verify_native_certificate(&certificate, challenge, now)
        .unwrap();
    assert_eq!(snapshot.check_session(&peer, now).unwrap(), peer.validity());
    assert!(
        snapshot
            .check_session(&peer, peer.validity().not_before_unix_ms - 1)
            .is_err()
    );
    assert!(matches!(
        snapshot.check_session(&peer, peer.validity().not_after_unix_ms),
        Err(Error::CollateralExpired)
    ));
    let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
    let boot = peer.boot();
    let expected_challenge: [u8; 32] =
        hex::decode(&boot.record().report_data.registration_challenge)
            .unwrap()
            .try_into()
            .unwrap();
    let registration = snapshot
        .verify_registration(parsed.evidence.boot_document, &expected_challenge, now)
        .unwrap();
    assert_eq!(registration.hardware().node_id(), boot.hardware().node_id());
    assert_eq!(registration.document_sha256(), boot.document_sha256());
    assert!(boot.integrated_time_unix_ms() <= now);
    assert_eq!(peer.validity(), boot.hardware().validity());
    assert!(
        snapshot
            .verify_registration(parsed.evidence.boot_document, &[0; 32], now)
            .is_err()
    );
    assert!(
        snapshot
            .verify_native_certificate(&certificate, [0; 32], now)
            .is_err()
    );
    assert!(
        snapshot
            .verify_native_certificate(&certificate, challenge, now + 360_000)
            .is_err()
    );
    // A fresh connection needs a valid certificate; an already-established channel does not
    // repeat that handshake just because its short-lived certificate subsequently expires.
    let retained = snapshot.reappraise_session(&peer, now + 360_000).unwrap();
    assert!(Arc::ptr_eq(&retained.artifacts, &peer.artifacts));
    snapshot.check_session(&retained, now + 360_000).unwrap();
    let mut damaged = parsed.evidence.boot_inclusion.to_vec();
    damaged[0] ^= 1;
    assert!(
        snapshot
            .verify_logged_boot(parsed.evidence.boot_document, &damaged, now)
            .is_err()
    );
}

#[test]
fn online_key_rotation_keeps_the_same_hardware_boot_and_release_verifiable() {
    let (mut verifier, mut bundle, certificate, challenge, now) = fixture();
    let before = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    let original = before
        .verify_native_certificate(&certificate, challenge, now)
        .unwrap();
    bundle = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-session-rotated-v1.json"
    ))
    .unwrap();
    let after = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    assert!(before.require_current_keys().is_err());
    assert!(before.check_session(&original, now).is_err());
    assert!(after.check_session(&original, now).is_err());
    let updated = after.reappraise_session(&original, now).unwrap();
    after.check_session(&updated, now).unwrap();
    assert!(Arc::ptr_eq(&original.artifacts, &updated.artifacts));
    assert_eq!(
        original.boot().document_sha256(),
        updated.boot().document_sha256()
    );
    assert_eq!(
        original.boot().hardware().node_id(),
        updated.boot().hardware().node_id()
    );
    assert_eq!(
        original.boot().record().gateway_release_id,
        updated.boot().record().gateway_release_id
    );
}

#[test]
fn learned_release_withdrawal_blocks_warm_reappraisal_but_keeps_owned_request_evidence() {
    use crate::signing::SigningKey;
    use serde_json::json;
    let (mut verifier, mut bundle, certificate, challenge, now) = fixture();
    let original = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), now)
        .unwrap();
    let session = original
        .verify_native_certificate(&certificate, challenge, now)
        .unwrap();
    let approval = &mut bundle["body"]["approvals"]["manifest"];
    approval["revision"] = json!(approval["revision"].as_u64().unwrap() + 1);
    approval["gateways"] = json!([]);
    let variants: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/logged-approval-variants.json"
    ))
    .unwrap();
    let digest = crate::approvals::payload_sha256(approval).unwrap();
    bundle["body"]["approvals"] = variants["approvals"][digest].clone();
    let refresh_time = now.max(variants["verified_at_ms"].as_i64().unwrap());
    bundle["body"]["allowed_igvms"] = json!([]);
    bundle["body_sha256"] = json!(crate::approvals::payload_sha256(&bundle["body"]).unwrap());
    let current = verifier
        .refresh(&serde_json::to_vec(&bundle).unwrap(), refresh_time)
        .unwrap();
    assert!(matches!(
        current.reappraise_session(&session, now),
        Err(Error::Approval(crate::approvals::Error::NotApproved(
            "gateway"
        )))
    ));
    assert!(current.check_session(&session, now).is_err());
    assert!(
        original
            .gateway(&session.boot().record().gateway_release_id)
            .is_some()
    );
    assert!(!session.artifacts.boot_document.is_empty());
    // An approval update must not replace the retained identity of an admitted request.
    let request = [1; 32];
    let response = [2; 32];
    let metadata = serde_json::json!({});
    let digest: [u8; 32] = sha2::Sha256::digest(b"{}").into();
    let message = [
        crate::receipt::SCHEMA.as_bytes(),
        b"\0",
        &request,
        &response,
        &digest,
    ]
    .concat();
    let receipt = crate::receipt::Receipt {
        schema: crate::receipt::SCHEMA.into(),
        boot_sha256: hex::encode(session.boot().document_sha256()),
        request_sha256: hex::encode(request),
        response_sha256: hex::encode(response),
        signature: URL_SAFE_NO_PAD.encode(
            SigningKey::from_seed(&[42; 32])
                .sign(&message, &[])
                .unwrap(),
        ),
    };
    receipt
        .verify(session.boot(), &request, &response, &metadata)
        .unwrap();
}
