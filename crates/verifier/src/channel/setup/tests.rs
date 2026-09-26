use super::*;
use crate::channel::{Direction, Kind, record::Records};
use serde::Deserialize;
use std::cell::Cell;

#[derive(Deserialize)]
struct Fixture {
    #[serde(rename = "seed_hex")]
    seed: String,
    #[serde(rename = "hello_hex")]
    hello: String,
    #[serde(rename = "response_hex")]
    response: String,
    #[serde(rename = "root_hex")]
    root: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/channel-setup-v1.json"
    ))
    .unwrap()
}

fn pending(vector: &Fixture) -> PendingSetup {
    PendingSetup {
        private_key: Some(
            <XWing as hpke::Kem>::PrivateKey::from_bytes(&hex::decode(&vector.seed).unwrap())
                .unwrap(),
        ),
        hello: hex::decode(&vector.hello).unwrap(),
        environment: Environment::Production,
    }
}

#[cfg(feature = "staging")]
#[test]
fn real_hardware_setup_binds_the_exchange_and_still_requires_the_client_secret() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let mut verifier = crate::evidence::Verifier::new(
        Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
        .unwrap();
    // The live qualification erased its client secret. A different recipient
    // secret must not establish a session even with genuine, fully valid evidence.
    let mut pending = PendingSetup {
        private_key: Some(<XWing as hpke::Kem>::PrivateKey::from_bytes(&[7; 32]).unwrap()),
        hello: URL_SAFE_NO_PAD
            .decode(fixture["e2ee"]["hello"].as_str().unwrap())
            .unwrap(),
        environment: Environment::Staging,
    };
    let response = URL_SAFE_NO_PAD
        .decode(fixture["e2ee"]["response"].as_str().unwrap())
        .unwrap();
    let session = pending.check_evidence(&response, &snapshot, now).unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let challenge = hex::decode(fixture["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let native = snapshot
        .verify_native_certificate(&certificate, challenge, now)
        .unwrap();
    assert_eq!(
        session.boot().document_sha256(),
        native.boot().document_sha256()
    );
    assert_eq!(
        session.boot().hardware().node_id(),
        native.boot().hardware().node_id()
    );
    assert!(matches!(
        pending.complete_verified(&response, &snapshot, now),
        Err(SetupError::Protocol(Error::Authentication))
    ));
}

#[test]
fn go_setup_matches_rust_exporter_and_session_keys() {
    let vector = fixture();
    let response = hex::decode(&vector.response).unwrap();
    let mut setup = pending(&vector);
    let parsed = setup.inspect(&response).unwrap();
    let id = parsed.session_id;
    assert_eq!(parsed.idle_seconds, 600);
    let checks = Cell::new(0);
    let mut session = setup
        .complete(&response, |evidence| {
            assert_eq!(
                evidence.boot_document,
                br#"{"fixture":"synthetic boot record"}"#
            );
            assert_eq!(
                evidence.boot_inclusion,
                br#"{"fixture":"synthetic inclusion"}"#
            );
            checks.set(checks.get() + 1);
            // This fixture intentionally tests framing and key agreement only.
            // Production supplies hardware/boot/current-approval verification here.
            Ok(())
        })
        .unwrap();
    assert_eq!(checks.get(), 1);
    assert_eq!(*session.id(), id);
    assert_eq!(session.idle_seconds(), 600);
    let root: [u8; 32] = hex::decode(vector.root).unwrap().try_into().unwrap();
    let mut request = session.request().unwrap();
    let mut expected_prefix = b"STGS\x01\x03".to_vec();
    expected_prefix.extend_from_slice(&id);
    expected_prefix.extend_from_slice(&0_u64.to_be_bytes());
    assert_eq!(request.prefix().as_slice(), expected_prefix);
    let mut server = Records::new(&root, &id, request.number(), Direction::Request).unwrap();
    let mut encoded = request.seal(Kind::Metadata, b"credentials").unwrap();
    assert_eq!(server.open(&mut encoded).unwrap().1, b"credentials");
    let mut server = Records::new(&root, &id, request.number(), Direction::Response).unwrap();
    let mut encoded = server.seal(Kind::Metadata, b"status=200").unwrap();
    assert_eq!(request.open(&mut encoded).unwrap().1, b"status=200");
}

#[test]
fn setup_checks_binding_possession_and_policy_before_session_release() {
    let vector = fixture();
    let response = hex::decode(&vector.response).unwrap();
    // Each server field that affects the exchange is authenticated by the quote.
    for index in [0, 4, 5, 6, 37, 38, 41, 42, SERVER_PREFIX_BYTES - 1] {
        let mut changed = response.clone();
        changed[index] ^= 1;
        let calls = Cell::new(0);
        assert!(
            pending(&vector)
                .complete(&changed, |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(calls.get(), 0);
    }
    for index in 0..32 {
        let mut changed = response.clone();
        changed[SERVER_PREFIX_BYTES + index] ^= 1;
        assert!(matches!(
            pending(&vector).complete(&changed, |_| Ok(())),
            Err(SetupError::Protocol(Error::Authentication))
        ));
    }
    let rejected = pending(&vector).complete(&response, |_| {
        Err(crate::Error::Node("fixture policy rejection".into()))
    });
    assert!(
        matches!(rejected, Err(SetupError::Verification(crate::Error::Node(message))) if message == "fixture policy rejection")
    );
    let fresh = PendingSetup::new(Environment::Production).unwrap();
    assert_eq!(fresh.hello().len(), CLIENT_SETUP_BYTES);
    assert_ne!(fresh.hello(), pending(&vector).hello());
    assert!(fresh.inspect(&response).is_err());
    let mut wrong_key = pending(&vector);
    wrong_key.private_key = Some(<XWing as hpke::Kem>::PrivateKey::from_bytes(&[99; 32]).unwrap());
    assert!(wrong_key.complete(&response, |_| Ok(())).is_err());
}

#[test]
fn setup_rejects_truncated_extended_and_oversized_evidence() {
    let vector = fixture();
    let response = hex::decode(&vector.response).unwrap();
    let setup = pending(&vector);
    for length in 0..response.len() {
        assert!(
            setup.inspect(&response[..length]).is_err(),
            "accepted {length} bytes"
        );
    }
    let mut changed = response.clone();
    changed.push(0);
    assert!(setup.inspect(&changed).is_err());
    changed = response;
    changed[SERVER_PREFIX_BYTES + 32..SERVER_PREFIX_BYTES + 36].fill(255);
    assert!(setup.inspect(&changed).is_err());
    assert!(setup.inspect(&vec![0; MAX_SERVER_SETUP_BYTES + 1]).is_err());
}

#[test]
fn evidence_recovery_keeps_setup_but_completion_never_reuses_its_secret() {
    let vector = fixture();
    let response = hex::decode(&vector.response).unwrap();
    let mut setup = pending(&vector);
    let hello = setup.hello().to_vec();
    assert!(
        setup
            .complete(&response, |_| Err(crate::Error::Node(
                "missing evidence".into()
            )))
            .is_err()
    );
    assert_eq!(setup.hello(), hello);
    let mut session = setup.complete(&response, |_| Ok(())).unwrap();
    assert!(matches!(
        setup.complete(&response, |_| Ok(())),
        Err(SetupError::Protocol(Error::Closed))
    ));
    assert!(session.request().is_ok());
    let mut bad_confirmation = response.clone();
    bad_confirmation[SERVER_PREFIX_BYTES] ^= 1;
    let mut setup = pending(&vector);
    assert!(matches!(
        setup.complete(&bad_confirmation, |_| Ok(())),
        Err(SetupError::Protocol(Error::Authentication))
    ));
    assert!(matches!(
        setup.complete(&response, |_| Ok(())),
        Err(SetupError::Protocol(Error::Closed))
    ));
}
