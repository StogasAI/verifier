use super::*;
use serde_json::{Value, json};

#[test]
fn certificate_renewal_matches_independent_vector_and_rejects_replay_outside_its_window() {
    let vector = fixture();
    let request = &vector["certificate_renewal"];
    let key = URL_SAFE_NO_PAD
        .decode(
            vector["record"]["report_data"]["signing_public_key"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let node = request["node_id"].as_str().unwrap();
    let now = request["issued_at_ms"].as_i64().unwrap();
    let bytes = serde_json::to_vec(request).unwrap();
    for delta in [-300_000, 0, 300_000] {
        verify_certificate_renewal(&bytes, node, &key, now + delta).unwrap();
    }
    for delta in [-300_001, 300_001] {
        assert!(verify_certificate_renewal(&bytes, node, &key, now + delta).is_err());
    }
    assert!(verify_certificate_renewal(&bytes, "another-node", &key, now).is_err());
    assert!(verify_certificate_renewal(&bytes, node, &[0; 32], now).is_err());
    let mut another_key = key.clone();
    another_key[0] ^= 1;
    assert!(verify_certificate_renewal(&bytes, node, &another_key, now).is_err());
    for (field, value) in [
        ("node_id", json!("other")),
        ("issued_at_ms", json!(now + 1)),
        ("signature", json!("A".repeat(86))),
        ("extra", json!(true)),
    ] {
        let mut changed = request.clone();
        changed[field] = value;
        assert!(
            verify_certificate_renewal(&serde_json::to_vec(&changed).unwrap(), node, &key, now)
                .is_err()
        );
    }
    assert!(verify_certificate_renewal(&vec![b' '; 5 * 1024 + 1], node, &key, now).is_err());
}

#[test]
fn go_csrs_bind_possession_and_exact_service_identity() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/boot-csr-v1.json"
    ))
    .unwrap();
    let digest = vector["tls_spki_sha256"].as_str().unwrap();
    let verify = |csr: &[u8], key: &str, hostname: &str| {
        crate::verify_certificate_csr(csr, key, Some(hostname), vec![hostname.into()])
    };
    for (name, hostname) in [
        ("prod", "api.stogas.ai"),
        ("staging", "api-staging.stogas.ai"),
    ] {
        let csr = URL_SAFE_NO_PAD
            .decode(vector["requests"][name].as_str().unwrap())
            .unwrap();
        verify(&csr, digest, hostname).unwrap();
        assert!(verify(&csr, &"00".repeat(32), hostname).is_err());
        assert!(verify(&csr, digest, "other.example").is_err());
        let mut trailing = csr.clone();
        trailing.push(0);
        assert!(verify(&trailing, digest, hostname).is_err());
        let mut bad_signature = csr;
        *bad_signature.last_mut().unwrap() ^= 1;
        assert!(verify(&bad_signature, digest, hostname).is_err());
    }
    for name in ["extra_san", "extra_subject"] {
        let csr = URL_SAFE_NO_PAD
            .decode(vector["requests"][name].as_str().unwrap())
            .unwrap();
        assert!(verify(&csr, digest, "api.stogas.ai").is_err());
    }
    for csr in [vec![], vec![0; 16 * 1024 + 1], vec![0x30, 0x01, 0x00]] {
        assert!(verify(&csr, digest, "api.stogas.ai").is_err());
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/node-boot-v1.json"
    ))
    .unwrap()
}

#[test]
fn canonical_boot_document_and_commitment_match_independent_and_go_vectors() {
    let vector = fixture();
    let document = crate::canonical_json(&vector["record"]).unwrap();
    let record = parse_record(document.as_bytes()).unwrap();
    assert_eq!(
        hex::encode(record.report_data.commitment().unwrap()),
        vector["report_data_sha512"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(document.as_bytes())),
        vector["document_sha256"]
    );
    for pointer in [
        "/registration_challenge",
        "/tls_spki_sha256",
        "/signing_public_key",
        "/hpke_public_key",
        "/schema",
    ] {
        let mut data = vector["record"]["report_data"].clone();
        *data.pointer_mut(pointer).unwrap() = json!("invalid");
        assert!(
            serde_json::from_value::<BootReportData>(data)
                .unwrap()
                .commitment()
                .is_err(),
            "accepted {pointer}"
        );
    }
    let mut weak = record.report_data;
    weak.signing_public_key = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    assert!(weak.commitment().is_err());
}

#[test]
fn boot_parser_rejects_alternate_bytes_unknown_fields_and_invalid_sizes() {
    let vector = fixture();
    let document = crate::canonical_json(&vector["record"]).unwrap();
    assert!(parse_record(document.trim_end().as_bytes()).is_err());
    assert!(
        parse_record(
            serde_json::to_string_pretty(&vector["record"])
                .unwrap()
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_record(&vec![
            0;
            crate::attestation::evidence::MAX_EVIDENCE_BYTES + 1
        ])
        .is_err()
    );
    for (pointer, value) in [
        ("/schema", json!("other")),
        ("/gateway_release_id", json!("AF".repeat(32))),
        ("/hardware_policy_sha256", json!("bad")),
    ] {
        let mut record = vector["record"].clone();
        *record.pointer_mut(pointer).unwrap() = value;
        assert!(parse_record(crate::canonical_json(&record).unwrap().as_bytes()).is_err());
    }
    let mut record = vector["record"].clone();
    record["node_id"] = json!("untrusted alias");
    assert!(parse_record(crate::canonical_json(&record).unwrap().as_bytes()).is_err());
    assert!(
        parse_record(br#"{"schema":"stogas.node-boot.v1","schema":"stogas.node-boot.v1"}"#)
            .is_err()
    );
}
