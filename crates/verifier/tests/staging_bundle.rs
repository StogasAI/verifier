use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stogas_verifier::{Environment, MAX_INPUT_BYTES, Verifier, verify_amd_collateral_admission};

const BUNDLE: &[u8] = include_bytes!("fixtures/staging-bundle-sequence-1927.json");
const VERIFIED_AT_UNIX_MS: i64 = 1_784_414_117_082;

fn fixture() -> Value {
    let mut value: Value = serde_json::from_slice(BUNDLE).expect("real bundle fixture");
    let round = value["body"]["nodes"][0]["report_data"]["drand"]["round"]
        .as_u64()
        .unwrap();
    let round = i64::try_from(round).unwrap();
    let drand_deadline = (1_692_803_367_i64 + (round - 1) * 3) * 1_000 + 180_000;
    let created_at = unix_ms(&value, "/body/created_at");
    value["body"]["expires_at"] = Value::String(
        DateTime::from_timestamp_millis(drand_deadline)
            .unwrap()
            .to_rfc3339(),
    );
    value["body"]["ttl_ms"] = Value::from(drand_deadline - created_at);
    value
}

fn checksummed_fixture(value: Value) -> (Vec<u8>, Environment) {
    let mut value = value;
    let body = serde_json::to_vec(value.get("body").expect("bundle body")).unwrap();
    value["body_sha256"] = Value::String(hex::encode(Sha256::digest(&body)));
    (serde_json::to_vec(&value).unwrap(), Environment::stogas())
}

fn unix_ms(value: &Value, pointer: &str) -> i64 {
    DateTime::parse_from_rfc3339(value.pointer(pointer).unwrap().as_str().unwrap())
        .unwrap()
        .timestamp_millis()
}

#[test]
fn admits_only_a_complete_cryptographically_valid_amd_stack() {
    let value = fixture();
    let now = unix_ms(&value, "/body/vendor_collateral/0/fetched_at");
    let request = serde_json::json!({
        "chip_id": value["body"]["nodes"][0]["chip_id"],
        "reported_tcb": value["body"]["nodes"][0]["reported_tcb"],
        "vendor_collateral": value["body"]["vendor_collateral"],
    });
    let verified = verify_amd_collateral_admission(
        &serde_json::to_vec(&request).unwrap(),
        now,
        now + 24 * 60 * 60 * 1000,
    )
    .unwrap();
    assert_eq!(verified.sha256.len(), 4);

    let mut corrupted = request;
    corrupted["vendor_collateral"].as_array_mut().unwrap().pop();
    assert!(
        verify_amd_collateral_admission(
            &serde_json::to_vec(&corrupted).unwrap(),
            now,
            now + 24 * 60 * 60 * 1000,
        )
        .unwrap_err()
        .to_string()
        .contains("exactly ARK, ASK, CRL, and VCEK")
    );
}

fn corrupt_collateral_der(value: &mut Value, collateral_type: &str) {
    let rows = value
        .pointer_mut("/body/vendor_collateral")
        .and_then(Value::as_array_mut)
        .unwrap();
    let row = rows
        .iter_mut()
        .find(|row| row["collateral_type"] == collateral_type)
        .unwrap();
    let mut der = URL_SAFE_NO_PAD
        .decode(row["payload"]["der_base64url"].as_str().unwrap())
        .unwrap();
    *der.last_mut().unwrap() ^= 1;
    let digest = hex::encode(Sha256::digest(&der));
    row["payload"]["der_base64url"] = Value::String(URL_SAFE_NO_PAD.encode(&der));
    row["payload"]["sha256"] = Value::String(digest.clone());
    row["sha256"] = Value::String(digest);
}

fn corrupt_quote_byte(value: &mut Value, offset: usize, mask: u8) {
    let encoded = value["body"]["nodes"][0]["quote"].as_str().unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    let mut report = URL_SAFE_NO_PAD
        .decode(envelope["report"].as_str().unwrap())
        .unwrap();
    report[offset] ^= mask;
    envelope["report"] = Value::String(URL_SAFE_NO_PAD.encode(report));
    value["body"]["nodes"][0]["quote"] =
        Value::String(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap()));
}

#[test]
fn verifies_real_staging_evidence_under_the_bundle_wide_freshness_invariant() {
    let (bundle, environment) = checksummed_fixture(fixture());
    let mut verifier = Verifier::default();
    let output = verifier
        .verify_bundle(&bundle, VERIFIED_AT_UNIX_MS, &environment)
        .expect("real staging bundle must pass every release, SNP, certificate, drand, and policy check");

    assert_eq!(output.bundle.sequence, 1_927);
    assert_eq!(output.bundle.releases.len(), 1);
    let release = &output.bundle.releases[0];
    assert_eq!(release.release_tag, "v0.0.1");
    assert_eq!(release.sequence, 1);
    assert_eq!(release.vcpu_count, 4);
    assert_eq!(release.launch.policy, "0x0000000000030000");
    assert_eq!(release.launch.vmpl, 0);
    assert_eq!(
        release.source_tree,
        "3d2e5aca18d9fea4da80731d88bfb3e054f9ff2a"
    );
    assert_eq!(release.stogas_signing_key_id, "stogas-ed25519-stamp-v1");
    assert_eq!(release.launch_policy_sha256.len(), 64);
    assert!(
        release
            .github_integrated_time_unix_ms
            .is_some_and(|time| time > 0)
    );
    assert!(matches!(
        release.provenance,
        stogas_verifier::ReleaseProvenance::Github
    ));
    assert_eq!(output.bundle.nodes.len(), 1);
    assert!(output.bundle.excluded_nodes.is_empty());
    assert_eq!(
        output.bundle.nodes[0].node_id,
        "bac54c87fdabb100322d57f0d3bf71ab5b1152ec0c4f2c8bfd16e896f2fc64bd"
    );
    assert_eq!(output.bundle.nodes[0].drand_round, 30_536_903);
}

#[test]
fn rejects_a_mutated_bundle_without_poisoning_the_release_cache() {
    let (bundle, environment) = checksummed_fixture(fixture());
    let mut verifier = Verifier::default();
    verifier
        .verify_bundle(&bundle, VERIFIED_AT_UNIX_MS, &environment)
        .expect("fixture must establish the release cache");
    let mut mutated = bundle.clone();
    let position = mutated
        .windows(b"bac54c87".len())
        .position(|window| window == b"bac54c87")
        .expect("fixture node id");
    mutated[position] = b'c';

    assert!(
        verifier
            .verify_bundle(&mutated, VERIFIED_AT_UNIX_MS, &environment,)
            .is_err()
    );

    let retry = verifier
        .verify_bundle(&bundle, VERIFIED_AT_UNIX_MS, &environment)
        .expect("failed verification must not poison the release cache");
    assert_eq!(retry.bundle.sequence, 1_927);
}

#[test]
fn rejects_resigned_mutations_at_every_node_trust_boundary() {
    let mutations: [(&str, Value, &str); 4] = [
        (
            "/body/nodes/0/report_data/catalog_hash",
            Value::String("00".repeat(32)),
            "report-data hash differs",
        ),
        (
            "/body/nodes/0/release_measurement",
            Value::String("00".repeat(48)),
            "release measurement",
        ),
        (
            "/body/nodes/0/chip_id",
            Value::String("00".repeat(64)),
            "no exact AMD VCEK evidence",
        ),
        (
            "/body/nodes/0/cert_expires_at",
            Value::String("2026-07-18T17:09:00.000Z".into()),
            "bundle outlives",
        ),
    ];
    for (pointer, replacement, expected) in mutations {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let (bytes, environment) = checksummed_fixture(value);
        let error = Verifier::default()
            .verify_bundle(&bytes, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(expected),
            "mutation {pointer} failed at the wrong boundary: {error}"
        );
    }

    let mut legacy = fixture();
    legacy["body"]["nodes"][0]["quote_verifier_jwt"] = Value::String("untrusted.jwt".into());
    let (bytes, environment) = checksummed_fixture(legacy);
    assert!(
        Verifier::default()
            .verify_bundle(&bytes, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string()
            .contains("unknown field")
    );
}

#[test]
fn rejects_corrupted_amd_chain_and_revocation_material_after_valid_resigning() {
    for collateral_type in ["ark", "ask", "vcek", "crl"] {
        let mut value = fixture();
        corrupt_collateral_der(&mut value, collateral_type);
        let (bytes, environment) = checksummed_fixture(value);
        let error = Verifier::default()
            .verify_bundle(&bytes, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("AMD") || error.contains("SNP signature"),
            "corrupted {collateral_type} failed at the wrong boundary: {error}"
        );
    }
}

#[test]
fn rejects_every_raw_snp_report_binding_after_valid_resigning() {
    let bindings = [
        (0x08, 1, "guest policy"),
        (0x10, 1, "family id"),
        (0x20, 1, "image id"),
        (0x30, 1, "VMPL"),
        (0x34, 1, "signature algorithm"),
        (0x48, 2, "masked chip key flag"),
        (0x50, 1, "report data"),
        (0x90, 1, "measurement"),
        (0xc0, 1, "host data"),
        (0xe0, 1, "id key digest"),
        (0x110, 1, "author key digest"),
        (0x180, 1, "reported TCB"),
        (0x1a0, 1, "chip id"),
    ];
    for (offset, mask, expected) in bindings {
        let mut value = fixture();
        corrupt_quote_byte(&mut value, offset, mask);
        let (bytes, environment) = checksummed_fixture(value);
        let error = Verifier::default()
            .verify_bundle(&bytes, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(expected),
            "SNP report mutation at {offset:#x} failed at the wrong boundary: {error}"
        );
    }
}

#[test]
fn enforces_bundle_time_and_resource_policy() {
    let (bundle, environment) = checksummed_fixture(fixture());
    let value: Value = serde_json::from_slice(&bundle).unwrap();
    let expires_at = unix_ms(&value, "/body/expires_at");
    assert!(
        Verifier::default()
            .verify_bundle(&bundle, expires_at, &environment)
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
    assert!(matches!(
        Verifier::default().verify_bundle(
            &vec![b' '; MAX_INPUT_BYTES + 1],
            VERIFIED_AT_UNIX_MS,
            &Environment::stogas(),
        ),
        Err(stogas_verifier::Error::TooLarge)
    ));

    let mut too_many_nodes = fixture();
    let node = too_many_nodes["body"]["nodes"][0].clone();
    too_many_nodes["body"]["nodes"] = Value::Array(vec![node; 1_025]);
    let (bytes, environment) = checksummed_fixture(too_many_nodes);
    assert!(
        Verifier::default()
            .verify_bundle(&bytes, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string()
            .contains("resource limit")
    );

    let mut too_long = fixture();
    let created_at = unix_ms(&too_long, "/body/created_at");
    too_long["body"]["expires_at"] = Value::String(
        DateTime::from_timestamp_millis(created_at + 900_001)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );
    too_long["body"]["ttl_ms"] = Value::from(900_001);
    let (too_long, environment) = checksummed_fixture(too_long);
    assert!(
        Verifier::default()
            .verify_bundle(&too_long, VERIFIED_AT_UNIX_MS, &environment)
            .unwrap_err()
            .to_string()
            .contains("exceeds the 900000 ms policy")
    );
}

#[test]
fn stricter_callers_exclude_nodes_that_were_stale_at_bundle_creation() {
    let mut value = fixture();
    let created_at = unix_ms(&value, "/body/created_at") + 61_000;
    value["body"]["created_at"] = Value::String(
        DateTime::from_timestamp_millis(created_at)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );
    value["body"]["ttl_ms"] = Value::from(unix_ms(&value, "/body/expires_at") - created_at);
    let (bundle, mut environment) = checksummed_fixture(value);
    environment.max_node_evidence_age_ms = 60_000;
    let output = Verifier::default()
        .verify_bundle(&bundle, created_at, &environment)
        .unwrap();
    assert!(output.bundle.nodes.is_empty());
    assert_eq!(output.bundle.excluded_nodes.len(), 1);
    assert!(
        output.bundle.excluded_nodes[0]
            .reason
            .contains("bundle was created")
    );
}

#[test]
fn extending_bundle_expiry_does_not_weaken_the_creation_time_freshness_policy() {
    let (bundle, environment) = checksummed_fixture(fixture());
    let baseline = Verifier::default()
        .verify_bundle(&bundle, VERIFIED_AT_UNIX_MS, &environment)
        .unwrap();
    assert_eq!(baseline.bundle.nodes.len(), 1);

    let mut extended: Value = serde_json::from_slice(&bundle).unwrap();
    let expires_at = unix_ms(&extended, "/body/expires_at");
    extended["body"]["expires_at"] = Value::String(
        DateTime::from_timestamp_millis(expires_at + 1)
            .unwrap()
            .to_rfc3339(),
    );
    extended["body"]["ttl_ms"] = Value::from(
        unix_ms(&extended, "/body/expires_at") - unix_ms(&extended, "/body/created_at"),
    );
    let (extended, environment) = checksummed_fixture(extended);
    let verified = Verifier::default()
        .verify_bundle(&extended, VERIFIED_AT_UNIX_MS, &environment)
        .unwrap();
    assert_eq!(verified.bundle.nodes.len(), 1);
    assert!(verified.bundle.excluded_nodes.is_empty());
}
