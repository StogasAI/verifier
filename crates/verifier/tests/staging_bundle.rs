use chrono::DateTime;
use serde_json::Value;
use stogas_verifier::{Environment, Verifier, verify_amd_collateral_admission};

const LEGACY_BUNDLE: &[u8] = include_bytes!("fixtures/staging-bundle-sequence-1927.json");
const VERIFIED_AT_UNIX_MS: i64 = 1_784_414_117_082;

fn fixture() -> Value {
    serde_json::from_slice(LEGACY_BUNDLE).expect("historical staging bundle fixture")
}

#[test]
fn rejects_legacy_bundle_shape() {
    assert!(
        Verifier::default()
            .verify_bundle(LEGACY_BUNDLE, VERIFIED_AT_UNIX_MS, &Environment::stogas())
            .is_err()
    );
}

#[test]
fn historical_fixture_still_exercises_the_complete_amd_collateral_stack() {
    let value = fixture();
    let fetched_at = value["body"]["vendor_collateral"][0]["fetched_at"]
        .as_str()
        .unwrap();
    let now = DateTime::parse_from_rfc3339(fetched_at)
        .unwrap()
        .timestamp_millis();
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
}
