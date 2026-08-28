use chrono::DateTime;
use serde_json::Value;
use stogas_verifier::{Verifier, verify_amd_collateral_admission};

const LEGACY_BUNDLE: &[u8] = include_bytes!("fixtures/staging-bundle-sequence-1927.json");
const VERIFIED_AT_UNIX_MS: i64 = 1_784_414_117_082;

fn fixture() -> Value {
    serde_json::from_slice(LEGACY_BUNDLE).expect("historical staging bundle fixture")
}

fn amd_collateral_request() -> (Vec<u8>, i64) {
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
    (serde_json::to_vec(&request).unwrap(), now)
}

#[test]
fn rejects_legacy_bundle_shape() {
    assert!(
        Verifier::default()
            .verify_bundle(LEGACY_BUNDLE, VERIFIED_AT_UNIX_MS)
            .is_err()
    );
}

#[cfg(feature = "snp")]
#[test]
fn historical_fixture_still_exercises_the_complete_amd_collateral_stack() {
    let (request, now) = amd_collateral_request();
    let verified =
        verify_amd_collateral_admission(&request, now, now + 24 * 60 * 60 * 1000).unwrap();
    assert_eq!(verified.sha256.len(), 4);
}

#[cfg(not(feature = "snp"))]
#[test]
fn historical_fixture_fails_closed_without_snp_support() {
    let (request, now) = amd_collateral_request();
    let error =
        verify_amd_collateral_admission(&request, now, now + 24 * 60 * 60 * 1000).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("AMD SNP verification is unavailable")
    );
}
