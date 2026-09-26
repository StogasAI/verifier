use super::*;
use crate::tests::take_json;
#[cfg(feature = "staging")]
use serde_json::{Value, json};
use std::ptr;

#[test]
fn output_handles_are_cleared_and_inputs_bounded_before_reading() {
    // SAFETY: null inputs deliberately exercise ABI checks; output is a writable local pointer.
    unsafe {
        let mut handle = ptr::dangling_mut();
        let failed = take_json(stogas_evidence_new(ptr::null(), 4097, &raw mut handle));
        assert_eq!(failed["code"], "invalid_operation");
        assert!(handle.is_null());
        assert!(
            !take_json(stogas_evidence_new(ptr::null(), 0, ptr::null_mut()))["ok"]
                .as_bool()
                .unwrap()
        );
        let mut snapshot = ptr::dangling_mut();
        assert_eq!(
            take_json(stogas_evidence_refresh(
                ptr::null(),
                ptr::null(),
                0,
                1,
                &raw mut snapshot
            ))["code"],
            "invalid_operation"
        );
        assert!(snapshot.is_null());
        assert_eq!(
            take_json(stogas_evidence_verify_logged_boot(
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                1
            ))["code"],
            "invalid_operation"
        );
        assert_eq!(
            take_json(stogas_evidence_verify_receipt(
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                1
            ))["code"],
            "invalid_operation"
        );
        stogas_evidence_free(ptr::null_mut());
        stogas_evidence_snapshot_free(ptr::null_mut());
    }
}

#[test]
fn compiled_authorities_never_substitute_another_environment() {
    let configuration = br#"{"environment":"prod"}"#;
    let mut handle = ptr::null_mut();
    // SAFETY: configuration is live, output writable, and failed construction returns no handle.
    let failure = unsafe {
        take_json(stogas_evidence_new(
            configuration.as_ptr(),
            configuration.len(),
            &raw mut handle,
        ))
    };
    assert_eq!(failure["ok"], false);
    assert!(handle.is_null());
}

#[cfg(feature = "staging")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep one ABI ownership lifecycle and its matching frees together."
)]
fn real_boot_verifies_and_snapshot_outlives_refresh_and_verifier() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use stogas_verifier::attestation::certificate::ParsedNativeCertificate;
    let fixture = hardware_fixture();
    let configuration =
        serde_json::to_vec(&json!({"environment":"staging", "root":fixture["root"]})).unwrap();
    let bundle = serde_json::to_vec(&fixture["bundle"]).unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
    let boot: Value = serde_json::from_slice(parsed.evidence.boot_document).unwrap();
    let challenge = hex::decode(
        boot["report_data"]["registration_challenge"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut handle = ptr::null_mut();
    let mut snapshot = ptr::null_mut();
    // SAFETY: every slice and handle remains live through the call; handles are freed once below.
    unsafe {
        assert_eq!(
            take_json(stogas_evidence_new(
                configuration.as_ptr(),
                configuration.len(),
                &raw mut handle
            ))["ok"],
            true
        );
        let refreshed = take_json(stogas_evidence_refresh(
            handle,
            bundle.as_ptr(),
            bundle.len(),
            now,
            &raw mut snapshot,
        ));
        assert_eq!(refreshed["ok"], true, "{refreshed}");
        assert!(
            !refreshed["value"]["gateways"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let evidence = parsed.evidence;
        let registered = take_json(stogas_evidence_verify_registration(
            snapshot,
            evidence.boot_document.as_ptr(),
            evidence.boot_document.len(),
            challenge.as_ptr(),
            challenge.len(),
            now,
        ));
        assert_eq!(registered["ok"], true, "{registered}");
        let mut rejected = ptr::dangling_mut();
        assert_eq!(
            take_json(stogas_evidence_refresh(
                handle,
                b"{}".as_ptr(),
                2,
                now,
                &raw mut rejected
            ))["ok"],
            false
        );
        assert!(rejected.is_null());
        let archive = serde_json::to_vec(&json!({
            "boot": boot,
            "inclusion": serde_json::from_slice::<Value>(evidence.boot_inclusion).unwrap(),
            "evidence_sha256": fixture["bundle"]["body_sha256"]
        }))
        .unwrap();
        let later = now + 366 * 24 * 60 * 60 * 1000;
        let archived = take_json(stogas_evidence_verify_boot_archive(
            handle,
            archive.as_ptr(),
            archive.len(),
            bundle.as_ptr(),
            bundle.len(),
            later,
        ));
        assert_eq!(archived["ok"], true, "{archived}");
        assert_eq!(archived["value"]["node_id"], registered["value"]["node_id"]);
        assert!(Arc::ptr_eq(
            (*handle).core.lock().unwrap().current().unwrap(),
            &(*snapshot).core,
        ));
        assert_eq!(
            take_json(stogas_evidence_verify_archive(
                handle,
                bundle.as_ptr(),
                bundle.len(),
                later
            ))["ok"],
            true
        );
        assert_eq!(
            take_json(stogas_evidence_verify_boot_archive(
                handle,
                ptr::null(),
                evidence::MAX_ARCHIVE_BYTES + 1,
                bundle.as_ptr(),
                bundle.len(),
                later
            ))["code"],
            "invalid_operation"
        );
        assert_eq!(
            take_json(stogas_evidence_verify_archive(
                handle,
                ptr::null(),
                stogas_verifier::MAX_INPUT_BYTES + 1,
                later
            ))["code"],
            "invalid_operation"
        );
        assert_eq!(
            take_json(stogas_evidence_verify_receipt_archive(
                handle,
                archive.as_ptr(),
                archive.len(),
                bundle.as_ptr(),
                bundle.len(),
                ptr::null(),
                0,
                ptr::null(),
                33,
                ptr::null(),
                0,
                later
            ))["code"],
            "invalid_operation"
        );
        stogas_evidence_free(handle);
        let logged = take_json(stogas_evidence_verify_logged_boot(
            snapshot,
            evidence.boot_document.as_ptr(),
            evidence.boot_document.len(),
            evidence.boot_inclusion.as_ptr(),
            evidence.boot_inclusion.len(),
            now,
        ));
        assert_eq!(logged["ok"], true, "{logged}");
        assert_eq!(logged["value"]["node_id"], registered["value"]["node_id"]);
        assert!(logged["value"]["integrated_time_unix_ms"].as_i64().unwrap() <= now);
        let expired = logged["value"]["valid_until_unix_ms"].as_i64().unwrap();
        assert_eq!(
            take_json(stogas_evidence_verify_logged_boot(
                snapshot,
                evidence.boot_document.as_ptr(),
                evidence.boot_document.len(),
                evidence.boot_inclusion.as_ptr(),
                evidence.boot_inclusion.len(),
                expired
            ))["code"],
            "expired_collateral"
        );
        assert_eq!(
            take_json(stogas_evidence_verify_registration(
                snapshot,
                evidence.boot_document.as_ptr(),
                evidence.boot_document.len(),
                challenge.as_ptr(),
                31,
                now
            ))["code"],
            "invalid_operation"
        );
        // Oversized lengths and short hashes fail before dereferencing their contents.
        for (receipt_len, hash_len) in [(stogas_verifier::receipt::MAX_BYTES + 1, 32), (0, 33)] {
            assert_eq!(
                take_json(stogas_evidence_verify_receipt(
                    snapshot,
                    evidence.boot_document.as_ptr(),
                    evidence.boot_document.len(),
                    evidence.boot_inclusion.as_ptr(),
                    evidence.boot_inclusion.len(),
                    ptr::null(),
                    receipt_len,
                    ptr::null(),
                    hash_len,
                    ptr::null(),
                    0,
                    now
                ))["code"],
                "invalid_operation"
            );
        }
        stogas_evidence_snapshot_free(snapshot);
    }
}

#[cfg(feature = "staging")]
fn hardware_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap()
}
