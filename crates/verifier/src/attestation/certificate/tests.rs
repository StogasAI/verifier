use super::*;
use crate::attestation::evidence::REPORT_BYTES;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    certificate: String,
    extension: String,
    signer_spki_sha256: String,
    boot_document: String,
    boot_inclusion: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/native-certificate-v1.json"
    ))
    .unwrap()
}

#[test]
fn go_certificate_decodes_and_binds_challenge_key_and_immutable_boot() {
    let v = vector();
    let der = URL_SAFE_NO_PAD.decode(v.certificate).unwrap();
    let parsed = ParsedNativeCertificate::parse(&der).unwrap();
    assert_eq!(hex::encode(parsed.signer_spki_sha256), v.signer_spki_sha256);
    assert_eq!(parsed.evidence.boot_document, v.boot_document.as_bytes());
    assert_eq!(parsed.evidence.boot_inclusion, v.boot_inclusion.as_bytes());
    assert!(parsed.valid_at(parsed.not_before_unix_ms).is_ok());
    assert!(parsed.valid_at(parsed.not_after_unix_ms - 1).is_ok());
    assert!(parsed.valid_at(parsed.not_before_unix_ms - 1).is_err());
    assert!(parsed.valid_at(parsed.not_after_unix_ms).is_err());
    let mut challenge = [0; 32];
    challenge[0] = 1;
    parsed
        .evidence
        .verify_channel_binding(
            Environment::Production,
            challenge,
            parsed.signer_spki_sha256,
        )
        .unwrap();
    challenge[0] ^= 1;
    assert!(
        parsed
            .evidence
            .verify_channel_binding(
                Environment::Production,
                challenge,
                parsed.signer_spki_sha256
            )
            .is_err()
    );
    challenge[0] ^= 1;
    let mut other_key = parsed.signer_spki_sha256;
    other_key[0] ^= 1;
    assert!(
        parsed
            .evidence
            .verify_channel_binding(Environment::Production, challenge, other_key)
            .is_err()
    );
    // This fixture carries an unsigned synthetic SNP report. Parsing and binding
    // intentionally do not call it verified hardware or verified boot inclusion.
}

#[test]
fn framing_rejects_all_truncations_trailing_bytes_and_length_overflows() {
    let extension = URL_SAFE_NO_PAD.decode(vector().extension).unwrap();
    for size in 0..extension.len() {
        assert!(
            SessionEvidence::from_extension(&extension[..size]).is_err(),
            "accepted truncation at {size}"
        );
    }
    let mut trailing = extension.clone();
    trailing.push(0);
    assert!(SessionEvidence::from_extension(&trailing).is_err());
    for index in 0..4 + 3 + MEDIA_TYPE.len() + 3 {
        let mut changed = extension.clone();
        changed[index] ^= 1;
        assert!(
            SessionEvidence::from_extension(&changed).is_err(),
            "accepted header mutation at {index}"
        );
    }
    let payload = 4 + 3 + MEDIA_TYPE.len() + 3;
    for (index, width) in [
        (payload + REPORT_BYTES, 2),
        (payload + REPORT_BYTES + 2 + 4, 4),
    ] {
        let mut changed = extension.clone();
        changed[index..index + width].fill(255);
        assert!(SessionEvidence::from_extension(&changed).is_err());
    }
    assert!(
        SessionEvidence::from_extension(&vec![0; MAX_EVIDENCE_BYTES + MEDIA_TYPE.len() + 11])
            .is_err()
    );
}

#[test]
fn altered_boot_and_report_are_not_valid_channel_bindings() {
    let extension = URL_SAFE_NO_PAD.decode(vector().extension).unwrap();
    let key: [u8; 32] = hex::decode(vector().signer_spki_sha256)
        .unwrap()
        .try_into()
        .unwrap();
    let mut challenge = [0; 32];
    challenge[0] = 1;
    let payload = 4 + 3 + MEDIA_TYPE.len() + 3;
    for index in [payload + 0x50, payload + REPORT_BYTES + 2 + 4 + 4] {
        let mut changed = extension.clone();
        changed[index] ^= 1;
        let parsed = SessionEvidence::from_extension(&changed).unwrap();
        assert!(
            parsed
                .verify_channel_binding(Environment::Production, challenge, key)
                .is_err()
        );
    }
}

#[test]
fn certificate_boundary_rejects_missing_extensions_and_trailing_der() {
    assert!(ParsedNativeCertificate::parse(&[]).is_err());
    assert!(ParsedNativeCertificate::parse(&vec![0; MAX_CERTIFICATE_BYTES + 1]).is_err());
    let mut der = URL_SAFE_NO_PAD.decode(vector().certificate).unwrap();
    der.push(0);
    assert!(ParsedNativeCertificate::parse(&der).is_err());
    der.pop();
    // The OID's DER body; alter the extension ID without changing certificate shape.
    let oid = [0x2b, 6, 1, 5, 5, 7, 1, 35];
    let at = der.windows(oid.len()).position(|v| v == oid).unwrap();
    der[at + oid.len() - 1] ^= 1;
    assert!(matches!(
        ParsedNativeCertificate::parse(&der),
        Err(Error::Extension)
    ));
}
