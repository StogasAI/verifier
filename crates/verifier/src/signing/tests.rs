use super::*;
use serde::Deserialize;
use spki::der::asn1::AnyRef;

#[derive(Deserialize)]
struct Vector {
    seed: String,
    pkcs8: String,
    public_key: String,
    spki: String,
    message: String,
    signature: String,
    context: String,
    context_signature: String,
    rekor_spki: String,
    rekor_signature: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("../../../../tests/fixtures/mldsa65-v1.json")).unwrap()
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

#[test]
fn matches_independent_go_keys_signatures_and_standard_spki() {
    let v = vector();
    let key = SigningKey::from_seed(&bytes(&v.seed).try_into().unwrap());
    assert_eq!(key.public_key().as_slice(), bytes(&v.public_key));
    assert_eq!(
        SigningKey::from_pkcs8(&bytes(&v.pkcs8))
            .unwrap()
            .public_key(),
        key.public_key()
    );
    assert_eq!(key.public_key_spki().unwrap(), bytes(&v.spki));
    assert_eq!(key.rekor_public_key_spki().unwrap(), bytes(&v.rekor_spki));
    let submission: serde_json::Value =
        serde_json::from_str(&key.prepare_rekor_submission(&bytes(&v.message)).unwrap()).unwrap();
    assert_eq!(
        STANDARD
            .decode(submission["spec"]["signature"]["content"].as_str().unwrap())
            .unwrap(),
        bytes(&v.rekor_signature)
    );
    assert_eq!(
        public_key_from_spki(&bytes(&v.spki)).unwrap(),
        key.public_key()
    );
    for (context, expected) in [
        ("", &v.signature),
        (v.context.as_str(), &v.context_signature),
    ] {
        let message = bytes(&v.message);
        let signature = key
            .sign_with_randomness(&message, context.as_bytes(), &[0; 32])
            .unwrap();
        assert_eq!(signature.as_slice(), bytes(expected));
        verify(key.public_key(), &message, context.as_bytes(), &signature).unwrap();
    }
}

#[test]
fn rejects_message_context_key_signature_and_length_substitution() {
    let v = vector();
    let public = bytes(&v.public_key);
    let message = bytes(&v.message);
    let signature = bytes(&v.signature);
    assert!(verify(&public, b"another document", b"", &signature).is_err());
    assert!(verify(&public, &message, v.context.as_bytes(), &signature).is_err());
    let other = SigningKey::from_seed(&[43; SEED_BYTES]);
    assert!(verify(other.public_key(), &message, b"", &signature).is_err());
    for offset in [0, 31, 48, 64, 1000, 3290, SIGNATURE_BYTES - 1] {
        let mut changed = signature.clone();
        changed[offset] ^= 1;
        assert!(verify(&public, &message, b"", &changed).is_err());
    }
    let mut changed = public.clone();
    changed[PUBLIC_KEY_BYTES - 1] ^= 1;
    assert!(verify(&changed, &message, b"", &signature).is_err());
    for key in [
        &[][..],
        &public[..PUBLIC_KEY_BYTES - 1],
        &[0; PUBLIC_KEY_BYTES + 1],
    ] {
        assert!(matches!(
            verify(key, &message, b"", &signature),
            Err(Error::Length)
        ));
    }
    for sig in [
        &[][..],
        &signature[..SIGNATURE_BYTES - 1],
        &[0; SIGNATURE_BYTES + 1],
    ] {
        assert!(matches!(
            verify(&public, &message, b"", sig),
            Err(Error::Length)
        ));
    }
}

#[test]
fn randomized_signatures_and_context_boundaries_verify() {
    let key = SigningKey::from_seed(&[7; SEED_BYTES]);
    let context = [3; 255];
    let first = key.sign(b"", &context).unwrap();
    let second = key.sign(b"", &context).unwrap();
    assert_ne!(first, second);
    verify(key.public_key(), b"", &context, &first).unwrap();
    verify(key.public_key(), b"", &context, &second).unwrap();
    assert!(matches!(key.sign(b"", &[3; 256]), Err(Error::Context)));
    assert!(matches!(
        verify(key.public_key(), b"", &[3; 256], &first),
        Err(Error::Context)
    ));
}

#[test]
fn rejects_spki_parameters_other_algorithms_trailing_bytes_and_wrong_lengths() {
    let v = vector();
    let encoded = bytes(&v.spki);
    let mut spki = SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();
    spki.algorithm.parameters = Some(AnyRef::NULL);
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    spki.algorithm.parameters = None;
    spki.algorithm.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    spki.algorithm.oid = ML_DSA_65_OID;
    spki.subject_public_key = spki::der::asn1::BitStringRef::from_bytes(&[0; 32]).unwrap();
    assert!(public_key_from_spki(&spki.to_der().unwrap()).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(public_key_from_spki(&trailing).is_err());
    assert!(public_key_from_spki(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn private_keys_accept_only_unambiguous_seed_encoding() {
    let v = vector();
    let encoded = bytes(&v.pkcs8);
    let mut info = pkcs8::PrivateKeyInfo::from_der(&encoded).unwrap();
    info.algorithm.parameters = Some(AnyRef::NULL);
    assert!(SigningKey::from_pkcs8(&info.to_der().unwrap()).is_err());
    info.algorithm.parameters = None;
    info.algorithm.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
    assert!(SigningKey::from_pkcs8(&info.to_der().unwrap()).is_err());
    for value in [
        vec![0; PRIVATE_KEY_BYTES],
        vec![0x80, 0x20],
        vec![0x04, 0x20],
        vec![0x80; 34],
    ] {
        let mut info = pkcs8::PrivateKeyInfo::from_der(&encoded).unwrap();
        info.private_key = &value;
        assert!(SigningKey::from_pkcs8(&info.to_der().unwrap()).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(SigningKey::from_pkcs8(&trailing).is_err());
}

#[test]
fn derived_rekor_key_signs_only_the_complete_document_digest() {
    use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey as _};
    // Exercise the composition with a real Stogas signature, including the exact
    // initial evidence reference. Logging only the quote or signature would lose
    // this binding even though each individual signature could still verify.
    let payload = serde_json::json!({
        "boot": serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../../tests/fixtures/node-boot-v1.json"
        )).unwrap()["record"],
        "evidence_sha256": "ab".repeat(32)
    });
    let message = crate::canonical_json(&payload).unwrap();
    let author = SigningKey::from_seed(&[17; SEED_BYTES]);
    let signature = author
        .sign(message.as_bytes(), b"publication-test")
        .unwrap();
    verify(
        author.public_key(),
        message.as_bytes(),
        b"publication-test",
        &signature,
    )
    .unwrap();
    let signed = serde_json::json!({"document": payload, "signature": STANDARD.encode(signature)});
    let document = crate::canonical_json(&signed).unwrap();
    let prepared = author
        .prepare_rekor_submission(document.as_bytes())
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&prepared).unwrap();
    assert_eq!(value["kind"], "hashedrekord");
    assert_eq!(value["spec"]["data"]["hash"]["algorithm"], "sha512");
    assert_eq!(
        value["spec"]["data"]["hash"]["value"],
        hex::encode(Sha512::digest(document.as_bytes()))
    );
    let public = String::from_utf8(
        STANDARD
            .decode(
                value["spec"]["signature"]["publicKey"]["content"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let der = STANDARD
        .decode(
            public
                .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
                .unwrap()
                .strip_suffix("\n-----END PUBLIC KEY-----\n")
                .unwrap(),
        )
        .unwrap();
    let key = VerifyingKey::from_public_key_der(&der).unwrap();
    let signature = Signature::from_slice(
        &STANDARD
            .decode(value["spec"]["signature"]["content"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    key.verify_prehashed_strict(
        Sha512::new_with_prefix(document.as_bytes()),
        None,
        &signature,
    )
    .unwrap();
    for pointer in [
        "/document/boot/report",
        "/document/evidence_sha256",
        "/signature",
    ] {
        let mut changed = signed.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!("altered");
        let changed = crate::canonical_json(&changed).unwrap();
        assert!(
            key.verify_prehashed_strict(
                Sha512::new_with_prefix(changed.as_bytes()),
                None,
                &signature
            )
            .is_err(),
            "accepted substitution at {pointer}"
        );
    }
    for partial in [
        message.as_bytes(),
        signed["signature"].as_str().unwrap().as_bytes(),
    ] {
        assert!(
            key.verify_prehashed_strict(Sha512::new_with_prefix(partial), None, &signature)
                .is_err()
        );
    }
}

#[test]
fn rekor_identity_is_stable_across_restarts_and_changes_only_with_the_author_key() {
    let author = SigningKey::from_seed(&[17; SEED_BYTES]);
    let document = "same signed document";
    let prepared = author
        .prepare_rekor_submission(document.as_bytes())
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&prepared).unwrap();
    // Reopening the same key preserves log identity and exact retry bytes.
    assert_eq!(
        prepared,
        SigningKey::from_seed(&[17; SEED_BYTES])
            .prepare_rekor_submission(document.as_bytes())
            .unwrap()
    );
    let rotated = SigningKey::from_seed(&[18; SEED_BYTES]);
    assert_ne!(
        author.rekor_public_key_spki().unwrap(),
        rotated.rekor_public_key_spki().unwrap()
    );
    assert_ne!(
        prepared,
        rotated
            .prepare_rekor_submission(document.as_bytes())
            .unwrap()
    );
    // The submission key must not reuse the ML-DSA seed directly as an Ed25519 seed.
    let unseparated = ed25519_dalek::SigningKey::from_bytes(&[17; SEED_BYTES]);
    assert_ne!(
        author.rekor_public_key_spki().unwrap(),
        unseparated
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
    );
    let next: serde_json::Value = serde_json::from_str(
        &author
            .prepare_rekor_submission(b"another signed document")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["spec"]["signature"]["publicKey"],
        next["spec"]["signature"]["publicKey"]
    );
    assert_ne!(
        value["spec"]["signature"]["content"],
        next["spec"]["signature"]["content"]
    );
    assert!(matches!(
        author.prepare_rekor_submission(&vec![0; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
}
