use super::*;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use serde_json::{Value, json};

const ARTIFACT: &[u8] = b"exact document bytes, including its independent author signature\n";
const NOW: i64 = 1_790_000_000_000;

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[33; 32])
}

fn root() -> TrustedRoot {
    let spki = log_key().verifying_key().to_public_key_der().unwrap();
    TrustedRoot::test_root(
        &json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": [],
            "tlogs": [{
                "baseUrl": "https://rekor.sigstore.dev", "hashAlgorithm": "SHA2_256",
                "publicKey": {"rawBytes":STANDARD.encode(&spki), "keyDetails":"PKIX_ED25519"},
                "logId": {"keyId":STANDARD.encode(Sha256::digest(&spki))}
            }]
        })
        .to_string(),
    )
    .unwrap()
}

/// Sign the one-leaf test log independently of the document submission signature.
fn seal_body(bundle: &mut Value, body: &Value) {
    let body = serde_json_canonicalizer::to_vec(body).unwrap();
    let log = log_key();
    let spki = log.verifying_key().to_public_key_der().unwrap();
    let id = Sha256::digest(&spki);
    let root = Sha256::digest([&[0][..], body.as_slice()].concat());
    let checkpoint = format!("rekor.sigstore.dev - 1\n1\n{}\n", STANDARD.encode(root));
    let checkpoint_signature = log.sign(checkpoint.as_bytes());
    let checkpoint = format!(
        "{checkpoint}\n— rekor.sigstore.dev {}\n",
        STANDARD.encode([&id[..4], checkpoint_signature.to_bytes().as_slice()].concat())
    );
    let set = serde_json_canonicalizer::to_vec(&json!({
        "body": STANDARD.encode(&body), "integratedTime": NOW / 1000,
        "logID": hex::encode(id), "logIndex":0
    }))
    .unwrap();
    bundle["verificationMaterial"]["tlogEntries"] = json!([{
        "logIndex":"0", "logId":{"keyId":STANDARD.encode(id)},
        "kindVersion":{"kind":"hashedrekord","version":"0.0.1"},
        "integratedTime": (NOW / 1000).to_string(),
        "canonicalizedBody":STANDARD.encode(&body),
        "inclusionPromise":{"signedEntryTimestamp":STANDARD.encode(log.sign(&set).to_bytes())},
        "inclusionProof":{"logIndex":"0","rootHash":STANDARD.encode(root),"treeSize":"1",
            "hashes":[], "checkpoint":{"envelope":checkpoint}}
    }]);
}

fn fixture(seed: u8) -> (Value, Value) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let signature = key
        .sign_prehashed(Sha512::new_with_prefix(ARTIFACT), None)
        .unwrap();
    let public_key = pem::encode(&pem::Pem::new("PUBLIC KEY", spki.as_bytes()));
    let body = json!({"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
        "data":{"hash":{"algorithm":"sha512","value":hex::encode(Sha512::digest(ARTIFACT))}},
        "signature":{"content":STANDARD.encode(signature.to_bytes()),
            "publicKey":{"content":STANDARD.encode(public_key)}}
    }});
    let mut bundle = json!({
        "mediaType":crate::SIGSTORE_BUNDLE_MEDIA_TYPE,
        "messageSignature":{
            "messageDigest":{"algorithm":"SHA2_512","digest":STANDARD.encode(Sha512::digest(ARTIFACT))},
            "signature":STANDARD.encode(signature.to_bytes())
        },
        "verificationMaterial":{
            "publicKey":{"hint":hex::encode(Sha256::digest(&spki))},
            "timestampVerificationData":{}, "tlogEntries":[]
        }
    });
    seal_body(&mut bundle, &body);
    (bundle, body)
}

#[test]
fn proves_exact_publication_with_different_temporary_keys_but_never_trusts_a_supplied_log() {
    // Qualify the fuzz seed's independently generated Go submission signature.
    // A valid artifact binding still cannot authenticate its synthetic log proof.
    let seed: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-document-v1.json"
    ))
    .unwrap();
    let artifact = seed["artifact"].as_str().unwrap().as_bytes();
    let parsed: Bundle = serde_json::from_value(seed["bundle"].clone()).unwrap();
    verify_binding(&parsed, artifact).unwrap();
    assert!(
        crate::verify_rekor_document_inclusion(
            &serde_json::to_vec(&seed["bundle"]).unwrap(),
            artifact,
            NOW
        )
        .is_err()
    );
    for seed in [8, 9] {
        let (bundle, _) = fixture(seed);
        assert_eq!(
            verify_with_root(&bundle, ARTIFACT, NOW, &root()).unwrap(),
            NOW / 1000
        );
        assert!(verify_with_root(&bundle, b"substituted document", NOW, &root()).is_err());
        assert!(verify_with_root(&bundle, ARTIFACT, NOW - 61_000, &root()).is_err());
        assert!(
            crate::verify_rekor_document_inclusion(
                &serde_json::to_vec(&bundle).unwrap(),
                ARTIFACT,
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_mutated_log_proofs_bundle_hints_and_ambiguous_formats() {
    let (original, _) = fixture(9);
    for (pointer, replacement) in [
        (
            "/mediaType",
            json!("application/vnd.dev.sigstore.bundle.v0.2+json"),
        ),
        (
            "/messageSignature/messageDigest/algorithm",
            json!("SHA2_256"),
        ),
        (
            "/messageSignature/messageDigest/digest",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/messageSignature/signature",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/verificationMaterial/publicKey/hint",
            json!("a".repeat(64)),
        ),
        (
            "/verificationMaterial/tlogEntries/0/kindVersion/kind",
            json!("dsse"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/integratedTime",
            json!("1"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
            json!(STANDARD.encode([0; 32])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/hashes",
            json!([STANDARD.encode([0; 32])]),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
            json!("bad checkpoint"),
        ),
        ("/verificationMaterial/tlogEntries", json!([])),
    ] {
        let mut bundle = original.clone();
        *bundle.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            verify_with_root(&bundle, ARTIFACT, NOW, &root()).is_err(),
            "{pointer}"
        );
    }
    let mut bundle = original.clone();
    bundle["verificationMaterial"]["tlogEntries"]
        .as_array_mut()
        .unwrap()
        .push(original["verificationMaterial"]["tlogEntries"][0].clone());
    assert!(verify_with_root(&bundle, ARTIFACT, NOW, &root()).is_err());
    bundle = original;
    bundle["dsseEnvelope"] = json!({});
    assert!(verify_with_root(&bundle, ARTIFACT, NOW, &root()).is_err());
}

#[test]
fn even_a_valid_log_cannot_substitute_the_artifact_hash_key_or_signature() {
    let (original, body) = fixture(9);
    for (pointer, replacement) in [
        ("/apiVersion", json!("0.0.2")),
        ("/kind", json!("rekord")),
        ("/spec/data/hash/algorithm", json!("sha256")),
        ("/spec/data/hash/value", json!("a".repeat(128))),
        ("/spec/signature/content", json!(STANDARD.encode([0; 64]))),
        (
            "/spec/signature/publicKey/content",
            json!(STANDARD.encode("bad public key")),
        ),
    ] {
        let mut changed = body.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let mut bundle = original.clone();
        seal_body(&mut bundle, &changed);
        assert!(
            verify_with_root(&bundle, ARTIFACT, NOW, &root()).is_err(),
            "{pointer}"
        );
    }
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut changed = body;
    // Plain Ed25519 over a SHA-512 digest is not Ed25519ph.
    let wrong = STANDARD.encode(key.sign(&Sha512::digest(ARTIFACT)).to_bytes());
    changed["spec"]["signature"]["content"] = json!(wrong);
    let mut bundle = original;
    bundle["messageSignature"]["signature"] = json!(wrong);
    seal_body(&mut bundle, &changed);
    assert!(verify_with_root(&bundle, ARTIFACT, NOW, &root()).is_err());
}

#[test]
fn bounds_outer_input_and_rejects_duplicate_fields() {
    assert!(matches!(
        crate::verify_rekor_document_inclusion(b"{}", &vec![0; crate::MAX_DOCUMENT_BYTES + 1], NOW),
        Err(crate::Error::TooLarge)
    ));
    for input in [
        br#"{"mediaType":"x","mediaType":"y"}"#.as_slice(),
        &vec![b' '; crate::MAX_BUNDLE_BYTES + 1],
    ] {
        assert!(crate::verify_rekor_document_inclusion(input, ARTIFACT, NOW).is_err());
    }
}
