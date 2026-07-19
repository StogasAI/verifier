#![cfg(not(target_arch = "wasm32"))]

use serde_json::Value;
use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};

const IGVM_DIGEST: &str = "1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6";
const POLICY_DIGEST: &str = "8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008";
const NOW_UNIX_MS: i64 = 1_784_246_400_000;

fn policy() -> GithubPolicy {
    GithubPolicy {
        repository: "https://github.com/StogasAI/gateway".into(),
        workflow_identity: "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1".into(),
        source_ref: "refs/tags/v0.0.1".into(),
        source_commit: "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f".into(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        require_github_hosted: true,
    }
}

const fn subjects() -> [Subject<'static>; 2] {
    [
        Subject {
            name: "gateway.igvm",
            sha256: IGVM_DIGEST,
        },
        Subject {
            name: "gateway-launch-policy.json",
            sha256: POLICY_DIGEST,
        },
    ]
}

fn native_accepts(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(bundle) = Bundle::from_json(text) else {
        return false;
    };
    let Ok(root) = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT) else {
        return false;
    };
    let verifier = Verifier::new(&root);
    let verification_policy = VerificationPolicy::default()
        .require_identity(&policy().workflow_identity)
        .require_issuer("https://token.actions.githubusercontent.com");
    subjects().iter().all(|subject| {
        Sha256Hash::from_hex(subject.sha256).is_ok_and(|digest| {
            verifier
                .verify(digest, &bundle, &verification_policy)
                .is_ok()
        })
    })
}

fn flip(value: &mut Value, pointer: &str) {
    let original = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .expect("mutation pointer must be a string");
    let mut changed = original.to_owned();
    changed.replace_range(..1, if original.starts_with('A') { "B" } else { "A" });
    *value.pointer_mut(pointer).unwrap() = Value::String(changed);
}

#[test]
fn rustcrypto_matches_sigstore_rust_for_the_claimed_profile() {
    let fixture = include_bytes!("../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl");
    assert!(native_accepts(fixture));
    assert!(verify_github_attestation(fixture, &subjects(), &policy(), NOW_UNIX_MS).is_ok());

    let mutations = [
        "/dsseEnvelope/signatures/0/sig",
        "/dsseEnvelope/payload",
        "/verificationMaterial/certificate/rawBytes",
        "/verificationMaterial/tlogEntries/0/logId/keyId",
        "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
        "/verificationMaterial/tlogEntries/0/inclusionProof/hashes/0",
        "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
        "/verificationMaterial/tlogEntries/0/canonicalizedBody",
    ];
    for pointer in mutations {
        let mut value: Value = serde_json::from_slice(fixture).unwrap();
        flip(&mut value, pointer);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            !native_accepts(&bytes),
            "native verifier accepted {pointer}"
        );
        assert!(
            verify_github_attestation(&bytes, &subjects(), &policy(), NOW_UNIX_MS).is_err(),
            "RustCrypto verifier accepted {pointer}"
        );
    }
}
