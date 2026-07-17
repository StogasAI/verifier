use serde_json::Value;
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};

const IGVM_DIGEST: &str = "1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6";
const POLICY_DIGEST: &str = "8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008";

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

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl"
    ))
    .unwrap()
}

fn flip_string(value: &mut Value, pointer: &str) {
    let text = value
        .pointer_mut(pointer)
        .and_then(|item| item.as_str())
        .expect("fixture path must be a string");
    let replacement = if text.starts_with('A') { 'B' } else { 'A' };
    let mut changed = text.to_owned();
    changed.replace_range(..1, &replacement.to_string());
    *value.pointer_mut(pointer).unwrap() = Value::String(changed);
}

#[test]
fn verifies_real_gateway_release_attestation() {
    let bundle = include_bytes!("../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl");
    let result = verify_github_attestation(bundle, &subjects(), &policy()).unwrap();
    assert_eq!(result.subjects.len(), 2);
}

#[test]
fn rejects_every_mutated_sigstore_trust_boundary() {
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
        let mut value = fixture();
        flip_string(&mut value, pointer);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            verify_github_attestation(&bytes, &subjects(), &policy()).is_err(),
            "mutation at {pointer} was accepted"
        );
    }
}

#[test]
fn rejects_each_github_identity_and_provenance_mismatch() {
    let bytes = include_bytes!("../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl");
    let policies = [
        GithubPolicy {
            repository: "https://github.com/StogasAI/not-gateway".into(),
            ..policy()
        },
        GithubPolicy {
            workflow_identity:
                "https://github.com/StogasAI/gateway/.github/workflows/other.yml@refs/tags/v0.0.1"
                    .into(),
            ..policy()
        },
        GithubPolicy {
            source_ref: "refs/heads/main".into(),
            ..policy()
        },
        GithubPolicy {
            source_commit: "0000000000000000000000000000000000000000".into(),
            ..policy()
        },
        GithubPolicy {
            predicate_type: "https://example.invalid/predicate".into(),
            ..policy()
        },
    ];

    for changed_policy in policies {
        assert!(verify_github_attestation(bytes, &subjects(), &changed_policy).is_err());
    }
}
