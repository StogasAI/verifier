#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/gateway-v0.0.1-attestation.jsonl");
const NOW_UNIX_MS: i64 = 1_784_246_400_000;
static DOCUMENT: LazyLock<(Vec<u8>, Vec<u8>)> = LazyLock::new(|| {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/rekor-document-v1.json")).unwrap();
    (
        serde_json::to_vec(&fixture["bundle"]).unwrap(),
        fixture["artifact"].as_str().unwrap().as_bytes().to_vec(),
    )
});

fuzz_target!(|data: &[u8]| {
    if data.first() == Some(&b'H') {
        // The GitHub DSSE seed cannot reach hashedrekord's key/digest parser.
        // Start with a valid independently generated submission binding instead;
        // the synthetic log proof itself must never establish trust.
        let candidate = mutate_fixture(&DOCUMENT.0, &data[1..]);
        let _ = stogas_offline_sigstore::verify_rekor_document_inclusion(
            &candidate,
            &DOCUMENT.1,
            NOW_UNIX_MS,
        );
        return;
    }
    let candidate = mutate_fixture_or_raw(FIXTURE, data);
    let subjects = [
        Subject {
            name: "gateway.igvm",
            sha256: "1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6",
        },
        Subject {
            name: "gateway-launch-policy.json",
            sha256: "8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008",
        },
    ];
    let policy = GithubPolicy {
        repository: "https://github.com/StogasAI/gateway".into(),
        workflow_identity: "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1".into(),
        source_ref: "refs/tags/v0.0.1".into(),
        source_commit: "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f".into(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        require_github_hosted: true,
    };
    let _ = verify_github_attestation(&candidate, &subjects, &policy, NOW_UNIX_MS);
    let _ = stogas_offline_sigstore::verify_rekor_document_inclusion(&candidate, data, NOW_UNIX_MS);
});

fn mutate_fixture_or_raw(fixture: &[u8], data: &[u8]) -> Vec<u8> {
    if data.first() != Some(&b'S') {
        return data.to_vec();
    }
    mutate_fixture(fixture, &data[1..])
}

fn mutate_fixture(fixture: &[u8], data: &[u8]) -> Vec<u8> {
    let mut candidate = fixture.to_vec();
    for mutation in data.chunks_exact(3) {
        let offset = usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % candidate.len();
        candidate[offset] = mutation[2];
    }
    candidate
}
