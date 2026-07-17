use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};

#[test]
#[ignore = "requires STOGAS_GITHUB_ATTESTATION_FIXTURE"]
fn verifies_real_gateway_release_attestation() {
    let path = std::env::var("STOGAS_GITHUB_ATTESTATION_FIXTURE").unwrap();
    let jsonl = std::fs::read_to_string(path).unwrap();
    let bundle = jsonl.lines().next().unwrap().as_bytes();
    let result = verify_github_attestation(
        bundle,
        &[
            Subject {
                name: "gateway.igvm",
                sha256: "1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6",
            },
            Subject {
                name: "gateway-launch-policy.json",
                sha256: "8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008",
            },
        ],
        &GithubPolicy {
            repository: "https://github.com/StogasAI/gateway".into(),
            workflow_identity: "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1".into(),
            source_ref: "refs/tags/v0.0.1".into(),
            source_commit: "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f".into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
    )
    .unwrap();
    assert_eq!(result.subjects.len(), 2);
}
