//! Offline verification of the narrow GitHub Actions Sigstore profile used by Stogas.

mod strict_json;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use thiserror::Error;

/// Maximum accepted serialized Sigstore bundle size.
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_SUBJECTS: usize = 16;
const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// Policy for one GitHub Actions build attestation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPolicy {
    /// Repository URI, for example `https://github.com/StogasAI/gateway`.
    pub repository: String,
    /// Workflow identity URI pinned to a workflow path and ref.
    pub workflow_identity: String,
    /// Git ref which invoked the workflow.
    pub source_ref: String,
    /// Git commit SHA which invoked the workflow.
    pub source_commit: String,
    /// Required in-toto predicate type.
    pub predicate_type: String,
    /// Require GitHub-hosted runner provenance.
    pub require_github_hosted: bool,
}

/// A subject which must be bound by the attestation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subject<'a> {
    /// Subject name in the in-toto statement.
    pub name: &'a str,
    /// Lowercase SHA-256 digest.
    pub sha256: &'a str,
}

/// Authenticated claims returned after cryptographic and policy verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAttestation {
    /// Authenticated integration/signing time in Unix seconds.
    pub integrated_time: i64,
    /// Predicate type from the verified in-toto statement.
    pub predicate_type: String,
    /// Subject names and SHA-256 digests from the verified statement.
    pub subjects: Vec<(String, String)>,
}

/// Offline Sigstore verification failure.
#[derive(Debug, Error)]
pub enum Error {
    /// Input exceeded a hard resource bound.
    #[error("sigstore bundle exceeds {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,
    /// JSON was malformed or used an unsupported representation.
    #[error("invalid Sigstore bundle: {0}")]
    InvalidBundle(String),
    /// The in-toto statement did not match policy.
    #[error("Sigstore policy mismatch: {0}")]
    Policy(String),
    /// Upstream cryptographic verification failed.
    #[error("Sigstore cryptographic verification failed: {0}")]
    Cryptographic(String),
}

/// Verify one Sigstore v0.3 bundle without network access.
///
/// The upstream verifier validates Fulcio, Rekor, SCT, inclusion material, authenticated signing
/// time, and the artifact signature. This function additionally pins the exact GitHub in-toto
/// policy and every expected artifact subject.
///
/// # Errors
///
/// Returns an error if parsing, cryptographic verification, or any pinned policy check fails.
pub fn verify_github_attestation(
    bundle_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
) -> Result<VerifiedAttestation, Error> {
    if bundle_bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::TooLarge);
    }
    let documents = parse_bundle_documents(bundle_bytes)?;
    let mut verified = None;
    let mut last_error = None;
    for value in documents {
        match verify_github_attestation_value(&value, expected_subjects, policy) {
            Ok(result) if verified.is_none() => verified = Some(result),
            Ok(_) => {
                return Err(Error::Policy(
                    "multiple attestations match the required subjects and policy".into(),
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    verified.ok_or_else(|| {
        last_error.unwrap_or_else(|| Error::InvalidBundle("attestation input is empty".into()))
    })
}

fn verify_github_attestation_value(
    value: &Value,
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
) -> Result<VerifiedAttestation, Error> {
    check_bundle_shape(value)?;
    let payload = decode_dsse_payload(value)?;
    let statement_value = strict_json::from_slice(&payload)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE statement: {error}")))?;
    let statement: Statement = serde_json::from_value(statement_value)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE statement: {error}")))?;
    check_statement(&statement, expected_subjects, policy)?;

    // Keep all Sigstore parsing and cryptography in the community verifier. The concrete API is
    // isolated here so SDKs never duplicate or weaken its policy.
    let integrated_time = verify_with_sigstore_rust(value, expected_subjects, policy)?;
    if integrated_time <= 0 {
        return Err(Error::Cryptographic(
            "Rekor integrated time must be positive".into(),
        ));
    }

    Ok(VerifiedAttestation {
        integrated_time,
        predicate_type: statement.predicate_type,
        subjects: statement
            .subject
            .into_iter()
            .map(|subject| (subject.name, subject.digest.sha256))
            .collect(),
    })
}

fn parse_bundle_documents(bundle_bytes: &[u8]) -> Result<Vec<Value>, Error> {
    match strict_json::from_slice(bundle_bytes) {
        Ok(value) => Ok(vec![value]),
        Err(single_error) => {
            let text = std::str::from_utf8(bundle_bytes)
                .map_err(|_| Error::InvalidBundle(single_error.to_string()))?;
            let lines: Vec<_> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            if lines.len() <= 1 || lines.len() > MAX_SUBJECTS {
                return Err(Error::InvalidBundle(single_error.to_string()));
            }
            lines
                .into_iter()
                .map(|line| {
                    strict_json::from_slice(line.as_bytes())
                        .map_err(|error| Error::InvalidBundle(error.to_string()))
                })
                .collect()
        }
    }
}

fn verify_with_sigstore_rust(
    value: &Value,
    subjects: &[Subject<'_>],
    github_policy: &GithubPolicy,
) -> Result<i64, Error> {
    use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
    use sigstore_types::{Bundle, Sha256Hash};
    use sigstore_verify::{VerificationPolicy, Verifier};

    let encoded =
        serde_json::to_string(value).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    let bundle =
        Bundle::from_json(&encoded).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .map_err(|error| Error::Cryptographic(error.to_string()))?;
    let verifier = Verifier::new(&root);
    let policy = VerificationPolicy::default()
        .require_identity(&github_policy.workflow_identity)
        .require_issuer("https://token.actions.githubusercontent.com");
    let mut authenticated_time = None;
    for subject in subjects {
        let digest = Sha256Hash::from_hex(subject.sha256)
            .map_err(|error| Error::Policy(error.to_string()))?;
        let result = verifier
            .verify(digest, &bundle, &policy)
            .map_err(|error| Error::Cryptographic(error.to_string()))?;
        let integrated_time = result.integrated_time.ok_or_else(|| {
            Error::Cryptographic("verified Rekor integrated time is absent".into())
        })?;
        if authenticated_time.is_some_and(|existing| existing != integrated_time) {
            return Err(Error::Cryptographic(
                "artifact subjects produced different authenticated times".into(),
            ));
        }
        authenticated_time = Some(integrated_time);
    }
    authenticated_time
        .ok_or_else(|| Error::Policy("at least one artifact subject is required".into()))
}

fn decode_dsse_payload(value: &Value) -> Result<Vec<u8>, Error> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload = value
        .pointer("/dsseEnvelope/payload")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidBundle("expected Sigstore v0.3 DSSE envelope".into()))?;
    STANDARD
        .decode(payload)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE payload encoding: {error}")))
}

fn check_bundle_shape(value: &Value) -> Result<(), Error> {
    let media_type = value
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidBundle("missing Sigstore bundle media type".into()))?;
    if media_type != SIGSTORE_BUNDLE_MEDIA_TYPE {
        return Err(Error::InvalidBundle(format!(
            "unsupported Sigstore bundle media type: {media_type}"
        )));
    }

    let envelope = value
        .get("dsseEnvelope")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::InvalidBundle("expected Sigstore v0.3 DSSE envelope".into()))?;
    if envelope.get("payloadType").and_then(Value::as_str) != Some(DSSE_PAYLOAD_TYPE) {
        return Err(Error::InvalidBundle("unsupported DSSE payload type".into()));
    }
    let signatures = envelope
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidBundle("missing DSSE signatures".into()))?;
    if signatures.len() != 1 {
        return Err(Error::InvalidBundle(
            "GitHub profile requires exactly one DSSE signature".into(),
        ));
    }
    if signatures[0]
        .get("sig")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::InvalidBundle("empty DSSE signature".into()));
    }

    let log_entries = value
        .pointer("/verificationMaterial/tlogEntries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidBundle("missing Rekor entry".into()))?;
    if log_entries.len() != 1 {
        return Err(Error::InvalidBundle(
            "GitHub profile requires exactly one Rekor entry".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<StatementSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementSubject {
    name: String,
    digest: StatementDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementDigest {
    sha256: String,
}

fn check_statement(
    statement: &Statement,
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
) -> Result<(), Error> {
    check_subjects(statement, expected_subjects)?;
    if statement.kind != "https://in-toto.io/Statement/v1" {
        return Err(Error::Policy("unsupported in-toto statement type".into()));
    }
    if statement.predicate_type != policy.predicate_type {
        return Err(Error::Policy("predicate type differs".into()));
    }
    check_github_build(statement, policy)
}

fn check_subjects(statement: &Statement, expected_subjects: &[Subject<'_>]) -> Result<(), Error> {
    if expected_subjects.is_empty() || expected_subjects.len() > MAX_SUBJECTS {
        return Err(Error::Policy(format!(
            "expected subject count must be between 1 and {MAX_SUBJECTS}"
        )));
    }
    if statement.subject.len() != expected_subjects.len() {
        return Err(Error::Policy(
            "attestation contains missing or unexpected subjects".into(),
        ));
    }
    let mut expected_names = HashSet::new();
    for expected in expected_subjects {
        if expected.name.is_empty()
            || !expected_names.insert(expected.name)
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Policy(
                "expected subjects require unique names and lowercase SHA-256 digests".into(),
            ));
        }
    }
    let actual_names: HashSet<_> = statement
        .subject
        .iter()
        .map(|subject| subject.name.as_str())
        .collect();
    if actual_names.len() != statement.subject.len() {
        return Err(Error::Policy(
            "attestation has duplicate subject names".into(),
        ));
    }
    for expected in expected_subjects {
        let matches = statement
            .subject
            .iter()
            .filter(|subject| {
                subject.name == expected.name && subject.digest.sha256 == expected.sha256
            })
            .count();
        if matches != 1 {
            return Err(Error::Policy(format!(
                "expected exactly one subject {} with digest {}",
                expected.name, expected.sha256
            )));
        }
    }
    Ok(())
}

fn check_github_build(statement: &Statement, policy: &GithubPolicy) -> Result<(), Error> {
    let invocation = statement
        .predicate
        .pointer("/buildDefinition/externalParameters/workflow")
        .ok_or_else(|| Error::Policy("missing GitHub workflow invocation".into()))?;
    let dependencies = statement
        .predicate
        .pointer("/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Policy("missing source repository".into()))?;
    if dependencies.len() != 1 {
        return Err(Error::Policy(
            "GitHub profile requires exactly one source dependency".into(),
        ));
    }
    let repository = invocation
        .get("repository")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Policy("missing workflow repository".into()))?;
    let workflow_path = invocation
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Policy("missing workflow path".into()))?;
    let dependency_uri = statement
        .predicate
        .pointer("/buildDefinition/resolvedDependencies/0/uri")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Policy("missing source repository".into()))?;
    let commit = statement
        .predicate
        .pointer("/buildDefinition/resolvedDependencies/0/digest/gitCommit")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Policy("missing source commit".into()))?;
    let workflow_ref = invocation
        .get("ref")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Policy("missing workflow ref".into()))?;
    let expected_identity = format!("{}/{}@{}", policy.repository, workflow_path, workflow_ref);
    if repository != policy.repository
        || dependency_uri != format!("git+{}@{}", policy.repository, policy.source_ref)
        || commit != policy.source_commit
        || workflow_ref != policy.source_ref
        || expected_identity != policy.workflow_identity
    {
        return Err(Error::Policy(
            "repository, workflow, commit, or ref differs".into(),
        ));
    }
    let runner = statement
        .predicate
        .pointer("/buildDefinition/internalParameters/github/runner_environment")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if policy.require_github_hosted && runner != "github-hosted" {
        return Err(Error::Policy(
            "build did not use the required hosted runner".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    fn statement(subject: Vec<StatementSubject>) -> Statement {
        Statement {
            kind: "https://in-toto.io/Statement/v1".into(),
            subject,
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            predicate: json!({
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "repository": "https://github.com/StogasAI/gateway",
                            "path": ".github/workflows/gateway-igvm-release.yml",
                            "ref": "refs/tags/v0.0.1"
                        }
                    },
                    "internalParameters": {
                        "github": { "runner_environment": "github-hosted" }
                    },
                    "resolvedDependencies": [{
                        "uri": "git+https://github.com/StogasAI/gateway@refs/tags/v0.0.1",
                        "digest": {
                            "gitCommit": "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f"
                        }
                    }]
                }
            }),
        }
    }

    fn subject(name: &str, digest: &str) -> StatementSubject {
        StatementSubject {
            name: name.into(),
            digest: StatementDigest {
                sha256: digest.into(),
            },
        }
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let bytes = vec![b' '; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(
            verify_github_attestation(&bytes, &[], &policy()),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn rejects_duplicate_json_keys() {
        let error =
            strict_json::from_slice(br#"{"mediaType":"first","mediaType":"second"}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key: mediaType"));
    }

    #[test]
    fn parses_github_json_and_jsonl_without_weakening_strict_json() {
        assert_eq!(parse_bundle_documents(br#"{"one":1}"#).unwrap().len(), 1);
        assert_eq!(
            parse_bundle_documents(b"{\"one\":1}\n\n{\"two\":2}\n")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_bundle_documents(b"{\"one\":1}\nnot-json").is_err());
    }

    #[test]
    fn rejects_extra_or_duplicate_subjects() {
        const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected = [Subject {
            name: "gateway.igvm",
            sha256: DIGEST,
        }];
        let extra = statement(vec![
            subject("gateway.igvm", DIGEST),
            subject("unexpected", DIGEST),
        ]);
        assert!(matches!(
            check_statement(&extra, &expected, &policy()),
            Err(Error::Policy(message)) if message.contains("unexpected subjects")
        ));

        let duplicate = statement(vec![
            subject("gateway.igvm", DIGEST),
            subject("gateway.igvm", DIGEST),
        ]);
        let duplicate_expected = [
            Subject {
                name: "gateway.igvm",
                sha256: DIGEST,
            },
            Subject {
                name: "gateway.igvm",
                sha256: DIGEST,
            },
        ];
        assert!(matches!(
            check_statement(&duplicate, &duplicate_expected, &policy()),
            Err(Error::Policy(message)) if message.contains("unique names")
        ));
    }

    #[test]
    fn accepts_only_the_exact_github_subject_set() {
        const IGVM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const POLICY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let statement = statement(vec![
            subject("gateway.igvm", IGVM),
            subject("gateway-launch-policy.json", POLICY),
        ]);
        check_statement(
            &statement,
            &[
                Subject {
                    name: "gateway.igvm",
                    sha256: IGVM,
                },
                Subject {
                    name: "gateway-launch-policy.json",
                    sha256: POLICY,
                },
            ],
            &policy(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_ambiguous_sigstore_bundle_shape() {
        let mut bundle = json!({
            "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "dsseEnvelope": {
                "payload": "e30=",
                "payloadType": DSSE_PAYLOAD_TYPE,
                "signatures": [{ "sig": "AA==" }]
            },
            "verificationMaterial": {
                "tlogEntries": [{}]
            }
        });
        check_bundle_shape(&bundle).unwrap();
        bundle["dsseEnvelope"]["signatures"] = json!([{ "sig": "AA==" }, { "sig": "AA==" }]);
        assert!(matches!(
            check_bundle_shape(&bundle),
            Err(Error::InvalidBundle(message)) if message.contains("exactly one DSSE signature")
        ));
    }
}
