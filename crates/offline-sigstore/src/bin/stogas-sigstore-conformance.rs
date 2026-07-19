//! Narrow adapter for the official Sigstore verification-conformance protocol.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{path::PathBuf, time::UNIX_EPOCH};
use stogas_offline_sigstore::{IdentityPolicy, Subject, verify_dsse_attestation};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleShape {
    dsse_envelope: Envelope,
}

#[derive(Deserialize)]
struct Envelope {
    payload: String,
}

#[derive(Deserialize)]
struct Statement {
    subject: Vec<StatementSubject>,
}

#[derive(Deserialize)]
struct StatementSubject {
    name: String,
    digest: StatementDigest,
}

#[derive(Deserialize)]
struct StatementDigest {
    sha256: String,
}

struct Arguments {
    artifact: String,
    bundle: PathBuf,
    identity: String,
    issuer: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let bundle = std::fs::read(&arguments.bundle)
        .map_err(|error| format!("could not read bundle: {error}"))?;
    let digest = artifact_digest(&arguments.artifact)?;
    let shape: BundleShape = serde_json::from_slice(&bundle)
        .map_err(|error| format!("could not inspect DSSE bundle: {error}"))?;
    let payload = STANDARD
        .decode(shape.dsse_envelope.payload)
        .map_err(|error| format!("invalid DSSE payload: {error}"))?;
    let statement: Statement = serde_json::from_slice(&payload)
        .map_err(|error| format!("invalid in-toto statement: {error}"))?;
    let matches = statement
        .subject
        .iter()
        .filter(|subject| subject.digest.sha256 == digest)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("artifact digest is absent or ambiguous in the statement".into());
    }
    let expected = [Subject {
        name: &matches[0].name,
        sha256: &digest,
    }];
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates the Unix epoch")?
            .as_millis(),
    )
    .map_err(|_| "system clock is too large")?;
    verify_dsse_attestation(
        &bundle,
        &expected,
        &IdentityPolicy {
            certificate_identity: arguments.identity,
            certificate_oidc_issuer: arguments.issuer,
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
        now,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() != Some("verify-bundle") {
        return Err("only verify-bundle is supported".into());
    }
    let mut bundle = None;
    let mut identity = None;
    let mut issuer = None;
    let mut artifact = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--staging" => return Err("staging Sigstore roots are unsupported".into()),
            "--bundle" => bundle = arguments.next().map(PathBuf::from),
            "--certificate-identity" => identity = arguments.next(),
            "--certificate-oidc-issuer" => issuer = arguments.next(),
            "--trusted-root" | "--key" => {
                return Err("custom roots and managed keys are outside the claimed profile".into());
            }
            value if value.starts_with('-') => return Err(format!("unsupported option: {value}")),
            value if artifact.is_none() => artifact = Some(value.to_owned()),
            value => return Err(format!("unexpected argument: {value}")),
        }
    }
    Ok(Arguments {
        artifact: artifact.ok_or_else(|| "artifact is absent".to_owned())?,
        bundle: bundle.ok_or_else(|| "bundle is absent".to_owned())?,
        identity: identity.ok_or_else(|| "certificate identity is absent".to_owned())?,
        issuer: issuer.ok_or_else(|| "certificate issuer is absent".to_owned())?,
    })
}

fn artifact_digest(value: &str) -> Result<String, String> {
    if let Some(digest) = value.strip_prefix("sha256:")
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(digest.to_owned());
    }
    let bytes =
        std::fs::read(value).map_err(|error| format!("could not read artifact: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
