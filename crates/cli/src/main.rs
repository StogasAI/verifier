use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stogas::SecurityMode;
use stogas_verifier::{
    MAX_INPUT_BYTES, VerificationOutput, Verifier, response_proof::MAX_PROOF_BYTES,
};
use tokio::io::AsyncReadExt as _;

const PRODUCTION_BUNDLE_URL: &str = "https://evidence.stogas.ai/bundles/latest.json";
const MAX_PROOF_INPUT_BYTES: usize = MAX_PROOF_BYTES * 2;

#[cfg(feature = "staging")]
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum InternalTrustTarget {
    Production,
    Staging,
}

#[cfg(feature = "staging")]
fn verifier_environment(target: InternalTrustTarget) -> stogas_verifier::Environment {
    match target {
        InternalTrustTarget::Production => stogas_verifier::Environment::stogas(),
        InternalTrustTarget::Staging => stogas_verifier::Environment::staging(),
    }
}

#[cfg(not(feature = "staging"))]
fn verifier_environment() -> stogas_verifier::Environment {
    stogas_verifier::Environment::stogas()
}

#[derive(Parser)]
#[command(name = "stogas-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

struct ProofCommandInput {
    proof: PathBuf,
    request: PathBuf,
    response: PathBuf,
    bundle: Option<PathBuf>,
    ledger: Option<PathBuf>,
    catalog: Option<PathBuf>,
    e2ee_transcript_sha256: Option<String>,
    json: bool,
    now_unix_ms: Option<i64>,
    policy: Option<PathBuf>,
}

struct VerifyCommandInput {
    bundle: PathBuf,
    policy: Option<PathBuf>,
    json: bool,
    now_unix_ms: Option<i64>,
    environment: stogas_verifier::Environment,
}

struct ServeCommandInput {
    bundle_url: String,
    upstream: String,
    listen: String,
    environment: stogas_verifier::Environment,
    bundle_refresh_seconds: u64,
    security: Option<SecurityMode>,
    browser_origin: Option<String>,
    policy: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a bundle without network access.
    Verify {
        /// Bundle path, or `-` for stdin.
        bundle: PathBuf,
        /// Caller-owned hardware appraisal policy. This replaces only mutable AMD security rules.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Emit stable JSON.
        #[arg(long)]
        json: bool,
        /// Exact Unix time in milliseconds, for tests and auditing only.
        #[arg(long, hide = true)]
        now_unix_ms: Option<i64>,
        /// Internal trust environment. Not compiled into public CLI releases.
        #[cfg(feature = "staging")]
        #[arg(long, hide = true, value_enum, default_value_t = InternalTrustTarget::Production)]
        target: InternalTrustTarget,
    },
    /// Verify a compact post-facto response receipt.
    Proof {
        /// Receipt JSON or an `X-Stogas-Proof` base64url value.
        proof: PathBuf,
        /// Exact plaintext request body sent to the inference endpoint.
        #[arg(long)]
        request: PathBuf,
        /// Exact response body, excluding the final `stogas` SSE comment itself.
        #[arg(long)]
        response: PathBuf,
        /// Currently valid bundle used for the request.
        #[arg(long, required_unless_present = "ledger", conflicts_with = "ledger")]
        bundle: Option<PathBuf>,
        /// Caller-owned hardware appraisal policy for current-bundle verification.
        #[arg(long, conflicts_with = "ledger")]
        policy: Option<PathBuf>,
        /// Immutable historical node-ledger record.
        #[arg(long, required_unless_present = "bundle", conflicts_with = "bundle")]
        ledger: Option<PathBuf>,
        /// Immutable catalog approval selected by the signed catalog sequence.
        #[arg(long, required_unless_present = "bundle", conflicts_with = "bundle")]
        catalog: Option<PathBuf>,
        /// Exact E2EE transcript SHA-256 for an encrypted exchange.
        #[arg(long)]
        e2ee_transcript_sha256: Option<String>,
        /// Emit stable JSON.
        #[arg(long)]
        json: bool,
        /// Exact Unix time in milliseconds, for tests and auditing only.
        #[arg(long, hide = true)]
        now_unix_ms: Option<i64>,
    },
    /// Run the verified loopback proxy.
    Serve {
        #[arg(long, default_value = PRODUCTION_BUNDLE_URL)]
        bundle_url: String,
        #[arg(long, default_value = "https://api.stogas.ai")]
        upstream: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Bundle refresh target in seconds. Scheduled attempts use ±10% jitter.
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
        bundle_refresh_seconds: u64,
        /// Protect inference with verified TLS, application E2EE, or both.
        #[arg(long, value_enum)]
        security: Option<SecurityMode>,
        /// Allow one browser origin and print a capability-protected browser base URL.
        #[arg(long)]
        browser_origin: Option<String>,
        /// Caller-owned hardware appraisal policy.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Internal trust environment. Not compiled into public CLI releases.
        #[cfg(feature = "staging")]
        #[arg(long, hide = true, value_enum, default_value_t = InternalTrustTarget::Production)]
        target: InternalTrustTarget,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Verify {
            bundle,
            policy,
            json,
            now_unix_ms,
            #[cfg(feature = "staging")]
            target,
        } => {
            let environment = verifier_environment(
                #[cfg(feature = "staging")]
                target,
            );
            run_verify(VerifyCommandInput {
                bundle,
                policy,
                json,
                now_unix_ms,
                environment,
            })
            .await?;
        }
        Command::Proof {
            proof,
            request,
            response,
            bundle,
            policy,
            ledger,
            catalog,
            e2ee_transcript_sha256,
            json,
            now_unix_ms,
        } => {
            run_proof(ProofCommandInput {
                proof,
                request,
                response,
                bundle,
                ledger,
                catalog,
                e2ee_transcript_sha256,
                json,
                now_unix_ms,
                policy,
            })
            .await?;
        }
        Command::Serve {
            bundle_url,
            upstream,
            listen,
            bundle_refresh_seconds,
            security,
            browser_origin,
            policy,
            #[cfg(feature = "staging")]
            target,
        } => {
            let environment = verifier_environment(
                #[cfg(feature = "staging")]
                target,
            );
            run_serve(ServeCommandInput {
                bundle_url,
                upstream,
                listen,
                environment,
                bundle_refresh_seconds,
                security,
                browser_origin,
                policy,
            })
            .await?;
        }
    }
    Ok(())
}

async fn run_verify(input: VerifyCommandInput) -> Result<()> {
    let bytes = if input.bundle.as_os_str() == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(u64::try_from(MAX_INPUT_BYTES + 1)?)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_INPUT_BYTES {
            bail!("bundle exceeds {MAX_INPUT_BYTES} bytes");
        }
        bytes
    } else {
        read_bounded_file(&input.bundle, MAX_INPUT_BYTES, "bundle").await?
    };
    let policy = match input.policy {
        Some(path) => Some(read_bounded_file(&path, MAX_INPUT_BYTES, "hardware policy").await?),
        None => None,
    };
    let mut verifier = Verifier::default();
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let output = match policy.as_deref() {
        Some(policy) => {
            verifier.verify_bundle_with_policy(&bytes, policy, now, &input.environment)?
        }
        None => verifier.verify_bundle(&bytes, now, &input.environment)?,
    };
    print_output(&output, input.json)
}

async fn run_serve(input: ServeCommandInput) -> Result<()> {
    let hardware_policy = match input.policy {
        Some(path) => Some(read_bounded_file(&path, MAX_INPUT_BYTES, "hardware policy").await?),
        None => None,
    };
    let security = resolved_security(input.security, input.browser_origin.as_deref());
    stogas::serve(stogas::ServeOptions {
        bundle_url: input.bundle_url,
        upstream: input.upstream,
        listen: input.listen,
        environment: input.environment,
        bundle_refresh_interval: Duration::from_secs(input.bundle_refresh_seconds),
        security,
        browser_origin: input.browser_origin,
        hardware_policy,
    })
    .await
}

async fn run_proof(input: ProofCommandInput) -> Result<()> {
    let proof = read_proof(&input.proof).await?;
    let request_sha256 = hash_file(&input.request, "request body").await?;
    let response_sha256 = hash_file(&input.response, "response body").await?;
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let mut verifier = Verifier::default();
    let output = if let Some(bundle) = input.bundle {
        let bundle = read_bounded_file(&bundle, MAX_INPUT_BYTES, "bundle").await?;
        match input.policy {
            Some(policy) => {
                let policy = read_bounded_file(&policy, MAX_INPUT_BYTES, "hardware policy").await?;
                verifier.verify_bundle_with_policy(
                    &bundle,
                    &policy,
                    now,
                    &stogas_verifier::Environment::stogas(),
                )?;
            }
            None => {
                verifier.verify_bundle(&bundle, now, &stogas_verifier::Environment::stogas())?;
            }
        }
        verifier.verify_response_proof_hashes(
            &proof,
            &request_sha256,
            &response_sha256,
            input.e2ee_transcript_sha256.as_deref(),
            now,
        )?
    } else {
        let ledger = input
            .ledger
            .context("a bundle or historical ledger is required")?;
        let ledger = read_bounded_file(&ledger, MAX_INPUT_BYTES, "ledger record").await?;
        let catalog = input
            .catalog
            .context("a historical catalog approval is required with a ledger")?;
        let catalog = read_bounded_file(&catalog, MAX_INPUT_BYTES, "catalog approval").await?;
        verifier.verify_historical_response_proof_hashes(
            &stogas_verifier::HistoricalResponseProofHashInput {
                proof_bytes: &proof,
                request_sha256: &request_sha256,
                response_sha256: &response_sha256,
                expected_e2ee_transcript_sha256: input.e2ee_transcript_sha256.as_deref(),
                now_unix_ms: now,
                ledger_bytes: &ledger,
                catalog_approval_bytes: &catalog,
                environment: &stogas_verifier::Environment::stogas(),
            },
        )?
    };
    if input.json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("Verified response");
        println!("  node: {}", output.node_id);
        println!("  catalog: {}", output.catalog.digest);
    }
    Ok(())
}

async fn hash_file(path: &PathBuf, label: &str) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("could not read {label} from {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

async fn read_proof(path: &PathBuf) -> Result<Vec<u8>> {
    let bytes = read_bounded_file(path, MAX_PROOF_INPUT_BYTES, "response proof").await?;
    let trimmed = std::str::from_utf8(&bytes)
        .context("response proof must be UTF-8 JSON or base64url")?
        .trim();
    if trimmed.starts_with('{') {
        return Ok(trimmed.as_bytes().to_vec());
    }
    let encoded = trimmed
        .strip_prefix("X-Stogas-Proof:")
        .unwrap_or(trimmed)
        .trim();
    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("response proof is neither JSON nor canonical base64url")
}

async fn read_bounded_file(path: &PathBuf, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum + 1)?)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{label} exceeds {maximum} bytes");
    }
    Ok(bytes)
}

fn resolved_security(
    requested: Option<SecurityMode>,
    browser_origin: Option<&str>,
) -> SecurityMode {
    requested.unwrap_or_else(|| {
        if browser_origin.is_some() {
            SecurityMode::E2ee
        } else {
            SecurityMode::Tls
        }
    })
}

fn print_output(output: &VerificationOutput, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(output)?);
        return Ok(());
    }
    println!("Verified bundle {}", output.bundle.sequence);
    println!("  releases: {}", output.bundle.releases.len());
    println!("  nodes: {}", output.bundle.nodes.len());
    println!("  excluded nodes: {}", output.bundle.excluded_nodes.len());
    println!("  bundle expires: {}", output.bundle.expires_at_unix_ms);
    Ok(())
}

fn wall_clock_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_refresh_interval_defaults_to_five_minutes() {
        let cli = Cli::try_parse_from(["stogas-verify", "serve"]).unwrap();
        let Command::Serve {
            bundle_refresh_seconds,
            ..
        } = cli.command
        else {
            panic!("serve command was not parsed");
        };
        assert_eq!(bundle_refresh_seconds, 300);
    }

    #[test]
    fn serve_refresh_interval_accepts_any_positive_whole_seconds() {
        for seconds in ["1", "841", "86400"] {
            assert!(
                Cli::try_parse_from([
                    "stogas-verify",
                    "serve",
                    "--bundle-refresh-seconds",
                    seconds,
                ])
                .is_ok()
            );
        }
        for seconds in ["0", "-1"] {
            assert!(
                Cli::try_parse_from([
                    "stogas-verify",
                    "serve",
                    "--bundle-refresh-seconds",
                    seconds,
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn native_and_browser_defaults_are_safe_and_explicit_overrides_win() {
        assert_eq!(resolved_security(None, None), SecurityMode::Tls);
        assert_eq!(
            resolved_security(None, Some("https://client.example")),
            SecurityMode::E2ee
        );
        assert_eq!(
            resolved_security(Some(SecurityMode::Both), Some("https://client.example")),
            SecurityMode::Both
        );
    }

    #[test]
    fn proof_requires_exact_bodies_and_one_trust_source() {
        let base = [
            "stogas-verify",
            "proof",
            "proof.txt",
            "--request",
            "request.json",
            "--response",
            "response.json",
        ];
        assert!(Cli::try_parse_from(base.into_iter().chain(["--bundle", "bundle.json"])).is_ok());
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--ledger",
                "ledger.json",
                "--catalog",
                "catalog.json"
            ]))
            .is_ok()
        );
        assert!(Cli::try_parse_from(base.into_iter().chain(["--ledger", "ledger.json"])).is_err());
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--catalog", "catalog.json"])).is_err()
        );
        assert!(Cli::try_parse_from(base).is_err());
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--bundle",
                "bundle.json",
                "--ledger",
                "ledger.json"
            ]))
            .is_err()
        );
    }

    #[cfg(not(feature = "staging"))]
    #[test]
    fn public_build_has_no_staging_trust_target() {
        assert!(
            Cli::try_parse_from(["stogas-verify", "verify", "-", "--target", "staging",]).is_err()
        );
        assert!(Cli::try_parse_from(["stogas-verify", "serve", "--target", "staging",]).is_err());
    }

    #[cfg(feature = "staging")]
    #[test]
    fn internal_build_accepts_the_hidden_staging_trust_target() {
        assert!(
            Cli::try_parse_from(["stogas-verify", "verify", "-", "--target", "staging",]).is_ok()
        );
        assert!(Cli::try_parse_from(["stogas-verify", "serve", "--target", "staging",]).is_ok());
    }
}
