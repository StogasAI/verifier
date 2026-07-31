use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use std::{
    io::Read as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stogas::SecurityMode;
use stogas_verifier::{
    MAX_INPUT_BYTES, VerificationOutput, Verifier,
    response_proof::{MAX_BODY_BYTES, MAX_PROOF_BYTES},
    verify_bundle,
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
    e2ee_transcript_sha256: Option<String>,
    json: bool,
    now_unix_ms: Option<i64>,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a bundle without network access.
    Verify {
        /// Bundle path, or `-` for stdin.
        bundle: PathBuf,
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
        /// Exact response body, excluding the `stogas.proof` SSE event itself.
        #[arg(long)]
        response: PathBuf,
        /// Currently valid bundle used for the request.
        #[arg(long, required_unless_present = "ledger", conflicts_with = "ledger")]
        bundle: Option<PathBuf>,
        /// Immutable historical node-ledger record.
        #[arg(long, required_unless_present = "bundle", conflicts_with = "bundle")]
        ledger: Option<PathBuf>,
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
        /// How often to fetch and verify the latest bundle.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u16).range(1..=840))]
        bundle_refresh_seconds: u16,
        /// Protect inference with verified TLS, application E2EE, or both.
        #[arg(long, value_enum)]
        security: Option<SecurityMode>,
        /// Allow one browser origin and print a capability-protected browser base URL.
        #[arg(long)]
        browser_origin: Option<String>,
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
            json,
            now_unix_ms,
            #[cfg(feature = "staging")]
            target,
        } => {
            let bytes = if bundle.as_os_str() == "-" {
                let mut input = Vec::new();
                std::io::stdin()
                    .take(u64::try_from(MAX_INPUT_BYTES + 1)?)
                    .read_to_end(&mut input)?;
                if input.len() > MAX_INPUT_BYTES {
                    bail!("bundle exceeds {MAX_INPUT_BYTES} bytes");
                }
                input
            } else {
                read_bounded_file(&bundle, MAX_INPUT_BYTES, "bundle").await?
            };
            let output = verify_bundle(&bytes, now_unix_ms.unwrap_or_else(wall_clock_ms), &{
                #[cfg(feature = "staging")]
                {
                    match target {
                        InternalTrustTarget::Production => stogas_verifier::Environment::stogas(),
                        InternalTrustTarget::Staging => stogas_verifier::Environment::staging(),
                    }
                }
                #[cfg(not(feature = "staging"))]
                {
                    stogas_verifier::Environment::stogas()
                }
            })?;
            print_output(&output, json)?;
        }
        Command::Proof {
            proof,
            request,
            response,
            bundle,
            ledger,
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
                e2ee_transcript_sha256,
                json,
                now_unix_ms,
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
            #[cfg(feature = "staging")]
            target,
        } => {
            serve(
                bundle_url,
                upstream,
                listen,
                {
                    #[cfg(feature = "staging")]
                    {
                        match target {
                            InternalTrustTarget::Production => {
                                stogas_verifier::Environment::stogas()
                            }
                            InternalTrustTarget::Staging => stogas_verifier::Environment::staging(),
                        }
                    }
                    #[cfg(not(feature = "staging"))]
                    {
                        stogas_verifier::Environment::stogas()
                    }
                },
                bundle_refresh_seconds,
                security,
                browser_origin,
            )
            .await?;
        }
    }
    Ok(())
}

async fn run_proof(input: ProofCommandInput) -> Result<()> {
    let proof = read_proof(&input.proof).await?;
    let request = read_bounded_file(&input.request, MAX_BODY_BYTES, "request body").await?;
    let response = read_bounded_file(&input.response, MAX_BODY_BYTES, "response body").await?;
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let mut verifier = Verifier::default();
    let output = if let Some(bundle) = input.bundle {
        let bundle = read_bounded_file(&bundle, MAX_INPUT_BYTES, "bundle").await?;
        verifier.verify_bundle(&bundle, now, &stogas_verifier::Environment::stogas())?;
        verifier.verify_response_proof(
            &proof,
            &request,
            &response,
            input.e2ee_transcript_sha256.as_deref(),
            now,
        )?
    } else {
        let ledger = input
            .ledger
            .context("a bundle or historical ledger is required")?;
        let ledger = read_bounded_file(&ledger, MAX_INPUT_BYTES, "ledger record").await?;
        verifier.verify_historical_response_proof(
            &stogas_verifier::HistoricalResponseProofInput {
                proof_bytes: &proof,
                request_body: &request,
                response_body: &response,
                expected_e2ee_transcript_sha256: input.e2ee_transcript_sha256.as_deref(),
                now_unix_ms: now,
                ledger_bytes: &ledger,
                environment: &stogas_verifier::Environment::stogas(),
            },
        )?
    };
    if input.json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("Verified response");
        println!("  node: {}", output.node_id);
        println!("  catalog: {}", output.catalog_digest);
        println!("  catalog nodes: {}", output.catalog_node_ids.join(", "));
    }
    Ok(())
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

async fn serve(
    bundle_url: String,
    upstream: String,
    listen: String,
    environment: stogas_verifier::Environment,
    bundle_refresh_seconds: u16,
    security: Option<SecurityMode>,
    browser_origin: Option<String>,
) -> Result<()> {
    stogas::serve(
        &bundle_url,
        &upstream,
        &listen,
        environment,
        Duration::from_secs(u64::from(bundle_refresh_seconds)),
        resolved_security(security, browser_origin.as_deref()),
        browser_origin.as_deref(),
    )
    .await
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
    fn serve_refresh_interval_defaults_to_one_minute() {
        let cli = Cli::try_parse_from(["stogas-verify", "serve"]).unwrap();
        let Command::Serve {
            bundle_refresh_seconds,
            ..
        } = cli.command
        else {
            panic!("serve command was not parsed");
        };
        assert_eq!(bundle_refresh_seconds, 60);
    }

    #[test]
    fn serve_refresh_interval_accepts_the_safe_whole_second_range() {
        for seconds in ["1", "840"] {
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
        for seconds in ["0", "841"] {
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
        assert!(Cli::try_parse_from(base.into_iter().chain(["--ledger", "ledger.json"])).is_ok());
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
