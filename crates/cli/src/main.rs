use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read as _,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use stogas::SecurityMode;
use stogas_verifier::{
    MAX_INPUT_BYTES,
    evidence::Verifier,
    receipt::{self, Receipt, VerifiedReceipt},
};
use tokio::io::AsyncReadExt as _;

#[derive(Parser)]
#[command(name = "stogas-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

struct ProofCommandInput {
    proof: Option<PathBuf>,
    stream: bool,
    request: PathBuf,
    response: PathBuf,
    bundle: PathBuf,
    boot: PathBuf,
    environment: stogas::Environment,
    now_unix_ms: Option<i64>,
}

struct VerifyCommandInput {
    bundle: PathBuf,
    environment: stogas::Environment,
    json: bool,
    now_unix_ms: Option<i64>,
}

struct ServeCommandInput {
    environment: stogas::Environment,
    upstream: Option<String>,
    listen: String,
    max_connections: usize,
    security: SecurityMode,
    browser_origin: Option<String>,
}

fn parse_environment(value: &str) -> Result<stogas::Environment, String> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| "environment is unsupported by this build".into())
}

#[derive(Subcommand)]
enum Command {
    /// Verify a bundle without network access.
    Verify {
        /// Bundle path, or `-` for stdin.
        bundle: PathBuf,
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Emit stable JSON.
        #[arg(long)]
        json: bool,
        /// Exact Unix time in milliseconds, for tests and auditing only.
        #[arg(long, hide = true)]
        now_unix_ms: Option<i64>,
    },
    /// Verify an exact-content receipt without network access.
    Proof {
        /// Detached receipt JSON; --response then contains only the exact signed bytes.
        #[arg(long, conflicts_with = "stream")]
        proof: Option<PathBuf>,
        /// Read a complete SSE response, including its metadata and terminal event.
        #[arg(long)]
        stream: bool,
        /// Exact plaintext request body sent to the inference endpoint.
        #[arg(long)]
        request: PathBuf,
        /// Buffered JSON with metadata, complete SSE, or detached signed response bytes.
        #[arg(long)]
        response: PathBuf,
        /// Archived evidence bundle identified by the boot archive.
        #[arg(long)]
        bundle: PathBuf,
        /// Immutable boot archive containing its quote, inclusion and evidence digest.
        #[arg(long)]
        boot: PathBuf,
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Emit stable JSON containing the verified content commitment.
        #[arg(long)]
        json: bool,
        /// Exact appraisal time in milliseconds, for tests and historical audits only.
        #[arg(long, hide = true)]
        now_unix_ms: Option<i64>,
    },
    /// Run the verified loopback proxy.
    Serve {
        #[arg(long, default_value = "prod", value_parser = parse_environment)]
        environment: stogas::Environment,
        /// Optional HTTPS API origin; the environment's evidence roots remain fixed.
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Maximum reusable channels, opened lazily.
        #[arg(long, default_value_t = 4)]
        max_connections: usize,
        #[arg(long, value_enum, default_value = "tls")]
        security: SecurityMode,
        /// Allow one browser origin to use the capability-protected local endpoint.
        #[arg(long)]
        browser_origin: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Verify {
            bundle,
            environment,
            json,
            now_unix_ms,
        } => {
            run_verify(VerifyCommandInput {
                bundle,
                environment,
                json,
                now_unix_ms,
            })
            .await?;
        }
        Command::Proof {
            proof,
            stream,
            request,
            response,
            bundle,
            boot,
            environment,
            json,
            now_unix_ms,
        } => {
            let output = run_proof(ProofCommandInput {
                proof,
                stream,
                request,
                response,
                bundle,
                boot,
                environment,
                now_unix_ms,
            })
            .await?;
            print_proof_output(&output, json)?;
        }
        Command::Serve {
            environment,
            upstream,
            listen,
            max_connections,
            security,
            browser_origin,
        } => {
            run_serve(ServeCommandInput {
                environment,
                upstream,
                listen,
                max_connections,
                security,
                browser_origin,
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
    let mut verifier = stogas_verifier::evidence::Verifier::stogas(input.environment)?;
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let output = verifier.refresh(&bytes, now)?;
    print_output(&output, input.json, now);
    Ok(())
}

async fn run_serve(input: ServeCommandInput) -> Result<()> {
    stogas::serve(stogas::ServeOptions {
        transport: stogas::TransportOptions {
            environment: input.environment,
            security: input.security,
            max_connections: input.max_connections,
            base_url: input.upstream,
        },
        listen: input.listen,
        browser_origin: input.browser_origin,
    })
    .await
}

async fn run_proof(input: ProofCommandInput) -> Result<VerifiedReceipt> {
    let verifier = Verifier::stogas(input.environment)?;
    verify_proof_files(&input, &verifier).await
}

async fn verify_proof_files(
    input: &ProofCommandInput,
    verifier: &Verifier,
) -> Result<VerifiedReceipt> {
    let now = input.now_unix_ms.unwrap_or_else(wall_clock_ms);
    let bundle = read_bounded_file(&input.bundle, MAX_INPUT_BYTES, "bundle").await?;
    let archive = read_bounded_file(&input.boot, 64 * 1024, "boot archive").await?;
    let boot = verifier.verify_boot_archive(&archive, &bundle, now)?;
    let request = hash_file(&input.request, "request body").await?;
    if let Some(path) = &input.proof {
        let proof = read_bounded_file(path, receipt::MAX_BYTES, "receipt").await?;
        let response = hash_file(&input.response, "response body").await?;
        return Ok(Receipt::parse(&proof)?.verify(&boot, &request, &response)?);
    }
    if input.stream {
        let mut response = tokio::fs::File::open(&input.response).await?;
        let mut stream = receipt::Stream::new(request);
        let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
        loop {
            let count = response.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            stream.push(&buffer[..count])?;
        }
        return Ok(stream.finish(&boot)?.receipt);
    }
    let response = read_bounded_file(
        &input.response,
        receipt::MAX_BUFFERED_BYTES,
        "buffered response",
    )
    .await?;
    Ok(receipt::verify_buffered(&boot, &request, &response)?.receipt)
}

fn print_proof_output(output: &VerifiedReceipt, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("Verified response");
        println!("  node: {}", output.node_id);
        println!("  request SHA-256: {}", output.request_sha256);
        println!("  response SHA-256: {}", output.response_sha256);
    }
    Ok(())
}

async fn hash_file(path: &PathBuf, label: &str) -> Result<[u8; 32]> {
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
    Ok(hasher.finalize().into())
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

fn print_output(output: &stogas_verifier::evidence::Snapshot, json: bool, now: i64) {
    if json {
        let mut summary = output.summary();
        summary["body_sha256"] = serde_json::json!(output.body_sha256());
        summary["collateral"] = serde_json::json!(output.collateral_summary(now));
        println!("{summary}");
        return;
    }
    let approvals = output.approvals().manifest();
    println!("Verified approval revision {}", approvals.revision);
    println!("  gateway releases: {}", approvals.gateways.len());
    println!("  catalogs: {}", approvals.catalogs.len());
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
    fn serve_uses_explicit_environment_and_transport_profile() {
        let cli = Cli::try_parse_from(["stogas-verify", "serve"]).unwrap();
        let Command::Serve {
            environment,
            security,
            max_connections,
            upstream,
            ..
        } = cli.command
        else {
            panic!("wrong command")
        };
        assert_eq!(environment, stogas::Environment::Production);
        assert_eq!(security, SecurityMode::Tls);
        assert_eq!(max_connections, 4);
        assert!(upstream.is_none());
        assert!(Cli::try_parse_from(["stogas-verify", "serve", "--security", "both"]).is_err());
        assert!(
            Cli::try_parse_from(["stogas-verify", "serve", "--bundle-refresh-seconds", "300"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stogas-verify",
                "serve",
                "--bundle-url",
                "https://untrusted.example"
            ])
            .is_err()
        );
        assert_eq!(
            Cli::try_parse_from(["stogas-verify", "serve", "--environment", "staging"]).is_ok(),
            cfg!(feature = "staging")
        );
        assert_eq!(
            Cli::try_parse_from([
                "stogas-verify",
                "verify",
                "bundle.json",
                "--environment",
                "staging"
            ])
            .is_ok(),
            cfg!(feature = "staging")
        );
        assert!(
            Cli::try_parse_from([
                "stogas-verify",
                "verify",
                "bundle.json",
                "--policy",
                "unsigned-policy.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn proof_requires_complete_boot_evidence_and_unambiguous_response_framing() {
        let base = [
            "stogas-verify",
            "proof",
            "--request",
            "request.json",
            "--response",
            "response",
        ];
        let evidence = ["--bundle", "bundle.json", "--boot", "boot.json"];
        assert!(Cli::try_parse_from(base.into_iter().chain(evidence)).is_ok());
        for framing in [vec!["--stream"], vec!["--proof", "receipt.json"]] {
            assert!(Cli::try_parse_from(base.into_iter().chain(evidence).chain(framing)).is_ok());
        }
        assert!(
            Cli::try_parse_from(base.into_iter().chain(evidence).chain([
                "--stream",
                "--proof",
                "receipt.json"
            ]))
            .is_err()
        );
        for missing in 0..evidence.len() / 2 {
            let mut incomplete = evidence.to_vec();
            incomplete.drain(missing * 2..missing * 2 + 2);
            assert!(Cli::try_parse_from(base.into_iter().chain(incomplete)).is_err());
        }
        for obsolete in [
            "--inclusion",
            "--ledger",
            "--catalog",
            "--policy",
            "--e2ee-transcript-sha256",
        ] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(evidence).chain([obsolete, "value"]))
                    .is_err()
            );
        }
        assert_eq!(
            Cli::try_parse_from(
                base.into_iter()
                    .chain(evidence)
                    .chain(["--environment", "staging"])
            )
            .is_ok(),
            cfg!(feature = "staging")
        );
    }
}

#[cfg(all(test, feature = "staging"))]
#[path = "proof_tests.rs"]
mod proof_tests;
