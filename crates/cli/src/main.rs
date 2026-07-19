use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::Read as _,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use stogas_verifier::{Environment, VerificationOutput, verify_bundle};

mod proxy;

const PRODUCTION_BUNDLE_URL: &str = "https://evidence.stogas.ai/bundles/latest.json";
const STAGING_BUNDLE_URL: &str = "https://evidence-staging.stogas.ai/bundles/latest.json";

#[derive(Parser)]
#[command(name = "stogas-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
        /// Trust environment.
        #[arg(long, value_enum, default_value_t = Target::Staging)]
        target: Target,
        /// Exact Unix time in milliseconds, for tests and auditing only.
        #[arg(long, hide = true)]
        now_unix_ms: Option<i64>,
        /// Maximum age of attested node evidence admitted to the trust set.
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(1..=3))]
        max_node_age_minutes: u16,
    },
    /// Run the verified loopback proxy.
    Serve {
        #[arg(long, default_value = PRODUCTION_BUNDLE_URL)]
        bundle_url: String,
        #[arg(long, default_value = "https://api.stogas.ai")]
        upstream: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long, value_enum, default_value_t = Target::Production)]
        target: Target,
        /// Maximum age of attested node evidence admitted to the trust set.
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(1..=3))]
        max_node_age_minutes: u16,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Target {
    Staging,
    Production,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Verify {
            bundle,
            json,
            target,
            now_unix_ms,
            max_node_age_minutes,
        } => {
            let bytes = if bundle.as_os_str() == "-" {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input)?;
                input
            } else {
                tokio::fs::read(&bundle)
                    .await
                    .with_context(|| format!("could not read {}", bundle.display()))?
            };
            let output = verify_bundle(
                &bytes,
                now_unix_ms.unwrap_or_else(wall_clock_ms),
                &environment(target, max_node_age_minutes),
            )?;
            print_output(&output, json)?;
        }
        Command::Serve {
            bundle_url,
            upstream,
            listen,
            target,
            max_node_age_minutes,
        } => {
            serve(bundle_url, upstream, listen, target, max_node_age_minutes).await?;
        }
    }
    Ok(())
}

fn environment(target: Target, max_node_age_minutes: u16) -> Environment {
    let mut environment = match target {
        Target::Staging | Target::Production => Environment::stogas(),
    };
    environment.max_node_evidence_age_ms = i64::from(max_node_age_minutes) * 60 * 1000;
    environment
}

async fn serve(
    bundle_url: String,
    upstream: String,
    listen: String,
    target: Target,
    max_node_age_minutes: u16,
) -> Result<()> {
    let expected_default = match target {
        Target::Staging => STAGING_BUNDLE_URL,
        Target::Production => PRODUCTION_BUNDLE_URL,
    };
    if bundle_url == PRODUCTION_BUNDLE_URL && matches!(target, Target::Staging) {
        bail!("staging serve requires --bundle-url {expected_default}");
    }
    proxy::serve(proxy::ServeConfig::new(
        &bundle_url,
        &upstream,
        &listen,
        environment(target, max_node_age_minutes),
    )?)
    .await
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
    println!(
        "  node trust expires: {}",
        output
            .bundle
            .trust_expires_at_unix_ms
            .map_or_else(|| "no usable nodes".into(), |value| value.to_string())
    );
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
