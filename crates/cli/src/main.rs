use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use stogas_verifier::{Environment, VerificationOutput, VerifierState, verify_bundle};

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
        /// Do not load or persist rollback state.
        #[arg(long)]
        no_store: bool,
        /// Trust environment.
        #[arg(long, value_enum, default_value_t = Target::Staging)]
        target: Target,
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
        #[arg(long, value_enum, default_value_t = Target::Production)]
        target: Target,
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
            no_store,
            target,
            now_unix_ms,
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
            let state_path = state_path(target)?;
            let prior = if no_store {
                None
            } else {
                read_state(&state_path).await?
            };
            let output = verify_bundle(
                &bytes,
                now_unix_ms.unwrap_or_else(wall_clock_ms),
                &environment(target)?,
                prior.as_ref(),
            )?;
            if !no_store {
                write_state(&state_path, &output.next_state).await?;
            }
            print_output(&output, json)?;
        }
        Command::Serve {
            bundle_url,
            upstream,
            listen,
            target,
        } => {
            serve(bundle_url, upstream, listen, target).await?;
        }
    }
    Ok(())
}

fn environment(target: Target) -> Result<Environment> {
    match target {
        Target::Staging => Ok(Environment::staging_legacy()),
        Target::Production => bail!(
            "production verifier trust root is not published; stable use is blocked until the dedicated fleet key rollout"
        ),
    }
}

async fn serve(bundle_url: String, upstream: String, listen: String, target: Target) -> Result<()> {
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
        environment(target)?,
        state_path(target)?,
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
    println!("  trust expires: {}", output.bundle.expires_at_unix_ms);
    Ok(())
}

fn state_path(target: Target) -> Result<PathBuf> {
    let project = ProjectDirs::from("ai", "StogasAI", "verifier")
        .context("platform data directory is unavailable")?;
    Ok(project.data_dir().join(format!(
        "state-{}.json",
        match target {
            Target::Staging => "staging",
            Target::Production => "production",
        }
    )))
}

async fn read_state(path: &Path) -> Result<Option<VerifierState>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("invalid verifier state")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn write_state(path: &Path, state: &VerifierState) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    tokio::fs::write(&temporary, serde_json::to_vec(state)?).await?;
    tokio::fs::rename(&temporary, path).await?;
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
