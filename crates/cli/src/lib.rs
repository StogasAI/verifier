//! Managed Stogas HTTP transport shared by the SDK bindings and optional CLI.

use anyhow::{Result, bail};
use clap::ValueEnum;
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};
use tokio::sync::oneshot;

pub use stogas_verifier::{
    Environment, Error, VerificationOutput, VerifiedBundle, VerifiedNode, Verifier, verify_bundle,
};

mod e2ee;
mod proxy;

const PRODUCTION_BUNDLE_URL: &str = "https://evidence.stogas.ai/bundles/latest.json";
const PRODUCTION_UPSTREAM: &str = "https://api.stogas.ai";

/// Connection protections applied by the managed transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SecurityMode {
    /// `WebPKI` plus attested certificate and public-key pinning.
    Tls,
    /// Application-layer encryption to every trusted gateway.
    E2ee,
    /// Attested TLS and application-layer encryption together.
    Both,
}

/// Configuration for an in-process managed transport.
#[derive(Clone, Debug)]
pub struct TransportOptions {
    /// Connection protection. Native SDKs default to attested TLS.
    pub security: SecurityMode,
    /// Scheduled bundle refresh interval. Any positive duration is accepted.
    pub bundle_refresh_interval: Duration,
    /// Evidence snapshot URL.
    pub bundle_url: String,
    /// Public Stogas API origin.
    pub base_url: String,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            security: SecurityMode::Tls,
            bundle_refresh_interval: Duration::from_mins(5),
            bundle_url: PRODUCTION_BUNDLE_URL.to_owned(),
            base_url: PRODUCTION_UPSTREAM.to_owned(),
        }
    }
}

impl TransportOptions {
    fn validate(&self) -> Result<()> {
        if self.bundle_refresh_interval.is_zero() {
            bail!("bundle refresh interval must be positive");
        }
        Ok(())
    }
}

/// A managed Rust transport running inside the caller's process.
///
/// The SDK returns a capability-protected loopback base URL so existing OpenAI-compatible clients
/// keep their native request and response types while Rust owns bundle refresh, TLS pinning, E2EE,
/// streaming, and fail-closed expiry.
pub struct Transport {
    base_url: String,
    refresh_address: SocketAddr,
    refresh_path: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Transport {
    /// Start a transport and verify the first bundle before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration is invalid, the first bundle cannot be verified, or the
    /// local transport runtime cannot start.
    pub fn start(options: &TransportOptions) -> Result<Self> {
        options.validate()?;
        let config = proxy::ServeConfig::new(proxy::ServeConfigInput {
            bundle_url: &options.bundle_url,
            upstream: &options.base_url,
            listen: "127.0.0.1:0",
            environment: Environment::stogas(),
            bundle_refresh_interval: options.bundle_refresh_interval,
            security: options.security,
            browser_origin: None,
            protect_loopback_path: true,
        })?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("stogas-transport".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => {
                        let _ =
                            runtime.block_on(proxy::serve_embedded(config, shutdown_rx, ready_tx));
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "could not initialize the Stogas transport runtime: {error}"
                        )));
                    }
                }
            })?;
        let endpoints = match ready_rx.recv() {
            Ok(Ok(endpoints)) => endpoints,
            Ok(Err(error)) => {
                let _ = worker.join();
                bail!(error);
            }
            Err(_) => {
                let _ = worker.join();
                bail!("Stogas transport stopped before initialization completed");
            }
        };
        Ok(Self {
            base_url: endpoints.base_url,
            refresh_address: endpoints.address,
            refresh_path: endpoints.refresh_path,
            shutdown: Some(shutdown_tx),
            thread: Some(worker),
        })
    }

    /// Capability-protected loopback URL to pass to an OpenAI-compatible client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch and atomically activate a newer bundle now.
    ///
    /// Returns `true` when the bundle bytes changed and `false` when active bytes were reused.
    ///
    /// # Errors
    ///
    /// Returns an error when the local transport is unavailable or the fetched replacement fails
    /// verification.
    pub fn refresh_bundle(&self) -> Result<bool> {
        let mut stream = TcpStream::connect_timeout(&self.refresh_address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.refresh_path, self.refresh_address
        )?;
        stream.flush()?;

        let mut response = BufReader::new(stream);
        let mut status_line = String::new();
        response.read_line(&mut status_line)?;
        let status = status_line
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("managed transport returned an invalid HTTP response")
            })?;
        match status {
            200 => Ok(true),
            204 => Ok(false),
            _ => {
                let mut remainder = String::new();
                response.read_to_string(&mut remainder)?;
                bail!(
                    "bundle refresh failed with HTTP {status}: {}",
                    remainder.trim()
                );
            }
        }
    }

    /// Stop the managed transport. Calling this more than once is harmless.
    pub fn close(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.close();
    }
}

/// Run the optional foreground transport frontend.
///
/// # Errors
///
/// Returns an error when configuration, initial evidence verification, listener binding, or the
/// transport runtime fails.
pub async fn serve(
    bundle_url: &str,
    upstream: &str,
    listen: &str,
    environment: Environment,
    bundle_refresh_interval: Duration,
    security: SecurityMode,
    browser_origin: Option<&str>,
) -> Result<()> {
    proxy::serve(proxy::ServeConfig::new(proxy::ServeConfigInput {
        bundle_url,
        upstream,
        listen,
        environment,
        bundle_refresh_interval,
        security,
        browser_origin,
        protect_loopback_path: false,
    })?)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_options_accept_any_positive_refresh_interval() {
        for interval in [
            Duration::from_nanos(1),
            Duration::from_mins(5),
            Duration::from_secs(u64::MAX),
        ] {
            let options = TransportOptions {
                bundle_refresh_interval: interval,
                ..TransportOptions::default()
            };
            assert!(options.validate().is_ok());
        }
        let options = TransportOptions {
            bundle_refresh_interval: Duration::ZERO,
            ..TransportOptions::default()
        };
        assert!(options.validate().is_err());
    }
}
