//! Managed Stogas HTTP transport shared by the SDK bindings and optional CLI.

use anyhow::{Result, bail};
use clap::ValueEnum;
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};
use tokio::sync::oneshot;

pub use stogas_verifier::{
    Environment, Error, VerificationOutput, VerifiedBundle, VerifiedNode, Verifier, verify_bundle,
    verify_bundle_with_policy,
};

mod e2ee;
mod proxy;

const PRODUCTION_BUNDLE_URL: &str = "https://evidence.stogas.ai/bundles/latest.json";
const PRODUCTION_UPSTREAM: &str = "https://api.stogas.ai";
const MAX_MANAGED_RESPONSE_LINE_BYTES: usize = 8 * 1024;
const MAX_MANAGED_ERROR_BYTES: usize = 8 * 1024;

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
    /// Scheduled bundle refresh target. Any positive duration is accepted and receives ±10% jitter.
    pub bundle_refresh_interval: Duration,
    /// Evidence snapshot URL.
    pub bundle_url: String,
    /// Public Stogas API origin.
    pub base_url: String,
    /// Caller-owned hardware appraisal policy. Fixed cryptographic checks are not configurable.
    pub hardware_policy: Option<Vec<u8>>,
}

/// Configuration for the optional foreground transport frontend.
#[derive(Clone, Debug)]
pub struct ServeOptions {
    /// Evidence snapshot URL.
    pub bundle_url: String,
    /// Public Stogas API origin.
    pub upstream: String,
    /// Loopback listener address.
    pub listen: String,
    /// Verification trust environment.
    pub environment: Environment,
    /// Scheduled bundle refresh target.
    pub bundle_refresh_interval: Duration,
    /// Connection protection.
    pub security: SecurityMode,
    /// Optional browser origin allowed to use the local transport.
    pub browser_origin: Option<String>,
    /// Caller-owned hardware appraisal policy. Fixed cryptographic checks are not configurable.
    pub hardware_policy: Option<Vec<u8>>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            security: SecurityMode::Tls,
            bundle_refresh_interval: Duration::from_mins(5),
            bundle_url: PRODUCTION_BUNDLE_URL.to_owned(),
            base_url: PRODUCTION_UPSTREAM.to_owned(),
            hardware_policy: None,
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
    terminal_error: Arc<Mutex<Option<String>>>,
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
            hardware_policy: options.hardware_policy.as_deref(),
            protect_loopback_path: true,
        })?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let terminal_error = Arc::new(Mutex::new(None));
        let worker_terminal_error = Arc::clone(&terminal_error);
        let worker = thread::Builder::new()
            .name("stogas-transport".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let message = format!(
                                "could not initialize the Stogas transport runtime: {error}"
                            );
                            ready_tx.send(Err(message.clone())).map_err(|_| {
                                anyhow::anyhow!(
                                    "the Stogas transport caller stopped during initialization: {message}"
                                )
                            })?;
                            bail!(message);
                        }
                    };
                    runtime.block_on(proxy::serve_embedded(config, shutdown_rx, ready_tx))
                }));
                let message = match outcome {
                    Ok(Ok(())) => "managed transport stopped".to_owned(),
                    Ok(Err(error)) => format!("managed transport stopped: {error}"),
                    Err(_) => "managed transport worker panicked".to_owned(),
                };
                record_transport_terminal_error(&worker_terminal_error, message);
            })?;
        let endpoints = match ready_rx.recv() {
            Ok(Ok(endpoints)) => endpoints,
            Ok(Err(error)) => {
                if worker.join().is_err() {
                    bail!("Stogas transport worker panicked during initialization");
                }
                bail!(error);
            }
            Err(_) => {
                if worker.join().is_err() {
                    bail!("Stogas transport worker panicked during initialization");
                }
                if let Some(error) = read_transport_terminal_error(&terminal_error) {
                    bail!("Stogas transport stopped before initialization completed: {error}");
                }
                bail!("Stogas transport stopped before initialization completed");
            }
        };
        Ok(Self {
            base_url: endpoints.base_url,
            refresh_address: endpoints.address,
            refresh_path: endpoints.refresh_path,
            shutdown: Some(shutdown_tx),
            thread: Some(worker),
            terminal_error,
        })
    }

    fn ensure_running(&self) -> Result<()> {
        if let Some(error) = read_transport_terminal_error(&self.terminal_error) {
            bail!(error);
        }
        if self
            .thread
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
        {
            bail!("managed transport is not running");
        }
        Ok(())
    }

    fn io_error(&self, error: std::io::Error) -> anyhow::Error {
        read_transport_terminal_error(&self.terminal_error)
            .map_or_else(|| error.into(), anyhow::Error::msg)
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
        self.ensure_running()?;
        let mut stream = TcpStream::connect_timeout(&self.refresh_address, Duration::from_secs(5))
            .map_err(|error| self.io_error(error))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|error| self.io_error(error))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| self.io_error(error))?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.refresh_path, self.refresh_address
        )
        .map_err(|error| self.io_error(error))?;
        stream.flush().map_err(|error| self.io_error(error))?;

        let mut response = BufReader::new(stream);
        let mut status_line = String::new();
        {
            let mut status_reader = (&mut response).take(
                u64::try_from(MAX_MANAGED_RESPONSE_LINE_BYTES.saturating_add(1))
                    .unwrap_or(u64::MAX),
            );
            status_reader
                .read_line(&mut status_line)
                .map_err(|error| self.io_error(error))?;
        }
        if status_line.len() > MAX_MANAGED_RESPONSE_LINE_BYTES || !status_line.ends_with('\n') {
            bail!("managed transport returned an invalid HTTP response");
        }
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
                let mut remainder = Vec::new();
                response
                    .take(
                        u64::try_from(MAX_MANAGED_ERROR_BYTES.saturating_add(1))
                            .unwrap_or(u64::MAX),
                    )
                    .read_to_end(&mut remainder)
                    .map_err(|error| self.io_error(error))?;
                if remainder.len() > MAX_MANAGED_ERROR_BYTES {
                    bail!("bundle refresh failed with HTTP {status}");
                }
                bail!(
                    "bundle refresh failed with HTTP {status}: {}",
                    String::from_utf8_lossy(&remainder).trim()
                );
            }
        }
    }

    /// Stop the managed transport. Calling this more than once is harmless.
    pub fn close(&mut self) {
        if let Some(shutdown) = self.shutdown.take()
            && shutdown.send(()).is_err()
        {
            record_transport_terminal_error(
                &self.terminal_error,
                "managed transport stopped before shutdown",
            );
        }
        if let Some(worker) = self.thread.take()
            && worker.join().is_err()
        {
            record_transport_terminal_error(
                &self.terminal_error,
                "managed transport worker panicked",
            );
        }
        record_transport_terminal_error(&self.terminal_error, "managed transport is closed");
    }
}

fn record_transport_terminal_error(
    terminal_error: &Mutex<Option<String>>,
    message: impl Into<String>,
) {
    let mut terminal_error = match terminal_error.lock() {
        Ok(terminal_error) => terminal_error,
        Err(poisoned) => poisoned.into_inner(),
    };
    if terminal_error.is_none() {
        *terminal_error = Some(message.into());
    }
}

fn read_transport_terminal_error(terminal_error: &Mutex<Option<String>>) -> Option<String> {
    match terminal_error.lock() {
        Ok(terminal_error) => terminal_error.clone(),
        Err(poisoned) => Some(
            poisoned
                .into_inner()
                .clone()
                .unwrap_or_else(|| "managed transport status is unavailable".to_owned()),
        ),
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
pub async fn serve(options: ServeOptions) -> Result<()> {
    proxy::serve(proxy::ServeConfig::new(proxy::ServeConfigInput {
        bundle_url: &options.bundle_url,
        upstream: &options.upstream,
        listen: &options.listen,
        environment: options.environment,
        bundle_refresh_interval: options.bundle_refresh_interval,
        security: options.security,
        browser_origin: options.browser_origin.as_deref(),
        hardware_policy: options.hardware_policy.as_deref(),
        protect_loopback_path: false,
    })?)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopped_transport(error: Option<&str>) -> Transport {
        Transport {
            base_url: "http://127.0.0.1:1".to_owned(),
            refresh_address: "127.0.0.1:1".parse().expect("valid test address"),
            refresh_path: "/refresh".to_owned(),
            shutdown: None,
            thread: None,
            terminal_error: Arc::new(Mutex::new(error.map(str::to_owned))),
        }
    }

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

    #[test]
    fn refresh_reports_the_worker_terminal_error() {
        let transport = stopped_transport(Some("managed transport stopped: verification failed"));

        let error = transport
            .refresh_bundle()
            .expect_err("a stopped transport must reject refresh");

        assert_eq!(
            error.to_string(),
            "managed transport stopped: verification failed"
        );
    }

    #[test]
    fn close_marks_a_transport_without_a_worker_as_closed() {
        let mut transport = stopped_transport(None);

        transport.close();

        let error = transport
            .refresh_bundle()
            .expect_err("a closed transport must reject refresh");
        assert_eq!(error.to_string(), "managed transport is closed");
    }
}
