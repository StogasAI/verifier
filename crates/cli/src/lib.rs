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

pub use stogas_verifier::evidence::{Error, Snapshot, Verifier};

pub mod encrypted_client;
pub mod encrypted_http;
pub mod encrypted_setup;
pub mod evidence_client;
pub mod http2_pool;
pub mod native_http;
pub mod native_tls;
mod proxy;
pub mod receipt_http;

const MAX_MANAGED_RESPONSE_LINE_BYTES: usize = 8 * 1024;
const MAX_MANAGED_ERROR_BYTES: usize = 8 * 1024;

pub use stogas_verifier::approvals::Environment;

/// The two independently verified transport profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SecurityMode {
    /// Fresh attestation in TLS 1.3 with mandatory hybrid key exchange.
    Tls,
    /// Reusable, forward-secret hybrid encryption over ordinary HTTPS.
    E2ee,
}

#[derive(Clone, Debug)]
pub struct TransportOptions {
    pub environment: Environment,
    pub security: SecurityMode,
    /// Maximum reusable connections or E2EE sessions. Opened lazily under capacity pressure.
    pub max_connections: usize,
    /// Optional HTTPS origin; compiled evidence authorities remain fixed.
    pub base_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub transport: TransportOptions,
    /// Loopback listener address.
    pub listen: String,
    /// One optional browser origin allowed to use the capability-protected local endpoint.
    pub browser_origin: Option<String>,
    /// Close when a supervising parent's stdin pipe closes.
    pub exit_on_stdin_close: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            environment: Environment::Production,
            security: SecurityMode::Tls,
            max_connections: 4,
            base_url: None,
        }
    }
}
impl TransportOptions {
    fn validate(&self) -> Result<()> {
        if self.max_connections == 0 {
            bail!("max_connections must be positive");
        }
        Ok(())
    }
}

/// A managed Rust transport running inside the caller's process.
///
/// The SDK returns a capability-protected loopback base URL so existing OpenAI-compatible clients
/// keep their native request and response types while Rust owns fresh attestation, evidence recovery,
/// encrypted streaming and receipt verification.
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
        let config = proxy::ServeConfig::new(options, "127.0.0.1:0", None)?;
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
                            ready_tx.send(Err(anyhow::anyhow!(message.clone()))).map_err(|_| {
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
                return Err(error);
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
    /// Returns `true` when the verified bundle contents changed.
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
        // Finalizers cannot wait on networking. The worker owns its bounded shutdown;
        // callers that need to wait for it use close().
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Run the optional foreground transport frontend.
///
/// # Errors
///
/// Returns an error when configuration, initial evidence verification, listener binding, or the
/// transport runtime fails.
pub async fn serve(options: ServeOptions) -> Result<()> {
    proxy::serve(
        proxy::ServeConfig::new(
            &options.transport,
            &options.listen,
            options.browser_origin.as_deref(),
        )?,
        options.exit_on_stdin_close,
    )
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
    fn connection_preference_requires_a_positive_maximum() {
        assert!(TransportOptions::default().validate().is_ok());
        assert!(
            TransportOptions {
                max_connections: 0,
                ..TransportOptions::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn drop_signals_shutdown_without_waiting_but_explicit_close_waits_for_cleanup() {
        let (shutdown, stopped) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let worker = thread::spawn(move || {
            stopped.blocking_recv().unwrap();
            // The caller releases us only after Drop returns. A blocking finalizer fails
            // this assertion rather than leaving the test hung indefinitely.
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            finished.send(()).unwrap();
        });
        let mut transport = stopped_transport(None);
        transport.shutdown = Some(shutdown);
        transport.thread = Some(worker);
        drop(transport);
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();

        let (shutdown, stopped) = oneshot::channel();
        let (finished, completion) = mpsc::channel();
        let mut transport = stopped_transport(None);
        transport.shutdown = Some(shutdown);
        transport.thread = Some(thread::spawn(move || {
            stopped.blocking_recv().unwrap();
            finished.send(()).unwrap();
        }));
        transport.close();
        completion.try_recv().unwrap();
        transport.close();
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
