use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
use tokio_rustls::client::TlsStream;

// A minimum spacing for discretionary privacy updates, not a deadline or cipher
// usage limit. Rustls separately enforces its cryptographic usage limits.
const KEY_UPDATE_INTERVAL: Duration = Duration::from_mins(1);

#[cfg(test)]
mod benchmark;

/// A verified TLS stream that includes standard key updates with normal writes.
///
/// No timer, idle traffic, or wait for a peer acknowledgement. After sixty seconds,
/// the next nonempty write queues an update before its application bytes, provided
/// both directions have made progress since the preceding update. This prevents
/// repeated control-only updates from exhausting the peer's protocol limits.
/// It does not promise erasure at request completion or a fixed key lifetime.
pub struct TrafficStream<T> {
    stream: TlsStream<T>,
    updated_at: Instant,
    read: bool,
    written: bool,
}

impl<T> TrafficStream<T> {
    pub(crate) fn new(stream: TlsStream<T>) -> Self {
        Self {
            stream,
            updated_at: Instant::now(),
            read: false,
            written: false,
        }
    }

    /// Inspect the transport and negotiated TLS state without bypassing key updates.
    pub fn get_ref(&self) -> (&T, &rustls::ClientConnection) {
        self.stream.get_ref()
    }

    fn before_write(&mut self) -> io::Result<()> {
        if self.read && self.written && self.updated_at.elapsed() >= KEY_UPDATE_INTERVAL {
            self.stream
                .get_mut()
                .1
                .refresh_traffic_keys()
                .map_err(io::Error::other)?;
            self.read = false;
            self.written = false;
            self.updated_at = Instant::now();
        }
        Ok(())
    }

    const fn wrote(&mut self, result: &Poll<io::Result<usize>>) {
        if matches!(result, Poll::Ready(Ok(n)) if *n > 0) {
            self.written = true;
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrafficStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.read = true;
        }
        result
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrafficStream<T> {
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !buf.is_empty() {
            self.before_write()?;
        }
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        self.wrote(&result);
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().any(|buf| !buf.is_empty()) {
            self.before_write()?;
        }
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        self.wrote(&result);
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
