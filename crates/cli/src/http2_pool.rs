//! Bounded HTTP/2 connections. The connector owns authentication. Submitted requests
//! are never replayed, and channel selection respects the peer's stream capacity.
use axum::http::{Request, Response};
use futures_util::{future::BoxFuture, task::AtomicWaker};
use http_body_util::Full;
use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    client::conn::http2,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    future::{Future, poll_fn},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::{Instant, timeout_at},
};

const SETUP_BUDGET: Duration = Duration::from_secs(15);

/// Caller resource preferences, independent of gateway quotas. No permanent spare is opened.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub connections: NonZeroUsize,
    pub waiting_requests: NonZeroUsize,
    pub waiting_bytes: NonZeroUsize,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP/2 pool is closed")]
    Closed,
    #[error("HTTP/2 pool wait budget is full")]
    Capacity,
    #[error("HTTP/2 setup or wait deadline expired before submission")]
    Deadline,
    #[error("HTTP/2 response deadline expired; execution is unknown")]
    ResponseDeadline,
    #[error("HTTP/2 pool state is unavailable")]
    State,
    #[error("connection setup failed: {0}")]
    Connect(Box<dyn std::error::Error + Send + Sync>),
    #[error("HTTP/2 setup failed: {0}")]
    Protocol(#[from] hyper::Error),
    #[error("HTTP/2 request failed: {source}")]
    Request {
        #[source]
        source: hyper::Error,
        /// True only when Hyper returns the unsubmitted request. Otherwise execution is unknown.
        not_sent: bool,
    },
    #[error("HTTP/2 close deadline expired")]
    CloseDeadline,
}
type Upload = OwnedBody<Full<Bytes>>;
type Connect<M> =
    dyn Fn(Instant) -> BoxFuture<'static, Result<Arc<Channel<M>>, Error>> + Send + Sync;
struct State<M> {
    channels: Vec<Arc<Channel<M>>>,
    connecting: bool,
    closed: bool,
    waiting_requests: usize,
    waiting_bytes: usize,
}
struct Inner<M> {
    state: Mutex<State<M>>,
    changed: Arc<Notify>,
    closing: Notify,
    limits: Limits,
    connect: Box<Connect<M>>,
}
/// Clones share setup and queue accounting. Dropping the last owner never blocks on network I/O.
pub struct Pool<M> {
    inner: Arc<Inner<M>>,
}
impl<M> Clone for Pool<M> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
struct Activity {
    active: AtomicUsize,
    maximum: AtomicUsize,
    retired: AtomicBool,
    finished: AtomicBool,
    force_close: AtomicBool,
    read: AtomicWaker,
    write: AtomicWaker,
    observer: AtomicWaker,
    changed: Arc<Notify>,
}
struct Channel<M> {
    sender: Mutex<Option<http2::SendRequest<Upload>>>,
    metadata: Arc<M>,
    activity: Arc<Activity>,
}
impl<M> Drop for Channel<M> {
    fn drop(&mut self) {
        self.activity.force_close();
    }
}
impl<M: Send + Sync + 'static> Pool<M> {
    /// The connector must finish authentication before returning the stream and its context.
    pub fn new<T, F, Fut>(limits: Limits, connect: F) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(Instant) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(T, M), Error>> + Send + 'static,
    {
        let changed = Arc::new(Notify::new());
        let notify = Arc::clone(&changed);
        let connect = Arc::new(connect);
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    channels: Vec::new(),
                    connecting: false,
                    closed: false,
                    waiting_requests: 0,
                    waiting_bytes: 0,
                }),
                changed,
                closing: Notify::new(),
                limits,
                connect: Box::new(move |deadline| {
                    let connect = Arc::clone(&connect);
                    let changed = Arc::clone(&notify);
                    Box::pin(async move {
                        let deadline = deadline.min(Instant::now() + SETUP_BUDGET);
                        timeout_at(deadline, async {
                            let (io, metadata) = connect(deadline).await?;
                            Channel::open(io, metadata, changed, deadline).await
                        })
                        .await
                        .map_err(|_| Error::Deadline)?
                    })
                }),
            }),
        }
    }
    /// Reserve a stream before handing credentials or input to HTTP. Queue accounting includes
    /// caller-retained input. Cancellation releases the wait and its establishment ownership.
    ///
    /// # Errors
    /// Returns setup, queue capacity, closure or deadline errors before submission.
    pub async fn acquire(
        &self,
        retained_bytes: usize,
        deadline: Instant,
    ) -> Result<Permit<M>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let _waiting = Waiting::new(Arc::clone(&self.inner), retained_bytes)?;
        timeout_at(deadline, async {
            loop {
                let notified = self.inner.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let closing = self.inner.closing.notified();
                tokio::pin!(closing);
                closing.as_mut().enable();
                let establish = {
                    let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
                    if state.closed {
                        return Err(Error::Closed);
                    }
                    state
                        .channels
                        .retain(|channel| !channel.activity.finished.load(Ordering::Acquire));
                    let mut eligible: Vec<_> = state
                        .channels
                        .iter()
                        .filter(|channel| {
                            !channel.activity.retired.load(Ordering::Acquire)
                                && channel.activity.active.load(Ordering::Acquire)
                                    < channel.activity.maximum.load(Ordering::Acquire)
                        })
                        .collect();
                    eligible.sort_by_key(|channel| channel.activity.active.load(Ordering::Acquire));
                    for channel in eligible {
                        let sender = channel.sender.lock().map_err(|_| Error::State)?;
                        if let Some(sender) = sender.as_ref().filter(|sender| !sender.is_closed()) {
                            channel.activity.active.fetch_add(1, Ordering::AcqRel);
                            return Ok(Permit {
                                sender: sender.clone(),
                                metadata: Arc::clone(&channel.metadata),
                                lease: Lease {
                                    activity: Arc::clone(&channel.activity),
                                    context: channel.metadata.clone(),
                                },
                            });
                        }
                        drop(sender);
                        channel.activity.retired.store(true, Ordering::Release);
                    }
                    let serving = state
                        .channels
                        .iter()
                        .filter(|channel| !channel.activity.retired.load(Ordering::Acquire))
                        .count();
                    if !state.connecting
                        && serving < self.inner.limits.connections.get()
                        && state.channels.len() <= self.inner.limits.connections.get()
                    {
                        state.connecting = true;
                        true
                    } else {
                        false
                    }
                };
                if establish {
                    let owner = Establishment {
                        inner: Arc::clone(&self.inner),
                    };
                    let channel = tokio::select! {
                        biased;
                        () = &mut closing => return Err(Error::Closed),
                        result = (self.inner.connect)(deadline) => result?,
                    };
                    {
                        let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
                        if state.closed {
                            return Err(Error::Closed);
                        }
                        state.channels.push(channel);
                    }
                    drop(owner);
                } else {
                    notified.await;
                }
            }
        })
        .await
        .map_err(|_| Error::Deadline)?
    }
    /// Stop assignments, let owned streams finish, then close TLS normally. The deadline aborts
    /// remaining connections; no background task or finalizer blocks the caller indefinitely.
    ///
    /// # Errors
    /// Returns a state error or a close deadline after forcing remaining sockets closed.
    pub async fn close(&self, deadline: Instant) -> Result<(), Error> {
        {
            let mut state = self.inner.state.lock().map_err(|_| Error::State)?;
            state.closed = true;
            for channel in &state.channels {
                channel.activity.retired.store(true, Ordering::Release);
                channel.sender.lock().map_err(|_| Error::State)?.take();
            }
        }
        self.inner.changed.notify_waiters();
        self.inner.closing.notify_waiters();
        let result = timeout_at(deadline, async {
            loop {
                let notified = self.inner.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let state = self.inner.state.lock().map_err(|_| Error::State)?;
                    if !state.connecting
                        && state
                            .channels
                            .iter()
                            .all(|channel| channel.activity.finished.load(Ordering::Acquire))
                    {
                        return Ok(());
                    }
                }
                notified.await;
            }
        })
        .await;
        if let Ok(result) = result {
            result
        } else {
            let state = self.inner.state.lock().map_err(|_| Error::State)?;
            for channel in &state.channels {
                channel.activity.force_close();
            }
            drop(state);
            Err(Error::CloseDeadline)
        }
    }
}
impl<M: Send + Sync + 'static> Channel<M> {
    async fn open<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        io: T,
        metadata: M,
        changed: Arc<Notify>,
        deadline: Instant,
    ) -> Result<Arc<Self>, Error> {
        let activity = Arc::new(Activity {
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            retired: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            force_close: AtomicBool::new(false),
            read: AtomicWaker::new(),
            write: AtomicWaker::new(),
            observer: AtomicWaker::new(),
            changed,
        });
        let io = OwnedIo {
            io,
            activity: Arc::clone(&activity),
        };
        let (sender, mut connection) = http2::Builder::new(TokioExecutor::new())
            .initial_max_send_streams(0)
            .handshake(TokioIo::new(io))
            .await?;
        let channel = Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            metadata: Arc::new(metadata),
            activity: Arc::clone(&activity),
        });
        let weak = Arc::downgrade(&channel);
        tokio::spawn(async move {
            let _ = poll_fn(|cx| {
                activity.observer.register(cx.waker());
                let result = Pin::new(&mut connection).poll(cx);
                let maximum = connection.current_max_send_streams();
                if activity.maximum.swap(maximum, Ordering::AcqRel) != maximum {
                    activity.changed.notify_waiters();
                }
                if let Some(channel) = weak.upgrade()
                    && let Ok(sender) = channel.sender.lock()
                    && sender.as_ref().is_some_and(http2::SendRequest::is_closed)
                    && !activity.retired.swap(true, Ordering::AcqRel)
                {
                    activity.changed.notify_waiters();
                }
                result
            })
            .await;
            activity.retired.store(true, Ordering::Release);
            activity.changed.notify_waiters();
        });
        timeout_at(deadline, async {
            loop {
                let notified = channel.activity.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if channel.activity.finished.load(Ordering::Acquire) {
                    return Err(Error::Closed);
                }
                if channel.activity.maximum.load(Ordering::Acquire) > 0 {
                    return Ok(());
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| Error::Deadline)??;
        Ok(channel)
    }
}
// Hyper's dispatcher can finish on GOAWAY while its separate HTTP/2 I/O task still
// serves responses. Count actual I/O ownership, not the dispatch future's lifetime.
struct OwnedIo<T> {
    io: T,
    activity: Arc<Activity>,
}
impl Activity {
    fn force_close(&self) {
        self.force_close.store(true, Ordering::Release);
        self.read.wake();
        self.write.wake();
    }
    fn poll_io(&self, cx: &Context<'_>, waker: &AtomicWaker) -> std::io::Result<()> {
        waker.register(cx.waker());
        if self.force_close.load(Ordering::Acquire) {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "HTTP/2 pool closed",
            ))
        } else {
            Ok(())
        }
    }
}
impl<T> Drop for OwnedIo<T> {
    fn drop(&mut self) {
        self.activity.finished.store(true, Ordering::Release);
        self.activity.changed.notify_waiters();
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for OwnedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.activity.poll_io(cx, &self.activity.read)?;
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buffer);
        // The separate Hyper I/O task processes SETTINGS/GOAWAY. Wake the pool's
        // dispatcher observer after input so idle pools see the changed state too.
        if matches!(result, Poll::Ready(_)) && buffer.filled().len() != before {
            self.activity.observer.wake();
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for OwnedIo<T> {
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.activity.poll_io(cx, &self.activity.write)?;
        Pin::new(&mut self.io).poll_write_vectored(cx, buffers)
    }
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.activity.poll_io(cx, &self.activity.write)?;
        Pin::new(&mut self.io).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.activity.poll_io(cx, &self.activity.write)?;
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.activity.poll_io(cx, &self.activity.write)?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct Waiting<M> {
    inner: Arc<Inner<M>>,
    bytes: usize,
}
impl<M> Waiting<M> {
    fn new(inner: Arc<Inner<M>>, bytes: usize) -> Result<Self, Error> {
        {
            let mut state = inner.state.lock().map_err(|_| Error::State)?;
            if state.closed {
                return Err(Error::Closed);
            }
            if state.waiting_requests >= inner.limits.waiting_requests.get()
                || bytes
                    > inner
                        .limits
                        .waiting_bytes
                        .get()
                        .saturating_sub(state.waiting_bytes)
            {
                return Err(Error::Capacity);
            }
            state.waiting_requests += 1;
            state.waiting_bytes += bytes;
        }
        Ok(Self { inner, bytes })
    }
}
impl<M> Drop for Waiting<M> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.waiting_requests -= 1;
            state.waiting_bytes -= self.bytes;
        }
    }
}
struct Establishment<M> {
    inner: Arc<Inner<M>>,
}
impl<M> Drop for Establishment<M> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.connecting = false;
        }
        self.inner.changed.notify_waiters();
    }
}
struct Lease {
    activity: Arc<Activity>,
    context: Arc<dyn Send + Sync>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.activity.active.fetch_sub(1, Ordering::AcqRel);
        self.activity.changed.notify_waiters();
    }
}
/// The selected stream and immutable authentication context. An unused permit sends nothing.
pub struct Permit<M> {
    sender: http2::SendRequest<Upload>,
    pub metadata: Arc<M>,
    lease: Lease,
}
impl<M: Send + Sync + 'static> Permit<M> {
    /// Retain the request's appraised context through upload and response consumption.
    pub fn retain_context<C: Send + Sync + 'static>(&mut self, context: Arc<C>) {
        self.lease.context = context;
    }

    /// Submit once. Disconnects, resets and GOAWAY races never cause automatic replay.
    /// The deadline covers response headers; the consumer owns the response body's deadline.
    /// Authentication context remains in the response extensions and body ownership.
    ///
    /// # Errors
    /// Returns an explicit unsubmitted error, or a transport/response timeout with unknown execution.
    pub async fn send(
        mut self,
        request: Request<Bytes>,
        deadline: Instant,
    ) -> Result<Response<OwnedBody<Incoming>>, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        if self.lease.activity.retired.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let lease = Arc::new(self.lease);
        let request = request.map(|body| OwnedBody {
            body: Full::new(body),
            lease: Some(Arc::clone(&lease)),
        });
        let mut response = timeout_at(deadline, self.sender.try_send_request(request))
            .await
            .map_err(|_| Error::ResponseDeadline)?
            .map_err(|mut error| {
                let not_sent = error.take_message().is_some();
                Error::Request {
                    source: error.into_error(),
                    not_sent,
                }
            })?;
        response.extensions_mut().insert(Arc::clone(&self.metadata));
        Ok(response.map(|body| OwnedBody {
            body,
            lease: Some(lease),
        }))
    }
}
/// Holds the slot until the real body ends or is dropped, including upload and response overlap.
pub struct OwnedBody<B> {
    body: B,
    lease: Option<Arc<Lease>>,
}
impl<B: Body + Unpin> Body for OwnedBody<B> {
    type Data = B::Data;
    type Error = B::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) || self.body.is_end_stream() {
            self.lease.take();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
#[cfg(test)]
mod tests;
