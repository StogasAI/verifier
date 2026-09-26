use super::*;
use http_body_util::BodyExt as _;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

struct Started {
    channel: usize,
    path: String,
    body: h2::RecvStream,
    response: h2::server::SendResponse<Bytes>,
}
impl Started {
    fn respond(mut self, bytes: &'static [u8], finish: bool) -> h2::SendStream<Bytes> {
        let mut stream = self
            .response
            .send_response(Response::new(()), false)
            .unwrap();
        stream.send_data(Bytes::from_static(bytes), finish).unwrap();
        stream
    }
}
enum Command {
    Goaway,
    Disconnect,
}
struct Harness {
    started: mpsc::UnboundedReceiver<Started>,
    commands: Arc<Mutex<Vec<mpsc::UnboundedSender<Command>>>>,
    calls: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn limits(connections: usize) -> Limits {
    Limits {
        connections: NonZeroUsize::new(connections).unwrap(),
        waiting_requests: NonZeroUsize::new(4).unwrap(),
        waiting_bytes: NonZeroUsize::new(1024).unwrap(),
    }
}
fn harness(connections: usize, streams: u32) -> (Pool<usize>, Harness) {
    let (started_tx, started) = mpsc::unbounded_channel();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    let pool = Pool::new(limits(connections), {
        let calls = Arc::clone(&calls);
        let commands = Arc::clone(&commands);
        let live = Arc::clone(&live);
        move |_| {
            let number = calls.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(1024 * 1024);
            let (command, mut command_rx) = mpsc::unbounded_channel();
            commands.lock().unwrap().push(command);
            let started = started_tx.clone();
            let live = Arc::clone(&live);
            tokio::spawn(async move {
                live.fetch_add(1, Ordering::SeqCst);
                let mut server = h2::server::Builder::new()
                    .max_concurrent_streams(streams)
                    .handshake(server)
                    .await
                    .unwrap();
                loop {
                    tokio::select! {
                        command = command_rx.recv() => match command {
                            Some(Command::Goaway) => server.graceful_shutdown(),
                            Some(Command::Disconnect) | None => break,
                        },
                        request = server.accept() => match request {
                            Some(Ok((request, response))) => {
                                let (parts, body) = request.into_parts();
                                if started.send(Started { channel: number, path: parts.uri.path().to_owned(), body, response }).is_err() { break; }
                            },
                            Some(Err(_)) | None => break,
                        },
                    }
                }
                live.fetch_sub(1, Ordering::SeqCst);
            });
            async move { Ok((client, number)) }
        }
    });
    (
        pool,
        Harness {
            started,
            commands,
            calls,
            live,
        },
    )
}
async fn start(
    pool: &Pool<usize>,
    path: &str,
) -> tokio::task::JoinHandle<Result<Response<OwnedBody<Incoming>>, Error>> {
    let permit = pool.acquire(1, deadline()).await.unwrap();
    let request = Request::builder()
        .uri(format!("https://gateway.test{path}"))
        .body(Bytes::new())
        .unwrap();
    tokio::spawn(permit.send(request, deadline()))
}
async fn next(harness: &mut Harness) -> Started {
    timeout_at(deadline(), harness.started.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn until(mut condition: impl FnMut() -> bool) {
    timeout_at(deadline(), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grows_only_at_peer_capacity_and_keeps_response_body_ownership() {
    let (pool, mut server) = harness(2, 2);
    let a = start(&pool, "/a").await;
    let a_seen = next(&mut server).await;
    let b = start(&pool, "/b").await;
    let b_seen = next(&mut server).await;
    assert_eq!((a_seen.channel, b_seen.channel), (0, 0));
    let c = start(&pool, "/c").await;
    let c_seen = next(&mut server).await;
    assert_eq!(c_seen.channel, 1);
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    let a_stream = a_seen.respond(b"a", false);
    let a_response = a.await.unwrap().unwrap();
    let d = start(&pool, "/d").await;
    let d_seen = next(&mut server).await;
    assert_eq!(
        d_seen.channel, 1,
        "headers must not release the active response slot"
    );
    let waiting = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().waiting_requests == 1).await;
    assert!(!waiting.is_finished());
    drop(a_response);
    drop(a_stream);
    let permit = waiting.await.unwrap().unwrap();
    assert_eq!(*permit.metadata, 0);
    drop(permit);
    for response in [b_seen, c_seen, d_seen] {
        response.respond(b"done", true);
    }
    for handle in [b, c, d] {
        assert_eq!(
            handle
                .await
                .unwrap()
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "done"
        );
    }
    pool.close(deadline()).await.unwrap();
    until(|| server.live.load(Ordering::SeqCst) == 0).await;
    assert!(matches!(
        pool.acquire(1, deadline()).await,
        Err(Error::Closed)
    ));
}

#[tokio::test]
async fn goaway_finishes_existing_work_and_opens_only_one_temporary_overlap() {
    let (pool, mut server) = harness(1, 1);
    let a = start(&pool, "/old").await;
    let old = next(&mut server).await;
    server.commands.lock().unwrap()[0]
        .send(Command::Goaway)
        .unwrap();
    until(|| {
        pool.inner.state.lock().unwrap().channels[0]
            .activity
            .retired
            .load(Ordering::Acquire)
    })
    .await;
    let b = start(&pool, "/new").await;
    let new = next(&mut server).await;
    assert_eq!(
        (old.path.as_str(), old.channel, new.channel),
        ("/old", 0, 1)
    );
    server.commands.lock().unwrap()[1]
        .send(Command::Goaway)
        .unwrap();
    until(|| {
        pool.inner.state.lock().unwrap().channels[1]
            .activity
            .retired
            .load(Ordering::Acquire)
    })
    .await;
    let pending = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().waiting_requests == 1).await;
    assert_eq!(
        server.calls.load(Ordering::SeqCst),
        2,
        "successive GOAWAY must not accumulate draining sockets"
    );
    old.respond(b"old finished", true);
    assert_eq!(
        a.await
            .unwrap()
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        "old finished"
    );
    drop(pending.await.unwrap().unwrap());
    assert_eq!(server.calls.load(Ordering::SeqCst), 3);
    new.respond(b"new finished", true);
    assert_eq!(
        b.await
            .unwrap()
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        "new finished"
    );
    pool.close(deadline()).await.unwrap();
}

#[tokio::test]
async fn cancellation_releases_wait_count_bytes_and_shared_setup_owner() {
    let entered = Arc::new(AtomicUsize::new(0));
    let pool: Pool<()> = Pool::new(limits(1), {
        let entered = Arc::clone(&entered);
        move |_| {
            entered.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<(tokio::io::DuplexStream, ()), Error>>()
        }
    });
    let owner = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1000, deadline()).await }
    });
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    assert!(matches!(
        pool.acquire(25, deadline()).await,
        Err(Error::Capacity)
    ));
    let follower = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(24, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().waiting_requests == 2).await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    owner.abort();
    assert!(matches!(owner.await, Err(error) if error.is_cancelled()));
    until(|| entered.load(Ordering::SeqCst) == 2).await;
    assert_eq!(pool.inner.state.lock().unwrap().waiting_bytes, 24);
    follower.abort();
    assert!(matches!(follower.await, Err(error) if error.is_cancelled()));
    let state = pool.inner.state.lock().unwrap();
    assert_eq!(
        (
            state.waiting_requests,
            state.waiting_bytes,
            state.connecting
        ),
        (0, 0, false)
    );
    drop(state);
}

#[tokio::test]
async fn disconnect_after_dispatch_is_not_replayed_and_later_request_reconnects() {
    let (pool, mut server) = harness(1, 2);
    let request = start(&pool, "/once").await;
    let seen = next(&mut server).await;
    assert!(seen.body.is_end_stream());
    server.commands.lock().unwrap()[0]
        .send(Command::Disconnect)
        .unwrap();
    assert!(matches!(
        request.await.unwrap(),
        Err(Error::Request {
            not_sent: false,
            ..
        })
    ));
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    let next_request = start(&pool, "/later").await;
    let seen = next(&mut server).await;
    assert_eq!((seen.channel, seen.path.as_str()), (1, "/later"));
    seen.respond(b"later", true);
    next_request
        .await
        .unwrap()
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    pool.close(deadline()).await.unwrap();
}

#[tokio::test]
async fn close_waits_for_body_completion_then_stops_all_channels() {
    let (pool, mut server) = harness(1, 2);
    let request = start(&pool, "/active").await;
    let seen = next(&mut server).await;
    let mut stream = seen.respond(b"before", false);
    let response = request.await.unwrap().unwrap();
    let close = tokio::spawn({
        let pool = pool.clone();
        async move { pool.close(deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().closed).await;
    assert!(matches!(
        pool.acquire(1, deadline()).await,
        Err(Error::Closed)
    ));
    assert!(!close.is_finished());
    stream
        .send_data(Bytes::from_static(b"after"), true)
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "beforeafter"
    );
    drop(stream);
    close.await.unwrap().unwrap();
    pool.close(deadline()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn setup_deadline_cancels_the_connector_and_does_not_leave_a_waiter() {
    let (tx, mut rx) = oneshot::channel::<()>();
    let owned = Arc::new(Mutex::new(Some(tx)));
    let pool: Pool<()> = Pool::new(limits(1), move |_| {
        let ownership = owned.lock().unwrap().take();
        async move {
            let _ownership = ownership;
            std::future::pending::<Result<(tokio::io::DuplexStream, ()), Error>>().await
        }
    });
    assert!(matches!(
        pool.acquire(1, deadline()).await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        rx.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    let state = pool.inner.state.lock().unwrap();
    assert_eq!(
        (
            state.waiting_requests,
            state.waiting_bytes,
            state.connecting
        ),
        (0, 0, false)
    );
    drop(state);
}

#[tokio::test]
async fn close_cancels_setup_and_prevents_a_reserved_permit_from_submitting() {
    let (pool, mut server) = harness(1, 1);
    let permit = pool.acquire(1, deadline()).await.unwrap();
    let close = tokio::spawn({
        let pool = pool.clone();
        async move { pool.close(deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().closed).await;
    assert!(matches!(
        permit.send(Request::new(Bytes::new()), deadline()).await,
        Err(Error::Closed)
    ));
    close.await.unwrap().unwrap();
    assert!(server.started.try_recv().is_err());

    let pool: Pool<()> = Pool::new(limits(1), |_| {
        std::future::pending::<Result<(tokio::io::DuplexStream, ()), Error>>()
    });
    let setup = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().connecting).await;
    pool.close(deadline()).await.unwrap();
    assert!(matches!(setup.await.unwrap(), Err(Error::Closed)));
}

#[tokio::test]
async fn close_deadline_closes_the_actual_socket_while_a_response_is_stalled() {
    let (pool, mut server) = harness(1, 1);
    let request = start(&pool, "/stalled").await;
    let seen = next(&mut server).await;
    let _stream = seen.respond(b"prefix", false);
    let response = request.await.unwrap().unwrap();
    let context = Arc::downgrade(response.extensions().get::<Arc<usize>>().unwrap());
    assert!(matches!(
        pool.close(Instant::now()).await,
        Err(Error::CloseDeadline)
    ));
    let body = response.into_body();
    drop(pool);
    assert!(
        context.upgrade().is_some(),
        "body must retain its request context after the pool is gone"
    );
    assert!(body.collect().await.is_err());
    until(|| server.live.load(Ordering::SeqCst) == 0).await;
    until(|| context.upgrade().is_none()).await;
}

#[tokio::test]
async fn peer_settings_reduction_and_zero_capacity_stop_assignments_without_reconnecting() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    fn settings(maximum: u32) -> [u8; 15] {
        let mut frame = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        frame[11..].copy_from_slice(&maximum.to_be_bytes());
        frame
    }
    let (updates, receiver) = mpsc::unbounded_channel::<u32>();
    let receiver = Arc::new(Mutex::new(Some(receiver)));
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = Pool::new(limits(1), {
        let calls = Arc::clone(&calls);
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut updates = receiver
                .lock()
                .unwrap()
                .take()
                .expect("must reuse the connection");
            let (client, mut server) = tokio::io::duplex(8192);
            tokio::spawn(async move {
                let mut preface = [0; 24];
                server.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                server.write_all(&settings(2)).await.unwrap();
                let mut input = [0; 4096];
                loop {
                    tokio::select! {
                        update = updates.recv() => match update {
                            Some(maximum) => server.write_all(&settings(maximum)).await.unwrap(),
                            None => break,
                        },
                        result = server.read(&mut input) => if result.unwrap_or(0) == 0 { break; },
                    }
                }
            });
            async move { Ok((client, ())) }
        }
    });
    let a = pool.acquire(1, deadline()).await.unwrap();
    let b = pool.acquire(1, deadline()).await.unwrap();
    updates.send(1).unwrap();
    until(|| {
        pool.inner.state.lock().unwrap().channels[0]
            .activity
            .maximum
            .load(Ordering::Acquire)
            == 1
    })
    .await;
    let wait = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().waiting_requests == 1).await;
    drop(a);
    assert!(!wait.is_finished());
    drop(b);
    let c = wait.await.unwrap().unwrap();
    updates.send(0).unwrap();
    until(|| {
        pool.inner.state.lock().unwrap().channels[0]
            .activity
            .maximum
            .load(Ordering::Acquire)
            == 0
    })
    .await;
    drop(c);
    let wait = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, deadline()).await }
    });
    until(|| pool.inner.state.lock().unwrap().waiting_requests == 1).await;
    assert!(!wait.is_finished());
    updates.send(3).unwrap();
    drop(wait.await.unwrap().unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    pool.close(deadline()).await.unwrap();
}

#[tokio::test]
async fn graceful_pool_close_completes_the_tls_shutdown() {
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let cert = rcgen::generate_simple_self_signed(vec!["gateway.test".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let client = Arc::new(client);
    let server = Arc::new(config);
    let (finished, finish) = oneshot::channel();
    let finished = Arc::new(Mutex::new(Some(finished)));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let observe_shutdown = Arc::clone(&clean_shutdown);
    let pool = Pool::new(limits(1), move |_| {
        let clean_shutdown = Arc::clone(&observe_shutdown);
        let (outgoing, incoming) = tokio::io::duplex(64 * 1024);
        let finished = finished.lock().unwrap().take().unwrap();
        let server = Arc::clone(&server);
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let tls = TlsAcceptor::from(server).accept(incoming).await.unwrap();
            let mut server = h2::server::handshake(tls).await.unwrap();
            while let Some(request) = server.accept().await {
                let (_, mut response) = match request {
                    Ok(value) => value,
                    Err(error)
                        if error
                            .get_io()
                            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe) =>
                    {
                        break;
                    }
                    Err(error) => panic!("unexpected server shutdown error: {error}"),
                };
                response.send_response(Response::new(()), true).unwrap();
            }
            finished.send(()).unwrap();
        });
        async move {
            let tls = TlsConnector::from(client)
                .connect(ServerName::try_from("gateway.test").unwrap(), outgoing)
                .await
                .map_err(|e| Error::Connect(Box::new(e)))?;
            Ok((
                ObserveShutdown {
                    io: tls,
                    completed: clean_shutdown,
                },
                (),
            ))
        }
    });
    let response = pool
        .acquire(0, deadline())
        .await
        .unwrap()
        .send(
            Request::builder()
                .uri("https://gateway.test/")
                .body(Bytes::new())
                .unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    response.into_body().collect().await.unwrap();
    pool.close(deadline()).await.unwrap();
    timeout_at(deadline(), finish).await.unwrap().unwrap();
    assert!(
        clean_shutdown.load(Ordering::SeqCst),
        "the actual TLS stream must complete shutdown before its socket is dropped"
    );
}

struct ObserveShutdown<T> {
    io: T,
    completed: Arc<AtomicBool>,
}
impl<T: AsyncRead + Unpin> AsyncRead for ObserveShutdown<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ObserveShutdown<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.io).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.completed.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[tokio::test(start_paused = true)]
async fn long_request_deadline_does_not_extend_setup_or_restart_it_for_http2_settings() {
    use tokio::io::AsyncReadExt as _;
    let origin = Instant::now();
    let (accepted, mut sockets) = mpsc::unbounded_channel();
    let pool = Pool::new(limits(1), move |deadline| {
        assert_eq!(deadline, origin + SETUP_BUDGET);
        let accepted = accepted.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            let (client, server) = tokio::io::duplex(1024);
            accepted.send(server).unwrap();
            Ok((client, ()))
        }
    });
    let waiting = tokio::spawn({
        let pool = pool.clone();
        async move { pool.acquire(1, origin + Duration::from_hours(1)).await }
    });
    until(|| pool.inner.state.lock().unwrap().connecting).await;
    tokio::time::advance(Duration::from_secs(7)).await;
    let mut server = sockets.recv().await.unwrap();
    let mut preface = [0; 24];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert!(!waiting.is_finished());
    tokio::time::advance(Duration::from_secs(8)).await;
    assert!(matches!(waiting.await.unwrap(), Err(Error::Deadline)));
    {
        let state = pool.inner.state.lock().unwrap();
        assert_eq!(state.waiting_requests, 0);
        assert_eq!(state.waiting_bytes, 0);
        assert!(!state.connecting);
        assert!(state.channels.is_empty());
        drop(state);
    }
    // The peer never sent SETTINGS. Its actual socket must still be closed on expiry.
    server.read_to_end(&mut Vec::new()).await.unwrap();
}
