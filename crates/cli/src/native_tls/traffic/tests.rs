use super::*;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Wire {
    io: DuplexStream,
    bytes: Arc<AtomicUsize>,
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.bytes.fetch_add(n, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn pair() -> (
    TrafficStream<Wire>,
    tokio_rustls::server::TlsStream<Wire>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["gateway.test".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let provider = Arc::new(provider);
    let mut server = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.send_tls13_tickets = 0;
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let (a, b) = tokio::io::duplex(4096);
    let sent = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let (client, server) = tokio::join!(
        TlsConnector::from(Arc::new(client)).connect(
            ServerName::try_from("gateway.test").unwrap(),
            Wire {
                io: a,
                bytes: sent.clone()
            }
        ),
        TlsAcceptor::from(Arc::new(server)).accept(Wire {
            io: b,
            bytes: received.clone()
        })
    );
    (
        TrafficStream::new(client.unwrap()),
        server.unwrap(),
        sent,
        received,
    )
}

// Drive both read halves without introducing application data. A standard key
// update and its reply must stay invisible to their application readers.
fn poll_control(
    client: &mut TrafficStream<Wire>,
    server: &mut tokio_rustls::server::TlsStream<Wire>,
) {
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..4 {
        let mut bytes = [0; 1];
        assert!(
            Pin::new(&mut *client)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        assert!(
            Pin::new(&mut *server)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        assert!(Pin::new(&mut *server).poll_flush(&mut cx).is_ready());
    }
}

async fn exchange(
    client: &mut TrafficStream<Wire>,
    server: &mut tokio_rustls::server::TlsStream<Wire>,
) {
    let request = [io::IoSlice::new(b"request"), io::IoSlice::new(b" data")];
    let n = client.write_vectored(&request).await.unwrap();
    assert!(n > 0);
    let mut data = vec![0; n];
    client.flush().await.unwrap();
    server.read_exact(&mut data).await.unwrap();
    assert_eq!(data, b"request data"[..n]);
    server.write_all(b"response").await.unwrap();
    server.flush().await.unwrap();
    let mut response = [0; 8];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
}

#[tokio::test(start_paused = true)]
async fn updates_travel_with_normal_writes_without_waiting_for_a_reply() {
    use futures_util::FutureExt as _;
    let (mut client, mut server, sent, received) = pair().await;
    exchange(&mut client, &mut server).await;
    let before = (sent.load(Ordering::SeqCst), received.load(Ordering::SeqCst));
    tokio::time::advance(KEY_UPDATE_INTERVAL).await;
    // Waiting readers, flushes and empty writes must never initiate an update.
    for _ in 0..64 {
        tokio::time::advance(KEY_UPDATE_INTERVAL).await;
        poll_control(&mut client, &mut server);
        client.write_all(&[]).await.unwrap();
        assert_eq!(
            client
                .write_vectored(&[io::IoSlice::new(&[])])
                .await
                .unwrap(),
            0
        );
        client.flush().await.unwrap();
    }
    assert_eq!(
        before,
        (sent.load(Ordering::SeqCst), received.load(Ordering::SeqCst))
    );
    // The peer has not been polled. Both the update and payload must be sent
    // without waiting for its reply; one four-byte data record costs 26 bytes.
    let n = client
        .write_vectored(&[io::IoSlice::new(b"next")])
        .now_or_never()
        .expect("an update must not add a wait for the peer")
        .unwrap();
    assert_eq!(n, 4);
    client.flush().now_or_never().unwrap().unwrap();
    assert_eq!(sent.load(Ordering::SeqCst) - before.0, 27 + 26);
    let mut next = [0; 4];
    server.read_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"next");
    // The peer replies before its next payload; decryption proves agreement.
    server.write_all(b"reply").await.unwrap();
    server.flush().await.unwrap();
    let mut reply = [0; 5];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
    assert_eq!(received.load(Ordering::SeqCst) - before.1, 27 + 27);
    let before = sent.load(Ordering::SeqCst);
    client.write_all(b"more").await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        sent.load(Ordering::SeqCst) - before,
        26,
        "warm writes before the spacing limit add no update"
    );
    server.read_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"more");
    tokio::time::advance(KEY_UPDATE_INTERVAL).await;
    let before = sent.load(Ordering::SeqCst);
    client.shutdown().await.unwrap();
    assert_eq!(
        sent.load(Ordering::SeqCst) - before,
        24,
        "closing adds only close_notify"
    );
    assert_eq!(server.read(&mut next).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn waiting_readers_and_one_way_streams_never_initiate_updates() {
    let (mut client, mut server, sent, _) = pair().await;
    exchange(&mut client, &mut server).await;
    let before = sent.load(Ordering::SeqCst);
    let waiting = tokio::spawn(async move {
        let mut byte = [0; 1];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [42]);
        client
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_hours(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        before,
        "an idle reader must not initiate network traffic"
    );
    server.write_all(&[42]).await.unwrap();
    server.flush().await.unwrap();
    let mut client = waiting.await.unwrap();
    for _ in 0..64 {
        tokio::time::advance(KEY_UPDATE_INTERVAL).await;
        server.write_all(&[43]).await.unwrap();
        server.flush().await.unwrap();
        let mut byte = [0; 1];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [43]);
    }
    assert_eq!(sent.load(Ordering::SeqCst), before);
    // Sending again can rotate; subsequent one-way writes cannot repeatedly
    // request updates when the peer has returned no further application data.
    client.write_all(b"x").await.unwrap();
    client.flush().await.unwrap();
    let mut byte = [0; 1];
    server.read_exact(&mut byte).await.unwrap();
    let before = sent.load(Ordering::SeqCst);
    for _ in 0..64 {
        tokio::time::advance(KEY_UPDATE_INTERVAL).await;
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        server.read_exact(&mut byte).await.unwrap();
    }
    assert_eq!(sent.load(Ordering::SeqCst) - before, 64 * 23);
}

#[tokio::test(start_paused = true)]
async fn a_blocked_update_write_does_not_block_reading_or_corrupt_pending_upload() {
    let (mut client, mut server, _, _) = pair().await;
    exchange(&mut client, &mut server).await;
    // Fill the small transport before the peer reads, leaving TLS output pending.
    let body = vec![7; 32 * 1024];
    let accepted = client.write(&body).await.unwrap();
    assert!(accepted > 4096);
    tokio::time::advance(KEY_UPDATE_INTERVAL).await;
    let suffix = client.write(b"suffix").await.unwrap();
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
    // An independently writable response must still reach its consumer.
    server.write_all(b"progress").await.unwrap();
    server.flush().await.unwrap();
    let mut progress = [0; 8];
    client.read_exact(&mut progress).await.unwrap();
    assert_eq!(&progress, b"progress");
    let mut received = vec![0; accepted + suffix];
    let (flush, read) = tokio::join!(client.flush(), server.read_exact(&mut received));
    flush.unwrap();
    read.unwrap();
    assert_eq!(received[..accepted], body[..accepted]);
    assert_eq!(&received[accepted..], &b"suffix"[..suffix]);
    poll_control(&mut client, &mut server);
    exchange(&mut client, &mut server).await;
}

#[tokio::test(start_paused = true)]
async fn key_update_preserves_two_unfinished_http2_responses() {
    use tokio::sync::oneshot;
    let (client, server, sent, _) = pair().await;
    let (finish, finished) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let mut responses = Vec::new();
        for _ in 0..3 {
            let (_, mut response) = connection.accept().await.unwrap().unwrap();
            let mut body = response
                .send_response(hyper::Response::new(()), false)
                .unwrap();
            body.send_data(hyper::body::Bytes::from_static(b"before"), false)
                .unwrap();
            responses.push(body);
        }
        // Keep servicing TLS/H2 while neither inference has finished.
        tokio::select! {
            _ = finished => {},
            request = connection.accept() => panic!("unexpected request/closure: {request:?}"),
        }
        for mut body in responses {
            body.send_data(hyper::body::Bytes::from_static(b"after"), true)
                .unwrap();
        }
        while let Some(request) = connection.accept().await {
            request.unwrap();
        }
    });
    let (mut requests, driver) = h2::client::handshake(client).await.unwrap();
    let client_task = tokio::spawn(driver);
    let mut responses = Vec::new();
    for _ in 0..2 {
        let request = hyper::Request::builder()
            .uri("https://gateway.test/")
            .body(())
            .unwrap();
        let (response, _) = requests.send_request(request, true).unwrap();
        responses.push(response.await.unwrap().into_body());
    }
    for body in &mut responses {
        assert_eq!(body.data().await.unwrap().unwrap(), b"before"[..]);
    }
    let before = sent.load(Ordering::SeqCst);
    tokio::time::advance(KEY_UPDATE_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        before,
        "silence does not initiate updates"
    );
    let request = hyper::Request::builder()
        .uri("https://gateway.test/")
        .body(())
        .unwrap();
    let (response, _) = requests.send_request(request, true).unwrap();
    let mut body = response.await.unwrap().into_body();
    assert_eq!(body.data().await.unwrap().unwrap(), b"before"[..]);
    responses.push(body);
    assert!(sent.load(Ordering::SeqCst) > before + 27);
    finish.send(()).unwrap();
    for body in &mut responses {
        assert_eq!(body.data().await.unwrap().unwrap(), b"after"[..]);
        assert!(body.data().await.is_none());
    }
    drop(responses);
    drop(requests);
    client_task.abort();
    let _ = client_task.await;
    server_task.await.unwrap();
}
