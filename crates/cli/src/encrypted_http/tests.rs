use super::*;
use aws_lc_rs::{aead, hkdf};
use axum::{Router, body::to_bytes, routing::post};
use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::ExportOnlyAead, kdf::HkdfSha256,
    kem::XWing, setup_sender,
};
use sha2::{Digest as _, Sha256, Sha512};
use std::time::Duration;
use stogas_verifier::{
    approvals::Environment,
    channel::{ClientSession, setup::PendingSetup},
};

// This HTTP test peer creates synthetic hardware bytes solely for transport tests.
// Managed setup uses complete_verified; its genuine-SNP tests reject this evidence.
pub fn session() -> (ClientSession, [u8; 32], [u8; 32]) {
    let mut pending = PendingSetup::new(Environment::Production).unwrap();
    let hello = pending.hello();
    let recipient = <XWing as hpke::Kem>::PublicKey::from_bytes(&hello[39..]).unwrap();
    let info = [b"stogas.e2ee.setup.v1\0".as_slice(), &Sha256::digest(hello)].concat();
    let (enc, sender) =
        setup_sender::<ExportOnlyAead, HkdfSha256, XWing>(&OpModeS::Base, &recipient, &info)
            .unwrap();
    let id = [22; 32];
    let mut response = b"STGS\x01\x02".to_vec();
    response.extend_from_slice(&id);
    response.extend_from_slice(&600_u32.to_be_bytes());
    response.extend_from_slice(&enc.to_bytes());
    let boot = br#"{"synthetic":"HTTP transport test"}"#;
    let boot_digest = Sha256::digest(boot);
    let transcript = Sha256::digest(
        [
            b"stogas.e2ee.transcript.v1\0".as_slice(),
            hello,
            &response,
            &boot_digest,
        ]
        .concat(),
    );
    let leaf = Sha512::digest(
        [
            b"\x00stogas.e2ee-session.v1\0\x01".as_slice(),
            &boot_digest,
            &transcript,
        ]
        .concat(),
    );
    let report_data = Sha512::digest(
        [
            b"stogas.quote-batch.v1\0".as_slice(),
            &1_u16.to_be_bytes(),
            &leaf,
        ]
        .concat(),
    );
    let mut evidence = vec![0_u8; 1184];
    evidence[0x50..0x90].copy_from_slice(&report_data);
    evidence.extend_from_slice(&[0, 4, 0, 1, 0, 0]);
    for field in [boot.as_slice(), b"test inclusion"] {
        evidence.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        evidence.extend_from_slice(field);
    }
    let mut confirmation = [0; 32];
    sender
        .export(
            &[b"stogas.e2ee.confirmation.v1\0".as_slice(), &transcript].concat(),
            &mut confirmation,
        )
        .unwrap();
    let mut root = [0; 32];
    sender
        .export(
            &[b"stogas.e2ee.root.v1\0".as_slice(), &transcript].concat(),
            &mut root,
        )
        .unwrap();
    response.extend_from_slice(&confirmation);
    response.extend_from_slice(&u32::try_from(evidence.len()).unwrap().to_be_bytes());
    response.extend_from_slice(&evidence);
    (pending.complete(&response, |_| Ok(())).unwrap(), root, id)
}

pub struct Records {
    key: aead::LessSafeKey,
    nonce: [u8; 12],
    sequence: u64,
}
impl Records {
    pub(crate) fn new(root: &[u8; 32], id: &[u8; 32], number: u64, direction: u8) -> Self {
        struct Size;
        impl hkdf::KeyType for Size {
            fn len(&self) -> usize {
                44
            }
        }
        let info = [
            b"stogas.e2ee.record.v1\0".as_slice(),
            id,
            &number.to_be_bytes(),
            &[direction],
        ]
        .concat();
        let mut material = [0; 44];
        hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, root)
            .expand(&[&info], Size)
            .unwrap()
            .fill(&mut material)
            .unwrap();
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &material[..32]).unwrap(),
            ),
            nonce: material[32..].try_into().unwrap(),
            sequence: 0,
        }
    }
    fn nonce(&mut self) -> aead::Nonce {
        let mut nonce = self.nonce;
        for (target, source) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *target ^= source;
        }
        self.sequence += 1;
        aead::Nonce::assume_unique_for_key(nonce)
    }
    pub(crate) fn seal(&mut self, kind: Kind, content: &[u8]) -> Vec<u8> {
        let prefix = u32::try_from(content.len() + 21).unwrap().to_be_bytes();
        let mut body = [vec![kind as u8], content.to_vec()].concat();
        let nonce = self.nonce();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(prefix), &mut body)
            .unwrap();
        [prefix.to_vec(), body].concat()
    }
    pub(crate) fn open(&mut self, record: &[u8]) -> (Kind, Vec<u8>) {
        let mut body = record[4..].to_vec();
        let nonce = self.nonce();
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(&record[..4]), &mut body)
            .unwrap();
        (Kind::try_from(plain[0]).unwrap(), plain[1..].to_vec())
    }
}

fn http() -> Client {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    Client::builder()
        .use_preconfigured_tls(config)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
pub struct Server {
    pub(crate) endpoint: Url,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    pub(crate) async fn new(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/session",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        Self {
            endpoint,
            task: tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn binary_upload_streams_bounded_records_and_authenticates_fragmented_response() {
    let (mut session, root, id) = session();
    let request_body = Bytes::from(vec![33; 3 * MAX_RECORD_PLAINTEXT + 13]);
    let expected = request_body.clone();
    let app = Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| {
            let expected = expected.clone();
            async move {
                assert_eq!(request.headers()["stogas-node-id"], "owner");
                assert!(!request.headers().contains_key("authorization"));
                let wire = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                assert_eq!(&wire[..6], b"STGS\x01\x03");
                assert_eq!(&wire[6..38], &id);
                assert_eq!(&wire[38..46], &0_u64.to_be_bytes());
                let mut records = Records::new(&root, &id, 0, 1);
                let mut input = &wire[46..];
                let mut data = Vec::new();
                let mut kinds = Vec::new();
                while !input.is_empty() {
                    let length = channel::record_size(&input[..4]).unwrap();
                    let (kind, bytes) = records.open(&input[..length]);
                    kinds.push(kind);
                    match kind {
                        Kind::Metadata => {
                            let value: Value = serde_json::from_slice(&bytes).unwrap();
                            assert_eq!(value["headers"]["authorization"], "Bearer inside");
                            assert_eq!(value["path"], "/v1/chat/completions");
                            assert!(value["headers"].get("content-length").is_none());
                        }
                        Kind::Data => data.extend_from_slice(&bytes),
                        Kind::Finished => assert!(bytes.is_empty()),
                        Kind::Keepalive => panic!("unexpected upload keepalive"),
                    }
                    input = &input[length..];
                }
                assert_eq!(data, expected);
                assert_eq!(
                    kinds,
                    [
                        Kind::Metadata,
                        Kind::Data,
                        Kind::Data,
                        Kind::Data,
                        Kind::Data,
                        Kind::Finished
                    ]
                );
                let mut records = Records::new(&root, &id, 0, 2);
                let wire = [
                    records.seal(Kind::Keepalive, &[]),
                    records.seal(
                        Kind::Metadata,
                        br#"{"status":200,"headers":{"Content-Type":"text/plain"}}"#,
                    ),
                    records.seal(Kind::Data, b"verified content"),
                    records.seal(Kind::Finished, &[]),
                ]
                .concat();
                Response::builder()
                    .header(header::CONTENT_TYPE, CONTENT_TYPE)
                    .body(Body::from_stream(stream::iter(wire.into_iter().map(
                        |byte| Ok::<_, std::io::Error>(Bytes::from(vec![byte])),
                    ))))
                    .unwrap()
            }
        }),
    );
    let server = Server::new(app).await;
    let request = Request::post("/v1/chat/completions")
        .header("authorization", "Bearer inside")
        .header("content-length", request_body.len())
        .body(request_body)
        .unwrap();
    let response = send(
        &http(),
        server.endpoint.clone(),
        "owner",
        session.request().unwrap(),
        request,
        deadline(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        "verified content"
    );
}

#[tokio::test]
async fn failures_never_return_successful_eof_or_repeat_submission() {
    for case in [
        "truncated",
        "trailing",
        "tag",
        "metadata",
        "empty-body",
        "outer-status",
        "outer-type",
        "stall",
    ] {
        let (mut session, root, id) = session();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let app = Router::new().route(
            "/v1/session",
            post(move |request: Request<Body>| {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    to_bytes(request.into_body(), 65536).await.unwrap();
                    let mut records = Records::new(&root, &id, 0, 2);
                    let metadata: &[u8] = match case {
                        "metadata" => br#"{"status":200,"headers":{"set-cookie":"unsafe"}}"#,
                        "empty-body" => br#"{"status":204,"headers":{}}"#,
                        _ => br#"{"status":200,"headers":{}}"#,
                    };
                    let mut wire = records.seal(Kind::Metadata, metadata);
                    wire.extend(records.seal(Kind::Data, b"content"));
                    if case != "truncated" {
                        wire.extend(records.seal(Kind::Finished, &[]));
                    }
                    if case == "trailing" {
                        wire.push(0);
                    }
                    if case == "tag" {
                        *wire.last_mut().unwrap() ^= 1;
                    }
                    let body = if case == "stall" {
                        use futures_util::StreamExt as _;
                        Body::from_stream(
                            stream::once(async { Ok::<_, std::io::Error>(Bytes::from(wire)) })
                                .chain(stream::pending()),
                        )
                    } else {
                        Body::from(wire)
                    };
                    Response::builder()
                        .status(if case == "outer-status" { 503 } else { 200 })
                        .header(
                            header::CONTENT_TYPE,
                            if case == "outer-type" {
                                "text/html"
                            } else {
                                CONTENT_TYPE
                            },
                        )
                        .body(body)
                        .unwrap()
                }
            }),
        );
        let server = Server::new(app).await;
        let request = Request::post("/v1/responses")
            .body(Bytes::from_static(b"{}"))
            .unwrap();
        let limit = if case == "stall" {
            Instant::now() + Duration::from_millis(100)
        } else {
            deadline()
        };
        if let Ok(response) = send(
            &http(),
            server.endpoint.clone(),
            "owner",
            session.request().unwrap(),
            request,
            limit,
            None,
        )
        .await
        {
            assert!(
                to_bytes(response.into_body(), 1024).await.is_err(),
                "case {case}"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "case {case}");
    }
}

#[test]
fn metadata_rejects_transport_overrides_and_unsupported_paths_before_submission() {
    for (method, path, headers) in [
        ("GET", "/v1/responses", vec![]),
        ("POST", "/v1/responses?query=x", vec![]),
        ("POST", "/v1/files", vec![]),
        ("POST", "/v1/responses", vec![("stogas-node-id", "forged")]),
        (
            "POST",
            "/v1/responses",
            vec![("authorization", "a"), ("authorization", "b")],
        ),
    ] {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        assert!(request_metadata(&request.body(Bytes::new()).unwrap()).is_err());
    }
    for metadata in [
        br#"{"status":100,"headers":{}}"#.as_slice(),
        br#"{"status":200,"headers":{"Content-Type":"a","content-type":"b"}}"#,
        br#"{"status":200,"headers":{},"extra":true}"#,
    ] {
        assert!(response_metadata(metadata).is_err());
    }
}

// External client serializers use this test-only HTTP bridge. Production clients
// always call complete_verified; this fixture pins synthetic boot bytes instead.
async fn client_fixture_proxy(session: ClientSession, endpoint: Url, node_id: String) -> Server {
    let session = Arc::new(std::sync::Mutex::new(session));
    let http = http();
    let prefix = format!("/{}", hex::encode(rand::random::<[u8; 32]>()));
    let route = format!("{prefix}/{{*path}}");
    let app = Router::new().route(
        &route,
        axum::routing::any(move |request: Request<Body>| {
            let session = Arc::clone(&session);
            let endpoint = endpoint.clone();
            let node_id = node_id.clone();
            let http = http.clone();
            let prefix = prefix.clone();
            async move {
                let (mut parts, body) = request.into_parts();
                parts.uri = parts
                    .uri
                    .path()
                    .strip_prefix(&prefix)
                    .unwrap()
                    .parse()
                    .unwrap();
                for name in [header::HOST, header::CONNECTION, header::TRANSFER_ENCODING] {
                    parts.headers.remove(name);
                }
                let bytes = to_bytes(body, MAX_REQUEST_BYTES).await.unwrap();
                let exchange = session.lock().unwrap().request().unwrap();
                send(
                    &http,
                    endpoint,
                    &node_id,
                    exchange,
                    Request::from_parts(parts, bytes),
                    Instant::now() + Duration::from_mins(1),
                    None,
                )
                .await
                .unwrap()
            }
        }),
    );
    let mut server = Server::new(app).await;
    server
        .endpoint
        .set_path(&format!("{}/v1", route.trim_end_matches("/{*path}")));
    server
}

#[tokio::test]
async fn open_source_client_compatibility_proxy() {
    use base64::Engine as _;
    if let Ok(upstream) = std::env::var("STOGAS_E2EE_TEST_UPSTREAM") {
        let endpoint = Url::parse(&upstream).unwrap().join("/v1/session").unwrap();
        assert_eq!(endpoint.scheme(), "http");
        assert_eq!(endpoint.host_str(), Some("127.0.0.1"));
        let fixture: Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/node-boot-v1.json"))
                .unwrap();
        let report = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(fixture["record"]["report"].as_str().unwrap())
            .unwrap();
        let node_id =
            stogas_verifier::attestation::snp_node_id(report[0x140..0x160].try_into().unwrap());
        let mut pending = PendingSetup::new(Environment::Production).unwrap();
        let response = http()
            .post(endpoint.clone())
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .body(pending.hello().to_vec())
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = response.bytes().await.unwrap();
        assert!(response.len() <= stogas_verifier::channel::setup::MAX_SERVER_SETUP_BYTES);
        let session = pending
            .complete(&response, |evidence| {
                assert_eq!(
                    hex::encode(Sha256::digest(evidence.boot_document)),
                    fixture["document_sha256"]
                );
                assert_eq!(evidence.boot_inclusion, b"{}");
                Ok(())
            })
            .unwrap();
        let proxy = client_fixture_proxy(session, endpoint, node_id).await;
        println!("STOGAS_E2EE_TEST_BASE_URL={}", proxy.endpoint);
        tokio::task::spawn_blocking(|| {
            use std::io::Read as _;
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        })
        .await
        .unwrap();
        drop(proxy);
        return;
    }

    // Exercise real encrypted carriage and capability routing without the external
    // Go fixture; an ordinary test run must not silently skip this test.
    let (session, root, id) = session();
    let peer = Server::new(Router::new().route(
        "/v1/session",
        post(move |request: Request<Body>| async move {
            let wire = to_bytes(request.into_body(), 65536).await.unwrap();
            let mut request_records = Records::new(&root, &id, 0, 1);
            let size = channel::record_size(&wire[46..50]).unwrap();
            let (kind, metadata) = request_records.open(&wire[46..46 + size]);
            assert_eq!(kind, Kind::Metadata);
            let metadata: Value = serde_json::from_slice(&metadata).unwrap();
            assert_eq!(metadata["path"], "/v1/chat/completions");
            assert_eq!(metadata["headers"]["authorization"], "Bearer fixture");
            assert!(metadata["headers"].get("host").is_none());
            let mut records = Records::new(&root, &id, 0, 2);
            Response::builder()
                .header(header::CONTENT_TYPE, CONTENT_TYPE)
                .body(Body::from(
                    [
                        records.seal(
                            Kind::Metadata,
                            br#"{"status":200,"headers":{"Content-Type":"application/json"}}"#,
                        ),
                        records.seal(Kind::Data, b"{\"ok\":true}"),
                        records.seal(Kind::Finished, &[]),
                    ]
                    .concat(),
                ))
                .unwrap()
        }),
    ))
    .await;
    let proxy = client_fixture_proxy(session, peer.endpoint.clone(), "owner".into()).await;
    let response = http()
        .post(format!("{}/chat/completions", proxy.endpoint))
        .header(header::AUTHORIZATION, "Bearer fixture")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "{\"ok\":true}");
    assert_eq!(
        http()
            .post(proxy.endpoint.join("/v1/chat/completions").unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sse_terminal_waits_for_authenticated_completion_without_receipt_opt_in() {
    use http_body_util::BodyExt as _;
    for fault in ["none", "truncated", "tag", "trailing", "stall"] {
        let (mut session, root, id) = session();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let gate = Arc::clone(&release);
        let app = Router::new().route(
            "/v1/session",
            post(move |request: Request<Body>| {
                let gate = Arc::clone(&gate);
                async move {
                    to_bytes(request.into_body(), 4096).await.unwrap();
                    let mut records = Records::new(&root, &id, 0, 2);
                    let initial = [
                        records.seal(
                            Kind::Metadata,
                            br#"{"status":200,"headers":{"Content-Type":"text/event-stream"}}"#,
                        ),
                        records.seal(Kind::Data, b"data: hello\n\ndata: [DONE]\n\n"),
                    ]
                    .concat();
                    let mut terminal = records.seal(Kind::Finished, &[]);
                    if fault == "tag" {
                        *terminal.last_mut().unwrap() ^= 1;
                    }
                    if fault == "truncated" {
                        terminal.clear();
                    }
                    if fault == "trailing" {
                        terminal.push(0);
                    }
                    let body = stream::unfold(Some((initial, terminal, gate)), |state| async {
                        let (initial, terminal, gate) = state?;
                        if !initial.is_empty() {
                            return Some((
                                Ok::<_, std::io::Error>(Bytes::from(initial)),
                                Some((Vec::new(), terminal, gate)),
                            ));
                        }
                        let _permit = gate.acquire().await.unwrap();
                        if terminal.is_empty() {
                            return None;
                        }
                        Some((Ok(Bytes::from(terminal)), None))
                    });
                    Response::builder()
                        .header(header::CONTENT_TYPE, CONTENT_TYPE)
                        .body(Body::from_stream(body))
                        .unwrap()
                }
            }),
        );
        let server = Server::new(app).await;
        let response = send(
            &http(),
            server.endpoint.clone(),
            "owner",
            session.request().unwrap(),
            Request::post("/v1/chat/completions")
                .body(Bytes::from_static(b"{}"))
                .unwrap(),
            Instant::now() + Duration::from_secs(1),
            None,
        )
        .await
        .unwrap();
        let mut body = response.into_body();
        let mut before = Vec::new();
        while !before.ends_with(b"[DONE]") {
            before.extend_from_slice(&body.frame().await.unwrap().unwrap().into_data().unwrap());
        }
        assert_eq!(before, b"data: hello\n\ndata: [DONE]");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), body.frame())
                .await
                .is_err()
        );
        if fault != "stall" {
            release.add_permits(1);
        }
        let completion = body.frame().await.unwrap();
        if fault == "none" {
            assert_eq!(completion.unwrap().into_data().unwrap(), b"\n\n".as_slice());
            assert!(body.frame().await.is_none());
        } else {
            assert!(
                completion.is_err(),
                "{fault} released a successful terminal event"
            );
        }
    }
}
