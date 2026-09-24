use super::*;
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Reply {
    body: Vec<u8>,
    etag: &'static str,
    status: StatusCode,
}

struct Origins {
    replies: RwLock<[Reply; 2]>,
    requests: Mutex<Vec<(usize, Option<String>)>>,
}

struct Server {
    state: Arc<Origins>,
    origins: [Url; 2],
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handler(
    State(state): State<Arc<Origins>>,
    Path(index): Path<usize>,
    headers: HeaderMap,
) -> Response<Body> {
    let etag = headers
        .get(IF_NONE_MATCH)
        .map(|v| v.to_str().unwrap().to_owned());
    state.requests.lock().unwrap().push((index, etag.clone()));
    let reply = state.replies.read().unwrap()[index].clone();
    if reply.status != StatusCode::OK {
        return Response::builder()
            .status(reply.status)
            .body(Body::empty())
            .unwrap();
    }
    if etag.as_deref() == Some(reply.etag) {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap()
    } else {
        Response::builder()
            .header(ETAG, reply.etag)
            .header("content-length", reply.body.len())
            .body(Body::from(reply.body))
            .unwrap()
    }
}

impl Server {
    async fn new(replies: [Reply; 2]) -> Self {
        let state = Arc::new(Origins {
            replies: RwLock::new(replies),
            requests: Mutex::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{index}", get(handler))
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            state,
            task,
            origins: [0, 1].map(|i| Url::parse(&format!("http://{address}/{i}")).unwrap()),
        }
    }

    fn client(&self, root: OnlineKey) -> EvidenceClient {
        let mut client = EvidenceClient::new(Environment::Staging, root).unwrap();
        client.origins.clone_from(&self.origins);
        client
    }
}

fn fixture() -> (OnlineKey, Value) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/current-evidence-v1.json"
    ))
    .unwrap();
    (
        serde_json::from_value(fixture["root"].clone()).unwrap(),
        fixture["bundle"]["body"].clone(),
    )
}

fn signed(mut body: Value) -> Vec<u8> {
    let approval = &body["approvals"]["manifest"];
    // This manifest has only ASCII field names and scalar/array values.
    let sorted: std::collections::BTreeMap<String, Value> =
        serde_json::from_value(approval.clone()).unwrap();
    let canonical = serde_json::to_vec(&sorted).unwrap();
    let mut message = b"stogas signed document v1\n".to_vec();
    message.extend_from_slice(&canonical);
    body["approvals"]["signature"]["signature"] =
        json!(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[242; 32]).sign(&message).to_bytes()));
    serde_json::to_vec(&json!({"schema":"stogas.confidential-bundle-envelope.v1", "body_sha256":stogas_verifier::approvals::payload_sha256(&body).unwrap(),"body":body})).unwrap()
}

const fn reply(body: Vec<u8>, etag: &'static str) -> Reply {
    Reply {
        body,
        etag,
        status: StatusCode::OK,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn stale_success_falls_through_to_replica_and_etags_never_cross_origins() {
    let (root, mut latest) = fixture();
    let target = stogas_verifier::approvals::payload_sha256(
        latest["catalogs"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .get("manifest")
            .unwrap(),
    )
    .unwrap();
    let mut old = latest.clone();
    old["catalogs"].as_array_mut().unwrap().pop();
    old["approvals"]["manifest"]["catalogs"]
        .as_array_mut()
        .unwrap()
        .retain(|id| id != &target);
    latest["approvals"]["manifest"]["revision"] = json!(2);
    let server = Server::new([
        reply(signed(old), "\"r2-old\""),
        reply(signed(latest), "\"aws-new\""),
    ])
    .await;
    let client = server.client(root);
    let original = client.refresh(deadline()).await.unwrap();
    assert!(original.catalog(&target).is_none());
    let required = target.clone();
    let updated = client
        .recover(deadline(), move |snapshot| {
            snapshot
                .catalog(&required)
                .ok_or(evidence::Error::Incomplete("catalog"))
                .map(|_| ())
        })
        .await
        .unwrap();
    assert!(updated.catalog(&target).is_some());
    assert!(original.catalog(&target).is_none());
    client.refresh(deadline()).await.unwrap();
    assert_eq!(
        *server.state.requests.lock().unwrap(),
        vec![
            (0, None),
            (0, Some("\"r2-old\"".into())),
            (1, None),
            (0, Some("\"r2-old\"".into())),
            (1, Some("\"aws-new\"".into())),
        ]
    );
}

#[tokio::test]
async fn concurrent_recovery_shares_success_and_failed_recovery_has_one_cooldown() {
    let (root, body) = fixture();
    let server = Server::new([
        reply(signed(body.clone()), "\"one\""),
        reply(signed(body), "\"two\""),
    ])
    .await;
    let client = Arc::new(server.client(root));
    let first = client.recover(deadline(), |_| Ok(()));
    let second = client.recover(deadline(), |_| Ok(()));
    let (first, second) = tokio::join!(first, second);
    assert!(Arc::ptr_eq(&first.unwrap(), &second.unwrap()));
    assert_eq!(server.state.requests.lock().unwrap().len(), 1);
    let missing = |_: &Snapshot| Err(evidence::Error::Incomplete("missing requested release"));
    assert!(matches!(
        client.recover(deadline(), missing).await,
        Err(Error::Verification(_))
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
    assert!(matches!(
        client.recover(deadline(), missing).await,
        Err(Error::Cooldown)
    ));
    assert!(matches!(
        client.refresh(deadline()).await,
        Err(Error::Cooldown)
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
    // A different request whose check succeeds keeps using accepted state during cooldown.
    assert!(client.recover(deadline(), |_| Ok(())).await.is_ok());
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn bad_or_oversized_delivery_preserves_snapshot_and_never_caches_the_candidate_etag() {
    let (root, body) = fixture();
    for hostile in [b"{malformed".to_vec(), vec![b' '; MAX_INPUT_BYTES + 1]] {
        let server = Server::new([
            reply(signed(body.clone()), "\"good\""),
            reply(signed(body.clone()), "\"backup\""),
        ])
        .await;
        let client = server.client(root.clone());
        let accepted = client.refresh(deadline()).await.unwrap();
        *server.state.replies.write().unwrap() = [
            reply(hostile, "\"bad\""),
            Reply {
                body: vec![],
                etag: "",
                status: StatusCode::SERVICE_UNAVAILABLE,
            },
        ];
        assert!(client.refresh(deadline()).await.is_err());
        assert!(Arc::ptr_eq(&accepted, &client.current().unwrap().unwrap()));
        assert_eq!(
            client.acquisition.lock().await.representations[0]
                .as_ref()
                .unwrap()
                .etag
                .as_ref()
                .unwrap(),
            "\"good\""
        );
    }
}

#[tokio::test]
async fn canceling_the_waiter_does_not_release_the_running_verification_permit() {
    let cpu = Arc::new(Semaphore::new(1));
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let task = tokio::spawn(run_cpu(Arc::clone(&cpu), move || {
        started.send(()).unwrap();
        blocked.recv().unwrap();
        Ok(())
    }));
    running.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(cpu.available_permits(), 0);
    release.send(()).unwrap();
    let permit = timeout_at(deadline(), cpu.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(permit);
    assert_eq!(cpu.available_permits(), 1);
}

#[tokio::test]
async fn native_setup_sends_nothing_before_evidence_and_never_redials_an_unresolved_peer() {
    use crate::native_tls;
    use rustls::pki_types::ServerName;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (root, body) = fixture();
    let server = Server::new([
        Reply {
            body: vec![],
            etag: "",
            status: StatusCode::SERVICE_UNAVAILABLE,
        },
        Reply {
            body: vec![],
            etag: "",
            status: StatusCode::SERVICE_UNAVAILABLE,
        },
    ])
    .await;
    let client = server.client(root.clone());
    let dials = AtomicUsize::new(0);
    let result = native_tls::connect_with_evidence(
        &client,
        || {
            dials.fetch_add(1, Ordering::SeqCst);
            async { Ok(tokio::io::duplex(16 * 1024).0) }
        },
        ServerName::try_from("api.example.test").unwrap(),
        deadline(),
    )
    .await;
    assert!(matches!(result, Err(native_tls::Error::Evidence(_))));
    assert_eq!(dials.load(Ordering::SeqCst), 0);

    *server.state.replies.write().unwrap() = [
        reply(signed(body.clone()), "\"primary\""),
        reply(signed(body), "\"replica\""),
    ];
    server.state.requests.lock().unwrap().clear();
    let client = server.client(root.clone());
    let acceptor = unattested_peer();
    let mut peer = None;
    let result = native_tls::connect_with_evidence(
        &client,
        || {
            dials.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(16 * 1024);
            let acceptor = acceptor.clone();
            peer = Some(tokio::spawn(async move {
                acceptor.accept(server).await.is_err()
            }));
            async { Ok(client) }
        },
        ServerName::try_from("api.example.test").unwrap(),
        deadline(),
    )
    .await;
    assert!(matches!(
        result,
        Err(native_tls::Error::Recovery { acquisition: Error::Verification(_), verification })
            if verification.reason().code() == "invalid_attestation"
    ));
    assert!(peer.unwrap().await.unwrap());
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        *server.state.requests.lock().unwrap(),
        vec![(0, None), (0, Some("\"primary\"".into())), (1, None),]
    );
}

#[tokio::test]
async fn native_pool_never_assigns_an_unattested_connection() {
    use crate::native_tls;
    use rustls::pki_types::ServerName;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (root, body) = fixture();
    let server = Server::new([
        reply(signed(body.clone()), "primary"),
        reply(signed(body), "replica"),
    ])
    .await;
    let acceptor = unattested_peer();
    server.state.requests.lock().unwrap().clear();
    let dials = Arc::new(AtomicUsize::new(0));
    let peer = Arc::new(Mutex::new(None));
    let pool = crate::native_http::Client::new(
        Arc::new(server.client(root)),
        {
            let peer = Arc::clone(&peer);
            let dials = Arc::clone(&dials);
            move || {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client, server) = tokio::io::duplex(16 * 1024);
                let acceptor = acceptor.clone();
                *peer.lock().unwrap() = Some(tokio::spawn(async move {
                    acceptor.accept(server).await.is_err()
                }));
                async { Ok(client) }
            }
        },
        ServerName::try_from("api.example.test").unwrap(),
        crate::http2_pool::Limits {
            connections: std::num::NonZeroUsize::new(4).unwrap(),
            waiting_requests: std::num::NonZeroUsize::new(8).unwrap(),
            waiting_bytes: std::num::NonZeroUsize::new(1024).unwrap(),
        },
    );
    let result = pool
        .send(
            axum::http::Request::builder()
                .uri("https://api.example.test/v1/chat/completions")
                .body(axum::body::Bytes::from_static(b"never sent"))
                .unwrap(),
            deadline(),
        )
        .await;
    assert!(
        matches!(result, Err(crate::native_http::Error::Pool(crate::http2_pool::Error::Connect(error)))
        if matches!(error.downcast_ref::<native_tls::Error>(), Some(native_tls::Error::Recovery { acquisition: Error::Verification(_), verification })
            if verification.reason().code() == "invalid_attestation"))
    );
    let peer = peer.lock().unwrap().take().unwrap();
    assert!(
        peer.await.unwrap(),
        "no unverified channel may reach HTTP/2 setup"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    pool.close(deadline()).await.unwrap();
}

fn unattested_peer() -> tokio_rustls::TlsAcceptor {
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;
    let cert = rcgen::generate_simple_self_signed(vec!["api.example.test".into()]).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

// Historical hardware fixtures exercise live-channel appraisal without inventing a signer
// capable of fabricating SNP evidence. The channel's clock is fixed to the capture time.
fn hardware_channel(client: &EvidenceClient, fixture: &Value) -> crate::native_http::Channel {
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = client
        .verifier
        .lock()
        .unwrap()
        .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
        .unwrap();
    let certificate = URL_SAFE_NO_PAD
        .decode(fixture["certificate"].as_str().unwrap())
        .unwrap();
    let challenge = hex::decode(fixture["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let session = Arc::new(
        snapshot
            .verify_native_certificate(&certificate, challenge, now)
            .unwrap(),
    );
    *client.current.write().unwrap() = Some(Arc::clone(&snapshot));
    crate::native_http::Channel::new(snapshot, session)
}

fn hardware_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn warm_appraisal_reuses_context_and_rotation_preserves_inflight_snapshot() {
    let fixture = hardware_fixture();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let server = Server::new([
        reply(
            serde_json::to_vec(&fixture["bundle"]).unwrap(),
            "\"original\"",
        ),
        reply(vec![], "\"unused\""),
    ])
    .await;
    let client = server.client(serde_json::from_value(fixture["root"].clone()).unwrap());
    let channel = hardware_channel(&client, &fixture);
    let original = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    let occupied_cpu = client.cpu.acquire().await.unwrap();
    let reused = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&original, &reused));
    drop(occupied_cpu);

    let rotation: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/logged-key-rotation.json"
    ))
    .unwrap();
    let mut body = fixture["bundle"]["body"].clone();
    body["keys"] = rotation["keys"].clone();
    body["hardware_policy"] = rotation["hardware_policy"].clone();
    body["approvals"]["manifest"]["key_manifest_sha256"] =
        json!(stogas_verifier::approvals::payload_sha256(&body["keys"]["manifest"]).unwrap());
    let sign = |manifest: &Value| {
        let canonical = serde_json::to_vec(manifest).unwrap();
        let message = [
            b"stogas signed document v1\n".as_slice(),
            canonical.as_slice(),
        ]
        .concat();
        json!({"key_id":"stogas-fixture-online-20260921", "signature": URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[243; 32]).sign(&message).to_bytes()
        )})
    };
    for kind in ["allowed_igvms", "catalogs"] {
        for artifact in body[kind].as_array_mut().unwrap() {
            artifact["signature"] = sign(&artifact["manifest"]);
        }
    }
    body["approvals"]["signature"] = sign(&body["approvals"]["manifest"]);
    let bundle = json!({"schema":"stogas.confidential-bundle-envelope.v1",
        "body_sha256":stogas_verifier::approvals::payload_sha256(&body).unwrap(), "body":body});
    *server.state.replies.write().unwrap() = [
        reply(serde_json::to_vec(&bundle).unwrap(), "\"rotation\""),
        reply(vec![], "\"unused\""),
    ];
    let updated = client.refresh(deadline()).await.unwrap();
    assert!(original.snapshot.require_current_keys().is_err());
    let first = channel.prepare(&client, deadline(), move || Ok(now));
    let second = channel.prepare(&client, deadline(), move || Ok(now));
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    assert!(Arc::ptr_eq(&first.snapshot, &updated));
    assert!(!Arc::ptr_eq(&first, &original));
    assert_eq!(
        first.session.boot().document_sha256(),
        original.session.boot().document_sha256()
    );
    assert!(
        original
            .snapshot
            .gateway(&original.session.boot().record().gateway_release_id)
            .is_some()
    );
    assert_eq!(server.state.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn warm_rejection_preserves_cause_and_old_requests_without_reusing_stale_approval() {
    let fixture = hardware_fixture();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let server = Server::new([
        reply(
            serde_json::to_vec(&fixture["bundle"]).unwrap(),
            "\"old-r2\"",
        ),
        reply(
            serde_json::to_vec(&fixture["bundle"]).unwrap(),
            "\"old-aws\"",
        ),
    ])
    .await;
    let client = server.client(serde_json::from_value(fixture["root"].clone()).unwrap());
    let channel = hardware_channel(&client, &fixture);
    let retained = channel
        .prepare(&client, deadline(), move || Ok(now))
        .await
        .unwrap();
    // A ready cached channel must still honor an already-expired caller budget.
    // Tokio may poll a ready future before observing its timeout.
    assert!(matches!(
        channel
            .prepare(&client, Instant::now(), move || Ok(now))
            .await,
        Err(crate::native_http::Error::Evidence(Error::Deadline))
    ));
    assert!(matches!(
        client
            .reappraise_session(
                Arc::clone(&retained.snapshot),
                Arc::clone(&retained.session),
                Instant::now(),
                now,
            )
            .await,
        Err(Error::Deadline)
    ));
    let mut body = fixture["bundle"]["body"].clone();
    body["approvals"]["manifest"]["revision"] =
        json!(body["approvals"]["manifest"]["revision"].as_u64().unwrap() + 1);
    body["approvals"]["manifest"]["gateways"] = json!([]);
    body["allowed_igvms"] = json!([]);
    let withdrawn = client
        .verifier
        .lock()
        .unwrap()
        .refresh(&signed(body), now)
        .unwrap();
    *client.current.write().unwrap() = Some(Arc::clone(&withdrawn));
    for _ in 0..2 {
        assert!(matches!(
            channel.prepare(&client, deadline(), move || Ok(now)).await,
            Err(crate::native_http::Error::Recovery {
                verification: evidence::Error::Approval(
                    stogas_verifier::approvals::Error::NotApproved("gateway")
                ),
                ..
            })
        ));
    }
    assert_eq!(server.state.requests.lock().unwrap().len(), 2);
    assert!(Arc::ptr_eq(&client.current().unwrap().unwrap(), &withdrawn));
    assert!(
        retained
            .snapshot
            .gateway(&retained.session.boot().record().gateway_release_id)
            .is_some()
    );
    assert!(matches!(
        channel
            .prepare(&client, Instant::now(), move || Ok(now))
            .await,
        Err(crate::native_http::Error::Evidence(Error::Deadline))
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn encrypted_setup_bounds_delivery_and_never_recovers_invalid_protocol_data() {
    use crate::encrypted_setup::{self, CONTENT_TYPE, Error};
    use axum::body::{Bytes, to_bytes};
    use axum::http::Request;
    use axum::routing::post;
    use futures_util::stream;
    use stogas_verifier::channel::setup::{CLIENT_SETUP_BYTES, MAX_SERVER_SETUP_BYTES};

    let (root, body) = fixture();
    let origins = Server::new([reply(signed(body), "\"evidence\""), reply(vec![], "unused")]).await;
    let evidence = origins.client(root);
    evidence.refresh(deadline()).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let app = Router::new().route(
        "/{scenario}",
        post(move |Path(case): Path<String>, request: Request<Body>| {
            let observed = Arc::clone(&observed);
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                assert!(!request.headers().contains_key("authorization"));
                assert!(!request.headers().contains_key("stogas-node-id"));
                assert_eq!(request.headers()["content-type"], CONTENT_TYPE);
                let hello = to_bytes(request.into_body(), CLIENT_SETUP_BYTES)
                    .await
                    .unwrap();
                assert_eq!(hello.len(), CLIENT_SETUP_BYTES);
                assert_eq!(&hello[..6], b"STGS\x01\x01");
                let mut response = Response::builder().header("content-type", CONTENT_TYPE);
                let body = match case.as_str() {
                    "status" => {
                        response = response.status(503);
                        Body::empty()
                    }
                    "type" => {
                        response = Response::builder().header("content-type", "text/html");
                        Body::from("an edge error")
                    }
                    "length" => Body::from(vec![0; MAX_SERVER_SETUP_BYTES + 1]),
                    "chunked" => Body::from_stream(stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from(vec![0; MAX_SERVER_SETUP_BYTES])),
                        Ok(Bytes::from_static(b"x")),
                    ])),
                    "malformed" => Body::from("invalid setup"),
                    "stall" => {
                        Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>())
                    }
                    _ => panic!("unknown test case"),
                };
                response.body(body).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = evidence.client.clone();
    for case in ["status", "type", "length", "chunked", "malformed", "stall"] {
        let limit = if case == "stall" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(5)
        };
        let result = encrypted_setup::connect(
            &evidence,
            &http,
            Url::parse(&format!("http://{address}/{case}")).unwrap(),
            Environment::Staging,
            Instant::now() + limit,
        )
        .await;
        match case {
            "malformed" => assert!(matches!(result, Err(Error::Setup(_)))),
            // The same absolute deadline also bounds setup-key generation. On
            // a busy runner it may expire there before HTTP starts.
            "stall" => assert!(
                matches!(
                    result,
                    Err(Error::Deadline | Error::Evidence(super::Error::Deadline))
                ),
                "unexpected setup result: {:?}",
                result.err()
            ),
            _ => assert!(matches!(result, Err(Error::Response))),
        }
    }
    let calls_before_expired_setup = calls.load(Ordering::SeqCst);
    assert!((5..=6).contains(&calls_before_expired_setup));
    assert_eq!(
        origins.state.requests.lock().unwrap().len(),
        1,
        "bad protocol data must not fetch evidence"
    );
    let result = encrypted_setup::connect(
        &evidence,
        &http,
        Url::parse(&format!("http://{address}/malformed")).unwrap(),
        Environment::Staging,
        Instant::now(),
    )
    .await;
    assert!(matches!(result, Err(Error::Deadline)));
    assert_eq!(calls.load(Ordering::SeqCst), calls_before_expired_setup);
    task.abort();
}
