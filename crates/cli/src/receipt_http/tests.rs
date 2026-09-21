use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::stream;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::time::Duration;
use stogas_verifier::{approvals::Environment, evidence};

fn peer() -> Arc<VerifiedSession> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let mut verifier = evidence::Verifier::new(
        Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&fixture["bundle"]).unwrap(), now)
        .unwrap();
    Arc::new(
        snapshot
            .verify_native_certificate(
                &URL_SAFE_NO_PAD
                    .decode(fixture["certificate"].as_str().unwrap())
                    .unwrap(),
                hex::decode(fixture["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                now,
            )
            .unwrap(),
    )
}
fn metadata(peer: &VerifiedSession, request: [u8; 32], response: &[u8]) -> Vec<u8> {
    let response: [u8; 32] = Sha256::digest(response).into();
    let key = SigningKey::from_bytes(&[42; 32]);
    let digest: [u8; 32] = Sha256::digest(b"{}").into();
    let message = [
        receipt::SCHEMA.as_bytes(),
        b"\0",
        &request,
        &response,
        &digest,
    ]
    .concat();
    serde_json::to_vec(&json!({"receipt": {
        "schema": receipt::SCHEMA,
        "boot_sha256": hex::encode(peer.boot().document_sha256()),
        "request_sha256": hex::encode(request), "response_sha256": hex::encode(response),
        "signature": URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes())
    }}))
    .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn buffered_receipts_use_original_hardware_identity_before_returning_success() {
    let peer = peer();
    let request = Sha256::digest(b"request").into();
    let content = br#"{"choices":[]}"#;
    let receipt = metadata(&peer, request, content);
    let wire = [
        &content[..content.len() - 1],
        b",\"stogas\":",
        &receipt,
        b"}",
    ]
    .concat();
    let verified = verify(
        Response::new(Body::from(wire.clone())),
        Arc::clone(&peer),
        request,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        to_bytes(verified.into_body(), usize::MAX).await.unwrap(),
        wire
    );
    assert!(matches!(
        verify(
            Response::new(Body::from(wire)),
            Arc::clone(&peer),
            [0; 32],
            deadline()
        )
        .await,
        Err(Error::Receipt(_))
    ));
    let failed = Response::builder()
        .status(429)
        .body(Body::from("limited"))
        .unwrap();
    assert_eq!(
        to_bytes(
            verify(failed, peer, request, deadline())
                .await
                .unwrap()
                .into_body(),
            usize::MAX
        )
        .await
        .unwrap(),
        "limited"
    );
}

#[tokio::test]
async fn terminal_delimiter_requires_eof_and_valid_receipt_without_repeating_the_request() {
    let peer = peer();
    let request = Sha256::digest(b"request").into();
    let content = b"data: {}\n\ndata: [DONE]\n\n";
    let receipt = metadata(&peer, request, content);
    let wire = [
        b"data: {}\n\n: stogas ",
        receipt.as_slice(),
        b"\n\ndata: [DONE]\n\n",
    ]
    .concat();
    for (body, digest, valid) in [
        (wire.clone(), request, true),
        (wire.clone(), [0; 32], false),
        (wire[..wire.len() - 1].to_vec(), request, false),
        ([wire.as_slice(), b"injected"].concat(), request, false),
    ] {
        let source = stream::iter(
            body.into_iter()
                .map(|byte| Ok::<_, std::io::Error>(Bytes::from(vec![byte]))),
        );
        let response = Response::builder()
            .header(CONTENT_TYPE, "text/event-stream; charset=utf-8")
            .body(Body::from_stream(source))
            .unwrap();
        let result = verify(response, Arc::clone(&peer), digest, deadline())
            .await
            .unwrap();
        let collected = to_bytes(result.into_body(), usize::MAX).await;
        if valid {
            assert_eq!(collected.unwrap(), wire);
        } else {
            assert!(collected.is_err());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn blocked_body_deadline_and_cancellation_release_retained_attestation() {
    for cancel in [false, true] {
        let peer = peer();
        let baseline = Arc::strong_count(&peer);
        let source = stream::pending::<Result<Bytes, std::io::Error>>();
        let response = Response::builder()
            .header(CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(source))
            .unwrap();
        let mut response = verify(response, Arc::clone(&peer), [0; 32], deadline())
            .await
            .unwrap();
        assert_eq!(Arc::strong_count(&peer), baseline + 1);
        if !cancel {
            assert!(response.body_mut().frame().await.unwrap().is_err());
            assert_eq!(Arc::strong_count(&peer), baseline);
        }
        drop(response);
        assert_eq!(Arc::strong_count(&peer), baseline);
    }
}
