use super::*;
use rustls::{
    ServerConfig,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::AsyncReadExt as _;
use tokio_rustls::TlsAcceptor;

fn snapshot() -> Arc<Snapshot> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/current-evidence-v1.json"
    ))
    .unwrap();
    evidence::Verifier::new(
        stogas_verifier::approvals::Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap()
    .refresh(
        &serde_json::to_vec(&fixture["bundle"]).unwrap(),
        fixture["verified_at_ms"].as_i64().unwrap(),
    )
    .unwrap()
}

#[test]
fn every_attempt_has_a_fresh_nonce_and_only_the_hybrid_tls13_profile() {
    let snapshot = snapshot();
    let first = Handshake::new(Arc::clone(&snapshot)).unwrap();
    let second = Handshake::new(snapshot).unwrap();
    assert_ne!(first.verifier.challenge, second.verifier.challenge);
    for handshake in [first, second] {
        let config = handshake.config;
        assert_eq!(config.alpn_protocols[0].len(), 60);
        assert_eq!(
            config.alpn_protocols[0],
            format!(
                "stogas-attest-v1.{}",
                URL_SAFE_NO_PAD.encode(handshake.verifier.challenge)
            )
            .as_bytes()
        );
        assert_eq!(
            &config.alpn_protocols[1..],
            &[b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(!config.enable_early_data);
        assert_eq!(config.crypto_provider().kx_groups.len(), 1);
        assert_eq!(
            config.crypto_provider().kx_groups[0].name(),
            NamedGroup::X25519MLKEM768
        );
        assert_eq!(
            handshake.verifier.supported_verify_schemes(),
            [SignatureScheme::ML_DSA_65]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn absolute_setup_deadline_closes_an_unresponsive_peer_without_blocking_the_runtime() {
    let snapshot = snapshot();
    for duration in [Duration::ZERO, Duration::from_secs(1)] {
        let (client, mut peer) = tokio::io::duplex(16 * 1024);
        let start = Instant::now();
        let result = connect(
            client,
            ServerName::try_from("api.example.test").unwrap(),
            Arc::clone(&snapshot),
            start + duration,
        )
        .await;
        assert!(matches!(result, Err(Error::Deadline)));
        assert_eq!(Instant::now() - start, duration);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes.is_empty(), duration.is_zero());
    }
}

#[derive(Debug)]
struct CertificateResolver {
    calls: Arc<AtomicUsize>,
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let alpn: Vec<_> = hello.alpn().unwrap().collect();
        assert!(alpn[0].starts_with(b"stogas-attest-v1."));
        assert_eq!(alpn[0].len(), 60);
        Some(Arc::clone(&self.key))
    }
}

#[tokio::test]
async fn real_tls_rejects_classical_negotiation_and_unattested_certificates_before_any_application_data()
 {
    let snapshot = snapshot();
    let certificate: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-certificate-v1.json"
    ))
    .unwrap();
    let signer: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/mldsa65-v1.json")).unwrap();
    // A genuine ML-DSA certificate/key pair, but deliberately synthetic boot
    // evidence. The wire handshake must reach and fail hardware appraisal.
    let key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(
            URL_SAFE_NO_PAD
                .decode(certificate["certificate"].as_str().unwrap())
                .unwrap(),
        )],
        rustls::crypto::aws_lc_rs::sign::any_supported_type(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(
                hex::decode(signer["pkcs8"].as_str().unwrap()).unwrap(),
            )
            .into(),
        )
        .unwrap(),
    ));
    for (version, group, certificate_expected) in [
        (
            &rustls::version::TLS12,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            false,
        ),
        (
            &rustls::version::TLS13,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            false,
        ),
        (
            &rustls::version::TLS13,
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            true,
        ),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![group];
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertificateResolver {
                calls: Arc::clone(&calls),
                key: Arc::clone(&key),
            }));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (client, server) = tokio::join!(
            connect(
                client,
                ServerName::try_from("api.example.test").unwrap(),
                Arc::clone(&snapshot),
                Instant::now() + Duration::from_secs(2)
            ),
            acceptor.accept(server)
        );
        assert!(server.is_err());
        if certificate_expected {
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(
                matches!(client, Err(Error::Verification(error)) if error.reason().code() == "invalid_attestation")
            );
        } else {
            assert!(matches!(client, Err(Error::Tls(_))));
        }
    }
}
