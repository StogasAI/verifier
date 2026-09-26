use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use stogas_verifier::attestation::certificate::ParsedNativeCertificate;
use stogas_verifier::signing::SigningKey;

struct Files {
    directory: PathBuf,
    fixture: Value,
    input: ProofCommandInput,
    boot_hash: String,
}

impl Files {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!("stogas-proof-{}", hex::encode(random)));
        std::fs::create_dir(&directory).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let certificate = URL_SAFE_NO_PAD
            .decode(fixture["certificate"].as_str().unwrap())
            .unwrap();
        let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
        let input = ProofCommandInput {
            proof: None,
            stream: false,
            request: directory.join("request"),
            response: directory.join("response"),
            bundle: directory.join("bundle"),
            boot: directory.join("boot"),
            environment: stogas::Environment::Staging,
            now_unix_ms: fixture["verified_at_ms"].as_i64(),
        };
        std::fs::write(
            &input.bundle,
            serde_json::to_vec(&fixture["bundle"]).unwrap(),
        )
        .unwrap();
        let archive = json!({
            "boot": serde_json::from_slice::<Value>(parsed.evidence.boot_document).unwrap(),
            "inclusion": serde_json::from_slice::<Value>(parsed.evidence.boot_inclusion).unwrap(),
            "evidence_sha256": fixture["bundle"]["body_sha256"]
        });
        std::fs::write(&input.boot, serde_json::to_vec(&archive).unwrap()).unwrap();
        std::fs::write(&input.request, b"{\n  \"messages\": []\n}\n").unwrap();
        Self {
            directory,
            boot_hash: hex::encode(Sha256::digest(parsed.evidence.boot_document)),
            fixture,
            input,
        }
    }

    fn receipt(&self, response: &[u8]) -> Value {
        let request = Sha256::digest(std::fs::read(&self.input.request).unwrap());
        let response = Sha256::digest(response);
        let digest = Sha256::digest(b"{}");
        let message = [
            receipt::SCHEMA.as_bytes(),
            b"\0",
            &request,
            &response,
            &digest,
        ]
        .concat();
        json!({
            "schema": receipt::SCHEMA,
            "boot_sha256": self.boot_hash,
            "request_sha256": hex::encode(request),
            "response_sha256": hex::encode(response),
            "signature": URL_SAFE_NO_PAD.encode(SigningKey::from_seed(&[42; 32]).sign(&message, &[]).unwrap())
        })
    }

    async fn verify(&self) -> Result<VerifiedReceipt> {
        let verifier = Verifier::new(
            self.input.environment,
            serde_json::from_value(self.fixture["root"].clone()).unwrap(),
        )?;
        verify_proof_files(&self.input, &verifier).await
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[tokio::test]
async fn offline_files_verify_exact_buffered_streamed_and_detached_content() {
    let mut files = Files::new();
    let response = b"{\n\"choices\":[], \"usage\":{\"output_tokens\":2}}";
    let metadata = json!({"receipt": files.receipt(response)});
    let buffered = [
        &response[..response.len() - 1],
        b",\"stogas\":",
        &serde_json::to_vec(&metadata).unwrap(),
        b"}",
    ]
    .concat();
    std::fs::write(&files.input.response, &buffered).unwrap();
    // Receipt audit remains valid after archived collateral expires; this does not
    // install those approvals for new sessions or assert a request execution time.
    files.input.now_unix_ms = files
        .input
        .now_unix_ms
        .map(|now| now + 366 * 24 * 60 * 60 * 1000);
    let verified = files.verify().await.unwrap();
    assert_eq!(verified.boot_sha256, files.boot_hash);
    assert_eq!(
        verified.response_sha256,
        hex::encode(Sha256::digest(response))
    );
    assert!(
        !serde_json::to_value(&verified)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("catalog")
    );

    // Detached mode hashes the file itself. It must not normalize JSON or strip framing.
    let proof = files.directory.join("receipt");
    std::fs::write(&proof, serde_json::to_vec(&metadata).unwrap()).unwrap();
    files.input.proof = Some(proof);
    std::fs::write(&files.input.response, response).unwrap();
    assert_eq!(
        files.verify().await.unwrap().response_sha256,
        verified.response_sha256
    );
    std::fs::write(&files.input.response, &buffered).unwrap();
    assert!(files.verify().await.is_err());

    files.input.proof = None;
    files.input.stream = true;
    let content = b"data: {\"choices\":[]}\n\ndata: [DONE]\n\n";
    let metadata = json!({"receipt": files.receipt(content)});
    let stream = [
        b": STOGAS PROCESSING\n\ndata: {\"choices\":[]}\n\n: stogas ".as_slice(),
        &serde_json::to_vec(&metadata).unwrap(),
        b"\n\ndata: [DONE]\n\n",
    ]
    .concat();
    std::fs::write(&files.input.response, &stream).unwrap();
    assert_eq!(
        files.verify().await.unwrap().response_sha256,
        hex::encode(Sha256::digest(content))
    );
    std::fs::write(&files.input.response, &stream[..stream.len() - 1]).unwrap();
    assert!(files.verify().await.is_err());
}

#[tokio::test]
async fn offline_files_fail_closed_on_changed_evidence_content_and_oversized_receipts() {
    let mut files = Files::new();
    let response = b"exact response\n";
    let proof = files.directory.join("receipt");
    std::fs::write(
        &proof,
        serde_json::to_vec(&json!({"receipt":files.receipt(response)})).unwrap(),
    )
    .unwrap();
    files.input.proof = Some(proof.clone());
    std::fs::write(&files.input.response, response).unwrap();
    files.verify().await.unwrap();
    for path in [
        &files.input.bundle,
        &files.input.boot,
        &files.input.request,
        &files.input.response,
    ] {
        let original = std::fs::read(path).unwrap();
        std::fs::write(path, b"{}").unwrap();
        assert!(
            files.verify().await.is_err(),
            "accepted changed {}",
            path.display()
        );
        std::fs::write(path, original).unwrap();
    }
    let original = std::fs::read(&proof).unwrap();
    std::fs::write(&proof, vec![b' '; receipt::MAX_METADATA_BYTES + 1]).unwrap();
    assert!(
        files
            .verify()
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
    std::fs::write(&proof, original).unwrap();
    std::fs::remove_file(&files.input.boot).unwrap();
    assert!(files.verify().await.is_err());
}
