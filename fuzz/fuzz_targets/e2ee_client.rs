#![no_main]

use hpke::{Kem as _, Serializable as _, kem::XWing};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use stogas_verifier::e2ee::{Recipient, Request, seal_request};

const NOW_MS: i64 = 1_800_000_000_000;
const BUNDLE_HASH: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

fuzz_target!(|data: &[u8]| {
    static PUBLIC_KEY: OnceLock<Vec<u8>> = OnceLock::new();
    let recipient = Recipient {
        public_key: PUBLIC_KEY
            .get_or_init(|| XWing::gen_keypair().1.to_bytes().to_vec())
            .clone(),
    };
    let request = Request {
        path: "/v1/responses",
        request_id: Some("018f4f70-7c88-7b9a-baf8-31a93d2cf613"),
        now_unix_ms: NOW_MS,
        expires_at_unix_ms: NOW_MS + 60_000,
        bundle_sha256: BUNDLE_HASH,
        recipients: std::slice::from_ref(&recipient),
        api_key: "sk-fuzz",
        accept: None,
        receipt: false,
        upstream_credentials: None,
        body: b"{}",
    };
    if let Ok(mut sealed) = seal_request(&request) {
        let _ = sealed.response.push(data);
        let _ = sealed.response.finish();
    }
});
