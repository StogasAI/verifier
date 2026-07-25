#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier::e2ee::{Recipient, Request, seal_request};

const P256_GENERATOR: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
    0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
    0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
    0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
    0x68, 0x37, 0xbf, 0x51, 0xf5,
];
const NOW_MS: i64 = 1_800_000_000_000;
const BUNDLE_HASH: &str =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

fuzz_target!(|data: &[u8]| {
    let recipient = Recipient {
        public_key: P256_GENERATOR.to_vec(),
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
        return_extra_fields: None,
        body: b"{}",
    };
    if let Ok(mut sealed) = seal_request(&request) {
        let _ = sealed.response.push(data);
        let _ = sealed.response.finish();
    }
});
