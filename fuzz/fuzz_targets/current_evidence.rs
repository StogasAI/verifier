#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use stogas_verifier::{
    approvals::{Environment, OnlineKey},
    evidence::Verifier,
};

fuzz_target!(|data: &[u8]| {
    static FIXTURE: OnceLock<(OnlineKey, Vec<u8>, i64)> = OnceLock::new();
    let (root, bundle, now) = FIXTURE.get_or_init(|| {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/current-evidence-v1.json"
        ))
        .unwrap();
        (
            serde_json::from_value(fixture["root"].clone()).unwrap(),
            serde_json::to_vec(&fixture["bundle"]).unwrap(),
            fixture["verified_at_ms"].as_i64().unwrap(),
        )
    });
    let mut verifier = Verifier::new(Environment::Staging, root.clone()).unwrap();
    verifier.refresh(bundle, *now).unwrap();
    let candidate = if data.first() == Some(&b'S') {
        let mut candidate = bundle.clone();
        for mutation in data[1..].chunks_exact(3) {
            let offset =
                usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % candidate.len();
            candidate[offset] = mutation[2];
        }
        candidate
    } else {
        data.to_vec()
    };
    let _ = verifier.refresh(&candidate, *now);
    // A rejected candidate must not make later valid input panic or corrupt retained state.
    let _ = verifier.refresh(bundle, *now);
});
