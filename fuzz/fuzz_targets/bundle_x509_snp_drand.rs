#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier::{Environment, Verifier};

const FIXTURE: &[u8] = include_bytes!(
    "../../crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json"
);
const NOW_UNIX_MS: i64 = 1_784_414_117_082;

fuzz_target!(|data: &[u8]| {
    let candidate = mutate_fixture_or_raw(FIXTURE, data);
    let mut verifier = Verifier::default();
    let _ = verifier.verify_bundle(
        &candidate,
        NOW_UNIX_MS,
        &Environment::stogas(),
    );
});

fn mutate_fixture_or_raw(fixture: &[u8], data: &[u8]) -> Vec<u8> {
    if data.first() != Some(&b'S') {
        return data.to_vec();
    }
    let mut candidate = fixture.to_vec();
    for mutation in data[1..].chunks_exact(3) {
        let offset = usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % candidate.len();
        candidate[offset] = mutation[2];
    }
    candidate
}
