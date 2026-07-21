#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier_ffi::{
    stogas_verifier_free, stogas_verifier_new, stogas_verifier_string_free,
    stogas_verifier_verify_bundle,
};

const FIXTURE: &[u8] = include_bytes!(
    "../../crates/verifier/tests/fixtures/staging-bundle-sequence-1927.json"
);

fuzz_target!(|data: &[u8]| {
    let bundle = if data.first() == Some(&b'S') {
        FIXTURE
    } else {
        data
    };
    let session = stogas_verifier_new();
    if session.is_null() {
        return;
    }
    // SAFETY: every pointer and length refers to a live slice for the synchronous call. Every
    // response and the session are released exactly once.
    unsafe {
        let verified = stogas_verifier_verify_bundle(
            session,
            bundle.as_ptr(),
            bundle.len(),
            1_784_414_117_082,
        );
        stogas_verifier_string_free(verified);
        stogas_verifier_free(session);
    }
});
