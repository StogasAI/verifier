#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier_ffi::{
    stogas_evidence_free, stogas_evidence_new, stogas_evidence_refresh,
    stogas_evidence_snapshot_free, stogas_verifier_string_free,
};

const CONFIGURATION: &[u8] = br#"{"environment":"prod","root":{"key_id":"stogas-fixture-root-20260920","public_key":"MCowBQYDK2VwAyEA3L5P2vQ8YUaIm4Kw5pD8iMEoZgUuo+oEKx95iLylrgg="}}"#;

fuzz_target!(|data: &[u8]| {
    let mut owner = std::ptr::null_mut();
    let mut snapshot = std::ptr::null_mut();
    // SAFETY: input slices and output pointers are live for each synchronous call.
    // Every returned string and handle is freed exactly once, including rejected candidates.
    unsafe {
        stogas_verifier_string_free(stogas_evidence_new(
            CONFIGURATION.as_ptr(),
            CONFIGURATION.len(),
            &raw mut owner,
        ));
        if !owner.is_null() {
            stogas_verifier_string_free(stogas_evidence_refresh(
                owner,
                data.as_ptr(),
                data.len(),
                1_789_953_060_035,
                &raw mut snapshot,
            ));
            stogas_evidence_snapshot_free(snapshot);
            stogas_evidence_free(owner);
        }
    }
});
