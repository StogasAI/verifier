#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier::{inspect_snp_quote, verify_heartbeat_admission};

fuzz_target!(|data: &[u8]| {
    if let Ok(quote) = std::str::from_utf8(data) {
        let _ = inspect_snp_quote(quote);
    }
    let _ = verify_heartbeat_admission(data, 1_784_394_453_044);
});
