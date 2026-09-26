#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier::{
    attestation::{BatchProof, certificate::ParsedNativeCertificate, evidence::SessionEvidence},
    inspect_snp_report,
};

fuzz_target!(|data: &[u8]| {
    let _ = inspect_snp_report(data);
    let _ = BatchProof::from_bytes(data);
    let _ = SessionEvidence::from_bytes(data);
    let _ = SessionEvidence::from_extension(data);
    let _ = ParsedNativeCertificate::parse(data);
});
