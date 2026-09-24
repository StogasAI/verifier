#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use stogas_verifier::signing;

fuzz_target!(|data: &[u8]| {
    let _ = signing::public_key_from_spki(data);
    let _ = signing::SigningKey::from_pkcs8(data);

    // Retain a valid starting point as well as arbitrary encodings. Shared
    // conformance vectors own the bytes; the corpus only needs a short marker.
    static VALID: OnceLock<Vec<u8>> = OnceLock::new();
    let mut candidate;
    let data = if data.first() == Some(&b'S') {
        candidate = VALID
            .get_or_init(|| {
                let vector: serde_json::Value =
                    serde_json::from_str(include_str!("../../tests/fixtures/mldsa65-v1.json"))
                        .unwrap();
                ["public_key", "signature", "message"]
                    .into_iter()
                    .flat_map(|field| hex::decode(vector[field].as_str().unwrap()).unwrap())
                    .collect()
            })
            .clone();
        for mutation in data[1..].chunks_exact(3) {
            let offset =
                usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % candidate.len();
            candidate[offset] = mutation[2];
        }
        candidate.as_slice()
    } else {
        data
    };

    // Exercise the signature decoder beyond its length check.
    let mut public = [0; signing::PUBLIC_KEY_BYTES];
    let mut signature = [0; signing::SIGNATURE_BYTES];
    let key_len = data.len().min(public.len());
    public[..key_len].copy_from_slice(&data[..key_len]);
    let rest = &data[key_len..];
    let signature_len = rest.len().min(signature.len());
    signature[..signature_len].copy_from_slice(&rest[..signature_len]);
    let _ = signing::verify(&public, &rest[signature_len..], b"", &signature);
});
