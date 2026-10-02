use super::*;
use ml_kem::{Decapsulate as _, KeyExport as _, MlKem768};

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn incremental_mlkem_matches_independent_fips_implementation() {
    for counter in 0..32_u8 {
        let seed = std::array::from_fn(|index| counter.wrapping_add(u8::try_from(index).unwrap()));
        let coins = std::array::from_fn(|index| counter.wrapping_sub(u8::try_from(index).unwrap()));
        let key = KeyPair::generate(&seed);
        let reference = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed.into());
        let public = reference.encapsulation_key().to_bytes();
        assert_eq!(key.vector(), &public[..KEY_BYTES]);
        assert_eq!(&key.header()[..32], &public[KEY_BYTES..]);
        let (reference_ct, reference_secret) = reference
            .encapsulation_key()
            .encapsulate_deterministic(&coins.into());
        let (encapsulation, ct1, secret) = Encapsulation::begin(key.header(), &coins).unwrap();
        let ct2 = encapsulation.finish(key.header(), key.vector()).unwrap();
        assert_eq!(ct1, reference_ct[..CT1_BYTES]);
        assert_eq!(ct2, reference_ct[CT1_BYTES..]);
        assert_eq!(secret.as_slice(), reference_secret.as_slice());
        assert_eq!(key.decapsulate(&ct1, &ct2).unwrap(), secret);
        // Both decapsulators use implicit rejection for every changed byte.
        for index in 0..if counter == 0 { reference_ct.len() } else { 0 } {
            let mut altered = reference_ct;
            altered[index] ^= 1;
            assert_eq!(
                key.decapsulate(&altered[..CT1_BYTES], &altered[CT1_BYTES..])
                    .unwrap()
                    .as_slice(),
                reference.decapsulate(&altered).as_slice(),
            );
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn incremental_keys_reject_changed_commitments_noncanonical_coefficients_and_lengths() {
    let key = KeyPair::generate(&[7; 64]);
    for length in [0, HEADER_BYTES - 1, HEADER_BYTES + 1] {
        assert!(Encapsulation::begin(&vec![0; length], &[8; 32]).is_err());
    }
    for position in 0..KEY_BYTES + HEADER_BYTES {
        let mut header = key.header().to_vec();
        let mut vector = key.vector().to_vec();
        if position < KEY_BYTES {
            vector[position] ^= 1;
        } else {
            header[position - KEY_BYTES] ^= 1;
        }
        let (encapsulation, _, _) = Encapsulation::begin(&header, &[8; 32]).unwrap();
        assert!(encapsulation.finish(&header, &vector).is_err());
    }
    // Even a matching public-key hash cannot make an out-of-field coefficient valid.
    let mut vector = key.vector().to_vec();
    vector[0] = 0xff;
    vector[1] |= 0x0f;
    let mut header = key.header().to_vec();
    let mut public = vector.clone();
    public.extend_from_slice(&header[..32]);
    header[32..].copy_from_slice(&libcrux_sha3::sha256(&public));
    let (encapsulation, _, _) = Encapsulation::begin(&header, &[8; 32]).unwrap();
    assert!(encapsulation.finish(&header, &vector).is_err());
    for length in [0, CT1_BYTES - 1, CT1_BYTES + 1] {
        assert!(key.decapsulate(&vec![0; length], &[0; CT2_BYTES]).is_err());
    }
    for length in [0, CT2_BYTES - 1, CT2_BYTES + 1] {
        assert!(key.decapsulate(&[0; CT1_BYTES], &vec![0; length]).is_err());
    }
}

// Unmodified Project Wycheproof vectors, Apache-2.0, pinned by the adjacent
// provenance file. This exercises the public incremental operations we use;
// no untrusted expanded-secret-key import exists in this protocol.
fn vector_cases(name: &str) -> Vec<serde_json::Value> {
    let source = match name {
        "mlkem_768_keygen_seed_test.json" => include_str!(
            "../../../../../../tests/fixtures/wycheproof/mlkem_768_keygen_seed_test.json"
        ),
        "mlkem_768_encaps_test.json" => {
            include_str!("../../../../../../tests/fixtures/wycheproof/mlkem_768_encaps_test.json")
        }
        "mlkem_768_test.json" => {
            include_str!("../../../../../../tests/fixtures/wycheproof/mlkem_768_test.json")
        }
        _ => panic!("unknown vector"),
    };
    let vector: serde_json::Value = serde_json::from_str(source).unwrap();
    vector["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["tests"].as_array().unwrap().iter().cloned())
        .collect()
}
fn bytes(case: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(case[name].as_str().unwrap()).unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_mlkem768_seed_key_generation() {
    let cases = vector_cases("mlkem_768_keygen_seed_test.json");
    assert_eq!(cases.len(), 100);
    for case in cases {
        let key = KeyPair::generate(&bytes(&case, "seed").try_into().unwrap());
        assert_eq!(key.0.as_slice(), bytes(&case, "dk"), "{}", case["tcId"]);
        let public = bytes(&case, "ek");
        assert_eq!(key.vector(), &public[..KEY_BYTES], "{}", case["tcId"]);
        assert_eq!(
            &key.header()[..32],
            &public[KEY_BYTES..],
            "{}",
            case["tcId"]
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_mlkem768_incremental_encapsulation() {
    let cases = vector_cases("mlkem_768_encaps_test.json");
    assert_eq!(cases.len(), 265);
    for case in cases {
        let public = bytes(&case, "ek");
        if public.len() != KEY_BYTES + 32 {
            assert_eq!(case["result"], "invalid", "{}", case["tcId"]);
            assert!(validate_public_key(&[], &public).is_err());
            continue;
        }
        let mut header = public[KEY_BYTES..].to_vec();
        header.extend_from_slice(&libcrux_sha3::sha256(&public));
        let (encapsulation, mut ciphertext, secret) =
            Encapsulation::begin(&header, &bytes(&case, "m").try_into().unwrap()).unwrap();
        let result = encapsulation.finish(&header, &public[..KEY_BYTES]);
        if case["result"] == "invalid" {
            assert!(result.is_err(), "{}", case["tcId"]);
        } else {
            ciphertext.extend(result.unwrap());
            assert_eq!(ciphertext, bytes(&case, "c"), "{}", case["tcId"]);
            assert_eq!(secret.as_slice(), bytes(&case, "K"), "{}", case["tcId"]);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_mlkem768_decapsulation_and_implicit_rejection() {
    let cases = vector_cases("mlkem_768_test.json");
    assert_eq!(cases.len(), 201);
    for case in cases {
        let seed: Result<[u8; 64], _> = bytes(&case, "seed").try_into();
        let Ok(seed) = seed else {
            assert_eq!(case["result"], "invalid", "{}", case["tcId"]);
            continue;
        };
        let key = KeyPair::generate(&seed);
        let ciphertext = bytes(&case, "c");
        let expected = bytes(&case, "K");
        let result = if ciphertext.len() == CT1_BYTES + CT2_BYTES {
            key.decapsulate(&ciphertext[..CT1_BYTES], &ciphertext[CT1_BYTES..])
        } else {
            Err(Error::Record)
        };
        if case["result"] == "invalid" {
            assert!(
                result.is_err() || result.unwrap().as_slice() != expected,
                "{}",
                case["tcId"]
            );
        } else {
            assert_eq!(result.unwrap().as_slice(), expected, "{}", case["tcId"]);
        }
    }
}
