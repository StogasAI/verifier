use super::*;
use wasm_bindgen_test::wasm_bindgen_test;

fn browser_cipher() -> HostCipher {
    let cipher = HostCipher::from_key(Zeroizing::new([42; 32])).unwrap();
    assert!(
        cipher.subtle.is_some(),
        "this test must use actual WebCrypto"
    );
    cipher
}

fn mock_cipher(body: &str) -> HostCipher {
    let subtle = js_sys::Function::new_no_args(body)
        .call0(&wasm_bindgen::JsValue::UNDEFINED)
        .unwrap();
    HostCipher {
        subtle: Some(subtle.unchecked_into()),
        key: Key::Pending(Zeroizing::new([42; 32])),
    }
}

#[wasm_bindgen_test]
async fn webcrypto_matches_rust_and_imports_a_nonextractable_key_once() {
    let mut cipher = browser_cipher();
    let mut rust = SoftwareCipher::from_key(Zeroizing::new([42; 32])).unwrap();
    for length in [0, 1, 15, 16, 17, 255, 4096, 65_516] {
        let mut plaintext = vec![7; length];
        let mut expected = plaintext.clone();
        let mut nonce = [1; 12];
        nonce[..4].copy_from_slice(&u32::try_from(length).unwrap().to_be_bytes());
        let tag = cipher
            .encrypt(nonce, b"authenticated header", &mut plaintext)
            .await
            .unwrap();
        let expected_tag = rust
            .encrypt(nonce, b"authenticated header", &mut expected)
            .await
            .unwrap();
        assert_eq!(plaintext, expected);
        assert_eq!(tag, expected_tag);
        let Key::Web(key) = &cipher.key else {
            panic!("unexpected software fallback");
        };
        assert!(!key.extractable());
        let imported = key.clone();
        plaintext.extend_from_slice(&tag);
        cipher
            .decrypt(nonce, b"authenticated header", &mut plaintext)
            .await
            .unwrap();
        assert_eq!(&plaintext[..length], &vec![7; length]);
        let Key::Web(key) = &cipher.key else {
            panic!("unexpected software fallback");
        };
        assert!(
            js_sys::Object::is(&imported, key),
            "directional key must be reused"
        );
    }
}

#[wasm_bindgen_test]
async fn authentication_failure_never_selects_the_software_fallback_or_releases_plaintext() {
    let mut cipher = browser_cipher();
    let mut sealed = b"private content".to_vec();
    let tag = cipher
        .encrypt([1; 12], b"header", &mut sealed)
        .await
        .unwrap();
    sealed.extend_from_slice(&tag);
    for index in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        let before = changed.clone();
        assert_eq!(
            cipher.decrypt([1; 12], b"header", &mut changed).await,
            Err(Error::Authentication)
        );
        assert_eq!(changed, before);
        assert!(matches!(cipher.key, Key::Web(_)));
    }
    assert_eq!(
        cipher.decrypt([2; 12], b"header", &mut sealed).await,
        Err(Error::Authentication)
    );
    assert_eq!(
        cipher.decrypt([1; 12], b"changed", &mut sealed).await,
        Err(Error::Authentication)
    );
}

#[wasm_bindgen_test]
async fn only_an_unavailable_algorithm_allows_import_fallback() {
    for name in [
        "NotSupportedError",
        "DataError",
        "OperationError",
        "SecurityError",
    ] {
        let mut cipher = mock_cipher(&format!(
            "return {{ importKey() {{ return Promise.reject({{ name: '{name}' }}); }} }};"
        ));
        let result = cipher.encrypt([1; 12], b"header", &mut [1; 16]).await;
        if name == "NotSupportedError" {
            assert!(result.is_ok());
            assert!(matches!(cipher.key, Key::Rust(_)));
        } else {
            assert_eq!(result, Err(Error::Crypto));
            assert!(matches!(cipher.key, Key::Closed));
        }
    }
    let mut cipher =
        mock_cipher("return { importKey() { throw { name: 'NotSupportedError' }; } };");
    assert!(
        cipher
            .encrypt([1; 12], b"header", &mut [1; 16])
            .await
            .is_ok()
    );
}

#[wasm_bindgen_test]
async fn imported_raw_bytes_are_cleared_and_record_failure_is_terminal() {
    let mut cipher = mock_cipher("return {
        importKey(format, bytes, algorithm, extractable, usages) {
            if (format !== 'raw' || algorithm !== 'AES-GCM' || extractable || bytes.length !== 32 || !bytes.every(x => x === 42)) throw Error('bad key');
            return Promise.resolve().then(() => {
                if (!bytes.every(x => x === 0)) throw Error('raw bytes retained');
                return {};
            });
        },
        encrypt() { return Promise.reject({ name: 'NotSupportedError' }); }
    };");
    assert_eq!(
        cipher.encrypt([1; 12], b"header", &mut [1; 16]).await,
        Err(Error::Crypto)
    );
    assert!(
        matches!(cipher.key, Key::Web(_)),
        "record failure must not switch backends"
    );
}

#[wasm_bindgen_test]
async fn missing_webcrypto_uses_the_portable_backend() {
    let mut cipher = HostCipher {
        subtle: None,
        key: Key::Rust(Box::new(
            SoftwareCipher::from_key(Zeroizing::new([42; 32])).unwrap(),
        )),
    };
    let mut bytes = b"content".to_vec();
    let tag = cipher
        .encrypt([1; 12], b"header", &mut bytes)
        .await
        .unwrap();
    bytes.extend_from_slice(&tag);
    cipher
        .decrypt([1; 12], b"header", &mut bytes)
        .await
        .unwrap();
    assert_eq!(&bytes[..7], b"content");
}
