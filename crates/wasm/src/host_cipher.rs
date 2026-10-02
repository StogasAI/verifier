#![allow(
    clippy::future_not_send,
    reason = "JavaScript promises run on their owning event loop"
)]

//! Browser/runtime AES-GCM. Protocol state and session secrets stay in the core.

use js_sys::{Array, Reflect, Uint8Array};
use stogas_verifier::channel::{
    Error,
    cipher::{Cipher, SoftwareCipher},
};
use wasm_bindgen::JsCast as _;
use web_sys::{AesGcmParams, CryptoKey, SubtleCrypto};
use zeroize::Zeroizing;

thread_local! {
    // Capabilities are stable for this Wasm instance; never switch after a failed
    // encryption or authentication operation.
    static SUBTLE: Option<SubtleCrypto> = subtle();
}

fn subtle() -> Option<SubtleCrypto> {
    let crypto = Reflect::get(&js_sys::global(), &"crypto".into()).ok()?;
    let subtle = Reflect::get(&crypto, &"subtle".into()).ok()?;
    for method in ["importKey", "encrypt", "decrypt"] {
        if !Reflect::get(&subtle, &method.into()).ok()?.is_function() {
            return None;
        }
    }
    // Some Fetch runtimes expose the service without a global SubtleCrypto
    // constructor. Its methods, not an instanceof check, establish availability.
    Some(subtle.unchecked_into())
}

enum Key {
    Pending(Zeroizing<[u8; 32]>),
    Web(CryptoKey),
    Rust(Box<SoftwareCipher>),
    Closed,
}

pub struct HostCipher {
    subtle: Option<SubtleCrypto>,
    key: Key,
}

impl HostCipher {
    async fn import(&mut self) -> Result<(), Error> {
        if !matches!(self.key, Key::Pending(_)) {
            return Ok(());
        }
        let Key::Pending(key) = std::mem::replace(&mut self.key, Key::Closed) else {
            return Err(Error::Closed);
        };
        let subtle = self.subtle.as_ref().ok_or(Error::Closed)?;
        let bytes = Uint8Array::from(key.as_slice());
        let usages = Array::of2(&"encrypt".into(), &"decrypt".into());
        let promise = subtle.import_key_with_str("raw", &bytes, "AES-GCM", false, &usages);
        // WebCrypto snapshots input bytes before returning its Promise.
        bytes.fill(0, 0, bytes.length());
        let imported = match promise {
            Ok(promise) => promise.await,
            Err(error) => Err(error),
        };
        match imported {
            Ok(imported) => {
                self.key = Key::Web(imported.unchecked_into());
                Ok(())
            }
            Err(error)
                if Reflect::get(&error, &"name".into())
                    .ok()
                    .and_then(|name| name.as_string())
                    .as_deref()
                    == Some("NotSupportedError") =>
            {
                // The algorithm is unavailable before any record operation.
                // Other import failures are terminal, including bad input.
                self.key = Key::Rust(Box::new(SoftwareCipher::from_key(key)?));
                self.subtle = None;
                Ok(())
            }
            Err(_) => Err(Error::Crypto),
        }
    }

    fn params(nonce: &[u8; 12], aad: &[u8]) -> AesGcmParams {
        let params = AesGcmParams::new("AES-GCM", &Uint8Array::from(nonce.as_slice()));
        params.set_additional_data(&Uint8Array::from(aad));
        params.set_tag_length(128);
        params
    }
}

impl Cipher for HostCipher {
    fn from_key(key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        let subtle = SUBTLE.with(Clone::clone);
        let key = if subtle.is_some() {
            Key::Pending(key)
        } else {
            Key::Rust(Box::new(SoftwareCipher::from_key(key)?))
        };
        Ok(Self { subtle, key })
    }

    async fn encrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        self.import().await?;
        match &self.key {
            Key::Rust(cipher) => cipher.encrypt_now(nonce, aad, plaintext),
            Key::Web(key) => {
                let encrypted = self
                    .subtle
                    .as_ref()
                    .ok_or(Error::Closed)?
                    .encrypt_with_object_and_u8_array(&Self::params(&nonce, aad), key, plaintext)
                    .map_err(|_| Error::Crypto)?
                    .await
                    .map_err(|_| Error::Crypto)?;
                let bytes = Uint8Array::new(&encrypted);
                let length = u32::try_from(plaintext.len()).map_err(|_| Error::Limit)?;
                if bytes.length() != length + 16 {
                    return Err(Error::Crypto);
                }
                bytes.subarray(0, length).copy_to(plaintext);
                let mut tag = [0_u8; 16];
                bytes.subarray(length, length + 16).copy_to(&mut tag);
                Ok(tag)
            }
            _ => Err(Error::Closed),
        }
    }

    async fn decrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        sealed: &mut [u8],
    ) -> Result<(), Error> {
        self.import().await?;
        match &self.key {
            Key::Rust(cipher) => cipher.decrypt_now(nonce, aad, sealed),
            Key::Web(key) => {
                let plaintext = self
                    .subtle
                    .as_ref()
                    .ok_or(Error::Closed)?
                    .decrypt_with_object_and_u8_array(&Self::params(&nonce, aad), key, sealed)
                    .map_err(|_| Error::Authentication)?
                    .await
                    .map_err(|_| Error::Authentication)?;
                let bytes = Uint8Array::new(&plaintext);
                let length = sealed.len().checked_sub(16).ok_or(Error::Record)?;
                if bytes.length() as usize != length {
                    bytes.fill(0, 0, bytes.length());
                    return Err(Error::Crypto);
                }
                bytes.copy_to(&mut sealed[..length]);
                bytes.fill(0, 0, bytes.length());
                Ok(())
            }
            _ => Err(Error::Closed),
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests;
