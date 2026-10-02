//! AES-GCM execution, separate from record framing, nonce allocation and limits.

use super::Error;
use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInOut as _, KeyInit as _},
};
use core::future::Future;
use zeroize::Zeroizing;

/// Platform AES-256-GCM execution. The record layer alone owns nonces, framing,
/// ordering and limits. Implementations must never expose unauthenticated plaintext.
pub trait Cipher: Sized {
    /// Consume one directional key. No session root is passed to the backend.
    ///
    /// # Errors
    /// Rejects an unavailable cryptographic implementation.
    fn from_key(key: Zeroizing<[u8; 32]>) -> Result<Self, Error>;

    /// Authenticate the first record synchronously while the session transaction
    /// is held, then retain this backend for subsequent independent records.
    ///
    /// # Errors
    /// Authentication failure never creates a live backend or commits a session.
    fn from_authenticated_start(
        key: Zeroizing<[u8; 32]>,
        nonce: [u8; 12],
        aad: &[u8],
        sealed: &mut [u8],
    ) -> Result<Self, Error> {
        SoftwareCipher::new(key.as_ref())?.decrypt_now(nonce, aad, sealed)?;
        Self::from_key(key)
    }

    /// Encrypt in place and return the full 128-bit authentication tag.
    fn encrypt<'a>(
        &'a mut self,
        nonce: [u8; 12],
        aad: &'a [u8],
        plaintext: &'a mut [u8],
    ) -> impl Future<Output = Result<[u8; 16], Error>> + 'a;

    /// Authenticate ciphertext including its final 16-byte tag, then replace
    /// only the ciphertext portion with plaintext. Authentication failure is final.
    fn decrypt<'a>(
        &'a mut self,
        nonce: [u8; 12],
        aad: &'a [u8],
        sealed: &'a mut [u8],
    ) -> impl Future<Output = Result<(), Error>> + 'a;
}

/// Portable Rust AES-GCM; native builds use the library's CPU acceleration.
pub struct SoftwareCipher(Aes256Gcm);

impl SoftwareCipher {
    pub(super) fn new(key: &[u8]) -> Result<Self, Error> {
        Aes256Gcm::new_from_slice(key)
            .map(Self)
            .map_err(|_| Error::Crypto)
    }

    /// Encrypt synchronously with the native or portable Rust implementation.
    /// # Errors
    /// Rejects input exceeding the AES-GCM message limit.
    pub fn encrypt_now(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        self.0
            .encrypt_inout_detached(&Nonce::from(nonce), aad, plaintext.into())
            .map(Into::into)
            .map_err(|_| Error::Crypto)
    }

    /// Authenticate and decrypt synchronously.
    /// # Errors
    /// Rejects a missing tag or an authentication failure.
    pub fn decrypt_now(&self, nonce: [u8; 12], aad: &[u8], sealed: &mut [u8]) -> Result<(), Error> {
        let length = sealed.len().checked_sub(16).ok_or(Error::Record)?;
        let (ciphertext, tag) = sealed.split_at_mut(length);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::Record)?;
        self.0
            .decrypt_inout_detached(&Nonce::from(nonce), aad, ciphertext.into(), &tag)
            .map_err(|_| Error::Authentication)
    }
}

impl Cipher for SoftwareCipher {
    fn from_key(key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        Self::new(key.as_ref())
    }

    fn from_authenticated_start(
        key: Zeroizing<[u8; 32]>,
        nonce: [u8; 12],
        aad: &[u8],
        sealed: &mut [u8],
    ) -> Result<Self, Error> {
        let cipher = Self::from_key(key)?;
        cipher.decrypt_now(nonce, aad, sealed)?;
        Ok(cipher)
    }

    async fn encrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        self.encrypt_now(nonce, aad, plaintext)
    }

    async fn decrypt(
        &mut self,
        nonce: [u8; 12],
        aad: &[u8],
        sealed: &mut [u8],
    ) -> Result<(), Error> {
        self.decrypt_now(nonce, aad, sealed)
    }
}
