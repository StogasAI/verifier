//! Post-quantum secret release sealing shared by Control adapters.

use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::AesGcm256, kdf::HkdfSha256, kem::XWing,
    setup_sender,
};
use thiserror::Error;

const HPKE_INFO: &[u8] = b"stogas.secret-release.v1";
const XWING_PUBLIC_KEY_BYTES: usize = 1_216;
const MAX_AAD_BYTES: usize = 64 * 1024;
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// One X-Wing HPKE ciphertext for a quote-bound node key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSecret {
    /// Serialized X-Wing encapsulated key.
    pub encapsulated_key: Vec<u8>,
    /// AES-256-GCM ciphertext and authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Secret release sealing failure.
#[derive(Debug, Error)]
pub enum Error {
    /// The quote-bound recipient key, associated data, or secret is invalid.
    #[error("invalid secret release input: {0}")]
    InvalidInput(&'static str),
    /// HPKE setup or encryption failed.
    #[error("secret release encryption failed")]
    Crypto,
}

/// Seal one secret with X-Wing, HKDF-SHA-256, and AES-256-GCM.
///
/// # Errors
///
/// Returns an error for an invalid X-Wing key, an empty or oversized input, or a cryptographic
/// failure.
pub fn seal(public_key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<SealedSecret, Error> {
    if public_key.len() != XWING_PUBLIC_KEY_BYTES {
        return Err(Error::InvalidInput(
            "X-Wing public key must contain 1216 bytes",
        ));
    }
    if aad.is_empty() || aad.len() > MAX_AAD_BYTES {
        return Err(Error::InvalidInput("associated data has an invalid size"));
    }
    if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
        return Err(Error::InvalidInput("secret has an invalid size"));
    }
    let public_key = <XWing as hpke::Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_| Error::InvalidInput("invalid X-Wing public key"))?;
    let (encapsulated_key, mut sender) =
        setup_sender::<AesGcm256, HkdfSha256, XWing>(&OpModeS::Base, &public_key, HPKE_INFO)
            .map_err(|_| Error::Crypto)?;
    let ciphertext = sender.seal(plaintext, aad).map_err(|_| Error::Crypto)?;
    Ok(SealedSecret {
        encapsulated_key: encapsulated_key.to_bytes().to_vec(),
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Kem as _, OpModeR, setup_receiver};

    #[test]
    fn seals_for_the_exact_quote_bound_recipient_and_aad() {
        let (private_key, public_key) = XWing::gen_keypair();
        let aad = br#"{"schema":"stogas.confidential-secret-release.v1"}"#;
        let sealed = seal(&public_key.to_bytes(), aad, b"provider-secret").unwrap();
        let encapsulated =
            <XWing as hpke::Kem>::EncappedKey::from_bytes(&sealed.encapsulated_key).unwrap();
        let mut wrong_aad_recipient = setup_receiver::<AesGcm256, HkdfSha256, XWing>(
            &OpModeR::Base,
            &private_key,
            &encapsulated,
            HPKE_INFO,
        )
        .unwrap();
        assert!(
            wrong_aad_recipient
                .open(&sealed.ciphertext, b"different")
                .is_err()
        );
        let mut recipient = setup_receiver::<AesGcm256, HkdfSha256, XWing>(
            &OpModeR::Base,
            &private_key,
            &encapsulated,
            HPKE_INFO,
        )
        .unwrap();
        assert_eq!(
            recipient.open(&sealed.ciphertext, aad).unwrap(),
            b"provider-secret"
        );
    }
}
