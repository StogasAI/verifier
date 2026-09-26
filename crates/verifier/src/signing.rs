//! The fixed ML-DSA-65 signature profile used for Stogas-controlled signatures.
//!
//! Pure ML-DSA signs the complete purpose-separated message. No implicit prehash or
//! algorithm fallback is accepted. Artifact, receipt and log formats own their encodings.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey, portable};
use sha2::{Digest as _, Sha512};
use spki::{
    AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef,
    der::{Decode as _, Encode as _, asn1::BitStringRef},
};
use zeroize::Zeroizing;

/// FIPS 204 ML-DSA-65 public key length.
pub const PUBLIC_KEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 signature length.
pub const SIGNATURE_BYTES: usize = 3309;
/// FIPS 204 key-generation seed length.
pub const SEED_BYTES: usize = 32;
const PRIVATE_KEY_BYTES: usize = 4032;
const ML_DSA_65_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// Signature errors contain no key or document material.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    /// The document exceeds the shared bounded-input profile.
    #[error("signed document exceeds the input limit")]
    TooLarge,
    /// The fixed profile's public key or signature length differs.
    #[error("invalid ML-DSA-65 key or signature length")]
    Length,
    /// The SPKI is malformed, uses another algorithm, or has parameters.
    #[error("invalid ML-DSA-65 public key encoding")]
    PublicKey,
    /// Private keys use the RFC 9881 seed-only PKCS #8 representation.
    #[error("invalid ML-DSA-65 seed private key encoding")]
    PrivateKey,
    /// Rekor compatibility keys use a separate 32-byte Ed25519 seed.
    #[error("invalid Rekor submission key seed")]
    SubmissionKey,
    /// FIPS 204 limits the signing context to 255 bytes.
    #[error("ML-DSA signing context exceeds 255 bytes")]
    Context,
    /// The signature is malformed or does not authenticate this message and context.
    #[error("ML-DSA-65 signature verification failed")]
    Verification,
    /// Signature generation failed.
    #[error("ML-DSA-65 signing failed")]
    Signing,
    /// The platform could not supply cryptographic randomness.
    #[error("cryptographic randomness is unavailable")]
    Randomness,
}

/// An expanded signing key, erased on drop and never implicitly cloned or formatted.
pub struct SigningKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    secret: Zeroizing<[u8; PRIVATE_KEY_BYTES]>,
    public: [u8; PUBLIC_KEY_BYTES],
}

impl SigningKey {
    /// Read an RFC 9881 seed-only PKCS #8 key. Expanded or duplicate representations
    /// are deliberately excluded; callers retain responsibility for erasing their input.
    ///
    /// # Errors
    /// Rejects other algorithms, parameters, malformed DER and non-seed key forms.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|_| Error::PrivateKey)?;
        if info.algorithm.oid != ML_DSA_65_OID
            || info.algorithm.parameters.is_some()
            || info.public_key.is_some()
        {
            return Err(Error::PrivateKey);
        }
        let Some(seed) = info.private_key.strip_prefix(&[0x80, 0x20]) else {
            return Err(Error::PrivateKey);
        };
        Ok(Self::from_seed(
            seed.try_into().map_err(|_| Error::PrivateKey)?,
        ))
    }

    /// Derive a key from a cryptographically random seed; the caller owns seed erasure.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        let mut key = Self {
            seed: Zeroizing::new(*seed),
            secret: Zeroizing::new([0; PRIVATE_KEY_BYTES]),
            public: [0; PUBLIC_KEY_BYTES],
        };
        portable::generate_key_pair_mut(*seed, &mut key.secret, &mut key.public);
        key
    }

    /// The FIPS 204 public key encoding, without an ASN.1 wrapper.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public
    }

    /// Encode the public key as RFC 9881 DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// Returns an error if DER encoding fails.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Error> {
        SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: ML_DSA_65_OID,
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(&self.public)
                .map_err(|_| Error::PublicKey)?,
        }
        .to_der()
        .map_err(|_| Error::PublicKey)
    }

    /// The stable Rekor submission public key associated with this signing key.
    /// Publish this association in authenticated signing metadata before using it
    /// to discover entries. It does not grant document-signing authority.
    ///
    /// # Errors
    /// Returns an error if derivation or DER encoding fails.
    pub fn rekor_public_key_spki(&self) -> Result<Vec<u8>, Error> {
        self.rekor_key()?.public_key_spki()
    }

    /// Prepare an exact Rekor v1 submission over SHA-512 of a complete signed document.
    ///
    /// Derives a purpose-separated Ed25519ph key for this operation and erases it
    /// on drop. The same signing key and document yield the same submission.
    /// Persist the signed document and submission before the first POST: ML-DSA
    /// signing uses randomness, so signing the document again changes its digest.
    ///
    /// # Errors
    /// Rejects oversized documents and derivation, encoding or signing failures.
    pub fn prepare_rekor_submission(&self, signed_document: &[u8]) -> Result<String, Error> {
        self.rekor_key()?.prepare_submission(signed_document)
    }

    fn rekor_key(&self) -> Result<RekorSubmissionKey, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2_v11::Sha512>::new(None, self.seed.as_ref())
            .expand(b"stogas.rekor.ed25519ph.v1", seed.as_mut())
            .map_err(|_| Error::Signing)?;
        RekorSubmissionKey::from_seed(seed.as_ref())
    }

    /// Sign using fresh per-signature randomness and the supplied protocol context.
    ///
    /// # Errors
    /// Rejects overlong contexts, unavailable randomness and signing failures.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<[u8; SIGNATURE_BYTES], Error> {
        check_context(context)?;
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *randomness).map_err(|_| Error::Randomness)?;
        self.sign_with_randomness(message, context, &randomness)
    }

    fn sign_with_randomness(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        check_context(context)?;
        let mut signature = [0; SIGNATURE_BYTES];
        portable::sign_mut(&self.secret, message, context, *randomness, &mut signature)
            .map_err(|_| Error::Signing)?;
        Ok(signature)
    }
}

/// A Rekor compatibility key for a publisher whose ML-DSA key cannot be exported.
///
/// It grants no Stogas approval authority. Bind its public key to the ML-DSA key
/// in authenticated metadata; document verification must require both proofs.
pub struct RekorSubmissionKey(ed25519_dalek::SigningKey);

impl RekorSubmissionKey {
    /// Import a separate random seed. The caller owns erasure of its input copy.
    ///
    /// # Errors
    /// Rejects seeds that are not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(
            seed.try_into().map_err(|_| Error::SubmissionKey)?,
        )))
    }

    /// Encode the submission public key for authenticated publication and log searches.
    ///
    /// # Errors
    /// Returns an error if DER encoding fails.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Error> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Error::PublicKey)
    }

    /// Sign SHA-512 of the complete signed document for Rekor v1. Persist the
    /// exact signed document and this deterministic submission before delivery.
    ///
    /// # Errors
    /// Rejects oversized documents and encoding or signing failures.
    pub fn prepare_submission(&self, signed_document: &[u8]) -> Result<String, Error> {
        if signed_document.len() > crate::MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let digest = Sha512::new_with_prefix(signed_document);
        let signature = self
            .0
            .sign_prehashed(digest.clone(), None)
            .map_err(|_| Error::Signing)?;
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(self.public_key_spki()?)
        );
        crate::canonical_json(&serde_json::json!({
            "apiVersion":"0.0.1", "kind":"hashedrekord", "spec":{
                "data":{"hash":{"algorithm":"sha512","value":hex::encode(digest.finalize())}},
                "signature":{"content":STANDARD.encode(signature.to_bytes()),
                    "publicKey":{"content":STANDARD.encode(pem)}}
            }
        }))
        .map_err(|_| Error::Signing)
    }
}

/// Verify pure ML-DSA-65 using a raw public key and the exact signed message/context.
///
/// # Errors
/// Rejects wrong lengths, overlong contexts and invalid signatures.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    check_context(context)?;
    let public_key = MLDSA65VerificationKey::new(public_key.try_into().map_err(|_| Error::Length)?);
    let signature = MLDSA65Signature::new(signature.try_into().map_err(|_| Error::Length)?);
    portable::verify(&public_key, message, context, &signature).map_err(|_| Error::Verification)
}

/// FIPS 204's external message representative for a remote pure ML-DSA signer.
/// This is not HashML-DSA: it preserves the exact message and protocol context.
///
/// # Errors
/// Rejects invalid public-key lengths and oversized messages or contexts.
pub fn message_representative(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; 64], Error> {
    use libcrux_sha3::portable::incremental::{Shake256Xof, Xof as _};
    check_context(context)?;
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(Error::Length);
    }
    if message.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let tr = libcrux_sha3::shake256::<64>(public_key);
    let mut hash = Shake256Xof::new();
    hash.absorb(&tr);
    hash.absorb(&[0, u8::try_from(context.len()).map_err(|_| Error::Context)?]);
    hash.absorb(context);
    hash.absorb_final(message);
    let mut mu = [0; 64];
    hash.squeeze(&mut mu);
    Ok(mu)
}

/// Extract an ML-DSA-65 public key from its strict DER `SubjectPublicKeyInfo` encoding.
///
/// # Errors
/// Rejects trailing bytes, algorithm parameters, other algorithms and wrong key lengths.
pub fn public_key_from_spki(der: &[u8]) -> Result<&[u8; PUBLIC_KEY_BYTES], Error> {
    let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|_| Error::PublicKey)?;
    if spki.algorithm.oid != ML_DSA_65_OID || spki.algorithm.parameters.is_some() {
        return Err(Error::PublicKey);
    }
    spki.subject_public_key
        .as_bytes()
        .ok_or(Error::PublicKey)?
        .try_into()
        .map_err(|_| Error::Length)
}

const fn check_context(context: &[u8]) -> Result<(), Error> {
    if context.len() > 255 {
        return Err(Error::Context);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
