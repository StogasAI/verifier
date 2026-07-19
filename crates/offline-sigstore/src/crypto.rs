//! WASM-safe signature verification used by X.509, Sigstore, and RFC 3161.

use const_oid::{ObjectIdentifier, db::rfc5912};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey as _, traits::PublicKeyParts as _};
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use signature::{Verifier as _, hazmat::PrehashVerifier as _};
use spki::SubjectPublicKeyInfoRef;

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Signature schemes accepted by the supported Sigstore profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    EcdsaP256Sha256,
    EcdsaP256Sha384,
    EcdsaP384Sha256,
    EcdsaP384Sha384,
    Ed25519,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
}

#[derive(Debug)]
struct RustCryptoAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    scheme: Scheme,
}

impl SignatureVerificationAlgorithm for RustCryptoAlgorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_raw(self.scheme, public_key, message, signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

static ECDSA_P256_SHA256: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: Scheme::EcdsaP256Sha256,
};
static ECDSA_P256_SHA384: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: Scheme::EcdsaP256Sha384,
};
static ECDSA_P384_SHA256: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: Scheme::EcdsaP384Sha256,
};
static ECDSA_P384_SHA384: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: Scheme::EcdsaP384Sha384,
};
static ED25519: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    scheme: Scheme::Ed25519,
};

macro_rules! rsa_algorithm {
    ($name:ident, $signature_alg_id:expr, $scheme:expr) => {
        static $name: RustCryptoAlgorithm = RustCryptoAlgorithm {
            public_key_alg_id: alg_id::RSA_ENCRYPTION,
            signature_alg_id: $signature_alg_id,
            scheme: $scheme,
        };
    };
}

rsa_algorithm!(
    RSA_PKCS1_SHA256,
    alg_id::RSA_PKCS1_SHA256,
    Scheme::RsaPkcs1Sha256
);
rsa_algorithm!(
    RSA_PKCS1_SHA384,
    alg_id::RSA_PKCS1_SHA384,
    Scheme::RsaPkcs1Sha384
);
rsa_algorithm!(
    RSA_PKCS1_SHA512,
    alg_id::RSA_PKCS1_SHA512,
    Scheme::RsaPkcs1Sha512
);
rsa_algorithm!(RSA_PSS_SHA256, alg_id::RSA_PSS_SHA256, Scheme::RsaPssSha256);
rsa_algorithm!(RSA_PSS_SHA384, alg_id::RSA_PSS_SHA384, Scheme::RsaPssSha384);
rsa_algorithm!(RSA_PSS_SHA512, alg_id::RSA_PSS_SHA512, Scheme::RsaPssSha512);

const RSA_PKCS1_SHA256_ABSENT_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_PKCS1_SHA384_ABSENT_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_PKCS1_SHA512_ABSENT_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);
rsa_algorithm!(
    RSA_PKCS1_SHA256_ABSENT,
    RSA_PKCS1_SHA256_ABSENT_ID,
    Scheme::RsaPkcs1Sha256
);
rsa_algorithm!(
    RSA_PKCS1_SHA384_ABSENT,
    RSA_PKCS1_SHA384_ABSENT_ID,
    Scheme::RsaPkcs1Sha384
);
rsa_algorithm!(
    RSA_PKCS1_SHA512_ABSENT,
    RSA_PKCS1_SHA512_ABSENT_ID,
    Scheme::RsaPkcs1Sha512
);

/// Complete X.509 algorithm set for the supported Fulcio and TSA roots.
pub static WEBPKI_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P384_SHA256,
    &ECDSA_P384_SHA384,
    &ED25519,
    &RSA_PKCS1_SHA256,
    &RSA_PKCS1_SHA384,
    &RSA_PKCS1_SHA512,
    &RSA_PKCS1_SHA256_ABSENT,
    &RSA_PKCS1_SHA384_ABSENT,
    &RSA_PKCS1_SHA512_ABSENT,
    &RSA_PSS_SHA256,
    &RSA_PSS_SHA384,
    &RSA_PSS_SHA512,
];

pub fn verify_spki(
    spki_der: &[u8],
    scheme: Scheme,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|error| format!("invalid SubjectPublicKeyInfo: {error}"))?;
    let raw = spki.subject_public_key.raw_bytes();
    let compatible = match scheme {
        Scheme::EcdsaP256Sha256 | Scheme::EcdsaP256Sha384 => {
            spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
                && spki
                    .algorithm
                    .parameters
                    .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                    == Some(rfc5912::SECP_256_R_1)
        }
        Scheme::EcdsaP384Sha256 | Scheme::EcdsaP384Sha384 => {
            spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
                && spki
                    .algorithm
                    .parameters
                    .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                    == Some(rfc5912::SECP_384_R_1)
        }
        Scheme::Ed25519 => spki.algorithm.oid == ED25519_OID,
        Scheme::RsaPkcs1Sha256
        | Scheme::RsaPkcs1Sha384
        | Scheme::RsaPkcs1Sha512
        | Scheme::RsaPssSha256
        | Scheme::RsaPssSha384
        | Scheme::RsaPssSha512 => spki.algorithm.oid == rfc5912::RSA_ENCRYPTION,
    };
    if !compatible {
        return Err("signature scheme does not match the public key".into());
    }
    verify_raw(scheme, raw, message, signature)
}

pub fn verify_spki_auto(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|error| format!("invalid SubjectPublicKeyInfo: {error}"))?;
    let scheme = if spki.algorithm.oid == ED25519_OID {
        Scheme::Ed25519
    } else if spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
            == Some(rfc5912::SECP_256_R_1)
    {
        Scheme::EcdsaP256Sha256
    } else {
        return Err("unsupported automatic signature key type".into());
    };
    verify_spki(spki_der, scheme, message, signature)
}

fn verify_raw(
    scheme: Scheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    match scheme {
        Scheme::EcdsaP256Sha256 | Scheme::EcdsaP256Sha384 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| format!("invalid P-256 key: {error}"))?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|error| format!("invalid P-256 signature: {error}"))?;
            match scheme {
                Scheme::EcdsaP256Sha256 => key.verify(message, &signature),
                Scheme::EcdsaP256Sha384 => key.verify_prehash(&Sha384::digest(message), &signature),
                _ => unreachable!(),
            }
            .map_err(|error| format!("P-256 signature verification failed: {error}"))
        }
        Scheme::EcdsaP384Sha256 | Scheme::EcdsaP384Sha384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| format!("invalid P-384 key: {error}"))?;
            let signature = p384::ecdsa::Signature::from_der(signature)
                .map_err(|error| format!("invalid P-384 signature: {error}"))?;
            match scheme {
                Scheme::EcdsaP384Sha256 => key.verify_prehash(&Sha256::digest(message), &signature),
                Scheme::EcdsaP384Sha384 => key.verify(message, &signature),
                _ => unreachable!(),
            }
            .map_err(|error| format!("P-384 signature verification failed: {error}"))
        }
        Scheme::Ed25519 => {
            let key_bytes: &[u8; 32] = public_key
                .try_into()
                .map_err(|_| "Ed25519 public key must contain 32 bytes".to_owned())?;
            let key = Ed25519Key::from_bytes(key_bytes)
                .map_err(|error| format!("invalid Ed25519 key: {error}"))?;
            let signature = Ed25519Signature::from_slice(signature)
                .map_err(|error| format!("invalid Ed25519 signature: {error}"))?;
            key.verify(message, &signature)
                .map_err(|error| format!("Ed25519 signature verification failed: {error}"))
        }
        rsa_scheme => verify_rsa(rsa_scheme, public_key, message, signature),
    }
}

fn verify_rsa(
    scheme: Scheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = RsaPublicKey::from_pkcs1_der(public_key)
        .map_err(|error| format!("invalid RSA key: {error}"))?;
    if !(2048..=8192).contains(&key.n().bits()) {
        return Err("RSA key size is outside 2048..=8192 bits".into());
    }
    macro_rules! verify_pkcs1 {
        ($digest:ty) => {{
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|error| format!("invalid RSA PKCS#1 signature: {error}"))?;
            rsa::pkcs1v15::VerifyingKey::<$digest>::new(key)
                .verify(message, &signature)
                .map_err(|error| format!("RSA PKCS#1 signature verification failed: {error}"))
        }};
    }
    macro_rules! verify_pss {
        ($digest:ty) => {{
            let signature = rsa::pss::Signature::try_from(signature)
                .map_err(|error| format!("invalid RSA-PSS signature: {error}"))?;
            rsa::pss::VerifyingKey::<$digest>::new(key)
                .verify(message, &signature)
                .map_err(|error| format!("RSA-PSS signature verification failed: {error}"))
        }};
    }
    match scheme {
        Scheme::RsaPkcs1Sha256 => verify_pkcs1!(Sha256),
        Scheme::RsaPkcs1Sha384 => verify_pkcs1!(Sha384),
        Scheme::RsaPkcs1Sha512 => verify_pkcs1!(Sha512),
        Scheme::RsaPssSha256 => verify_pss!(Sha256),
        Scheme::RsaPssSha384 => verify_pss!(Sha384),
        Scheme::RsaPssSha512 => verify_pss!(Sha512),
        _ => Err("not an RSA signature scheme".into()),
    }
}
