//! The published ML-KEM Braid incremental interface, backed by libcrux.
//! Private key bytes and suspended encapsulation material have explicit owners.

use super::Error;
use libcrux_ml_kem::mlkem768::incremental as kem;
use zeroize::Zeroizing;

type Secret = Zeroizing<[u8; 32]>;

pub(super) const HEADER_BYTES: usize = kem::pk1_len();
pub(super) const KEY_BYTES: usize = kem::pk2_len();
pub(super) const CT1_BYTES: usize = kem::Ciphertext1::len();
pub(super) const CT2_BYTES: usize = kem::Ciphertext2::len();

pub(super) fn validate_public_key(header: &[u8], vector: &[u8]) -> Result<(), Error> {
    if header.len() != HEADER_BYTES || vector.len() != KEY_BYTES {
        return Err(Error::Record);
    }
    kem::validate_pk_bytes(header, vector).map_err(|_| Error::Authentication)
}

#[derive(Clone)]
pub(super) struct KeyPair(Zeroizing<[u8; kem::key_pair_compressed_len()]>);

impl KeyPair {
    pub fn generate(seed: &[u8; 64]) -> Self {
        let mut bytes = Zeroizing::new([0; kem::key_pair_compressed_len()]);
        kem::generate_key_pair_compressed(*seed, &mut bytes);
        Self(bytes)
    }

    pub fn header(&self) -> &[u8] {
        // FIPS 203 expanded key: dk || ek_vector || ek_seed || H(ek) || z.
        &self.0[2 * KEY_BYTES..2 * KEY_BYTES + HEADER_BYTES]
    }

    pub fn vector(&self) -> &[u8] {
        &self.0[KEY_BYTES..2 * KEY_BYTES]
    }

    pub fn decapsulate(&self, ct1: &[u8], ct2: &[u8]) -> Result<Secret, Error> {
        let ct1 = kem::Ciphertext1 {
            value: ct1.try_into().map_err(|_| Error::Record)?,
        };
        let ct2 = kem::Ciphertext2 {
            value: ct2.try_into().map_err(|_| Error::Record)?,
        };
        Ok(Zeroizing::new(kem::decapsulate_compressed_key(
            &self.0, &ct1, &ct2,
        )))
    }
}

#[derive(Clone)]
pub(super) struct Encapsulation(Zeroizing<[u8; kem::encaps_state_len()]>);

impl Encapsulation {
    pub fn begin(header: &[u8], randomness: &[u8; 32]) -> Result<(Self, Vec<u8>, Secret), Error> {
        if header.len() != HEADER_BYTES {
            return Err(Error::Record);
        }
        let mut state = Zeroizing::new([0; kem::encaps_state_len()]);
        let mut secret = Zeroizing::new([0; 32]);
        let ct1 = kem::encapsulate1(header, *randomness, state.as_mut(), secret.as_mut())
            .map_err(|_| Error::Crypto)?;
        Ok((Self(state), ct1.value.to_vec(), secret))
    }

    pub fn finish(self, header: &[u8], vector: &[u8]) -> Result<Vec<u8>, Error> {
        // This checks both FIPS public-key validity and the header's commitment
        // to the complete key before using the second, previously missing part.
        validate_public_key(header, vector)?;
        Ok(
            kem::encapsulate2(&self.0, vector.try_into().map_err(|_| Error::Record)?)
                .value
                .to_vec(),
        )
    }
}

#[cfg(test)]
mod tests;
