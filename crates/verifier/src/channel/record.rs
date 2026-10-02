use super::{
    Direction, Error, Kind,
    cipher::{Cipher, SoftwareCipher},
};
use hkdf::Hkdf;
use sha2_v11::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const RECORD_OVERHEAD: usize = 4 + 1 + 16;
pub const MAX_RECORD_PLAINTEXT: usize = MAX_RECORD_BYTES - RECORD_OVERHEAD;
pub(super) const MAX_RECORDS: u64 = 1 << 24;
pub(super) const MAX_REQUEST_BODY: u64 = 128 * 1024 * 1024;
pub(super) const MAX_RESPONSE_BODY: u64 = 64 * 1024 * 1024;
pub const MAX_REQUEST_WIRE_BYTES: u64 = super::session::REQUEST_PREFIX_BYTES as u64
    + MAX_REQUEST_BODY
    + MAX_RECORD_PLAINTEXT as u64
    + MAX_RECORDS * RECORD_OVERHEAD as u64
    + 2
    + super::ratchet::MAX_HEADER_BYTES as u64;
pub const MAX_RESPONSE_WIRE_BYTES: u64 = MAX_RESPONSE_BODY
    + MAX_RECORD_PLAINTEXT as u64
    + MAX_RECORDS * RECORD_OVERHEAD as u64
    + 2
    + super::ratchet::MAX_HEADER_BYTES as u64;
const KEY_DOMAIN: &[u8] = b"stogas.e2ee.record.v3\0";

// One owner per direction. No Clone implementation: recreating encryption
// counters under the same request key would reuse GCM nonces.
pub(super) struct Records<C: Cipher = SoftwareCipher> {
    cipher: Option<C>,
    header: Option<Vec<u8>>,
    nonce: [u8; 12],
    pub(super) sequence: u64,
    pub(super) body_bytes: u64,
    direction: Direction,
    pub(super) started: bool,
    finished: bool,
    failed: bool,
}

impl<C: Cipher> Records<C> {
    pub(super) fn new(
        secret: &[u8; 32],
        session_id: &[u8; 32],
        number: u64,
        direction: Direction,
        header: Vec<u8>,
    ) -> Result<Self, Error> {
        let (key, nonce) = key_material(secret, session_id, number, direction)?;
        Ok(Self::from_cipher(
            C::from_key(key)?,
            nonce,
            direction,
            Some(header),
        ))
    }

    const fn from_cipher(
        cipher: C,
        nonce: [u8; 12],
        direction: Direction,
        header: Option<Vec<u8>>,
    ) -> Self {
        Self {
            cipher: Some(cipher),
            header,
            nonce,
            sequence: 0,
            body_bytes: 0,
            direction,
            started: false,
            finished: false,
            failed: false,
        }
    }

    pub(super) fn authenticate_start<'a>(
        secret: &[u8; 32],
        session_id: &[u8; 32],
        number: u64,
        direction: Direction,
        encoded: &'a mut [u8],
    ) -> Result<(Self, Kind, &'a [u8]), Error> {
        let offset = start_header(encoded)?.len() + 6;
        let (key, nonce) = key_material(secret, session_id, number, direction)?;
        let (aad, sealed) = encoded.split_at_mut(offset);
        let cipher = match C::from_authenticated_start(key, nonce, aad, sealed) {
            Ok(cipher) => cipher,
            Err(error) => {
                sealed.zeroize();
                return Err(error);
            }
        };
        let mut records = Self::from_cipher(cipher, nonce, direction, None);
        let (kind, plaintext) = records.accept_open(sealed)?;
        Ok((records, kind, plaintext))
    }

    pub(super) async fn seal_async(
        &mut self,
        kind: Kind,
        content: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut operation = Operation::new(self);
        let mut encoded = Zeroizing::new(operation.records.encode(kind, content)?);
        let offset = operation.records.prefix_size(&encoded)?;
        let nonce = operation.records.record_nonce();
        let (prefix, plaintext) = encoded.split_at_mut(offset);
        let tag = operation
            .records
            .cipher
            .as_mut()
            .ok_or(Error::Closed)?
            .encrypt(nonce, prefix, plaintext)
            .await?;
        encoded.extend_from_slice(&tag);
        operation.records.advance(kind, content.len());
        operation.completed = true;
        Ok(std::mem::take(&mut *encoded))
    }

    pub(super) async fn open_async<'a>(
        &mut self,
        encoded: &'a mut [u8],
    ) -> Result<(Kind, &'a [u8]), Error> {
        let mut operation = Operation::new(self);
        let offset = operation.records.check_encoded(encoded)?;
        let nonce = operation.records.record_nonce();
        let (prefix, sealed) = encoded.split_at_mut(offset);
        if let Err(error) = operation
            .records
            .cipher
            .as_mut()
            .ok_or(Error::Closed)?
            .decrypt(nonce, prefix, sealed)
            .await
        {
            sealed.zeroize();
            return Err(error);
        }
        let result = operation.records.accept_open(sealed)?;
        operation.completed = true;
        Ok(result)
    }

    fn encode(&self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.check(kind, content.len())?;
        let header = if self.sequence == 0 {
            Some(self.header.as_deref().ok_or(Error::Closed)?)
        } else {
            None
        };
        let length = RECORD_OVERHEAD + content.len() + header.map_or(0, |header| 2 + header.len());
        if length > MAX_RECORD_BYTES {
            return Err(Error::Limit);
        }
        let length = u32::try_from(length).map_err(|_| Error::Limit)?;
        let mut encoded = Vec::with_capacity(length as usize);
        encoded.extend_from_slice(&length.to_be_bytes());
        if let Some(header) = header {
            let length = u16::try_from(header.len()).map_err(|_| Error::Limit)?;
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(header);
        }
        encoded.push(kind as u8);
        encoded.extend_from_slice(content);
        Ok(encoded)
    }

    fn prefix_size(&self, encoded: &[u8]) -> Result<usize, Error> {
        if self.sequence == 0 {
            let length = u16::from_be_bytes(
                encoded
                    .get(4..6)
                    .ok_or(Error::Record)?
                    .try_into()
                    .map_err(|_| Error::Record)?,
            ) as usize;
            if !(super::ratchet::MIN_HEADER_BYTES..=super::ratchet::MAX_HEADER_BYTES)
                .contains(&length)
                || encoded.len() < 6 + length + 1
            {
                return Err(Error::Record);
            }
            Ok(6 + length)
        } else {
            Ok(4)
        }
    }

    fn check_encoded(&self, encoded: &[u8]) -> Result<usize, Error> {
        if self.failed || self.finished || self.cipher.is_none() {
            return Err(Error::Closed);
        }
        if self.sequence >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        if encoded.len() < RECORD_OVERHEAD || record_size(&encoded[..4])? != encoded.len() {
            return Err(Error::Record);
        }
        let offset = self.prefix_size(encoded)?;
        if encoded.len() < offset + 17 {
            return Err(Error::Record);
        }
        Ok(offset)
    }

    fn accept_open<'a>(&mut self, sealed: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        let length = sealed.len() - 16;
        let plaintext = &mut sealed[..length];
        let kind = match Kind::try_from(plaintext[0]) {
            Ok(kind) => kind,
            Err(error) => {
                plaintext.zeroize();
                return Err(error);
            }
        };
        let size = plaintext.len() - 1;
        if let Err(error) = self.check(kind, size) {
            plaintext.zeroize();
            return Err(error);
        }
        self.advance(kind, size);
        Ok((kind, &plaintext[1..]))
    }

    pub(super) fn complete(&mut self) -> Result<(), Error> {
        if self.finished && !self.failed {
            Ok(())
        } else {
            Err(self.fail(Error::Truncated))
        }
    }

    pub(super) fn close(&mut self) {
        self.failed = true;
        self.cipher = None;
        self.nonce.zeroize();
    }

    fn fail(&mut self, error: Error) -> Error {
        self.close();
        error
    }

    fn check(&self, kind: Kind, size: usize) -> Result<(), Error> {
        if self.failed || self.finished || self.cipher.is_none() {
            return Err(Error::Closed);
        }
        if self.sequence >= MAX_RECORDS || size > MAX_RECORD_PLAINTEXT {
            return Err(Error::Limit);
        }
        match kind {
            Kind::Metadata if self.started || size == 0 => Err(Error::Record),
            Kind::Data => {
                if !self.started || size == 0 {
                    return Err(Error::Record);
                }
                let max_body = match self.direction {
                    Direction::Request => MAX_REQUEST_BODY,
                    Direction::Response => MAX_RESPONSE_BODY,
                };
                if self.body_bytes > max_body || size as u64 > max_body - self.body_bytes {
                    return Err(Error::Limit);
                }
                Ok(())
            }
            Kind::Finished if !self.started || size != 0 => Err(Error::Record),
            Kind::Keepalive if self.direction != Direction::Response || size != 0 => {
                Err(Error::Record)
            }
            _ => Ok(()),
        }
    }

    fn advance(&mut self, kind: Kind, size: usize) {
        self.header = None;
        self.sequence += 1;
        match kind {
            Kind::Metadata => self.started = true,
            Kind::Data => self.body_bytes += size as u64,
            Kind::Finished => {
                self.finished = true;
                self.cipher = None;
                self.nonce.zeroize();
            }
            Kind::Keepalive => (),
        }
    }

    fn record_nonce(&self) -> [u8; 12] {
        let mut nonce = self.nonce;
        for (target, value) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *target ^= value;
        }
        nonce
    }
}

impl Records<SoftwareCipher> {
    pub(super) fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        let mut operation = Operation::new(self);
        let mut encoded = Zeroizing::new(operation.records.encode(kind, content)?);
        let offset = operation.records.prefix_size(&encoded)?;
        let nonce = operation.records.record_nonce();
        let (prefix, plaintext) = encoded.split_at_mut(offset);
        let tag = operation
            .records
            .cipher
            .as_ref()
            .ok_or(Error::Closed)?
            .encrypt_now(nonce, prefix, plaintext)?;
        encoded.extend_from_slice(&tag);
        operation.records.advance(kind, content.len());
        operation.completed = true;
        Ok(std::mem::take(&mut *encoded))
    }

    pub(super) fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        let mut operation = Operation::new(self);
        let offset = operation.records.check_encoded(encoded)?;
        let nonce = operation.records.record_nonce();
        let (prefix, sealed) = encoded.split_at_mut(offset);
        if let Err(error) = operation
            .records
            .cipher
            .as_ref()
            .ok_or(Error::Closed)?
            .decrypt_now(nonce, prefix, sealed)
        {
            sealed.zeroize();
            return Err(error);
        }
        let result = operation.records.accept_open(sealed)?;
        operation.completed = true;
        Ok(result)
    }
}

// Dropping an unfinished async operation permanently closes the direction. A
// cancelled operation can never retry its nonce under the same key.
struct Operation<'a, C: Cipher> {
    records: &'a mut Records<C>,
    completed: bool,
}

impl<'a, C: Cipher> Operation<'a, C> {
    const fn new(records: &'a mut Records<C>) -> Self {
        Self {
            records,
            completed: false,
        }
    }
}

impl<C: Cipher> Drop for Operation<'_, C> {
    fn drop(&mut self) {
        if !self.completed {
            self.records.close();
        }
    }
}

impl<C: Cipher> Drop for Records<C> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Validate the complete encoded length before allocating or reading a body.
///
/// # Errors
/// Rejects non-four-byte prefixes and lengths outside the fixed wire bounds.
pub fn record_size(prefix: &[u8]) -> Result<usize, Error> {
    let value = u32::from_be_bytes(prefix.try_into().map_err(|_| Error::Record)?) as usize;
    if !(RECORD_OVERHEAD..=MAX_RECORD_BYTES).contains(&value) {
        return Err(Error::Record);
    }
    Ok(value)
}

fn key_material(
    secret: &[u8; 32],
    session_id: &[u8; 32],
    number: u64,
    direction: Direction,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 12]), Error> {
    let mut material = Zeroizing::new([0_u8; 44]);
    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::Crypto)?
        .expand_multi_info(
            &[
                KEY_DOMAIN,
                session_id,
                &number.to_be_bytes(),
                &[direction as u8],
            ],
            material.as_mut(),
        )
        .map_err(|_| Error::Crypto)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&material[..32]);
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&material[32..]);
    Ok((key, nonce))
}

pub(super) fn start_header(encoded: &[u8]) -> Result<&[u8], Error> {
    if encoded.len() < 6 + super::ratchet::MIN_HEADER_BYTES + 17
        || record_size(&encoded[..4])? != encoded.len()
    {
        return Err(Error::Record);
    }
    let length = u16::from_be_bytes([encoded[4], encoded[5]]) as usize;
    if !(super::ratchet::MIN_HEADER_BYTES..=super::ratchet::MAX_HEADER_BYTES).contains(&length)
        || encoded.len() < 6 + length + 17
    {
        return Err(Error::Record);
    }
    Ok(&encoded[6..6 + length])
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
