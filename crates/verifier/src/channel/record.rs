use super::{Direction, Error, Kind};
use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInOut as _, KeyInit as _},
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
    + MAX_RECORDS * RECORD_OVERHEAD as u64;
pub const MAX_RESPONSE_WIRE_BYTES: u64 =
    MAX_RESPONSE_BODY + MAX_RECORD_PLAINTEXT as u64 + MAX_RECORDS * RECORD_OVERHEAD as u64;
const KEY_DOMAIN: &[u8] = b"stogas.e2ee.record.v1\0";

// One owner per direction. No Clone implementation: recreating encryption
// counters under the same request key would reuse GCM nonces.
pub(super) struct Records {
    cipher: Option<Aes256Gcm>,
    nonce: [u8; 12],
    pub(super) sequence: u64,
    pub(super) body_bytes: u64,
    direction: Direction,
    pub(super) started: bool,
    finished: bool,
    failed: bool,
}

impl Records {
    pub(super) fn new(
        root: &[u8; 32],
        session_id: &[u8; 32],
        number: u64,
        direction: Direction,
    ) -> Result<Self, Error> {
        let mut info = Vec::with_capacity(KEY_DOMAIN.len() + 32 + 8 + 1);
        info.extend_from_slice(KEY_DOMAIN);
        info.extend_from_slice(session_id);
        info.extend_from_slice(&number.to_be_bytes());
        info.push(direction as u8);
        let mut material = Zeroizing::new([0_u8; 44]);
        Hkdf::<Sha256>::from_prk(root)
            .map_err(|_| Error::Crypto)?
            .expand(&info, material.as_mut())
            .map_err(|_| Error::Crypto)?;
        let cipher = Aes256Gcm::new_from_slice(&material[..32]).map_err(|_| Error::Crypto)?;
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&material[32..]);
        Ok(Self {
            cipher: Some(cipher),
            nonce,
            sequence: 0,
            body_bytes: 0,
            direction,
            started: false,
            finished: false,
            failed: false,
        })
    }

    pub(super) fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        if let Err(error) = self.check(kind, content.len()) {
            return Err(self.fail(error));
        }
        let length = u32::try_from(RECORD_OVERHEAD + content.len()).map_err(|_| Error::Limit)?;
        let prefix = length.to_be_bytes();
        let mut encoded = Vec::with_capacity(length as usize);
        encoded.extend_from_slice(&prefix);
        encoded.push(kind as u8);
        encoded.extend_from_slice(content);
        let nonce = self.record_nonce();
        let result = self
            .cipher
            .as_ref()
            .ok_or(Error::Closed)?
            .encrypt_inout_detached(&Nonce::from(nonce), &prefix, encoded[4..].as_mut().into());
        let Ok(tag) = result else {
            encoded.zeroize();
            return Err(self.fail(Error::Crypto));
        };
        encoded.extend_from_slice(&tag);
        self.advance(kind, content.len());
        Ok(encoded)
    }

    // Plaintext borrows the caller's exclusive encoded buffer. No application
    // bytes escape until tag, grammar, size and sequence checks all succeed.
    pub(super) fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        let outcome = self.open_inner(encoded);
        if outcome.is_err() {
            self.close();
        }
        outcome
    }

    fn open_inner<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        if self.failed || self.finished || self.cipher.is_none() {
            return Err(Error::Closed);
        }
        if self.sequence >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        if encoded.len() < RECORD_OVERHEAD || record_size(&encoded[..4])? != encoded.len() {
            return Err(Error::Record);
        }
        let nonce = self.record_nonce();
        let (prefix, sealed) = encoded.split_at_mut(4);
        let tagless_len = sealed.len() - 16;
        let (plaintext, tag) = sealed.split_at_mut(tagless_len);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::Record)?;
        if self
            .cipher
            .as_ref()
            .ok_or(Error::Closed)?
            .decrypt_inout_detached(&Nonce::from(nonce), prefix, plaintext.as_mut().into(), &tag)
            .is_err()
        {
            plaintext.zeroize();
            return Err(Error::Authentication);
        }
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

impl Drop for Records {
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
