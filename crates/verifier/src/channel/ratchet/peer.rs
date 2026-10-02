//! SPQR with the previous-chain-length variant in Double Ratchet §5.7.
//! Receives stage only the small active state and newly skipped keys. Existing
//! delayed-message keys stay in place until the caller authenticates the record.

use super::{
    ChunkSize, Error, Retention,
    braid::{Braid, EpochKey, Message},
};
use hkdf::Hkdf;
use sha2_v11::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const PROTOCOL: &[u8] = b"stogas.e2ee.spqr.v3_MLKEM768_HKDFSHA256";
pub(super) const MIN_HEADER_BYTES: usize = 16 + 9;
pub const MAX_HEADER_BYTES: usize = 16 + 11 + super::MAX_PIECE;
pub const MAX_SKIPPED_KEYS: usize = 4096;
pub const SKIPPED_KEY_LIFETIME_MS: u64 = 60_000;

type KeyId = (u64, u64);
type Secret = Zeroizing<[u8; 32]>;

/// One allocation from the sending chain. A dropped allocation is never reused.
pub struct SendKey {
    pub header: Vec<u8>,
    pub secret: Secret,
}

#[derive(Clone)]
struct Chain {
    key: Secret,
    number: u64,
}

impl Chain {
    fn step(&mut self) -> Result<Secret, Error> {
        let number = self.number.checked_add(1).ok_or(Error::Limit)?;
        let mut material = Zeroizing::new([0; 64]);
        Hkdf::<Sha256>::new(None, self.key.as_ref())
            .expand_multi_info(
                &[PROTOCOL, b":Chain Step", &number.to_be_bytes()],
                material.as_mut(),
            )
            .map_err(|_| Error::Crypto)?;
        self.key.copy_from_slice(&material[..32]);
        self.number = number;
        let mut message = Zeroizing::new([0; 32]);
        message.copy_from_slice(&material[32..]);
        Ok(message)
    }
}

#[derive(Clone)]
struct Chains {
    send: Option<Chain>,
    receive: Option<Chain>,
}

#[derive(Clone)]
struct Active {
    braid: Braid,
    root: Secret,
    alice: bool,
    epoch: u64,
    sending: u64,
    receiving: u64,
    previous_sent: u64,
    chains: BTreeMap<u64, Chains>,
}

impl Active {
    fn install(&mut self, epoch: u64, material: &[u8; 96]) {
        self.root.copy_from_slice(&material[..32]);
        let mut a2b = Zeroizing::new([0; 32]);
        let mut b2a = Zeroizing::new([0; 32]);
        a2b.copy_from_slice(&material[32..64]);
        b2a.copy_from_slice(&material[64..]);
        let (send, receive) = if self.alice { (a2b, b2a) } else { (b2a, a2b) };
        self.chains.insert(
            epoch,
            Chains {
                send: Some(Chain {
                    key: send,
                    number: 0,
                }),
                receive: Some(Chain {
                    key: receive,
                    number: 0,
                }),
            },
        );
        self.epoch = epoch;
    }

    fn incorporate(&mut self, key: Option<EpochKey>) -> Result<(), Error> {
        if let Some(key) = key {
            if self.epoch.checked_add(1) != Some(key.epoch) {
                return Err(Error::Record);
            }
            let mut material = Zeroizing::new([0; 96]);
            Hkdf::<Sha256>::new(Some(self.root.as_ref()), key.secret.as_ref())
                .expand_multi_info(&[PROTOCOL, b":Chain Add Epoch"], material.as_mut())
                .map_err(|_| Error::Crypto)?;
            self.install(key.epoch, &material);
        }
        Ok(())
    }

    fn discard_empty(&mut self) {
        self.chains
            .retain(|_, chains| chains.send.is_some() || chains.receive.is_some());
    }

    fn sending_chain(&mut self, epoch: u64) -> Result<&mut Chain, Error> {
        if epoch != self.sending {
            if self.sending.checked_add(1) != Some(epoch) {
                return Err(Error::Record);
            }
            let previous = self
                .chains
                .get_mut(&self.sending)
                .ok_or(Error::Record)?
                .send
                .take()
                .ok_or(Error::Record)?;
            self.previous_sent = previous.number;
            self.sending = epoch;
            self.discard_empty();
        }
        self.chains
            .get_mut(&epoch)
            .and_then(|chains| chains.send.as_mut())
            .ok_or(Error::Record)
    }

    fn receive_chain(&mut self, epoch: u64) -> Result<&mut Chain, Error> {
        self.chains
            .get_mut(&epoch)
            .and_then(|chains| chains.receive.as_mut())
            .ok_or(Error::Record)
    }

    fn skip(
        &mut self,
        epoch: u64,
        until: u64,
        keys: &mut Vec<(KeyId, Secret)>,
        available: usize,
    ) -> Result<(), Error> {
        let chain = self.receive_chain(epoch)?;
        let count = until.checked_sub(chain.number).ok_or(Error::Record)?;
        if count > available.saturating_sub(keys.len()) as u64 {
            return Err(Error::Limit);
        }
        while chain.number < until {
            let key = chain.step()?;
            keys.push(((epoch, chain.number), key));
        }
        Ok(())
    }

    fn receive_key(
        &mut self,
        header: &Header,
        keys: &mut Vec<(KeyId, Secret)>,
        available: usize,
    ) -> Result<Secret, Error> {
        let epoch = header.message.epoch - 1;
        if epoch > self.receiving {
            if self.receiving.checked_add(1) != Some(epoch) {
                return Err(Error::Record);
            }
            self.skip(self.receiving, header.previous, keys, available)?;
            self.chains
                .get_mut(&self.receiving)
                .ok_or(Error::Record)?
                .receive = None;
            self.receiving = epoch;
            self.discard_empty();
        } else if epoch < self.receiving {
            return Err(Error::Record);
        }
        self.skip(epoch, header.number - 1, keys, available)?;
        self.receive_chain(epoch)?.step()
    }
}

struct Header {
    previous: u64,
    number: u64,
    message: Message,
}

impl Header {
    fn decode(bytes: &[u8], size: ChunkSize) -> Result<Self, Error> {
        if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&bytes.len()) {
            return Err(Error::Record);
        }
        let previous = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::Record)?);
        let number = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::Record)?);
        if number == 0 {
            return Err(Error::Record);
        }
        let message = Message::decode(&bytes[16..], size)?;
        Ok(Self {
            previous,
            number,
            message,
        })
    }
}

struct Skipped {
    secret: Secret,
    expires: Option<u64>,
}

/// Session key agreement and independent, advancing directional message chains.
/// This layer performs no I/O, owns no clock, and never persists secret state.
pub struct Peer {
    active: Active,
    size: ChunkSize,
    skipped: BTreeMap<KeyId, Skipped>,
    next_expiry: Option<u64>,
    last_now: u64,
    retention: Retention,
}

impl Peer {
    #[must_use]
    #[allow(
        clippy::missing_panics_doc,
        reason = "The fixed 96-byte HKDF output is within the specified SHA-256 bound."
    )]
    pub fn new(alice: bool, secret: &[u8; 32], size: ChunkSize, retention: Retention) -> Self {
        let mut material = Zeroizing::new([0; 96]);
        Hkdf::<Sha256>::new(None, secret)
            .expand_multi_info(&[PROTOCOL, b":Chain Start"], material.as_mut())
            .expect("fixed HKDF output is within SHA-256 bounds");
        let mut active = Active {
            braid: Braid::new(alice, secret, size),
            root: Zeroizing::new([0; 32]),
            alice,
            epoch: 0,
            sending: 0,
            receiving: 0,
            previous_sent: 0,
            chains: BTreeMap::new(),
        };
        active.install(0, &material);
        Self {
            active,
            size,
            skipped: BTreeMap::new(),
            next_expiry: None,
            last_now: 0,
            retention,
        }
    }

    pub(super) fn send_with(
        &mut self,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<SendKey, Error> {
        let mut active = self.active.clone();
        let (message, key) = active.braid.send(random)?;
        active.incorporate(key)?;
        let chain = active.sending_chain(message.epoch - 1)?;
        let secret = chain.step()?;
        let number = chain.number;
        let mut header = Vec::with_capacity(MAX_HEADER_BYTES);
        header.extend_from_slice(&active.previous_sent.to_be_bytes());
        header.extend_from_slice(&number.to_be_bytes());
        message.encode(&mut header);
        self.active = active;
        Ok(SendKey { header, secret })
    }

    /// Derive a candidate key, authenticate the complete public header and
    /// ciphertext through `authenticate`, then commit the state atomically.
    /// The caller serializes this operation with other allocations and receives.
    ///
    /// `now_ms` uses the adapter's elapsed-time clock. Clock regressions are
    /// clamped; no receive extends an existing skipped key's lifetime.
    ///
    /// # Errors
    /// Rejects malformed, replayed, expired, too-distant or unauthenticated input.
    /// Authentication failure cannot consume a key or advance the ratchet.
    pub fn receive<T>(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
        authenticate: impl FnOnce(&[u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.expire(now_ms);
        let header = Header::decode(bytes, self.size)?;
        let id = (header.message.epoch - 1, header.number);
        let mut active = self.active.clone();
        let key = active.braid.receive(&header.message)?;
        active.incorporate(key)?;
        let mut pending = Vec::new();
        let existing = self.skipped.get(&id);
        let secret = if let Some(existing) = existing {
            &existing.secret
        } else {
            // A separate owner keeps this secret alive through authentication;
            // it is never inserted into the delayed-message key cache.
            let secret = active.receive_key(&header, &mut pending, MAX_SKIPPED_KEYS)?;
            let output = authenticate(&secret)?;
            self.commit(active, pending);
            return Ok(output);
        };
        let output = authenticate(secret)?;
        self.skipped.remove(&id);
        self.active = active;
        Ok(output)
    }

    fn commit(&mut self, active: Active, pending: Vec<(KeyId, Secret)>) {
        let expires = self.retention.deadline(self.last_now);
        if let Some(expires) = expires.filter(|_| !pending.is_empty()) {
            self.next_expiry = Some(
                self.next_expiry
                    .map_or(expires, |previous| previous.min(expires)),
            );
        }
        // New gaps follow the active receiving chain, so their IDs are newer
        // than every retained key. Evict after authentication, before insertion,
        // to bound peak memory as well as retained memory.
        let evictions = (self.skipped.len() + pending.len()).saturating_sub(MAX_SKIPPED_KEYS);
        for _ in 0..evictions {
            self.skipped.pop_first();
        }
        for (id, secret) in pending {
            self.skipped.insert(id, Skipped { secret, expires });
        }
        self.active = active;
    }

    /// Erase expired delayed-message keys, also when the session is idle.
    pub fn expire(&mut self, now_ms: u64) {
        self.last_now = self.last_now.max(now_ms);
        if self
            .next_expiry
            .is_some_and(|expiry| self.last_now >= expiry)
        {
            self.skipped
                .retain(|_, key| key.expires.is_none_or(|expires| self.last_now < expires));
            self.next_expiry = self.skipped.values().filter_map(|key| key.expires).min();
        }
    }

    pub fn discard_delayed(&mut self) {
        self.skipped.clear();
        self.next_expiry = None;
    }
}

#[cfg(test)]
mod tests;
