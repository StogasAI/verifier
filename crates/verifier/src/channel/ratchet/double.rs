//! Classical Double Ratchet (§3), with deferred key generation (§8.5).
//! Message keys are consumed only after the enclosing Triple Ratchet authenticates.

use super::{Error, MAX_SKIPPED_KEYS, Retention};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2_v11::Sha256;
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const ROOT_INFO: &[u8] = b"stogas.e2ee.double.v3_X25519_HKDFSHA256:Root";
pub(super) const HEADER_BYTES: usize = 48;
type Secret = Zeroizing<[u8; 32]>;
type KeyId = ([u8; 32], u64);

#[derive(Clone)]
struct Chain {
    secret: Secret,
    count: u64,
}

impl Chain {
    fn step(&mut self) -> Result<Secret, Error> {
        let count = self.count.checked_add(1).ok_or(Error::Limit)?;
        let keyed =
            Hmac::<Sha256>::new_from_slice(self.secret.as_ref()).map_err(|_| Error::Crypto)?;
        let message = mac(keyed.clone(), 1);
        self.secret = mac(keyed, 2);
        self.count = count;
        Ok(message)
    }
}

fn mac(mut mac: Hmac<Sha256>, label: u8) -> Secret {
    mac.update(&[label]);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

#[derive(Clone)]
struct Active {
    root: Secret,
    local: Option<StaticSecret>,
    public: [u8; 32],
    remote: Option<[u8; 32]>,
    send: Option<Chain>,
    receive: Option<Chain>,
    previous_sent: u64,
}

impl Active {
    fn advance(&mut self) -> Result<Chain, Error> {
        let local = self.local.as_ref().ok_or(Error::Pending)?;
        let remote = PublicKey::from(self.remote.ok_or(Error::Pending)?);
        let shared = local.diffie_hellman(&remote);
        if !shared.was_contributory() {
            return Err(Error::Authentication);
        }
        let mut material = Zeroizing::new([0; 64]);
        Hkdf::<Sha256>::new(Some(self.root.as_ref()), shared.as_bytes())
            .expand(ROOT_INFO, material.as_mut())
            .map_err(|_| Error::Crypto)?;
        self.root.copy_from_slice(&material[..32]);
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(&material[32..]);
        Ok(Chain { secret, count: 0 })
    }

    fn skip(&mut self, until: u64, pending: &mut Vec<(KeyId, Secret)>) -> Result<(), Error> {
        let Some(chain) = &mut self.receive else {
            return if until == 0 {
                Ok(())
            } else {
                Err(Error::Record)
            };
        };
        let count = until.checked_sub(chain.count).ok_or(Error::Record)?;
        if count > MAX_SKIPPED_KEYS.saturating_sub(pending.len()) as u64 {
            return Err(Error::Limit);
        }
        let remote = self.remote.ok_or(Error::Record)?;
        while chain.count < until {
            let number = chain.count;
            pending.push(((remote, number), chain.step()?));
        }
        Ok(())
    }

    fn receive_key(
        &mut self,
        header: &Header,
        pending: &mut Vec<(KeyId, Secret)>,
    ) -> Result<Secret, Error> {
        if self.remote != Some(header.public) {
            // A second remote turn cannot precede our next outgoing DH key.
            // The responder's first incoming turn has no previous remote key.
            if self.remote.is_some() && self.send.is_none() {
                return Err(Error::Record);
            }
            self.skip(header.previous, pending)?;
            self.remote = Some(header.public);
            self.receive = Some(self.advance()?);
            self.previous_sent = self.send.as_ref().map_or(0, |chain| chain.count);
            self.send = None;
        }
        self.skip(header.number, pending)?;
        self.receive.as_mut().ok_or(Error::Record)?.step()
    }
}

struct Header {
    public: [u8; 32],
    previous: u64,
    number: u64,
}

impl Header {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; HEADER_BYTES] = bytes.try_into().map_err(|_| Error::Record)?;
        Ok(Self {
            public: bytes[..32].try_into().map_err(|_| Error::Record)?,
            previous: u64::from_be_bytes(bytes[32..40].try_into().map_err(|_| Error::Record)?),
            number: u64::from_be_bytes(bytes[40..].try_into().map_err(|_| Error::Record)?),
        })
    }

    fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..32].copy_from_slice(&self.public);
        bytes[32..40].copy_from_slice(&self.previous.to_be_bytes());
        bytes[40..].copy_from_slice(&self.number.to_be_bytes());
        bytes
    }
}

struct Skipped {
    secret: Secret,
    expires: Option<u64>,
    order: u64,
}

/// The send candidate owns only small active state, never a copy of delayed keys.
pub(super) struct SendCandidate {
    active: Active,
    pub header: [u8; HEADER_BYTES],
    pub secret: Secret,
}

pub(super) struct DoubleRatchet {
    active: Active,
    skipped: BTreeMap<KeyId, Skipped>,
    // DH public keys have no chronological ordering. This second index gives
    // bounded logarithmic removal on delivery, expiry and oldest-key eviction.
    order: BTreeMap<u64, KeyId>,
    next_order: u64,
    last_now: u64,
    retention: Retention,
}

impl DoubleRatchet {
    pub fn initiator(root: Secret, remote: [u8; 32], retention: Retention) -> Self {
        Self::new(root, None, Some(remote), retention)
    }

    pub fn responder(root: Secret, local: StaticSecret, retention: Retention) -> Self {
        Self::new(root, Some(local), None, retention)
    }

    fn new(
        root: Secret,
        local: Option<StaticSecret>,
        remote: Option<[u8; 32]>,
        retention: Retention,
    ) -> Self {
        let public = local
            .as_ref()
            .map_or([0; 32], |key| PublicKey::from(key).to_bytes());
        Self {
            active: Active {
                root,
                local,
                public,
                remote,
                send: None,
                receive: None,
                previous_sent: 0,
            },
            skipped: BTreeMap::new(),
            order: BTreeMap::new(),
            next_order: 0,
            last_now: 0,
            retention,
        }
    }

    pub fn prepare_send(
        &self,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<SendCandidate, Error> {
        let mut active = self.active.clone();
        if active.send.is_none() {
            if active.remote.is_none() {
                return Err(Error::Pending);
            }
            let mut bytes = Zeroizing::new([0; 32]);
            random(bytes.as_mut())?;
            let local = StaticSecret::from(*bytes);
            active.public = PublicKey::from(&local).to_bytes();
            active.local = Some(local);
            active.send = Some(active.advance()?);
        }
        let chain = active.send.as_mut().ok_or(Error::Pending)?;
        let number = chain.count;
        let secret = chain.step()?;
        let header = Header {
            public: active.public,
            previous: active.previous_sent,
            number,
        }
        .encode();
        Ok(SendCandidate {
            active,
            header,
            secret,
        })
    }

    pub fn commit_send(&mut self, candidate: SendCandidate) {
        self.active = candidate.active;
    }

    pub fn receive<T>(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
        authenticate: impl FnOnce(&[u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.expire(now_ms);
        let header = Header::decode(bytes)?;
        let id = (header.public, header.number);
        if let Some(skipped) = self.skipped.get(&id) {
            let output = authenticate(&skipped.secret)?;
            let order = skipped.order;
            self.skipped.remove(&id);
            self.order.remove(&order);
            return Ok(output);
        }
        let mut active = self.active.clone();
        let mut pending = Vec::new();
        let secret = active.receive_key(&header, &mut pending)?;
        let next_order = self
            .next_order
            .checked_add(pending.len() as u64)
            .ok_or(Error::Limit)?;
        let output = authenticate(&secret)?;
        let expires = self.retention.deadline(self.last_now);
        while self.skipped.len() + pending.len() > MAX_SKIPPED_KEYS {
            if let Some((_, id)) = self.order.pop_first() {
                self.skipped.remove(&id);
            }
        }
        for (id, secret) in pending {
            let order = self.next_order;
            self.order.insert(order, id);
            self.skipped.insert(
                id,
                Skipped {
                    secret,
                    expires,
                    order,
                },
            );
            self.next_order += 1;
        }
        debug_assert_eq!(self.next_order, next_order);
        self.active = active;
        Ok(output)
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.last_now = self.last_now.max(now_ms);
        while let Some((_, id)) = self.order.first_key_value() {
            if self.skipped[id]
                .expires
                .is_none_or(|expires| expires > self.last_now)
            {
                break;
            }
            self.skipped.remove(id);
            self.order.pop_first();
        }
    }

    pub fn discard_delayed(&mut self) {
        self.skipped.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests;
