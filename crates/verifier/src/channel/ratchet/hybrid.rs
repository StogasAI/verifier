//! The published Triple Ratchet (§6): independent EC and PQ message keys,
//! combined once before the record cipher. Both receivers commit after one AEAD.

use super::{
    ChunkSize, Error, Retention, SendKey,
    double::{self, DoubleRatchet},
    peer,
};
use hkdf::Hkdf;
use sha2_v11::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const PROTOCOL: &[u8] = b"stogas.e2ee.triple.v3_X25519_MLKEM768_HKDFSHA256";
pub const MIN_HEADER_BYTES: usize = double::HEADER_BYTES + peer::MIN_HEADER_BYTES;
pub const MAX_HEADER_BYTES: usize = double::HEADER_BYTES + peer::MAX_HEADER_BYTES;
type Secret = Zeroizing<[u8; 32]>;

/// The responder's initial X25519 key, whose public value is bound into setup.
/// It is ephemeral session material, never a persisted identity key.
pub struct InitialKey(StaticSecret);

impl InitialKey {
    /// # Errors
    /// Rejects failure of the platform random source.
    pub fn generate() -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| Error::Crypto)?;
        Ok(Self::from_bytes(secret))
    }

    #[must_use]
    pub fn from_bytes(secret: Secret) -> Self {
        let key = Self(StaticSecret::from(*secret));
        drop(secret);
        key
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// Borrow only to transfer into another session owner. Erase any copy after
    /// that transfer; retaining it extends exposure of the initial DH secret.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

fn split_root(root: &[u8; 32]) -> (Secret, Secret) {
    let mut material = Zeroizing::new([0; 64]);
    Hkdf::<Sha256>::new(None, root)
        .expand_multi_info(&[PROTOCOL, b":Initialization"], material.as_mut())
        .expect("fixed HKDF output is within SHA-256 bounds");
    let mut classical = Zeroizing::new([0; 32]);
    let mut quantum = Zeroizing::new([0; 32]);
    classical.copy_from_slice(&material[..32]);
    quantum.copy_from_slice(&material[32..]);
    (classical, quantum)
}

fn combine(classical: &[u8; 32], quantum: &[u8; 32]) -> Secret {
    let mut secret = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(quantum), classical)
        .expand(PROTOCOL, secret.as_mut())
        .expect("fixed HKDF output is within SHA-256 bounds");
    secret
}

/// One Triple Ratchet endpoint. No I/O, clock or persisted secret state.
pub struct Peer {
    classical: DoubleRatchet,
    quantum: peer::Peer,
}

impl Peer {
    /// Initialize the client after authenticating the responder's setup key.
    #[must_use]
    pub fn initiator(root: &[u8; 32], size: ChunkSize, responder: [u8; 32]) -> Self {
        let (classical, quantum) = split_root(root);
        Self {
            classical: DoubleRatchet::initiator(classical, responder, Retention::Owned),
            quantum: peer::Peer::new(true, &quantum, size, Retention::Owned),
        }
    }

    /// Consume the private counterpart of the setup-bound responder key.
    #[must_use]
    pub fn responder(root: &[u8; 32], size: ChunkSize, initial: InitialKey) -> Self {
        let (classical, quantum) = split_root(root);
        Self {
            classical: DoubleRatchet::responder(classical, initial.0, Retention::Timed),
            quantum: peer::Peer::new(false, &quantum, size, Retention::Timed),
        }
    }

    /// Allocate independent message keys and combine them for one record stream.
    ///
    /// # Errors
    /// Rejects exhausted counters, random-source failure or a responder send
    /// before its first authenticated client message.
    pub fn send(&mut self) -> Result<SendKey, Error> {
        self.send_with(&mut |bytes| getrandom::fill(bytes).map_err(|_| Error::Crypto))
    }

    fn send_with(
        &mut self,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<SendKey, Error> {
        let classical = self.classical.prepare_send(random)?;
        let quantum = self.quantum.send_with(random)?;
        let secret = combine(&classical.secret, &quantum.secret);
        let mut header = Vec::with_capacity(classical.header.len() + quantum.header.len());
        header.extend_from_slice(&classical.header);
        header.extend_from_slice(&quantum.header);
        self.classical.commit_send(classical);
        Ok(SendKey { header, secret })
    }

    /// Authenticate the complete composite header and ciphertext before either
    /// component consumes a key or commits its next state.
    ///
    /// # Errors
    /// Rejects malformed, replayed, expired, too-distant or unauthenticated input.
    pub fn receive<T>(
        &mut self,
        header: &[u8],
        now_ms: u64,
        authenticate: impl FnOnce(&[u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&header.len()) {
            return Err(Error::Record);
        }
        let (classical_header, quantum_header) = header.split_at(double::HEADER_BYTES);
        let Self { classical, quantum } = self;
        classical.receive(classical_header, now_ms, |classical_key| {
            quantum.receive(quantum_header, now_ms, |quantum_key| {
                authenticate(&combine(classical_key, quantum_key))
            })
        })
    }

    /// Erase expired delayed-message keys in both component ratchets.
    pub fn expire(&mut self, now_ms: u64) {
        self.classical.expire(now_ms);
        self.quantum.expire(now_ms);
    }

    /// Erase keys for replies that no outstanding request can receive. Client
    /// adapters call this when the last first-response owner finishes or drops.
    /// It does not discard active chains needed for subsequent messages.
    pub fn discard_delayed(&mut self) {
        self.classical.discard_delayed();
        self.quantum.discard_delayed();
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod benchmark;
