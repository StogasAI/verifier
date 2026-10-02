//! Independent implementation of the public-domain Double, Sparse Post-Quantum
//! and Triple Ratchet specifications. This is not Signal's implementation.

use super::Error;

mod braid;
mod double;
mod erasure;
mod hybrid;
mod kem;
mod peer;

pub use hybrid::{InitialKey, MAX_HEADER_BYTES, MIN_HEADER_BYTES, Peer};
pub use peer::{MAX_SKIPPED_KEYS, SKIPPED_KEY_LIFETIME_MS, SendKey};

const MAX_PIECE: usize = ChunkSize::FULL.0 as usize;

// Admission deadlines apply to delayed request starts. Response keys belong
// to outstanding request owners, which can legitimately wait much longer.
#[derive(Clone, Copy)]
pub(super) enum Retention {
    Timed,
    Owned,
}

impl Retention {
    const fn deadline(self, now: u64) -> Option<u64> {
        match self {
            Self::Timed => Some(now.saturating_add(SKIPPED_KEY_LIFETIME_MS)),
            Self::Owned => None,
        }
    }
}

/// Maximum KEM payload in one recovery message. The full profile sends each
/// available piece at once. Smaller chunks trade bandwidth for recovery speed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkSize(u16);

impl ChunkSize {
    pub const FULL: Self = Self(1152);

    /// # Errors
    /// Requires an even width from 32 through 1152 bytes. The minimum preserves
    /// the published 32-byte profile's bound of at most 36 erasure symbols.
    pub const fn new(bytes: u16) -> Result<Self, Error> {
        if bytes < 32 || bytes > Self::FULL.0 || !bytes.is_multiple_of(2) {
            Err(Error::Limit)
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for ChunkSize {
    fn default() -> Self {
        Self::FULL
    }
}
