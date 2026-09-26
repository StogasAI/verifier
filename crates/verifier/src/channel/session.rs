use super::{Direction, Error, Kind, record::Records};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize as _, Zeroizing};

const REPLAY_WINDOW: u64 = 4096;
const REQUEST_HEADER: &[u8] = b"STGS\x01\x03";
pub const REQUEST_PREFIX_BYTES: usize = REQUEST_HEADER.len() + 32 + 8;

struct Starts {
    next: u64,
    first_pending: u64,
    pending: [u64; 64],
}

impl Default for Starts {
    fn default() -> Self {
        Self {
            next: 0,
            first_pending: 0,
            pending: [0; 64],
        }
    }
}

impl Starts {
    const fn allocate(&mut self) -> Result<u64, Error> {
        if self.next == u64::MAX {
            return Err(Error::Limit);
        }
        if self.next - self.first_pending >= REPLAY_WINDOW {
            return Err(Error::Pending);
        }
        let number = self.next;
        let position = (number % REPLAY_WINDOW) as usize;
        self.pending[position / 64] |= 1_u64 << (position % 64);
        self.next += 1;
        Ok(number)
    }

    const fn release(&mut self, number: u64) {
        let position = (number % REPLAY_WINDOW) as usize;
        self.pending[position / 64] &= !(1_u64 << (position % 64));
        while self.first_pending < self.next {
            let position = (self.first_pending % REPLAY_WINDOW) as usize;
            if self.pending[position / 64] & (1_u64 << (position % 64)) != 0 {
                break;
            }
            self.first_pending += 1;
        }
    }
}

struct PendingStart {
    starts: Arc<Mutex<Starts>>,
    number: u64,
}

impl Drop for PendingStart {
    fn drop(&mut self) {
        self.starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(self.number);
    }
}

/// A verified E2EE session. The transport serializes allocation through mutable
/// access; separate requests can then encrypt and read responses independently.
pub struct ClientSession {
    root: Option<Zeroizing<[u8; 32]>>,
    id: [u8; 32],
    idle_seconds: u32,
    starts: Arc<Mutex<Starts>>,
}

impl ClientSession {
    // Only the verified setup path constructs sessions in production.
    pub(crate) fn new(root: Zeroizing<[u8; 32]>, id: [u8; 32], idle_seconds: u32) -> Self {
        Self {
            root: Some(root),
            id,
            idle_seconds,
            starts: Arc::new(Mutex::new(Starts::default())),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Authenticated server hint. The transport tracks elapsed idle time and
    /// renews before unsent work; the hint does not promise continued reachability.
    #[must_use]
    pub const fn idle_seconds(&self) -> u32 {
        self.idle_seconds
    }

    /// Reserve a new unique request number. Abandoned numbers are never reused.
    ///
    /// # Errors
    /// Returns Pending if delayed unacknowledged starts fill the replay window,
    /// Limit on sequence exhaustion, or Closed after disposal.
    pub fn request(&mut self) -> Result<ClientRequest, Error> {
        let root = self.root.as_ref().ok_or(Error::Closed)?;
        let number = self.starts.lock().map_err(|_| Error::Closed)?.allocate()?;
        let pending = PendingStart {
            starts: Arc::clone(&self.starts),
            number,
        };
        let outgoing = Records::new(root, &self.id, number, Direction::Request)?;
        let incoming = Records::new(root, &self.id, number, Direction::Response)?;
        Ok(ClientRequest {
            writer: RequestEncoder {
                session_id: self.id,
                number,
                records: outgoing,
            },
            reader: ResponseReader {
                pending: Some(pending),
                records: incoming,
            },
        })
    }

    /// Erase the root and reject new requests. Existing requests retain only
    /// their independent directional keys until they complete or are dropped.
    pub fn close(&mut self) {
        self.root = None;
    }
}

/// One request with unique directional keys and one owner of each record state.
pub struct ClientRequest {
    writer: RequestEncoder,
    reader: ResponseReader,
}

/// The request half can upload while the independent response half receives an
/// early rejection. Neither half can clone or reset its encryption counters.
pub struct RequestEncoder {
    session_id: [u8; 32],
    number: u64,
    records: Records,
}

pub(super) struct ResponseReader {
    pending: Option<PendingStart>,
    records: Records,
}

impl ClientRequest {
    /// Separate upload and response ownership without copying keys or counters.
    #[must_use]
    pub fn split(self) -> (RequestEncoder, super::ResponseDecoder) {
        (
            self.writer,
            super::ResponseDecoder::from_reader(self.reader),
        )
    }

    #[must_use]
    pub fn prefix(&self) -> [u8; REQUEST_PREFIX_BYTES] {
        self.writer.prefix()
    }

    #[must_use]
    pub const fn number(&self) -> u64 {
        self.writer.number
    }

    /// # Errors
    /// Invalid ordering, exhausted bounds or prior failure close the writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.writer.seal(kind, content)
    }

    /// # Errors
    /// Invalid authentication, order or bounds permanently close the decoder.
    pub fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        self.reader.open(encoded)
    }

    /// # Errors
    /// Returns Truncated if completion was missing or any record failed.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.reader.complete()
    }
}

impl RequestEncoder {
    /// Fixed dispatch prefix. Its identity/number select the cryptographic key;
    /// the gateway authenticates the first record before trusting either value.
    #[must_use]
    pub fn prefix(&self) -> [u8; REQUEST_PREFIX_BYTES] {
        let mut prefix = [0; REQUEST_PREFIX_BYTES];
        prefix[..REQUEST_HEADER.len()].copy_from_slice(REQUEST_HEADER);
        prefix[REQUEST_HEADER.len()..REQUEST_HEADER.len() + 32].copy_from_slice(&self.session_id);
        prefix[REQUEST_HEADER.len() + 32..].copy_from_slice(&self.number.to_be_bytes());
        prefix
    }
    /// Encode metadata, body bytes or completion without bulk base64.
    ///
    /// # Errors
    /// Invalid ordering, exhausted bounds or prior failure close the writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.records.seal(kind, content)
    }
}

impl ResponseReader {
    /// Authenticate one complete response record in place. The first valid
    /// response acknowledges server ownership, freeing request-start capacity.
    ///
    /// # Errors
    /// Invalid authentication, order or bounds permanently close the decoder.
    pub fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        let result = self.records.open(encoded)?;
        self.pending = None;
        Ok(result)
    }

    /// Confirm an authenticated terminal record before treating EOF as success.
    ///
    /// # Errors
    /// Returns Truncated if completion was missing or any record failed.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.records.complete()
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.close();
        self.id.zeroize();
    }
}
