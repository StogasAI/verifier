use super::{
    Direction, Error, Kind,
    cipher::{Cipher, SoftwareCipher},
    ratchet::{ChunkSize, Peer},
    record::{Records, start_header},
};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize as _, Zeroizing};

const REPLAY_WINDOW: u64 = 4096;
const REQUEST_HEADER: &[u8] = b"STGS\x03\x03";
pub const REQUEST_PREFIX_BYTES: usize = REQUEST_HEADER.len() + 32 + 8;

struct Starts {
    next: u64,
    first_pending: u64,
    confirmed_next: u64,
    pending: [u64; 64],
}

impl Default for Starts {
    fn default() -> Self {
        Self {
            next: 0,
            first_pending: 0,
            confirmed_next: 0,
            pending: [0; 64],
        }
    }
}

impl Starts {
    const fn allocate(&mut self) -> Result<u64, Error> {
        if self.next == u64::MAX {
            return Err(Error::Limit);
        }
        if self.next - self.confirmed_next >= REPLAY_WINDOW {
            return Err(if self.first_pending == self.next {
                Error::Limit
            } else {
                Error::Pending
            });
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

struct Shared {
    starts: Starts,
    peer: Peer,
}

struct PendingStart {
    shared: Arc<Mutex<Shared>>,
    number: u64,
}

impl Drop for PendingStart {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.starts.release(self.number);
        if state.starts.first_pending == state.starts.next {
            state.peer.discard_delayed();
        }
    }
}

/// A verified E2EE session. The transport serializes allocation through mutable
/// access; separate requests can then encrypt and read responses independently.
pub struct ClientSession {
    shared: Option<Arc<Mutex<Shared>>>,
    id: [u8; 32],
    idle_seconds: u32,
}

impl ClientSession {
    // Only the verified setup path constructs sessions in production.
    pub(crate) fn new(
        root: Zeroizing<[u8; 32]>,
        id: [u8; 32],
        idle_seconds: u32,
        size: ChunkSize,
        responder: [u8; 32],
    ) -> Self {
        let peer = Peer::initiator(&root, size, responder);
        drop(root);
        Self {
            shared: Some(Arc::new(Mutex::new(Shared {
                starts: Starts::default(),
                peer,
            }))),
            id,
            idle_seconds,
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
    /// Limit when sequence space or the unacknowledged cancellation window is
    /// exhausted (renew the session), or Closed after disposal.
    pub fn request(&mut self) -> Result<ClientRequest, Error> {
        self.request_with::<SoftwareCipher>()
    }

    /// Allocate the same verified request state with a platform AES-GCM backend.
    ///
    /// # Errors
    /// Applies the same request-start, sequence and disposal bounds as `request`.
    pub fn request_with<C: Cipher>(&mut self) -> Result<ClientRequest<C>, Error> {
        let shared = self.shared.as_ref().ok_or(Error::Closed)?;
        let mut state = shared.lock().map_err(|_| Error::Closed)?;
        let number = state.starts.allocate()?;
        let allocated = state.peer.send();
        if allocated.is_err() {
            state.starts.release(number);
        }
        let allocated = allocated?;
        drop(state);
        let pending = PendingStart {
            shared: Arc::clone(shared),
            number,
        };
        let outgoing = Records::<C>::new(
            &allocated.secret,
            &self.id,
            number,
            Direction::Request,
            allocated.header,
        )?;
        Ok(ClientRequest {
            writer: RequestEncoder {
                session_id: self.id,
                number,
                records: outgoing,
            },
            reader: ResponseReader {
                pending: Some(pending),
                session_id: self.id,
                records: None,
                failed: false,
            },
        })
    }

    /// Advance elapsed-clock accounting. Delayed-response keys remain owned by
    /// pending requests and are discarded when the final first-response owner ends.
    ///
    /// # Errors
    /// Rejects a closed or poisoned session.
    pub fn expire(&mut self, now_ms: u64) -> Result<(), Error> {
        let shared = self.shared.as_ref().ok_or(Error::Closed)?;
        shared
            .lock()
            .map_err(|_| Error::Closed)?
            .peer
            .expire(now_ms);
        Ok(())
    }

    /// Reject new requests and release this session owner. Pending first response
    /// headers retain the peer until authenticated or cancelled; started streams
    /// retain only their independent directional keys.
    pub fn close(&mut self) {
        self.shared = None;
    }
}

/// One request with unique directional keys and one owner of each record state.
pub struct ClientRequest<C: Cipher = SoftwareCipher> {
    writer: RequestEncoder<C>,
    reader: ResponseReader<C>,
}

/// The request half can upload while the independent response half receives an
/// early rejection. Neither half can clone or reset its encryption counters.
pub struct RequestEncoder<C: Cipher = SoftwareCipher> {
    session_id: [u8; 32],
    number: u64,
    records: Records<C>,
}

pub(super) struct ResponseReader<C: Cipher = SoftwareCipher> {
    pending: Option<PendingStart>,
    session_id: [u8; 32],
    records: Option<Records<C>>,
    failed: bool,
}

impl<C: Cipher> ClientRequest<C> {
    /// Separate upload and response ownership without copying keys or counters.
    #[must_use]
    pub fn split(self) -> (RequestEncoder<C>, super::ResponseDecoder<C>) {
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
    pub async fn seal_async(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.writer.seal_async(kind, content).await
    }

    /// # Errors
    /// Invalid authentication, order or bounds permanently close the decoder.
    pub async fn open_async<'a>(
        &mut self,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(Kind, &'a [u8]), Error> {
        self.reader.open_async(encoded, now_ms).await
    }

    /// # Errors
    /// Returns Truncated if completion was missing or any record failed.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.reader.complete()
    }
}

impl<C: Cipher> RequestEncoder<C> {
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
    pub async fn seal_async(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.records.seal_async(kind, content).await
    }
}

impl<C: Cipher> ResponseReader<C> {
    pub async fn open_async<'a>(
        &mut self,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(Kind, &'a [u8]), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if self.records.is_none() {
            return self.start(encoded, now_ms);
        }
        self.records
            .as_mut()
            .ok_or(Error::Closed)?
            .open_async(encoded)
            .await
    }

    fn start<'a>(&mut self, encoded: &'a mut [u8], now_ms: u64) -> Result<(Kind, &'a [u8]), Error> {
        // Taking this owner before parsing also releases pending capacity on any
        // error. No unauthenticated failure acknowledges delivery.
        self.failed = true;
        let pending = self.pending.take().ok_or(Error::Closed)?;
        let header = start_header(encoded)?.to_vec();
        let mut state = pending.shared.lock().map_err(|_| Error::Closed)?;
        let (records, kind, content) = state.peer.receive(&header, now_ms, |secret| {
            Records::<C>::authenticate_start(
                secret,
                &self.session_id,
                pending.number,
                Direction::Response,
                encoded,
            )
        })?;
        state.starts.confirmed_next = state.starts.confirmed_next.max(pending.number + 1);
        drop(state);
        self.records = Some(records);
        self.failed = false;
        Ok((kind, content))
    }

    pub fn complete(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        self.records.as_mut().ok_or(Error::Truncated)?.complete()
    }
}

impl ClientRequest<SoftwareCipher> {
    /// # Errors
    /// Invalid ordering, exhausted bounds or prior failure close the writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.writer.seal(kind, content)
    }

    /// # Errors
    /// Invalid authentication, order or bounds permanently close the decoder.
    pub fn open<'a>(
        &mut self,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(Kind, &'a [u8]), Error> {
        self.reader.open(encoded, now_ms)
    }
}

impl RequestEncoder<SoftwareCipher> {
    /// # Errors
    /// Invalid ordering, exhausted bounds or prior failure close the writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.records.seal(kind, content)
    }
}

impl ResponseReader<SoftwareCipher> {
    pub(super) fn open<'a>(
        &mut self,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(Kind, &'a [u8]), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if self.records.is_none() {
            return self.start(encoded, now_ms);
        }
        self.records.as_mut().ok_or(Error::Closed)?.open(encoded)
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.close();
        self.id.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_exhaustion_never_wraps_or_reuses_a_pending_slot() {
        let mut starts = Starts {
            next: u64::MAX - 1,
            first_pending: u64::MAX - 1,
            confirmed_next: u64::MAX - 1,
            ..Starts::default()
        };
        assert_eq!(starts.allocate(), Ok(u64::MAX - 1));
        assert_eq!(starts.allocate(), Err(Error::Limit));
        starts.release(u64::MAX - 1);
        assert_eq!(starts.allocate(), Err(Error::Limit));
        assert_eq!(starts.next, u64::MAX);
        assert!(starts.pending.iter().all(|bits| *bits == 0));
    }
}
