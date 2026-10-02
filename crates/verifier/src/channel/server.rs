use super::{
    Direction, Error, Kind,
    ratchet::{ChunkSize, InitialKey, Peer},
    record::{Records, start_header},
};
use zeroize::Zeroizing;

const REPLAY_WINDOW: u64 = 4096;

/// Server-side request admission. The caller serializes access to this owner;
/// accepted requests have independent upload and response cipher owners.
pub struct ServerSession {
    peer: Option<Peer>,
    id: [u8; 32],
    next: u64,
    accepted: [u64; 64],
}

impl ServerSession {
    /// Construct from the root exported by the authenticated server setup.
    #[must_use]
    pub fn new(
        root: Zeroizing<[u8; 32]>,
        id: [u8; 32],
        size: ChunkSize,
        initial: InitialKey,
    ) -> Self {
        let peer = Peer::responder(&root, size, initial);
        drop(root);
        Self {
            peer: Some(peer),
            id,
            next: 0,
            accepted: [0; 64],
        }
    }

    /// Authenticate the first record before consuming a request number or key.
    /// The returned plaintext borrows the caller's record buffer.
    ///
    /// # Errors
    /// Rejects replay, expiry, excessive gaps, malformed records or closed state.
    pub fn accept_start<'a>(
        &mut self,
        number: u64,
        encoded: &'a mut [u8],
        now_ms: u64,
    ) -> Result<(ServerReader, ServerWriter, &'a [u8]), Error> {
        let peer = self.peer.as_mut().ok_or(Error::Closed)?;
        let position = (number % REPLAY_WINDOW) as usize;
        if number < self.next {
            if self.next - number > REPLAY_WINDOW
                || self.accepted[position / 64] & (1 << (position % 64)) != 0
            {
                return Err(Error::Record);
            }
        } else if number == u64::MAX || number - self.next >= REPLAY_WINDOW {
            return Err(Error::Limit);
        }
        let header = start_header(encoded)?.to_vec();
        let (incoming, _, metadata) = peer.receive(&header, now_ms, |secret| {
            let result =
                Records::authenticate_start(secret, &self.id, number, Direction::Request, encoded)?;
            if result.1 != Kind::Metadata {
                return Err(Error::Record);
            }
            Ok(result)
        })?;
        let response = peer.send()?;
        let outgoing = Records::new(
            &response.secret,
            &self.id,
            number,
            Direction::Response,
            response.header,
        )?;
        if number >= self.next {
            for stale in self.next..=number {
                let position = (stale % REPLAY_WINDOW) as usize;
                self.accepted[position / 64] &= !(1 << (position % 64));
            }
            self.next = number + 1;
        }
        self.accepted[position / 64] |= 1 << (position % 64);
        Ok((ServerReader(incoming), ServerWriter(outgoing), metadata))
    }

    /// Erase delayed-start keys when their bounded lifetime ends.
    pub fn expire(&mut self, now_ms: u64) {
        if let Some(peer) = &mut self.peer {
            peer.expire(now_ms);
        }
    }

    /// Erase session secrets. Already admitted requests retain their own keys.
    pub fn close(&mut self) {
        self.peer = None;
    }
}

/// The independently owned request-body cipher.
pub struct ServerReader(Records);

impl ServerReader {
    /// # Errors
    /// Authentication, framing or order failure permanently closes this reader.
    pub fn open<'a>(&mut self, encoded: &'a mut [u8]) -> Result<(Kind, &'a [u8]), Error> {
        self.0.open(encoded)
    }
    /// # Errors
    /// A missing authenticated terminal record is a truncated upload.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.0.complete()
    }
    pub fn close(&mut self) {
        self.0.close();
    }
}

/// The independently owned response-body cipher.
pub struct ServerWriter(Records);

impl ServerWriter {
    /// # Errors
    /// Invalid framing, order or usage bounds permanently close this writer.
    pub fn seal(&mut self, kind: Kind, content: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(kind, content)
    }
    pub fn close(&mut self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ClientSession;

    #[test]
    fn admission_rejects_forgery_and_replay_and_streams_outlive_the_session() {
        let root = Zeroizing::new([1; 32]);
        let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
        let mut client = ClientSession::new(
            root.clone(),
            [2; 32],
            600,
            ChunkSize::FULL,
            initial.public_key(),
        );
        let mut server = ServerSession::new(root, [2; 32], ChunkSize::FULL, initial);
        let mut delayed = client.request().unwrap();
        let mut request = client.request().unwrap();
        let mut start = request.seal(Kind::Metadata, b"metadata").unwrap();
        // X25519 masks the high bit, so this alternate encoding derives the
        // same DH result. The authenticated header must still reject it.
        let mut aliased = start.clone();
        aliased[6 + 31] ^= 128;
        assert!(matches!(
            server.accept_start(request.number(), &mut aliased, 0),
            Err(Error::Authentication)
        ));
        let mut forged = start.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(
            server
                .accept_start(request.number(), &mut forged, 0)
                .is_err()
        );
        let (mut reader, mut writer, metadata) = server
            .accept_start(request.number(), &mut start.clone(), 0)
            .map(|(r, w, m)| (r, w, m.to_vec()))
            .unwrap();
        assert_eq!(metadata, b"metadata");
        assert!(
            server
                .accept_start(request.number(), &mut start, 0)
                .is_err()
        );
        let mut delayed_start = delayed.seal(Kind::Metadata, b"delayed").unwrap();
        assert!(
            server
                .accept_start(
                    delayed.number(),
                    &mut delayed_start,
                    super::super::ratchet::SKIPPED_KEY_LIFETIME_MS
                )
                .is_err()
        );
        server.close();
        let mut body = request.seal(Kind::Data, b"upload").unwrap();
        assert_eq!(
            reader.open(&mut body).unwrap(),
            (Kind::Data, b"upload".as_slice())
        );
        reader
            .open(&mut request.seal(Kind::Finished, b"").unwrap())
            .unwrap();
        reader.complete().unwrap();
        let mut reply = writer.seal(Kind::Metadata, b"response").unwrap();
        assert_eq!(
            request.open(&mut reply, 0).unwrap(),
            (Kind::Metadata, b"response".as_slice())
        );
        request
            .open(&mut writer.seal(Kind::Finished, b"").unwrap(), 0)
            .unwrap();
        request.complete().unwrap();
    }
}

#[cfg(test)]
mod exchange_tests {
    use super::*;
    use crate::channel::ClientSession;

    #[test]
    fn concurrent_streams_authenticate_across_recovery_epochs_and_session_close() {
        for width in [32, 34, 256, 1152] {
            let size = ChunkSize::new(width).unwrap();
            let root = Zeroizing::new([31; 32]);
            let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
            let mut client =
                ClientSession::new(root.clone(), [32; 32], 600, size, initial.public_key());
            let mut server = ServerSession::new(root, [32; 32], size, initial);
            let mut maximum_epoch = 0;
            for round in 0..100 {
                let mut pending = Vec::new();
                for index in 0..24 {
                    let mut request = client.request().unwrap();
                    let metadata = [u8::try_from(round).unwrap(), index];
                    let start = request.seal(Kind::Metadata, &metadata).unwrap();
                    maximum_epoch =
                        maximum_epoch.max(u64::from_be_bytes(start[70..78].try_into().unwrap()));
                    pending.push((request, start, metadata));
                }
                let mut admitted = Vec::new();
                for (request, mut start, metadata) in pending.into_iter().rev() {
                    let (reader, writer, actual) = server
                        .accept_start(request.number(), &mut start, round)
                        .unwrap();
                    assert_eq!(actual, metadata);
                    admitted.push((request, reader, writer));
                }
                if round == 99 {
                    client.close();
                    server.close();
                }
                for (mut request, mut reader, mut writer) in admitted.into_iter().rev() {
                    let mut data = request.seal(Kind::Data, b"request").unwrap();
                    assert_eq!(
                        reader.open(&mut data).unwrap(),
                        (Kind::Data, b"request".as_slice())
                    );
                    reader
                        .open(&mut request.seal(Kind::Finished, b"").unwrap())
                        .unwrap();
                    reader.complete().unwrap();
                    // Closing the session keeps only the owners required by
                    // already allocated, not-yet-authenticated response starts.
                    let mut response = writer.seal(Kind::Metadata, b"response metadata").unwrap();
                    assert_eq!(
                        request.open(&mut response, round).unwrap(),
                        (Kind::Metadata, b"response metadata".as_slice())
                    );
                    let mut response = writer.seal(Kind::Data, b"response").unwrap();
                    assert_eq!(
                        request.open(&mut response, round).unwrap(),
                        (Kind::Data, b"response".as_slice())
                    );
                    request
                        .open(&mut writer.seal(Kind::Finished, b"").unwrap(), round)
                        .unwrap();
                    request.complete().unwrap();
                }
            }
            assert!(maximum_epoch >= 4, "ratchet stalled at width {width}");
            assert!(matches!(client.request(), Err(Error::Closed)));
        }
    }
}
