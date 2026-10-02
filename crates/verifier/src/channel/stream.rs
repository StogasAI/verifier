use super::session::ResponseReader;
use super::{
    ClientRequest, Error, Kind,
    cipher::{Cipher, SoftwareCipher},
    record_size,
};
use zeroize::{Zeroize as _, Zeroizing};

/// Incremental response framing shared by native and browser transports. Only one encoded
/// record is retained; authenticated plaintext borrows that buffer during the callback.
pub struct ResponseDecoder<C: Cipher = SoftwareCipher> {
    request: Option<ResponseReader<C>>,
    buffer: Zeroizing<Vec<u8>>,
    needed: usize,
    finished: bool,
}

impl<C: Cipher> ResponseDecoder<C> {
    #[must_use]
    pub fn new(request: ClientRequest<C>) -> Self {
        request.split().1
    }

    pub(super) fn from_reader(request: ResponseReader<C>) -> Self {
        Self {
            request: Some(request),
            buffer: Zeroizing::new(Vec::new()),
            needed: 4,
            finished: false,
        }
    }

    /// Decode with a platform AES-GCM backend, preserving the native record rules.
    /// The callback runs only after authentication and must consume or copy its bytes.
    ///
    /// # Errors
    /// Failure or cancellation closes the decoder and discards its buffered bytes.
    pub async fn push_async(
        &mut self,
        input: &[u8],
        now_ms: u64,
        mut emit: impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut operation = DecodeOperation::new(self);
        if operation.decoder.request.is_none() {
            return Err(Error::Closed);
        }
        operation
            .decoder
            .read_async(input, now_ms, &mut emit)
            .await?;
        operation.completed = true;
        Ok(())
    }

    async fn read_async(
        &mut self,
        mut input: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while self.fill(&mut input)? {
            let (kind, content) = self
                .request
                .as_mut()
                .ok_or(Error::Closed)?
                .open_async(&mut self.buffer, now_ms)
                .await?;
            self.finished = kind == Kind::Finished;
            emit(kind, content)?;
            self.clear_buffer();
        }
        Ok(())
    }

    // Both execution paths use this one bounded, incremental frame parser.
    fn fill(&mut self, input: &mut &[u8]) -> Result<bool, Error> {
        while !input.is_empty() {
            if self.finished {
                return Err(Error::Record);
            }
            let take = input.len().min(self.needed - self.buffer.len());
            self.buffer.extend_from_slice(&input[..take]);
            *input = &input[take..];
            if self.buffer.len() != self.needed {
                continue;
            }
            if self.needed == 4 {
                self.needed = record_size(&self.buffer)?;
                let additional = self.needed - self.buffer.len();
                self.buffer
                    .try_reserve_exact(additional)
                    .map_err(|_| Error::Limit)?;
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn clear_buffer(&mut self) {
        self.buffer.as_mut_slice().zeroize();
        self.buffer.clear();
        self.needed = 4;
    }

    fn close(&mut self) {
        self.request = None;
        self.clear_buffer();
    }

    /// Confirm outer EOF followed the authenticated terminal record with no partial frame.
    /// Consumes the decoder and erases its remaining key material.
    ///
    /// # Errors
    /// Returns Truncated for premature EOF and Closed after an earlier decoding failure.
    pub fn finish(mut self) -> Result<(), Error> {
        let request = self.request.as_mut().ok_or(Error::Closed)?;
        if !self.buffer.is_empty() {
            return Err(Error::Truncated);
        }
        request.complete()
    }
}

impl ResponseDecoder<SoftwareCipher> {
    /// Accept any fragmentation, including several records in one network chunk.
    /// Authenticated Finished still requires `finish` at the outer stream's EOF.
    ///
    /// # Errors
    /// Invalid framing, authentication, ordering or callback failure closes decoding.
    pub fn push(
        &mut self,
        input: &[u8],
        now_ms: u64,
        mut emit: impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut operation = DecodeOperation::new(self);
        if operation.decoder.request.is_none() {
            return Err(Error::Closed);
        }
        operation.decoder.read(input, now_ms, &mut emit)?;
        operation.completed = true;
        Ok(())
    }

    fn read(
        &mut self,
        mut input: &[u8],
        now_ms: u64,
        emit: &mut impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while self.fill(&mut input)? {
            let (kind, content) = self
                .request
                .as_mut()
                .ok_or(Error::Closed)?
                .open(&mut self.buffer, now_ms)?;
            self.finished = kind == Kind::Finished;
            emit(kind, content)?;
            self.clear_buffer();
        }
        Ok(())
    }
}

struct DecodeOperation<'a, C: Cipher> {
    decoder: &'a mut ResponseDecoder<C>,
    completed: bool,
}

impl<'a, C: Cipher> DecodeOperation<'a, C> {
    const fn new(decoder: &'a mut ResponseDecoder<C>) -> Self {
        Self {
            decoder,
            completed: false,
        }
    }
}

impl<C: Cipher> Drop for DecodeOperation<'_, C> {
    fn drop(&mut self) {
        if !self.completed {
            self.decoder.close();
        }
    }
}
