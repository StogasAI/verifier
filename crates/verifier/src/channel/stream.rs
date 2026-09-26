use super::session::ResponseReader;
use super::{ClientRequest, Error, Kind, record_size};
use zeroize::{Zeroize as _, Zeroizing};

/// Incremental response framing shared by native and browser transports. Only one encoded
/// record is retained; authenticated plaintext borrows that buffer during the callback.
pub struct ResponseDecoder {
    request: Option<ResponseReader>,
    buffer: Zeroizing<Vec<u8>>,
    needed: usize,
    finished: bool,
}

impl ResponseDecoder {
    #[must_use]
    pub fn new(request: ClientRequest) -> Self {
        request.split().1
    }

    pub(super) fn from_reader(request: ResponseReader) -> Self {
        Self {
            request: Some(request),
            buffer: Zeroizing::new(Vec::new()),
            needed: 4,
            finished: false,
        }
    }

    /// Accept any network fragmentation, including several records in one chunk.
    /// The callback must consume or copy its borrowed bytes before returning. A Finished event
    /// authenticates completion; the adapter must still call `finish` at outer EOF.
    ///
    /// # Errors
    /// Rejects invalid lengths before body allocation, authentication/order errors and bytes
    /// after completion. Any error erases request keys and permanently closes this decoder.
    pub fn push(
        &mut self,
        input: &[u8],
        mut emit: impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.request.is_none() {
            return Err(Error::Closed);
        }
        let result = self.read(input, &mut emit);
        if result.is_err() {
            self.request = None;
            self.buffer.as_mut_slice().zeroize();
            self.buffer.clear();
        }
        result
    }

    fn read(
        &mut self,
        mut input: &[u8],
        emit: &mut impl FnMut(Kind, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while !input.is_empty() {
            if self.finished {
                return Err(Error::Record);
            }
            let take = input.len().min(self.needed - self.buffer.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
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
            let (kind, content) = self
                .request
                .as_mut()
                .ok_or(Error::Closed)?
                .open(&mut self.buffer)?;
            self.finished = kind == Kind::Finished;
            emit(kind, content)?;
            self.buffer.as_mut_slice().zeroize();
            self.buffer.clear();
            self.needed = 4;
        }
        Ok(())
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
