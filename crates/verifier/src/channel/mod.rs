//! Binary session transport. Verification and HTTP adapters stay outside the
//! record layer; application credentials are released only after verified setup.

mod record;
mod session;
pub mod setup;
mod stream;

pub use record::{
    MAX_RECORD_BYTES, MAX_RECORD_PLAINTEXT, MAX_REQUEST_WIRE_BYTES, MAX_RESPONSE_WIRE_BYTES,
    record_size,
};
pub use session::{ClientRequest, ClientSession, RequestEncoder};
pub use stream::ResponseDecoder;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid encrypted record")]
    Record,
    #[error("encrypted record authentication failed")]
    Authentication,
    #[error("encrypted record usage limit reached")]
    Limit,
    #[error("encrypted channel is closed")]
    Closed,
    #[error("encrypted stream ended without completion")]
    Truncated,
    #[error("encrypted session awaits request-start acknowledgements")]
    Pending,
    #[error("encrypted session key derivation failed")]
    Crypto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Metadata = 1,
    Data = 2,
    Finished = 3,
    Keepalive = 4,
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Metadata),
            2 => Ok(Self::Data),
            3 => Ok(Self::Finished),
            4 => Ok(Self::Keepalive),
            _ => Err(Error::Record),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Direction {
    Request = 1,
    Response = 2,
}

#[cfg(test)]
mod tests;
