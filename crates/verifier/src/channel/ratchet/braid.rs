//! ML-KEM Braid, revision 1, §2.4–2.6. State names follow the public specification.
//! <https://signal.org/docs/specifications/mlkembraid/>

use super::{
    ChunkSize, Error,
    erasure::{Chunk, Decoder, Encoder},
    kem,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2_v11::Sha256;
use zeroize::Zeroizing;

const PROTOCOL: &[u8] = b"stogas.e2ee.braid.v3_MLKEM768_HMACSHA256";
const MAC_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Kind {
    None = 0,
    Header = 1,
    Key = 2,
    KeyAndAck = 3,
    Ack = 4,
    Ciphertext1 = 5,
    Ciphertext2 = 6,
}

impl Kind {
    const fn piece_size(self) -> usize {
        match self {
            Self::None | Self::Ack => 0,
            Self::Header => kem::HEADER_BYTES + MAC_BYTES,
            Self::Key | Self::KeyAndAck => kem::KEY_BYTES,
            Self::Ciphertext1 => kem::CT1_BYTES,
            Self::Ciphertext2 => kem::CT2_BYTES + MAC_BYTES,
        }
    }
}

impl TryFrom<u8> for Kind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Header),
            2 => Ok(Self::Key),
            3 => Ok(Self::KeyAndAck),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Ciphertext1),
            6 => Ok(Self::Ciphertext2),
            _ => Err(Error::Record),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Message {
    pub epoch: u64,
    pub kind: Kind,
    pub chunk: Option<Chunk>,
}

impl Message {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.push(self.kind as u8);
        if let Some(chunk) = &self.chunk {
            bytes.extend_from_slice(&chunk.point.to_be_bytes());
            bytes.extend_from_slice(&chunk.bytes);
        }
    }

    pub fn decode(bytes: &[u8], chunk_size: ChunkSize) -> Result<Self, Error> {
        let epoch = u64::from_be_bytes(
            bytes
                .get(..8)
                .ok_or(Error::Record)?
                .try_into()
                .map_err(|_| Error::Record)?,
        );
        if epoch == 0 {
            return Err(Error::Record);
        }
        let kind = Kind::try_from(*bytes.get(8).ok_or(Error::Record)?)?;
        let width = kind.piece_size().min(usize::from(chunk_size.get()));
        let chunk = if width == 0 {
            if bytes.len() != 9 {
                return Err(Error::Record);
            }
            None
        } else {
            if bytes.len() != 11 + width {
                return Err(Error::Record);
            }
            Some(Chunk {
                point: u16::from_be_bytes([bytes[9], bytes[10]]),
                bytes: bytes[11..].to_vec(),
            })
        };
        Ok(Self { epoch, kind, chunk })
    }

    fn chunk(&self) -> Result<&Chunk, Error> {
        self.chunk.as_ref().ok_or(Error::Record)
    }
}

pub(super) struct EpochKey {
    pub epoch: u64,
    pub secret: Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
struct Authenticator {
    root: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl Authenticator {
    fn new(secret: &[u8; 32]) -> Self {
        let mut auth = Self {
            root: Zeroizing::new([0; 32]),
            mac: Zeroizing::new([0; 32]),
        };
        auth.update(1, secret);
        auth
    }

    fn update(&mut self, epoch: u64, secret: &[u8; 32]) {
        let mut material = Zeroizing::new([0; 64]);
        Hkdf::<Sha256>::new(Some(self.root.as_ref()), secret)
            .expand_multi_info(
                &[PROTOCOL, b":Authenticator Update", &epoch.to_be_bytes()],
                material.as_mut(),
            )
            .expect("fixed HKDF output is within SHA-256 bounds");
        self.root.copy_from_slice(&material[..32]);
        self.mac.copy_from_slice(&material[32..]);
    }

    fn message_mac(&self, epoch: u64, header: bool, pieces: &[&[u8]]) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.mac.as_ref()).expect("HMAC accepts 32-byte keys");
        mac.update(PROTOCOL);
        mac.update(if header { b":ekheader" } else { b":ciphertext" });
        mac.update(&epoch.to_be_bytes());
        for piece in pieces {
            mac.update(piece);
        }
        mac
    }

    fn append(&self, epoch: u64, header: bool, pieces: &[&[u8]], output: &mut Vec<u8>) {
        output.extend_from_slice(
            &self
                .message_mac(epoch, header, pieces)
                .finalize()
                .into_bytes(),
        );
    }

    fn verify(&self, epoch: u64, header: bool, pieces: &[&[u8]], tag: &[u8]) -> Result<(), Error> {
        self.message_mac(epoch, header, pieces)
            .verify_slice(tag)
            .map_err(|_| Error::Authentication)
    }
}

#[derive(Clone)]
enum State {
    KeysUnsampled,
    KeysSampled {
        keys: Box<kem::KeyPair>,
        header: Encoder,
    },
    HeaderSent {
        keys: Box<kem::KeyPair>,
        ct1: Decoder,
        key: Encoder,
    },
    Ct1Received {
        keys: Box<kem::KeyPair>,
        ct1: Vec<u8>,
        key: Encoder,
    },
    EkSentCt1Received {
        keys: Box<kem::KeyPair>,
        ct1: Vec<u8>,
        ct2: Decoder,
    },
    NoHeaderReceived(Decoder),
    HeaderReceived(Vec<u8>),
    Ct1Sampled {
        header: Vec<u8>,
        secret: Box<kem::Encapsulation>,
        ct1: Vec<u8>,
        ciphertext: Encoder,
        key: Decoder,
    },
    EkReceivedCt1Sampled {
        header: Vec<u8>,
        secret: Box<kem::Encapsulation>,
        ct1: Vec<u8>,
        ciphertext: Encoder,
        key: Vec<u8>,
    },
    Ct1Acknowledged {
        header: Vec<u8>,
        secret: Box<kem::Encapsulation>,
        ct1: Vec<u8>,
        key: Decoder,
    },
    Ct2Sampled(Encoder),
    Closed,
}

#[derive(Clone)]
pub(super) struct Braid {
    epoch: u64,
    auth: Authenticator,
    chunk_size: ChunkSize,
    state: State,
}

impl Braid {
    pub fn new(alice: bool, secret: &[u8; 32], chunk_size: ChunkSize) -> Self {
        Self {
            epoch: 1,
            auth: Authenticator::new(secret),
            chunk_size,
            state: if alice {
                State::KeysUnsampled
            } else {
                State::NoHeaderReceived(
                    Decoder::new(kem::HEADER_BYTES + MAC_BYTES, chunk_size)
                        .expect("fixed piece size"),
                )
            },
        }
    }

    pub fn send(
        &mut self,
        random: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(Message, Option<EpochKey>), Error> {
        let mut output_key = None;
        let state = std::mem::replace(&mut self.state, State::Closed);
        self.state = match state {
            State::KeysUnsampled => {
                let mut seed = Zeroizing::new([0; 64]);
                random(seed.as_mut())?;
                let keys = Box::new(kem::KeyPair::generate(&seed));
                let mut message = keys.header().to_vec();
                self.auth
                    .append(self.epoch, true, &[keys.header()], &mut message);
                State::KeysSampled {
                    keys,
                    header: Encoder::new(message, self.chunk_size)?,
                }
            }
            State::HeaderReceived(header) => {
                let mut coins = Zeroizing::new([0; 32]);
                random(coins.as_mut())?;
                let (secret, ct1, shared) = kem::Encapsulation::begin(&header, &coins)?;
                let key = self.output_key(&shared);
                self.auth.update(self.epoch, &key.secret);
                output_key = Some(key);
                let ciphertext = Encoder::new(ct1.clone(), self.chunk_size)?;
                State::Ct1Sampled {
                    header,
                    secret: Box::new(secret),
                    ct1,
                    ciphertext,
                    key: Decoder::new(kem::KEY_BYTES, self.chunk_size)?,
                }
            }
            State::Closed => return Err(Error::Closed),
            state => state,
        };
        let (kind, chunk) = match &mut self.state {
            State::KeysSampled { header, .. } => (Kind::Header, Some(header.next())),
            State::HeaderSent { key, .. } => (Kind::Key, Some(key.next())),
            State::Ct1Received { key, .. } => (Kind::KeyAndAck, Some(key.next())),
            State::Ct1Sampled { ciphertext, .. }
            | State::EkReceivedCt1Sampled { ciphertext, .. } => {
                (Kind::Ciphertext1, Some(ciphertext.next()))
            }
            State::Ct2Sampled(ciphertext) => (Kind::Ciphertext2, Some(ciphertext.next())),
            State::EkSentCt1Received { .. }
            | State::NoHeaderReceived(_)
            | State::Ct1Acknowledged { .. } => (Kind::None, None),
            _ => return Err(Error::Closed),
        };
        Ok((
            Message {
                epoch: self.epoch,
                kind,
                chunk,
            },
            output_key,
        ))
    }

    // Old messages still identify their own receiving epoch; they never roll
    // back the SCKA. The surrounding SPQR layer owns bounded delayed-message keys.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep the published state transitions in one exhaustive match."
    )]
    pub fn receive(&mut self, message: &Message) -> Result<Option<EpochKey>, Error> {
        if message.epoch == 0 || matches!(self.state, State::Closed) {
            return Err(Error::Closed);
        }
        if message.epoch < self.epoch {
            return Ok(None);
        }
        if message.epoch > self.epoch {
            if self.epoch.checked_add(1) != Some(message.epoch)
                || !matches!(self.state, State::Ct2Sampled(_))
            {
                return Err(Error::Record);
            }
            self.epoch = message.epoch;
            self.state = State::KeysUnsampled;
            return Ok(None);
        }
        let mut output_key = None;
        let state = std::mem::replace(&mut self.state, State::Closed);
        self.state = match state {
            State::KeysSampled { keys, .. } if message.kind == Kind::Ciphertext1 => {
                let mut ct1 = Decoder::new(kem::CT1_BYTES, self.chunk_size)?;
                ct1.push(message.chunk()?)?;
                let key = Encoder::new(keys.vector().to_vec(), self.chunk_size)?;
                // A complete first chunk already satisfies the next state's
                // completion condition; no duplicate message or extra RTT is needed.
                if let Some(complete) = ct1.message() {
                    State::Ct1Received {
                        keys,
                        ct1: complete.to_vec(),
                        key,
                    }
                } else {
                    State::HeaderSent { keys, ct1, key }
                }
            }
            State::HeaderSent { keys, mut ct1, key } if message.kind == Kind::Ciphertext1 => {
                ct1.push(message.chunk()?)?;
                if let Some(complete) = ct1.message() {
                    State::Ct1Received {
                        keys,
                        ct1: complete.to_vec(),
                        key,
                    }
                } else {
                    State::HeaderSent { keys, ct1, key }
                }
            }
            State::Ct1Received { keys, ct1, .. } if message.kind == Kind::Ciphertext2 => {
                let mut ct2 = Decoder::new(kem::CT2_BYTES + MAC_BYTES, self.chunk_size)?;
                ct2.push(message.chunk()?)?;
                self.receive_ct2(keys, ct1, ct2, &mut output_key)?
            }
            State::EkSentCt1Received { keys, ct1, mut ct2 }
                if message.kind == Kind::Ciphertext2 =>
            {
                ct2.push(message.chunk()?)?;
                self.receive_ct2(keys, ct1, ct2, &mut output_key)?
            }
            State::NoHeaderReceived(mut header) if message.kind == Kind::Header => {
                header.push(message.chunk()?)?;
                if let Some(complete) = header.message() {
                    self.auth.verify(
                        self.epoch,
                        true,
                        &[&complete[..kem::HEADER_BYTES]],
                        &complete[kem::HEADER_BYTES..],
                    )?;
                    State::HeaderReceived(complete[..kem::HEADER_BYTES].to_vec())
                } else {
                    State::NoHeaderReceived(header)
                }
            }
            State::Ct1Sampled {
                header,
                secret,
                ct1,
                ciphertext,
                mut key,
            } if matches!(message.kind, Kind::Key | Kind::KeyAndAck) => {
                key.push(message.chunk()?)?;
                if let Some(complete) = key.message() {
                    if message.kind == Kind::KeyAndAck {
                        self.complete_encapsulation(secret, &header, &ct1, complete)?
                    } else {
                        // Validate now, even if the acknowledgement is delayed.
                        kem::validate_public_key(&header, complete)?;
                        State::EkReceivedCt1Sampled {
                            header,
                            secret,
                            ct1,
                            ciphertext,
                            key: complete.to_vec(),
                        }
                    }
                } else if message.kind == Kind::KeyAndAck {
                    State::Ct1Acknowledged {
                        header,
                        secret,
                        ct1,
                        key,
                    }
                } else {
                    State::Ct1Sampled {
                        header,
                        secret,
                        ct1,
                        ciphertext,
                        key,
                    }
                }
            }
            State::EkReceivedCt1Sampled {
                header,
                secret,
                ct1,
                key,
                ..
            } if message.kind == Kind::KeyAndAck => {
                self.complete_encapsulation(secret, &header, &ct1, &key)?
            }
            State::Ct1Acknowledged {
                header,
                secret,
                ct1,
                mut key,
            } if message.kind == Kind::KeyAndAck => {
                key.push(message.chunk()?)?;
                if let Some(complete) = key.message() {
                    self.complete_encapsulation(secret, &header, &ct1, complete)?
                } else {
                    State::Ct1Acknowledged {
                        header,
                        secret,
                        ct1,
                        key,
                    }
                }
            }
            state => state,
        };
        Ok(output_key)
    }

    fn output_key(&self, shared: &[u8; 32]) -> EpochKey {
        let mut secret = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(None, shared)
            .expand_multi_info(
                &[PROTOCOL, b":SCKA Key", &self.epoch.to_be_bytes()],
                secret.as_mut(),
            )
            .expect("fixed HKDF output is within SHA-256 bounds");
        EpochKey {
            epoch: self.epoch,
            secret,
        }
    }

    fn receive_ct2(
        &mut self,
        keys: Box<kem::KeyPair>,
        ct1: Vec<u8>,
        ct2: Decoder,
        output: &mut Option<EpochKey>,
    ) -> Result<State, Error> {
        let Some(complete) = ct2.message() else {
            return Ok(State::EkSentCt1Received { keys, ct1, ct2 });
        };
        let key = self.output_key(&*keys.decapsulate(&ct1, &complete[..kem::CT2_BYTES])?);
        self.auth.update(self.epoch, &key.secret);
        self.auth.verify(
            self.epoch,
            false,
            &[&ct1, &complete[..kem::CT2_BYTES]],
            &complete[kem::CT2_BYTES..],
        )?;
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Limit)?;
        *output = Some(key);
        Ok(State::NoHeaderReceived(Decoder::new(
            kem::HEADER_BYTES + MAC_BYTES,
            self.chunk_size,
        )?))
    }

    fn complete_encapsulation(
        &self,
        secret: Box<kem::Encapsulation>,
        header: &[u8],
        ct1: &[u8],
        key: &[u8],
    ) -> Result<State, Error> {
        let ct2 = secret.finish(header, key)?;
        let mut message = ct2.clone();
        self.auth
            .append(self.epoch, false, &[ct1, &ct2], &mut message);
        Ok(State::Ct2Sampled(Encoder::new(message, self.chunk_size)?))
    }
}

#[cfg(test)]
mod tests;
