//! Systematic Reed–Solomon chunks over GF(2^16), as recommended by ML-KEM Braid §3.6.
//! Only public KEM material is encoded. No secret-dependent arithmetic occurs here.

use super::{ChunkSize, Error, MAX_PIECE};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Chunk {
    pub point: u16,
    pub bytes: Vec<u8>,
}

// x^16 + x^12 + x^3 + x + 1, the degree-16 primitive polynomial in RFC 5510 §6.
const fn multiply(mut a: u16, mut b: u16) -> u16 {
    let mut result = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        b >>= 1;
        let high = a & 0x8000;
        a <<= 1;
        if high != 0 {
            a ^= 0x100b;
        }
    }
    result
}

const fn inverse(value: u16) -> u16 {
    // a^(65534); callers only invert nonzero differences between distinct points.
    let mut result = 1;
    let mut power = value;
    let mut exponent = 65_534_u16;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
        exponent >>= 1;
    }
    result
}

fn denominators(points: &[u16]) -> Vec<u16> {
    points
        .iter()
        .map(|&point| {
            inverse(
                points
                    .iter()
                    .filter(|&&other| other != point)
                    .fold(1, |product, &other| multiply(product, point ^ other)),
            )
        })
        .collect()
}

fn evaluate<'a>(
    point: u16,
    points: &[u16],
    denominators: &[u16],
    chunks: impl Iterator<Item = &'a [u8]>,
    output: &mut [u8],
) {
    let numerator = points
        .iter()
        .fold(1, |product, &other| multiply(product, point ^ other));
    for ((&source, &denominator), bytes) in points.iter().zip(denominators).zip(chunks) {
        let weight = multiply(multiply(numerator, inverse(point ^ source)), denominator);
        for (target, bytes) in output.chunks_exact_mut(2).zip(bytes.chunks_exact(2)) {
            let value = u16::from_be_bytes([target[0], target[1]])
                ^ multiply(weight, u16::from_be_bytes([bytes[0], bytes[1]]));
            target.copy_from_slice(&value.to_be_bytes());
        }
    }
}

#[derive(Clone)]
pub(super) struct Encoder {
    message: Vec<u8>,
    width: usize,
    next: u16,
    points: Vec<u16>,
    denominators: Vec<u16>,
}

impl Encoder {
    pub fn new(message: Vec<u8>, chunk_size: ChunkSize) -> Result<Self, Error> {
        let width = width(message.len(), chunk_size)?;
        let mut message = message;
        message.resize(message.len().div_ceil(width) * width, 0);
        Ok(Self {
            message,
            width,
            next: 0,
            points: Vec::new(),
            denominators: Vec::new(),
        })
    }

    pub fn next(&mut self) -> Chunk {
        let point = self.next;
        // The finite encoding domain repeats; epochs and message counters never do.
        self.next = self.next.wrapping_add(1);
        let count = self.message.len() / self.width;
        let bytes = if usize::from(point) < count {
            self.message[usize::from(point) * self.width..(usize::from(point) + 1) * self.width]
                .to_vec()
        } else {
            if self.points.is_empty() {
                self.points = (0..u16::try_from(count).expect("bounded KEM piece")).collect();
                self.denominators = denominators(&self.points);
            }
            let mut output = vec![0; self.width];
            evaluate(
                point,
                &self.points,
                &self.denominators,
                self.message.chunks_exact(self.width),
                &mut output,
            );
            output
        };
        Chunk { point, bytes }
    }
}

#[derive(Clone)]
pub(super) struct Decoder {
    size: usize,
    width: usize,
    chunks: BTreeMap<u16, Vec<u8>>,
    message: Option<Vec<u8>>,
}

fn width(size: usize, chunk_size: ChunkSize) -> Result<usize, Error> {
    if size == 0 || size > MAX_PIECE || !size.is_multiple_of(2) {
        return Err(Error::Record);
    }
    Ok(size.min(usize::from(chunk_size.get())))
}

impl Decoder {
    pub fn new(size: usize, chunk_size: ChunkSize) -> Result<Self, Error> {
        Ok(Self {
            size,
            width: width(size, chunk_size)?,
            chunks: BTreeMap::new(),
            message: None,
        })
    }

    pub fn push(&mut self, chunk: &Chunk) -> Result<(), Error> {
        if chunk.bytes.len() != self.width {
            return Err(Error::Record);
        }
        if self.message.is_some() {
            return Ok(());
        }
        if let Some(previous) = self.chunks.get(&chunk.point) {
            return if previous == &chunk.bytes {
                Ok(())
            } else {
                Err(Error::Authentication)
            };
        }
        self.chunks.insert(chunk.point, chunk.bytes.clone());
        let count = self.size.div_ceil(self.width);
        if self.chunks.len() != count {
            return Ok(());
        }
        let points: Vec<_> = self.chunks.keys().copied().collect();
        let mut weights = None;
        let mut message = vec![0; count * self.width];
        for (index, output) in message.chunks_exact_mut(self.width).enumerate() {
            let index = u16::try_from(index).map_err(|_| Error::Limit)?;
            if let Some(bytes) = self.chunks.get(&index) {
                output.copy_from_slice(bytes);
            } else {
                evaluate(
                    index,
                    &points,
                    weights.get_or_insert_with(|| denominators(&points)),
                    self.chunks.values().map(Vec::as_slice),
                    output,
                );
            }
        }
        if message[self.size..].iter().any(|&byte| byte != 0) {
            return Err(Error::Record);
        }
        message.truncate(self.size);
        self.chunks.clear();
        self.message = Some(message);
        Ok(())
    }

    pub fn message(&self) -> Option<&[u8]> {
        self.message.as_deref()
    }
}

#[cfg(test)]
mod tests;
