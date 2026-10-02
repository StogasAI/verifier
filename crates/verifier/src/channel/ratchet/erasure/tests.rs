use super::*;

// Independent polynomial long division, rather than the encoder's shift recurrence.
fn reference_multiply(a: u16, b: u16) -> u16 {
    let mut polynomial = 0_u32;
    for index in 0..16 {
        if b & (1 << index) != 0 {
            polynomial ^= u32::from(a) << index;
        }
    }
    for index in (16..32).rev() {
        if polynomial & (1 << index) != 0 {
            polynomial ^= 0x1_100b << (index - 16);
        }
    }
    u16::try_from(polynomial).unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn field_matches_polynomial_reference_and_every_nonzero_element_has_an_inverse() {
    for value in 0..=u16::MAX {
        assert_eq!(multiply(value, 0), 0);
        assert_eq!(multiply(value, 1), value);
        for other in [0, 1, 2, 0x8000, 0xffff, value.rotate_left(7)] {
            assert_eq!(multiply(value, other), reference_multiply(value, other));
            assert_eq!(multiply(value, other), multiply(other, value));
        }
        if value != 0 {
            assert_eq!(multiply(value, inverse(value)), 1);
        }
    }
}

#[test]
fn any_distinct_chunks_recover_full_compact_and_uneven_pieces() {
    for size in [64_usize, 96, 128, 160, 960, 1152] {
        for width in [32, 34, 64, 256, 1152] {
            let chunk_size = ChunkSize::new(width).unwrap();
            let message: Vec<_> = (0..size)
                .map(|index| (index * 13).to_le_bytes()[0])
                .collect();
            let count = size.div_ceil(usize::from(width).min(size));
            let mut encoder = Encoder::new(message.clone(), chunk_size).unwrap();
            let chunks: Vec<_> = (0..count + 2).map(|_| encoder.next()).collect();
            // Exhaust every pair of lost messages, then deliver survivors in reverse.
            for first_lost in 0..chunks.len() {
                for second_lost in first_lost + 1..chunks.len() {
                    let mut decoder = Decoder::new(size, chunk_size).unwrap();
                    for (index, chunk) in chunks.iter().enumerate().rev() {
                        if index == first_lost || index == second_lost {
                            continue;
                        }
                        decoder.push(chunk).unwrap();
                        decoder.push(chunk).unwrap(); // Replays do not count as new symbols.
                    }
                    assert_eq!(decoder.message(), Some(message.as_slice()));
                }
            }
            // Arbitrary points near the end of GF(2^16), including encoder wrap.
            encoder.next = u16::MAX - 1;
            let mut decoder = Decoder::new(size, chunk_size).unwrap();
            for _ in 0..count {
                decoder.push(&encoder.next()).unwrap();
            }
            assert_eq!(decoder.message(), Some(message.as_slice()));
        }
    }
}

#[test]
fn erasure_input_is_bounded_and_conflicting_duplicates_are_rejected() {
    for size in [0, 1, MAX_PIECE + 1, MAX_PIECE + 2, usize::MAX] {
        assert!(Decoder::new(size, ChunkSize::FULL).is_err());
    }
    for value in [0, 1, 30, 31, 33, 1153, 1154, u16::MAX] {
        assert!(ChunkSize::new(value).is_err());
    }
    let chunk_size = ChunkSize::new(32).unwrap();
    let mut encoder = Encoder::new(vec![0xab; 96], chunk_size).unwrap();
    let mut decoder = Decoder::new(96, chunk_size).unwrap();
    let mut chunk = encoder.next();
    decoder.push(&chunk).unwrap();
    for _ in 0..100 {
        decoder.push(&chunk).unwrap();
    }
    assert_eq!(decoder.chunks.len(), 1);
    assert!(decoder.message().is_none());
    chunk.bytes[0] ^= 1;
    assert_eq!(decoder.push(&chunk), Err(Error::Authentication));
    chunk.bytes.pop();
    assert_eq!(decoder.push(&chunk), Err(Error::Record));
}
