use super::*;

fn records(direction: Direction) -> Records {
    let mut header = vec![0; crate::channel::ratchet::MIN_HEADER_BYTES];
    header[48 + 15] = 1;
    header[48 + 23] = 1;
    Records::new(&[1; 32], &[2; 32], 42, direction, header).unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One matrix applies each invalid record to both sealing and opening."
)]
fn authentic_invalid_grammar_and_usage_bounds_permanently_close_both_directions() {
    for (direction, started, body, sequence, kind, data, expected) in [
        (
            Direction::Request,
            false,
            0,
            0,
            Kind::Metadata,
            vec![],
            Error::Record,
        ),
        (
            Direction::Request,
            false,
            0,
            0,
            Kind::Data,
            vec![1],
            Error::Record,
        ),
        (
            Direction::Request,
            false,
            0,
            0,
            Kind::Finished,
            vec![],
            Error::Record,
        ),
        (
            Direction::Request,
            false,
            0,
            0,
            Kind::Keepalive,
            vec![],
            Error::Record,
        ),
        (
            Direction::Response,
            true,
            0,
            1,
            Kind::Metadata,
            vec![1],
            Error::Record,
        ),
        (
            Direction::Response,
            true,
            0,
            1,
            Kind::Data,
            vec![],
            Error::Record,
        ),
        (
            Direction::Response,
            true,
            0,
            1,
            Kind::Finished,
            vec![1],
            Error::Record,
        ),
        (
            Direction::Response,
            true,
            0,
            1,
            Kind::Keepalive,
            vec![1],
            Error::Record,
        ),
        (
            Direction::Response,
            true,
            0,
            1,
            Kind::Data,
            vec![1; MAX_RECORD_PLAINTEXT + 1],
            Error::Limit,
        ),
        (
            Direction::Request,
            true,
            MAX_REQUEST_BODY,
            1,
            Kind::Data,
            vec![1],
            Error::Limit,
        ),
        (
            Direction::Response,
            true,
            MAX_RESPONSE_BODY,
            1,
            Kind::Data,
            vec![1],
            Error::Limit,
        ),
        (
            Direction::Response,
            true,
            u64::MAX,
            1,
            Kind::Data,
            vec![1],
            Error::Limit,
        ),
        (
            Direction::Response,
            true,
            0,
            MAX_RECORDS,
            Kind::Keepalive,
            vec![],
            Error::Limit,
        ),
    ] {
        let mut encoder = records(direction);
        let mut decoder = records(direction);
        for state in [&mut encoder, &mut decoder] {
            state.started = started;
            state.sequence = sequence;
            state.body_bytes = body;
        }
        let mut prefix = vec![0; 4];
        if sequence == 0 {
            let header = encoder.header.as_ref().unwrap();
            prefix.extend_from_slice(&u16::try_from(header.len()).unwrap().to_be_bytes());
            prefix.extend_from_slice(header);
        }
        let size = prefix.len() + 1 + data.len() + 16;
        prefix[..4].copy_from_slice(&u32::try_from(size).unwrap().to_be_bytes());
        let mut plaintext = [vec![kind as u8], data.clone()].concat();
        let tag = encoder
            .cipher
            .as_ref()
            .unwrap()
            .encrypt_now(encoder.record_nonce(), &prefix, &mut plaintext)
            .unwrap();
        let mut wire = [prefix, plaintext, tag.to_vec()].concat();
        assert_eq!(encoder.seal(kind, &data).as_ref(), Err(&expected));
        let expected = if wire.len() > MAX_RECORD_BYTES {
            Error::Record
        } else {
            expected
        };
        assert_eq!(decoder.open(&mut wire), Err(expected));
        assert!(encoder.cipher.is_none());
        assert!(decoder.cipher.is_none());
        assert_eq!(encoder.seal(Kind::Keepalive, &[]), Err(Error::Closed));
        assert_eq!(decoder.complete(), Err(Error::Truncated));
    }
}

#[test]
fn response_keepalives_preserve_body_budget_and_completion_and_release_keys() {
    let mut encoder = records(Direction::Response);
    let mut decoder = records(Direction::Response);
    for kind in [
        Kind::Keepalive,
        Kind::Keepalive,
        Kind::Metadata,
        Kind::Keepalive,
        Kind::Finished,
    ] {
        let content = if kind == Kind::Metadata {
            b"metadata".as_slice()
        } else {
            &[]
        };
        assert_eq!(
            decoder
                .open(&mut encoder.seal(kind, content).unwrap())
                .unwrap(),
            (kind, content)
        );
    }
    assert_eq!(decoder.body_bytes, 0);
    assert_eq!(decoder.sequence, 5);
    assert_eq!(decoder.complete(), Ok(()));
    assert!(encoder.cipher.is_none());
    assert!(decoder.cipher.is_none());
}

#[test]
fn every_key_context_component_is_required_and_first_header_has_one_encoding() {
    let mut encoder = records(Direction::Request);
    let header = encoder.header.as_ref().unwrap().clone();
    let wire = encoder.seal(Kind::Metadata, b"credentials").unwrap();
    for (key, id, number, direction) in [
        ([3; 32], [2; 32], 42, Direction::Request),
        ([1; 32], [3; 32], 42, Direction::Request),
        ([1; 32], [2; 32], 43, Direction::Request),
        ([1; 32], [2; 32], 42, Direction::Response),
    ] {
        let mut decoder = Records::new(&key, &id, number, direction, header.clone()).unwrap();
        assert_eq!(decoder.open(&mut wire.clone()), Err(Error::Authentication));
    }
    for length in [
        0,
        24,
        26,
        u16::try_from(super::super::ratchet::MAX_HEADER_BYTES).unwrap() + 1,
        u16::MAX,
    ] {
        let mut changed = wire.clone();
        changed[4..6].copy_from_slice(&length.to_be_bytes());
        assert!(records(Direction::Request).open(&mut changed).is_err());
    }
}
