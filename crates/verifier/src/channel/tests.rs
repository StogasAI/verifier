use super::{Direction, Error, Kind, record::Records, record_size, session::ClientSession};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Vector {
    root_hex: String,
    session_id_hex: String,
    streams: Vec<Stream>,
    invalid_firsts: Vec<InvalidFirst>,
}

#[derive(Deserialize)]
struct InvalidFirst {
    direction: u8,
    encoded_hex: String,
}

#[derive(Deserialize)]
struct Stream {
    number: String,
    direction: u8,
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    kind: u8,
    plaintext_hex: String,
    encoded_hex: String,
}

fn fixture() -> Vector {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/channel-records-v1.json"
    ))
    .unwrap()
}

#[test]
fn records_match_independent_vectors() {
    let fixture = fixture();
    let root: [u8; 32] = hex::decode(fixture.root_hex).unwrap().try_into().unwrap();
    let id: [u8; 32] = hex::decode(fixture.session_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    for stream in fixture.streams {
        let direction = if stream.direction == 1 {
            Direction::Request
        } else {
            Direction::Response
        };
        let number = stream.number.parse().unwrap();
        let mut encoder = Records::new(&root, &id, number, direction).unwrap();
        let mut decoder = Records::new(&root, &id, number, direction).unwrap();
        for record in stream.records {
            let kind = Kind::try_from(record.kind).unwrap();
            let plaintext = hex::decode(record.plaintext_hex).unwrap();
            let mut expected = hex::decode(record.encoded_hex).unwrap();
            assert_eq!(encoder.seal(kind, &plaintext).unwrap(), expected);
            assert_eq!(record_size(&expected[..4]).unwrap(), expected.len());
            assert_eq!(
                decoder.open(&mut expected).unwrap(),
                (kind, plaintext.as_slice())
            );
        }
        assert_eq!(decoder.complete(), Ok(()));
        assert_eq!(decoder.open(&mut [0; 21]), Err(Error::Closed));
        assert_eq!(decoder.complete(), Err(Error::Truncated));
    }
    for invalid in fixture.invalid_firsts {
        let direction = if invalid.direction == 1 {
            Direction::Request
        } else {
            Direction::Response
        };
        let mut decoder = Records::new(&root, &id, 0, direction).unwrap();
        assert_eq!(
            decoder.open(&mut hex::decode(invalid.encoded_hex).unwrap()),
            Err(Error::Record)
        );
        assert_eq!(decoder.complete(), Err(Error::Truncated));
    }
}

#[test]
fn record_body_count_and_size_boundaries_close_exhausted_state() {
    use super::record::{MAX_RECORD_PLAINTEXT, MAX_RECORDS, MAX_REQUEST_BODY, MAX_RESPONSE_BODY};
    for (direction, limit) in [
        (Direction::Request, MAX_REQUEST_BODY),
        (Direction::Response, MAX_RESPONSE_BODY),
    ] {
        let mut encoder = Records::new(&[1; 32], &[2; 32], 0, direction).unwrap();
        let mut decoder = Records::new(&[1; 32], &[2; 32], 0, direction).unwrap();
        let mut metadata = encoder.seal(Kind::Metadata, b"headers").unwrap();
        decoder.open(&mut metadata).unwrap();
        let mut largest = encoder
            .seal(Kind::Data, &vec![42; MAX_RECORD_PLAINTEXT])
            .unwrap();
        assert_eq!(
            decoder.open(&mut largest).unwrap().1.len(),
            MAX_RECORD_PLAINTEXT
        );
        encoder.body_bytes = limit - 1;
        decoder.body_bytes = limit - 1;
        let mut last = encoder.seal(Kind::Data, &[1]).unwrap();
        decoder.open(&mut last).unwrap();
        // A peer ignoring its body bound can still emit an authentic record.
        encoder.body_bytes = 0;
        let mut excess = encoder.seal(Kind::Data, &[2]).unwrap();
        assert_eq!(decoder.open(&mut excess), Err(Error::Limit));
        assert_eq!(decoder.complete(), Err(Error::Truncated));
        encoder.sequence = MAX_RECORDS;
        assert_eq!(encoder.seal(Kind::Finished, &[]), Err(Error::Limit));
        assert_eq!(encoder.seal(Kind::Finished, &[]), Err(Error::Closed));
    }
    let mut encoder = Records::new(&[1; 32], &[2; 32], 0, Direction::Request).unwrap();
    assert_eq!(
        encoder.seal(Kind::Metadata, &vec![0; MAX_RECORD_PLAINTEXT + 1]),
        Err(Error::Limit)
    );
    for size in [0_u32, 20, 65537, u32::MAX] {
        assert_eq!(record_size(&size.to_be_bytes()), Err(Error::Record));
    }
    assert_eq!(record_size(&[0; 3]), Err(Error::Record));
}

#[test]
fn record_mutation_order_and_truncation_fail_closed() {
    let fixture = fixture();
    let root: [u8; 32] = hex::decode(fixture.root_hex).unwrap().try_into().unwrap();
    let id: [u8; 32] = hex::decode(fixture.session_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let mut first = hex::decode(&fixture.streams[0].records[0].encoded_hex).unwrap();
    for index in 0..first.len() {
        let mut decoder = Records::new(&root, &id, 0, Direction::Request).unwrap();
        let mut mutated = first.clone();
        mutated[index] ^= 1;
        assert!(decoder.open(&mut mutated).is_err());
        assert_eq!(decoder.open(&mut first.clone()), Err(Error::Closed));
    }
    for length in 0..first.len() {
        let mut decoder = Records::new(&root, &id, 0, Direction::Request).unwrap();
        assert!(decoder.open(&mut first[..length].to_vec()).is_err());
    }
    let mut decoder = Records::new(&root, &id, 0, Direction::Request).unwrap();
    let mut second = hex::decode(&fixture.streams[0].records[1].encoded_hex).unwrap();
    assert_eq!(decoder.open(&mut second), Err(Error::Authentication));
    let mut decoder = Records::new(&root, &id, 0, Direction::Request).unwrap();
    decoder.open(&mut first.clone()).unwrap();
    assert_eq!(decoder.open(&mut first.clone()), Err(Error::Authentication));
    let mut decoder = Records::new(&root, &id, 0, Direction::Request).unwrap();
    decoder.open(&mut first).unwrap();
    assert_eq!(decoder.complete(), Err(Error::Truncated));
}

#[test]
fn client_bounds_unacknowledged_distance_and_never_reuses_numbers() {
    let mut session = ClientSession::new(Zeroizing::new([1; 32]), [2; 32], 600);
    let mut requests: Vec<_> = (0..4096).map(|_| session.request().unwrap()).collect();
    assert!(matches!(session.request(), Err(Error::Pending)));
    // Later acknowledgements cannot let the sender retire a delayed first start.
    let mut response = Records::new(&[1; 32], &[2; 32], 4095, Direction::Response).unwrap();
    let mut keepalive = response.seal(Kind::Keepalive, &[]).unwrap();
    requests.last_mut().unwrap().open(&mut keepalive).unwrap();
    assert!(matches!(session.request(), Err(Error::Pending)));
    let mut response = Records::new(&[1; 32], &[2; 32], 0, Direction::Response).unwrap();
    let mut keepalive = response.seal(Kind::Keepalive, &[]).unwrap();
    requests.first_mut().unwrap().open(&mut keepalive).unwrap();
    let next = session.request().unwrap();
    assert_eq!(next.number(), 4096);
    assert!(matches!(session.request(), Err(Error::Pending)));
    drop(requests);
    drop(next);
    assert_eq!(session.request().unwrap().number(), 4097);
    session.close();
    assert!(matches!(session.request(), Err(Error::Closed)));
}

#[test]
fn invalid_response_cannot_acknowledge_and_active_keys_survive_close() {
    let mut session = ClientSession::new(Zeroizing::new([1; 32]), [2; 32], 600);
    let mut first = session.request().unwrap();
    assert!(first.open(&mut [0; 21]).is_err());
    for _ in 1..4096 {
        drop(session.request().unwrap());
    }
    assert!(matches!(session.request(), Err(Error::Pending)));
    drop(first);
    let mut admitted = session.request().unwrap();
    session.close();
    assert!(admitted.seal(Kind::Metadata, b"credentials").is_ok());
    let mut response =
        Records::new(&[1; 32], &[2; 32], admitted.number(), Direction::Response).unwrap();
    let mut metadata = response.seal(Kind::Metadata, b"status=200").unwrap();
    assert_eq!(admitted.open(&mut metadata).unwrap().1, b"status=200");
    let mut end = response.seal(Kind::Finished, &[]).unwrap();
    admitted.open(&mut end).unwrap();
    assert_eq!(admitted.complete(), Ok(()));
}

#[test]
fn split_request_preserves_independent_owners_during_early_response() {
    let mut session = ClientSession::new(Zeroizing::new([1; 32]), [2; 32], 600);
    let (mut upload, mut response) = session.request().unwrap().split();
    for _ in 1..4096 {
        drop(session.request().unwrap());
    }
    assert!(matches!(session.request(), Err(Error::Pending)));
    let mut server = Records::new(&[1; 32], &[2; 32], 0, Direction::Response).unwrap();
    let rejection = server.seal(Kind::Metadata, b"status=429").unwrap();
    response
        .push(&rejection, |kind, bytes| {
            assert_eq!(kind, Kind::Metadata);
            assert_eq!(bytes, b"status=429");
            Ok(())
        })
        .unwrap();
    assert_eq!(session.request().unwrap().number(), 4096);
    session.close();
    // Upload and response retain only their own directional keys after root disposal.
    let mut server = Records::new(&[1; 32], &[2; 32], 0, Direction::Request).unwrap();
    let mut encoded = upload.seal(Kind::Metadata, b"credentials").unwrap();
    assert_eq!(server.open(&mut encoded).unwrap().1, b"credentials");
    drop(response);
    let mut encoded = upload.seal(Kind::Data, b"body").unwrap();
    assert_eq!(server.open(&mut encoded).unwrap().1, b"body");
    let mut encoded = upload.seal(Kind::Finished, &[]).unwrap();
    assert_eq!(server.open(&mut encoded).unwrap().0, Kind::Finished);
    assert_eq!(server.complete(), Ok(()));
    assert_eq!(upload.seal(Kind::Data, b"late"), Err(Error::Closed));
}

#[test]
fn response_stream_accepts_all_fragment_boundaries_and_rejects_every_truncation() {
    let vector = fixture();
    let root: [u8; 32] = hex::decode(&vector.root_hex).unwrap().try_into().unwrap();
    let id: [u8; 32] = hex::decode(&vector.session_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let stream = vector
        .streams
        .iter()
        .find(|stream| stream.direction == 2 && stream.number == "0")
        .unwrap();
    let encoded: Vec<u8> = stream
        .records
        .iter()
        .flat_map(|record| hex::decode(&record.encoded_hex).unwrap())
        .collect();
    let expected: Vec<_> = stream
        .records
        .iter()
        .map(|record| {
            (
                Kind::try_from(record.kind).unwrap(),
                hex::decode(&record.plaintext_hex).unwrap(),
            )
        })
        .collect();
    let decoder = || {
        super::ResponseDecoder::new(
            ClientSession::new(Zeroizing::new(root), id, 600)
                .request()
                .unwrap(),
        )
    };
    for split in 0..=encoded.len() {
        let mut reader = decoder();
        let mut events = Vec::new();
        let mut receive = |kind, data: &[u8]| {
            events.push((kind, data.to_vec()));
            Ok(())
        };
        reader.push(&encoded[..split], &mut receive).unwrap();
        reader.push(&[], &mut receive).unwrap();
        reader.push(&encoded[split..], &mut receive).unwrap();
        reader.finish().unwrap();
        assert_eq!(events, expected, "split {split}");
    }
    let mut reader = decoder();
    for byte in &encoded {
        reader.push(&[*byte], |_, _| Ok(())).unwrap();
    }
    reader.finish().unwrap();
    for length in 0..encoded.len() {
        let mut reader = decoder();
        reader.push(&encoded[..length], |_, _| Ok(())).unwrap();
        assert_eq!(reader.finish(), Err(Error::Truncated), "length {length}");
    }
    for split_extra in [false, true] {
        let mut reader = decoder();
        let result = if split_extra {
            reader.push(&encoded, |_, _| Ok(())).unwrap();
            reader.push(&[0], |_, _| Ok(()))
        } else {
            reader.push(&[encoded.as_slice(), &[0]].concat(), |_, _| Ok(()))
        };
        assert_eq!(result, Err(Error::Record));
        assert_eq!(reader.finish(), Err(Error::Closed));
    }
}

#[test]
fn response_stream_bad_lengths_tags_and_consumer_errors_permanently_close_it() {
    let vector = fixture();
    let root: [u8; 32] = hex::decode(&vector.root_hex).unwrap().try_into().unwrap();
    let id: [u8; 32] = hex::decode(&vector.session_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let first = vector
        .streams
        .iter()
        .find(|stream| stream.direction == 2 && stream.number == "0")
        .unwrap();
    let first = hex::decode(&first.records[0].encoded_hex).unwrap();
    let decoder = || {
        super::ResponseDecoder::new(
            ClientSession::new(Zeroizing::new(root), id, 600)
                .request()
                .unwrap(),
        )
    };
    for length in [0_u32, 20, 65537, u32::MAX] {
        let mut reader = decoder();
        assert_eq!(
            reader.push(&length.to_be_bytes(), |_, _| panic!(
                "invalid length emitted data"
            )),
            Err(Error::Record)
        );
        assert_eq!(
            reader.push(&first, |_, _| panic!("failed decoder revived")),
            Err(Error::Closed)
        );
    }
    let mut corrupted = first.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut reader = decoder();
    assert_eq!(
        reader.push(&corrupted, |_, _| panic!(
            "unauthenticated plaintext escaped"
        )),
        Err(Error::Authentication)
    );
    assert_eq!(reader.finish(), Err(Error::Closed));
    let mut reader = decoder();
    assert_eq!(
        reader.push(&first, |_, _| Err(Error::Record)),
        Err(Error::Record)
    );
    assert_eq!(
        reader.push(&first, |_, _| panic!("consumer failure was ignored")),
        Err(Error::Closed)
    );
}

#[test]
fn response_stream_reuses_one_record_buffer_across_large_and_small_records() {
    let root = [1; 32];
    let id = [2; 32];
    let mut session = ClientSession::new(Zeroizing::new(root), id, 600);
    let mut reader = super::ResponseDecoder::new(session.request().unwrap());
    let mut encoder = Records::new(&root, &id, 0, Direction::Response).unwrap();
    for (kind, data) in [
        (Kind::Metadata, vec![b'm'; super::MAX_RECORD_PLAINTEXT]),
        (Kind::Data, vec![b'd'; super::MAX_RECORD_PLAINTEXT]),
        (Kind::Keepalive, vec![]),
        (Kind::Data, b"small".to_vec()),
        (Kind::Finished, vec![]),
    ] {
        let record = encoder.seal(kind, &data).unwrap();
        let mut events = 0;
        for fragment in record.chunks(517) {
            reader
                .push(fragment, |seen_kind, plaintext| {
                    events += 1;
                    assert_eq!(seen_kind, kind);
                    assert_eq!(plaintext, data);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(events, 1);
    }
    reader.finish().unwrap();
}
