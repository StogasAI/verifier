use super::*;
use sha2_v11::Digest as _;

fn random(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
    let mut counter = 0u64;
    move |bytes| {
        for piece in bytes.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update([seed]);
            hash.update(counter.to_be_bytes());
            piece.copy_from_slice(&hash.finalize()[..piece.len()]);
            counter += 1;
        }
        Ok(())
    }
}

fn peers(size: ChunkSize) -> [Peer; 2] {
    let initial = InitialKey::from_bytes(Zeroizing::new([3; 32]));
    [
        Peer::initiator(&[5; 32], size, initial.public_key()),
        Peer::responder(&[5; 32], size, initial),
    ]
}

fn deliver(receiver: &mut Peer, packet: &SendKey, now: u64) {
    receiver
        .receive(&packet.header, now, |secret| {
            assert_eq!(secret, packet.secret.as_ref());
            Ok(())
        })
        .unwrap();
    assert!(
        receiver
            .receive::<()>(&packet.header, now, |secret| {
                assert_ne!(
                    secret,
                    packet.secret.as_ref(),
                    "replay recovered a consumed hybrid key"
                );
                Err(Error::Authentication)
            })
            .is_err()
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn initialization_and_combination_match_independent_hkdf_vectors() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/channel-triple-v3.json"
    ))
    .unwrap();
    let decode = |value: &serde_json::Value, name: &str| -> [u8; 32] {
        hex::decode(value[name].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let (classical, quantum) = split_root(&decode(&vector, "root_hex"));
    assert_eq!(*classical, decode(&vector, "classical_root_hex"));
    assert_eq!(*quantum, decode(&vector, "quantum_root_hex"));
    for case in vector["cases"].as_array().unwrap() {
        assert_eq!(
            *combine(&decode(case, "classical_hex"), &decode(case, "quantum_hex")),
            decode(case, "combined_hex")
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn hybrid_sessions_agree_across_fresh_classical_and_post_quantum_epochs() {
    let mut peers = peers(ChunkSize::FULL);
    let mut rng = random(1);
    let mut previous = [0; 32];
    let mut largest_epoch = 0;
    for round in 0..25 {
        for side in 0..2 {
            let packet = peers[side].send_with(&mut rng).unwrap();
            assert_ne!(*packet.secret, previous);
            previous = *packet.secret;
            let epoch = u64::from_be_bytes(packet.header[64..72].try_into().unwrap());
            largest_epoch = largest_epoch.max(epoch);
            deliver(&mut peers[1 - side], &packet, round);
        }
    }
    assert!(largest_epoch >= 10);
}

#[test]
fn concurrent_reordering_loss_and_old_messages_cross_both_component_epochs() {
    for width in [32, 34, 256, 1152] {
        let mut peers = peers(ChunkSize::new(width).unwrap());
        let mut rng = random(2);
        let initial = peers[0].send_with(&mut rng).unwrap();
        deliver(&mut peers[1], &initial, 0);
        let mut queues: [Vec<SendKey>; 2] = [Vec::new(), Vec::new()];
        let mut maximum_epoch = 0;
        for round in 0..400 {
            for side in [1, 0] {
                let count = if round % 3 == side { 17 } else { 3 };
                for _ in 0..count {
                    let packet = peers[side].send_with(&mut rng).unwrap();
                    maximum_epoch = maximum_epoch.max(u64::from_be_bytes(
                        packet.header[64..72].try_into().unwrap(),
                    ));
                    queues[side].push(packet);
                }
                let newest = queues[side].pop().unwrap();
                deliver(&mut peers[1 - side], &newest, round as u64);
                while queues[side].len() > 31 {
                    let packet = queues[side].remove(if round % 2 == 0 {
                        0
                    } else {
                        queues[side].len() / 2
                    });
                    deliver(&mut peers[1 - side], &packet, round as u64);
                }
            }
        }
        for side in 0..2 {
            for packet in queues[side].drain(..).rev() {
                deliver(&mut peers[1 - side], &packet, 400);
            }
        }
        assert!(maximum_epoch >= 4, "width {width}");
    }
}

#[test]
fn invalid_composite_headers_and_ciphertexts_never_commit_either_component() {
    let mut peers = peers(ChunkSize::FULL);
    let mut rng = random(3);
    let old = peers[0].send_with(&mut rng).unwrap();
    let newer = peers[0].send_with(&mut rng).unwrap();
    deliver(&mut peers[1], &newer, 0);
    let reply = peers[1].send_with(&mut rng).unwrap();
    deliver(&mut peers[0], &reply, 0);
    let next = peers[0].send_with(&mut rng).unwrap();
    for packet in [&old, &next] {
        for index in 0..packet.header.len() {
            let mut forged = packet.header.clone();
            forged[index] ^= 1;
            assert!(
                peers[1]
                    .receive::<()>(&forged, 0, |_| Err(Error::Authentication))
                    .is_err()
            );
        }
        for len in 0..packet.header.len() {
            assert!(
                peers[1]
                    .receive::<()>(&packet.header[..len], 0, |_| Err(Error::Authentication))
                    .is_err()
            );
        }
        assert!(
            peers[1]
                .receive::<()>(&packet.header, 0, |_| Err(Error::Authentication))
                .is_err()
        );
        deliver(&mut peers[1], packet, 0);
    }
    assert!(
        peers[1]
            .receive::<()>(&vec![0; MAX_HEADER_BYTES + 1], 0, |_| panic!(
                "oversized header"
            ))
            .is_err()
    );
}

#[test]
fn random_source_failures_do_not_partially_commit_a_send() {
    let mut peers = peers(ChunkSize::FULL);
    let mut rng = random(4);
    let mut rejected = [0, 0];
    for round in 0..25 {
        for side in 0..2 {
            for (fail_at, rejected_count) in rejected.iter_mut().enumerate() {
                let mut calls = 0;
                let result = peers[side].send_with(&mut |bytes| {
                    let current = calls;
                    calls += 1;
                    if current == fail_at {
                        return Err(Error::Crypto);
                    }
                    rng(bytes)
                });
                match result {
                    Ok(packet) => deliver(&mut peers[1 - side], &packet, round),
                    Err(Error::Crypto) => *rejected_count += 1,
                    Err(error) => panic!("unexpected send error: {error}"),
                }
            }
            let packet = peers[side].send_with(&mut rng).unwrap();
            deliver(&mut peers[1 - side], &packet, round);
        }
    }
    assert!(rejected.iter().all(|count| *count > 0));
}

#[test]
fn discarded_delayed_keys_cannot_decrypt_but_active_chains_continue() {
    let mut peers = peers(ChunkSize::FULL);
    let mut rng = random(6);
    let initial = peers[0].send_with(&mut rng).unwrap();
    deliver(&mut peers[1], &initial, 0);
    let old = peers[1].send_with(&mut rng).unwrap();
    let latest = peers[1].send_with(&mut rng).unwrap();
    deliver(&mut peers[0], &latest, 0);
    peers[0].expire(u64::MAX);
    // An outstanding request owns this key despite elapsed time.
    assert!(
        peers[0]
            .receive::<()>(&old.header, u64::MAX, |secret| {
                assert_eq!(secret, old.secret.as_ref());
                Err(Error::Authentication)
            })
            .is_err()
    );
    peers[0].discard_delayed();
    assert!(
        peers[0]
            .receive::<()>(&old.header, u64::MAX, |_| panic!(
                "discarded response key survived"
            ))
            .is_err()
    );
    let next = peers[1].send_with(&mut rng).unwrap();
    deliver(&mut peers[0], &next, u64::MAX);
    let reply = peers[0].send_with(&mut rng).unwrap();
    deliver(&mut peers[1], &reply, 1);
}
