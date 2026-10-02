use super::*;
use sha2_v11::Digest as _;

struct Packet {
    header: [u8; HEADER_BYTES],
    secret: Secret,
}

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

fn peers() -> [DoubleRatchet; 2] {
    let secret = StaticSecret::from([3; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    [
        DoubleRatchet::initiator(Zeroizing::new([42; 32]), public, Retention::Timed),
        DoubleRatchet::responder(Zeroizing::new([42; 32]), secret, Retention::Timed),
    ]
}

fn send(peer: &mut DoubleRatchet, rng: &mut impl FnMut(&mut [u8]) -> Result<(), Error>) -> Packet {
    let candidate = peer.prepare_send(rng).unwrap();
    let packet = Packet {
        header: candidate.header,
        secret: candidate.secret.clone(),
    };
    peer.commit_send(candidate);
    packet
}

fn deliver(peer: &mut DoubleRatchet, packet: &Packet, now: u64) {
    peer.receive(&packet.header, now, |secret| {
        assert_eq!(secret, packet.secret.as_ref());
        Ok(())
    })
    .unwrap();
    assert!(
        peer.receive::<()>(&packet.header, now, |secret| {
            assert_ne!(
                secret,
                packet.secret.as_ref(),
                "replay recovered a consumed key"
            );
            Err(Error::Authentication)
        })
        .is_err()
    );
}

fn capture(peer: &DoubleRatchet) -> DoubleRatchet {
    DoubleRatchet {
        active: peer.active.clone(),
        skipped: peer
            .skipped
            .iter()
            .map(|(id, value)| {
                (
                    *id,
                    Skipped {
                        secret: value.secret.clone(),
                        expires: value.expires,
                        order: value.order,
                    },
                )
            })
            .collect(),
        order: peer.order.clone(),
        next_order: peer.next_order,
        last_now: peer.last_now,
        retention: peer.retention,
    }
}

#[test]
fn captured_state_loses_access_after_fresh_dh_from_both_peers() {
    let mut peers = peers();
    let mut honest = random(80);
    let first = send(&mut peers[0], &mut honest);
    deliver(&mut peers[1], &first, 0);
    let reply = send(&mut peers[1], &mut honest);
    deliver(&mut peers[0], &reply, 0);
    let mut captured = capture(&peers[1]);

    // The stolen private key can still decrypt the other side's next DH turn.
    let exposed = send(&mut peers[0], &mut honest);
    deliver(&mut peers[1], &exposed, 1);
    deliver(&mut captured, &exposed, 1);

    let fresh = send(&mut peers[1], &mut honest);
    deliver(&mut peers[0], &fresh, 2);
    let recovered = send(&mut peers[0], &mut honest);
    deliver(&mut peers[1], &recovered, 3);

    // Advance the stolen state with an attacker's guessed private key. The
    // public transcript alone must not recover the honest peer's new key.
    let _ = send(&mut captured, &mut random(81));
    let mut attempted = false;
    assert_eq!(
        captured.receive(&recovered.header, 3, |secret| {
            attempted = true;
            assert_ne!(secret, recovered.secret.as_ref());
            Err::<(), _>(Error::Authentication)
        }),
        Err(Error::Authentication)
    );
    assert!(attempted);

    // Completed message keys are absent even in a complete state capture;
    // replay rejection alone would not establish this retention property.
    for peer in [&peers[0], &peers[1]] {
        let state = capture(peer);
        for old in [&first, &reply, &exposed, &fresh, &recovered] {
            assert_ne!(state.active.root, old.secret);
            for chain in [&state.active.send, &state.active.receive]
                .into_iter()
                .flatten()
            {
                assert_ne!(chain.secret, old.secret);
            }
            assert!(state.skipped.values().all(|key| key.secret != old.secret));
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn double_ratchet_matches_independent_x25519_hkdf_hmac_vectors() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/channel-double-v3.json"
    ))
    .unwrap();
    let mut peers = peers();
    for turn in vector["turns"].as_array().unwrap() {
        let side = usize::try_from(turn["side"].as_u64().unwrap()).unwrap();
        let private = hex::decode(turn["private_hex"].as_str().unwrap()).unwrap();
        let mut expected = turn["messages"].as_array().unwrap().iter().peekable();
        for number in 0..4096 {
            let packet = send(&mut peers[side], &mut |bytes| {
                bytes.copy_from_slice(&private);
                Ok(())
            });
            let header = Header::decode(&packet.header).unwrap();
            assert_eq!(header.number, number);
            assert_eq!(header.previous, turn["previous"].as_u64().unwrap());
            assert_eq!(
                hex::encode(header.public),
                turn["public_hex"].as_str().unwrap()
            );
            if expected
                .peek()
                .is_some_and(|entry| entry["number"].as_u64() == Some(number))
            {
                let entry = expected.next().unwrap();
                assert_eq!(
                    hex::encode(*packet.secret),
                    entry["secret_hex"].as_str().unwrap()
                );
                assert_eq!(
                    hex::encode(*peers[side].active.send.as_ref().unwrap().secret),
                    entry["next_chain_hex"].as_str().unwrap()
                );
                deliver(&mut peers[1 - side], &packet, number);
                for peer in &peers {
                    assert_eq!(
                        hex::encode(*peer.active.root),
                        turn["root_hex"].as_str().unwrap()
                    );
                }
            }
        }
        assert!(expected.next().is_none());
        assert!(peers[1 - side].active.send.is_none());
    }
}

#[test]
fn dropped_reordered_and_delayed_messages_survive_many_dh_turns() {
    let mut peers = peers();
    let mut rng = random(1);
    let first = send(&mut peers[0], &mut rng);
    deliver(&mut peers[1], &first, 0);
    let mut queues: [Vec<Packet>; 2] = [Vec::new(), Vec::new()];
    let mut unique = std::collections::BTreeSet::new();
    for round in 0..100 {
        for side in [1, 0] {
            let count = if round % 3 == 0 { 17 } else { 3 };
            for _ in 0..count {
                let packet = send(&mut peers[side], &mut rng);
                assert!(unique.insert(*packet.secret));
                queues[side].push(packet);
            }
            let newest = queues[side].pop().unwrap();
            deliver(&mut peers[1 - side], &newest, round);
            while queues[side].len() > 31 {
                let selected = if round % 2 == 0 {
                    0
                } else {
                    queues[side].len() / 2
                };
                let packet = queues[side].remove(selected);
                deliver(&mut peers[1 - side], &packet, round);
            }
        }
    }
    for side in 0..2 {
        for packet in queues[side].drain(..).rev() {
            deliver(&mut peers[1 - side], &packet, 100);
        }
    }
    for peer in &peers {
        assert!(peer.skipped.is_empty() && peer.order.is_empty());
    }
}

#[test]
fn authentication_failure_cannot_consume_current_old_or_new_dh_keys() {
    let mut peers = peers();
    let mut rng = random(2);
    let old = send(&mut peers[0], &mut rng);
    let newer = send(&mut peers[0], &mut rng);
    deliver(&mut peers[1], &newer, 0);
    let reply = send(&mut peers[1], &mut rng);
    deliver(&mut peers[0], &reply, 0);
    let next_turn = send(&mut peers[0], &mut rng);
    for packet in [&old, &next_turn] {
        for offset in 0..HEADER_BYTES {
            let mut changed = packet.header;
            changed[offset] ^= 1;
            assert!(
                peers[1]
                    .receive::<()>(&changed, 0, |_| Err(Error::Authentication))
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
    let current = send(&mut peers[0], &mut rng);
    assert!(
        peers[1]
            .receive::<()>(&current.header, 0, |_| Err(Error::Authentication))
            .is_err()
    );
    deliver(&mut peers[1], &current, 0);
}

#[test]
fn skipped_key_bounds_apply_across_both_chains_and_all_dh_turns() {
    for count in [4096, 4097] {
        let mut peers = peers();
        let mut rng = random(3);
        let first = send(&mut peers[0], &mut rng);
        deliver(&mut peers[1], &first, 0);
        for _ in 1..count {
            send(&mut peers[0], &mut rng);
        }
        let reply = send(&mut peers[1], &mut rng);
        deliver(&mut peers[0], &reply, 0);
        let next = send(&mut peers[0], &mut rng);
        let last = send(&mut peers[0], &mut rng);
        if count == 4096 {
            deliver(&mut peers[1], &last, 1);
            assert_eq!(peers[1].skipped.len(), MAX_SKIPPED_KEYS);
            deliver(&mut peers[1], &next, 1);
        } else {
            assert!(matches!(
                peers[1].receive::<()>(&last.header, 1, |_| panic!(
                    "exceeded joint derivation budget"
                )),
                Err(Error::Limit)
            ));
            deliver(&mut peers[1], &next, 1);
            assert_eq!(peers[1].skipped.len(), MAX_SKIPPED_KEYS);
            deliver(&mut peers[1], &last, 1);
        }
        // Each subsequent full gap replaces old delayed keys and both indices.
        for round in 0..3 {
            let mut packet = send(&mut peers[0], &mut rng);
            for _ in 0..MAX_SKIPPED_KEYS {
                packet = send(&mut peers[0], &mut rng);
            }
            deliver(&mut peers[1], &packet, 2 + round);
            assert_eq!(peers[1].skipped.len(), MAX_SKIPPED_KEYS);
            assert_eq!(peers[1].order.len(), MAX_SKIPPED_KEYS);
        }
    }
}

#[test]
fn expiry_cannot_be_renewed_by_traffic_forgery_or_clock_regression() {
    let mut peers = peers();
    let mut rng = random(4);
    let packets: Vec<_> = (0..6).map(|_| send(&mut peers[0], &mut rng)).collect();
    deliver(&mut peers[1], &packets[3], 10);
    deliver(&mut peers[1], &packets[5], 20);
    let root = peers[1].active.root.clone();
    assert!(
        peers[1]
            .receive::<()>(&packets[0].header, 60_010, |_| panic!("expired key"))
            .is_err()
    );
    assert!(
        peers[1]
            .receive::<()>(&packets[1].header, 0, |_| panic!(
                "clock regression revived a key"
            ))
            .is_err()
    );
    assert_eq!(peers[1].active.root, root);
    deliver(&mut peers[1], &packets[4], 60_019);
    assert!(peers[1].skipped.is_empty() && peers[1].order.is_empty());
}

#[test]
fn invalid_headers_low_order_keys_random_failure_and_counter_exhaustion_fail_closed() {
    let mut rng = random(5);
    let mut peers = peers();
    assert!(matches!(
        peers[1].prepare_send(&mut rng),
        Err(Error::Pending)
    ));
    assert!(matches!(
        peers[0].prepare_send(&mut |_| Err(Error::Crypto)),
        Err(Error::Crypto)
    ));
    for mut public in [[0; 32], {
        let mut bytes = [0; 32];
        bytes[0] = 1;
        bytes
    }] {
        for high_bit in [0, 128] {
            public[31] = high_bit;
            let mut header = [0; HEADER_BYTES];
            header[..32].copy_from_slice(&public);
            assert!(matches!(
                peers[1].receive::<()>(&header, 0, |_| panic!("low-order key")),
                Err(Error::Authentication)
            ));
        }
    }
    for len in (0..HEADER_BYTES).chain([HEADER_BYTES + 1]) {
        assert!(
            peers[1]
                .receive::<()>(&vec![0; len], 0, |_| panic!("malformed header"))
                .is_err()
        );
    }
    let packet = send(&mut peers[0], &mut rng);
    deliver(&mut peers[1], &packet, 0);
    peers[0].active.send.as_mut().unwrap().count = u64::MAX;
    assert!(matches!(peers[0].prepare_send(&mut rng), Err(Error::Limit)));
    let mut forged = packet.header;
    forged[40..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        peers[1].receive::<()>(&forged, 0, |_| panic!("overflow")),
        Err(Error::Limit)
    ));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wycheproof_x25519_and_ratchet_contributory_policy() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/wycheproof/x25519_test.json"
    ))
    .unwrap();
    let mut tested = 0;
    for group in vector["testGroups"].as_array().unwrap() {
        for case in group["tests"].as_array().unwrap() {
            let decode = |name: &str| -> [u8; 32] {
                hex::decode(case[name].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let local = StaticSecret::from(decode("private"));
            let public = decode("public");
            let shared = local.diffie_hellman(&PublicKey::from(public));
            assert_eq!(
                *shared.as_bytes(),
                decode("shared"),
                "case {}",
                case["tcId"]
            );
            let mut peer =
                DoubleRatchet::responder(Zeroizing::new([5; 32]), local, Retention::Timed);
            peer.active.remote = Some(public);
            let advanced = peer.active.advance();
            // RFC 7748 allows noncanonical/twist encodings. This protocol
            // accepts their correct result but rejects every all-zero DH.
            if shared.as_bytes() == &[0; 32] {
                assert!(
                    matches!(advanced, Err(Error::Authentication)),
                    "case {}",
                    case["tcId"]
                );
                assert_eq!(*peer.active.root, [5; 32]);
            } else {
                assert!(advanced.is_ok(), "case {}", case["tcId"]);
            }
            tested += 1;
        }
    }
    assert_eq!(tested, 518);
}
