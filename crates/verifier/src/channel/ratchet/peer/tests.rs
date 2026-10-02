use super::*;
use sha2::{Digest as _, Sha256 as SeedHash};
use std::collections::{BTreeSet, VecDeque};

fn random(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
    let mut counter = 0_u64;
    move |output| {
        for part in output.chunks_mut(32) {
            let mut hash = SeedHash::new();
            hash.update(seed.to_be_bytes());
            hash.update(counter.to_be_bytes());
            counter += 1;
            part.copy_from_slice(&hash.finalize()[..part.len()]);
        }
        Ok(())
    }
}

fn pair(size: ChunkSize) -> (Peer, Peer) {
    (
        Peer::new(true, &[5; 32], size, Retention::Timed),
        Peer::new(false, &[5; 32], size, Retention::Timed),
    )
}

fn deliver(receiver: &mut Peer, packet: &SendKey, now: u64) {
    receiver
        .receive::<()>(&packet.header, now, |secret| {
            if *secret == *packet.secret {
                Ok(())
            } else {
                Err(Error::Authentication)
            }
        })
        .unwrap();
    assert!(receiver.active.chains.len() <= 3);
    assert!(receiver.skipped.len() <= MAX_SKIPPED_KEYS);
}

fn capture(peer: &Peer) -> Peer {
    Peer {
        active: peer.active.clone(),
        size: peer.size,
        skipped: peer
            .skipped
            .iter()
            .map(|(id, key)| {
                (
                    *id,
                    Skipped {
                        secret: key.secret.clone(),
                        expires: key.expires,
                    },
                )
            })
            .collect(),
        next_expiry: peer.next_expiry,
        last_now: peer.last_now,
        retention: peer.retention,
    }
}

#[test]
fn captured_completed_state_erases_message_keys_and_fresh_kem_changes_future_chains() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let mut rng = random(80);
    let mut completed = Vec::new();
    for _ in 0..25 {
        let packet = alice.send_with(&mut rng).unwrap();
        deliver(&mut bob, &packet, 0);
        completed.push(packet.secret);
        let packet = bob.send_with(&mut rng).unwrap();
        deliver(&mut alice, &packet, 0);
        completed.push(packet.secret);
    }
    for peer in [&alice, &bob] {
        let snapshot = capture(peer);
        assert!(snapshot.skipped.is_empty());
        for old in &completed {
            assert_ne!(&snapshot.active.root, old);
            for chain in snapshot.active.chains.values() {
                for state in [&chain.send, &chain.receive].into_iter().flatten() {
                    assert_ne!(&state.key, old);
                }
            }
        }
    }
    // Start with identical complete captured states, then change only future
    // KEM entropy. This catches failure to mix fresh Braid output into message
    // chains; epoch-counter progress alone cannot establish that property.
    let initial_epoch = alice.active.epoch.max(bob.active.epoch);
    let mut outcomes = Vec::new();
    for seed in [81, 82] {
        let (mut a, mut b) = (capture(&alice), capture(&bob));
        let mut rng = random(seed);
        let mut latest = Zeroizing::new([0; 32]);
        for _ in 0..25 {
            let packet = a.send_with(&mut rng).unwrap();
            deliver(&mut b, &packet, 0);
            let packet = b.send_with(&mut rng).unwrap();
            deliver(&mut a, &packet, 0);
            latest = packet.secret;
        }
        assert!(a.active.epoch >= initial_epoch + 2 && b.active.epoch >= initial_epoch + 2);
        outcomes.push(latest);
    }
    assert_ne!(outcomes[0], outcomes[1]);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn full_updates_derive_unique_keys_and_delete_finished_chains_in_both_directions() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let mut rng = random(0);
    let mut keys = BTreeSet::new();
    for _ in 0..25 {
        let packet = alice.send_with(&mut rng).unwrap();
        assert!(keys.insert(*packet.secret));
        deliver(&mut bob, &packet, 0);
        let packet = bob.send_with(&mut rng).unwrap();
        assert!(keys.insert(*packet.secret));
        deliver(&mut alice, &packet, 0);
    }
    assert_eq!(alice.active.epoch, 10);
    assert_eq!(bob.active.epoch, 10);
    for peer in [&alice, &bob] {
        assert!(peer.skipped.is_empty());
        for (epoch, chains) in &peer.active.chains {
            assert!(*epoch >= peer.active.epoch - 1);
            assert_eq!(chains.send.is_some(), *epoch >= peer.active.sending);
            assert_eq!(chains.receive.is_some(), *epoch >= peer.active.receiving);
        }
    }
}

#[test]
fn delayed_messages_remain_independent_after_multiple_epochs_and_replay_fails() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let mut rng = random(1);
    let mut delayed_alice = Vec::new();
    let mut delayed_bob = Vec::new();
    for round in 0..25 {
        delayed_alice.push(alice.send_with(&mut rng).unwrap());
        let packet = alice.send_with(&mut rng).unwrap();
        deliver(&mut bob, &packet, round);
        delayed_bob.push(bob.send_with(&mut rng).unwrap());
        let packet = bob.send_with(&mut rng).unwrap();
        deliver(&mut alice, &packet, round);
    }
    assert!(alice.active.epoch >= 8);
    assert!(bob.active.epoch >= 8);
    assert_eq!(alice.skipped.len(), 25);
    assert_eq!(bob.skipped.len(), 25);
    for (packets, receiver) in [(delayed_alice, &mut bob), (delayed_bob, &mut alice)] {
        for packet in packets.into_iter().rev() {
            deliver(receiver, &packet, 50);
            assert!(
                receiver
                    .receive::<()>(&packet.header, 50, |_| panic!(
                        "replay reached authentication"
                    ))
                    .is_err()
            );
        }
        assert!(receiver.skipped.is_empty());
    }
}

#[test]
fn failed_authentication_never_consumes_current_skipped_or_new_epoch_keys() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let mut rng = random(2);
    for round in 0..15 {
        let skipped = alice.send_with(&mut rng).unwrap();
        let packet = alice.send_with(&mut rng).unwrap();
        // Every public header byte is bound by the record layer. Even mutations
        // accepted by the parser cannot change the ratchet before its AEAD agrees.
        for offset in 0..packet.header.len() {
            let mut changed = packet.header.clone();
            changed[offset] ^= 1;
            assert!(
                bob.receive::<()>(&changed, round, |_| Err::<(), _>(Error::Authentication))
                    .is_err()
            );
        }
        assert_eq!(
            bob.receive::<()>(&packet.header, round, |_| Err::<(), _>(
                Error::Authentication
            )),
            Err(Error::Authentication)
        );
        deliver(&mut bob, &packet, round);
        assert_eq!(
            bob.receive::<()>(&skipped.header, round, |_| Err::<(), _>(
                Error::Authentication
            )),
            Err(Error::Authentication)
        );
        deliver(&mut bob, &skipped, round);
        let packet = bob.send_with(&mut rng).unwrap();
        assert_eq!(
            alice.receive::<()>(&packet.header, round, |_| Err::<(), _>(
                Error::Authentication
            )),
            Err(Error::Authentication)
        );
        deliver(&mut alice, &packet, round);
    }
    assert!(alice.active.epoch >= 6);
}

#[test]
fn cache_limits_are_global_and_expiry_is_not_extended_by_clock_regression_or_bad_input() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let mut rng = random(3);
    let first = alice.send_with(&mut rng).unwrap();
    for _ in 1..MAX_SKIPPED_KEYS {
        let _ = alice.send_with(&mut rng).unwrap();
    }
    let last = alice.send_with(&mut rng).unwrap();
    deliver(&mut bob, &last, 10);
    assert_eq!(bob.skipped.len(), MAX_SKIPPED_KEYS);
    let gap = alice.send_with(&mut rng).unwrap();
    let next = alice.send_with(&mut rng).unwrap();
    assert_eq!(
        bob.receive::<()>(&next.header, 20, |_| Err(Error::Authentication)),
        Err(Error::Authentication)
    );
    assert_eq!(
        bob.receive::<()>(&first.header, 30, |_| Err::<(), _>(Error::Authentication)),
        Err(Error::Authentication)
    );
    bob.expire(0);
    assert_eq!(bob.next_expiry, Some(10 + SKIPPED_KEY_LIFETIME_MS));
    deliver(&mut bob, &next, 30);
    assert_eq!(bob.skipped.len(), MAX_SKIPPED_KEYS);
    assert!(
        bob.receive::<()>(&first.header, 30, |_| panic!("retired key"))
            .is_err()
    );
    bob.expire(10 + SKIPPED_KEY_LIFETIME_MS);
    assert_eq!(bob.skipped.len(), 1);
    assert!(
        bob.receive::<()>(&first.header, 0, |_| panic!("expired key"))
            .is_err()
    );
    deliver(&mut bob, &gap, 10 + SKIPPED_KEY_LIFETIME_MS);
    assert!(bob.skipped.is_empty());
}

#[test]
fn impossible_counters_and_epochs_do_not_advance_or_allocate() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    let packet = alice.send_with(&mut random(4)).unwrap();
    for (offset, value) in [(8, 0), (8, u64::MAX), (16, 0), (16, 3), (16, u64::MAX)] {
        let mut changed = packet.header.clone();
        changed[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        assert!(
            bob.receive::<()>(&changed, 0, |_| panic!("invalid counter"))
                .is_err()
        );
        assert!(bob.skipped.is_empty());
        assert_eq!(bob.active.epoch, 0);
    }
    deliver(&mut bob, &packet, 0);
    alice
        .active
        .chains
        .get_mut(&0)
        .unwrap()
        .send
        .as_mut()
        .unwrap()
        .number = u64::MAX;
    assert!(matches!(alice.send_with(&mut random(4)), Err(Error::Limit)));
    assert_eq!(
        alice.active.chains[&0].send.as_ref().unwrap().number,
        u64::MAX
    );
}

#[test]
fn loss_reordering_asymmetric_batches_and_different_chunk_sizes_make_progress() {
    for width in [32, 34, 256, 1152] {
        let (mut alice, mut bob) = pair(ChunkSize::new(width).unwrap());
        let mut rng = random(u64::from(width));
        let mut to_alice = VecDeque::new();
        let mut to_bob = VecDeque::new();
        for round in 0..500 {
            for _ in 0..=(round % 5) {
                to_bob.push_back(alice.send_with(&mut rng).unwrap());
            }
            for _ in 0..=(round % 3) {
                to_alice.push_back(bob.send_with(&mut rng).unwrap());
            }
            // Offline intervals delay both directions; later fair delivery is
            // necessary for progress, and is distinct from bounded message loss.
            if round < 60 && round % 13 < 8 {
                continue;
            }
            for (queue, peer) in [(&mut to_bob, &mut bob), (&mut to_alice, &mut alice)] {
                while let Some(packet) = if round % 3 == 0 {
                    queue.pop_back()
                } else {
                    queue.pop_front()
                } {
                    if round < 60 && packet.header[15] % 7 == 0 {
                        continue;
                    }
                    deliver(peer, &packet, round);
                    assert!(
                        peer.receive::<()>(&packet.header, round, |_| panic!("duplicate"))
                            .is_err()
                    );
                }
            }
        }
        assert!(
            alice.active.epoch.min(bob.active.epoch) >= 5,
            "no progress for {width}"
        );
        assert!(alice.active.epoch.abs_diff(bob.active.epoch) <= 1);
    }
}

#[test]
fn randomness_failure_is_transactional_and_does_not_reuse_an_allocation() {
    let (mut alice, mut bob) = pair(ChunkSize::FULL);
    assert!(matches!(
        alice.send_with(&mut |_| Err(Error::Crypto)),
        Err(Error::Crypto)
    ));
    let mut rng = random(5);
    let first = alice.send_with(&mut rng).unwrap();
    let second = alice.send_with(&mut rng).unwrap();
    assert_ne!(*first.secret, *second.secret);
    deliver(&mut bob, &second, 0);
    deliver(&mut bob, &first, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn initialization_epoch_and_directional_chains_match_independent_hkdf_vectors() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/channel-ratchet-v3.json"
    ))
    .unwrap();
    let root: [u8; 32] = hex::decode(vector["root_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut alice = Peer::new(true, &root, ChunkSize::FULL, Retention::Timed);
    let mut bob = Peer::new(false, &root, ChunkSize::FULL, Retention::Timed);
    for epoch in vector["epochs"].as_array().unwrap() {
        let number = epoch["epoch"].as_u64().unwrap();
        let material = hex::decode(epoch["material_hex"].as_str().unwrap()).unwrap();
        assert_eq!(alice.active.root.as_slice(), &material[..32]);
        assert_eq!(alice.active.root, bob.active.root);
        for (index, (sender, receiver)) in [(&alice, &bob), (&bob, &alice)].into_iter().enumerate()
        {
            let mut sending = sender.active.chains[&number].send.clone().unwrap();
            let mut receiving = receiver.active.chains[&number].receive.clone().unwrap();
            assert_eq!(sending.key, receiving.key);
            for expected in epoch["chains"][index]["steps"].as_array().unwrap() {
                let until = expected["number"].as_u64().unwrap();
                let mut message = Zeroizing::new([0; 32]);
                while sending.number < until {
                    message = sending.step().unwrap();
                    assert_eq!(message, receiving.step().unwrap());
                }
                assert_eq!(
                    hex::encode(*message),
                    expected["message_hex"].as_str().unwrap()
                );
                assert_eq!(
                    hex::encode(*sending.key),
                    expected["next_hex"].as_str().unwrap()
                );
            }
        }
        if let Some(shared) = epoch["next_shared_hex"].as_str() {
            let shared: [u8; 32] = hex::decode(shared).unwrap().try_into().unwrap();
            for peer in [&mut alice, &mut bob] {
                peer.active
                    .incorporate(Some(EpochKey {
                        epoch: number + 1,
                        secret: Zeroizing::new(shared),
                    }))
                    .unwrap();
            }
        }
    }
}
