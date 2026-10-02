use super::*;
use sha2::{Digest as _, Sha256 as SeedHash};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(in crate::channel::ratchet) fn random(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
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

fn remember(keys: &mut BTreeMap<u64, [u8; 32]>, key: Option<EpochKey>) {
    if let Some(key) = key {
        assert!(
            keys.insert(key.epoch, *key.secret).is_none(),
            "an epoch must emit exactly once"
        );
    }
}

fn state_name(braid: &Braid) -> &'static str {
    match braid.state {
        State::KeysUnsampled => "KeysUnsampled",
        State::KeysSampled { .. } => "KeysSampled",
        State::HeaderSent { .. } => "HeaderSent",
        State::Ct1Received { .. } => "Ct1Received",
        State::EkSentCt1Received { .. } => "EkSentCt1Received",
        State::NoHeaderReceived(_) => "NoHeaderReceived",
        State::HeaderReceived(_) => "HeaderReceived",
        State::Ct1Sampled { .. } => "Ct1Sampled",
        State::EkReceivedCt1Sampled { .. } => "EkReceivedCt1Sampled",
        State::Ct1Acknowledged { .. } => "Ct1Acknowledged",
        State::Ct2Sampled(_) => "Ct2Sampled",
        State::Closed => "Closed",
    }
}

#[test]
fn full_updates_progress_without_an_extra_round_trip_or_duplicate_ciphertext() {
    let mut alice = Braid::new(true, &[1; 32], ChunkSize::FULL);
    let mut bob = Braid::new(false, &[1; 32], ChunkSize::FULL);
    let mut random = random(7);
    let mut alice_keys = BTreeMap::new();
    let mut bob_keys = BTreeMap::new();
    let mut kinds = Vec::new();
    for _ in 0..10 {
        let (message, key) = alice.send(&mut random).unwrap();
        kinds.push(message.kind);
        remember(&mut alice_keys, key);
        remember(&mut bob_keys, bob.receive(&message).unwrap());
        let (message, key) = bob.send(&mut random).unwrap();
        kinds.push(message.kind);
        remember(&mut bob_keys, key);
        remember(&mut alice_keys, alice.receive(&message).unwrap());
    }
    assert_eq!(
        &kinds[..10],
        &[
            Kind::Header,
            Kind::Ciphertext1,
            Kind::KeyAndAck,
            Kind::Ciphertext2,
            Kind::None,
            Kind::Header,
            Kind::Ciphertext1,
            Kind::KeyAndAck,
            Kind::Ciphertext2,
            Kind::None
        ]
    );
    assert_eq!(alice_keys, bob_keys);
    assert_eq!(alice_keys.len(), 4);
}

#[test]
fn loss_reordering_replay_asymmetric_bursts_and_offline_periods_preserve_epoch_agreement() {
    let mut visited = BTreeSet::new();
    for width in [32, 34, 256, 1152] {
        for (alice_burst, bob_burst) in [(1, 1), (7, 1), (1, 7), (16, 16)] {
            let size = ChunkSize::new(width).unwrap();
            let mut alice = Braid::new(true, &[1; 32], size);
            let mut bob = Braid::new(false, &[1; 32], size);
            let mut random = random(u64::from(width));
            let mut alice_keys = BTreeMap::new();
            let mut bob_keys = BTreeMap::new();
            let mut outgoing = [VecDeque::new(), VecDeque::new()];
            for round in 0..900 {
                for (sender, keys, count, queue) in
                    [(&mut alice, &mut alice_keys, alice_burst, &mut outgoing[0])]
                {
                    visited.insert(state_name(sender));
                    for _ in 0..count {
                        let (message, key) = sender.send(&mut random).unwrap();
                        remember(keys, key);
                        queue.push_back(message);
                    }
                }
                visited.insert(state_name(&bob));
                for _ in 0..bob_burst {
                    let (message, key) = bob.send(&mut random).unwrap();
                    remember(&mut bob_keys, key);
                    outgoing[1].push_back(message);
                }
                // Periods of no delivery, reordering across bursts, dropped messages,
                // and repeated public chunks. Later rounds guarantee fair delivery.
                if round < 100 && round % 13 < 8 {
                    continue;
                }
                for (queue, receiver, keys) in [(&mut outgoing[0], &mut bob, &mut bob_keys)] {
                    while let Some(message) = if round % 3 == 0 {
                        queue.pop_back()
                    } else {
                        queue.pop_front()
                    } {
                        if round < 100 && message.chunk.as_ref().is_some_and(|c| c.point % 7 == 3) {
                            continue;
                        }
                        visited.insert(state_name(receiver));
                        remember(keys, receiver.receive(&message).unwrap());
                        remember(keys, receiver.receive(&message).unwrap());
                        visited.insert(state_name(receiver));
                    }
                }
                while let Some(message) = if round % 3 == 0 {
                    outgoing[1].pop_back()
                } else {
                    outgoing[1].pop_front()
                } {
                    if round < 100 && message.chunk.as_ref().is_some_and(|c| c.point % 7 == 3) {
                        continue;
                    }
                    visited.insert(state_name(&alice));
                    remember(&mut alice_keys, alice.receive(&message).unwrap());
                    remember(&mut alice_keys, alice.receive(&message).unwrap());
                    visited.insert(state_name(&alice));
                }
                for (epoch, key) in &alice_keys {
                    if let Some(other) = bob_keys.get(epoch) {
                        assert_eq!(key, other);
                    }
                }
            }
            assert!(
                alice_keys.len().min(bob_keys.len()) >= 8,
                "no recovery progress at width {width}"
            );
            assert!(alice_keys.len().abs_diff(bob_keys.len()) <= 1);
        }
    }
    assert_eq!(
        visited,
        BTreeSet::from([
            "KeysUnsampled",
            "KeysSampled",
            "HeaderSent",
            "Ct1Received",
            "EkSentCt1Received",
            "NoHeaderReceived",
            "HeaderReceived",
            "Ct1Sampled",
            "EkReceivedCt1Sampled",
            "Ct1Acknowledged",
            "Ct2Sampled",
        ])
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn public_messages_have_one_bounded_canonical_encoding() {
    for width in [32, 34, 1152] {
        let size = ChunkSize::new(width).unwrap();
        for kind in [
            Kind::None,
            Kind::Header,
            Kind::Key,
            Kind::KeyAndAck,
            Kind::Ack,
            Kind::Ciphertext1,
            Kind::Ciphertext2,
        ] {
            let message = Message {
                epoch: 1,
                kind,
                chunk: (kind.piece_size() != 0).then(|| Chunk {
                    point: 42,
                    bytes: vec![7; kind.piece_size().min(usize::from(width))],
                }),
            };
            let mut bytes = Vec::new();
            message.encode(&mut bytes);
            assert_eq!(Message::decode(&bytes, size).unwrap(), message);
            for length in 0..bytes.len() {
                assert!(Message::decode(&bytes[..length], size).is_err());
            }
            bytes.push(0);
            assert!(Message::decode(&bytes, size).is_err());
        }
    }
    assert!(Message::decode(&[0; 9], ChunkSize::FULL).is_err());
    let mut bytes = vec![0; 9];
    bytes[7] = 1;
    for kind in 7..=u8::MAX {
        bytes[8] = kind;
        assert!(Message::decode(&bytes, ChunkSize::FULL).is_err());
    }
}

#[test]
fn one_way_traffic_cannot_claim_recovery_and_randomness_failure_closes_the_state() {
    let mut alice = Braid::new(true, &[1; 32], ChunkSize::FULL);
    let mut bob = Braid::new(false, &[1; 32], ChunkSize::FULL);
    let mut random = random(7);
    for _ in 0..100 {
        let (message, key) = alice.send(&mut random).unwrap();
        assert!(key.is_none());
        assert!(bob.receive(&message).unwrap().is_none());
    }
    assert_eq!(alice.epoch, 1);
    assert_eq!(bob.epoch, 1);
    let mut failed = Braid::new(true, &[1; 32], ChunkSize::FULL);
    assert!(failed.send(&mut |_| Err(Error::Crypto)).is_err());
    assert!(matches!(failed.send(&mut random), Err(Error::Closed)));
}

#[test]
fn fresh_entropy_changes_later_secrets_after_snapshots_of_every_protocol_state() {
    let mut snapshots = BTreeMap::new();
    for (a_burst, b_burst) in [(1, 1), (7, 1), (1, 7)] {
        let mut alice = Braid::new(true, &[17; 32], ChunkSize::new(32).unwrap());
        let mut bob = Braid::new(false, &[17; 32], ChunkSize::new(32).unwrap());
        let mut rng = random(111);
        for _ in 0..300 {
            for _ in 0..a_burst {
                for peer in [&alice, &bob] {
                    snapshots
                        .entry(state_name(peer))
                        .or_insert_with(|| (alice.clone(), bob.clone()));
                }
                let (packet, _) = alice.send(&mut rng).unwrap();
                for peer in [&alice, &bob] {
                    snapshots
                        .entry(state_name(peer))
                        .or_insert_with(|| (alice.clone(), bob.clone()));
                }
                bob.receive(&packet).unwrap();
            }
            for _ in 0..b_burst {
                for peer in [&alice, &bob] {
                    snapshots
                        .entry(state_name(peer))
                        .or_insert_with(|| (alice.clone(), bob.clone()));
                }
                let (packet, _) = bob.send(&mut rng).unwrap();
                for peer in [&alice, &bob] {
                    snapshots
                        .entry(state_name(peer))
                        .or_insert_with(|| (alice.clone(), bob.clone()));
                }
                alice.receive(&packet).unwrap();
            }
        }
    }
    assert_eq!(snapshots.len(), 11);
    // Both runs start with identical compromised state. Each uses independent
    // new entropy afterward. Shared future epoch secrets must agree within a
    // run and diverge between runs after both sides have sampled fresh entropy.
    // This is a recovery regression test, not a computational-security proof.
    for (state, (alice, bob)) in snapshots {
        let initial_epoch = alice.epoch.max(bob.epoch);
        let mut outcomes = Vec::new();
        for seed in [112, 113] {
            let (mut alice, mut bob) = (alice.clone(), bob.clone());
            let mut rng = random(seed);
            let (mut a_keys, mut b_keys) = (BTreeMap::new(), BTreeMap::new());
            for _ in 0..400 {
                let (packet, key) = alice.send(&mut rng).unwrap();
                remember(&mut a_keys, key);
                remember(&mut b_keys, bob.receive(&packet).unwrap());
                let (packet, key) = bob.send(&mut rng).unwrap();
                remember(&mut b_keys, key);
                remember(&mut a_keys, alice.receive(&packet).unwrap());
            }
            let epoch = initial_epoch + 2;
            assert_eq!(a_keys.get(&epoch), b_keys.get(&epoch), "{state}");
            outcomes.push(*a_keys.get(&epoch).expect("recovery made progress"));
        }
        assert_ne!(
            outcomes[0], outcomes[1],
            "fresh entropy had no effect after {state}"
        );
    }
}
