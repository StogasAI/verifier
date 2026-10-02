use super::*;
use std::time::Instant;

enum Endpoint {
    Hybrid(Box<Peer>),
    Sparse(Box<peer::Peer>),
}

impl Endpoint {
    fn send(&mut self) -> SendKey {
        match self {
            Self::Hybrid(peer) => peer.send(),
            Self::Sparse(peer) => {
                peer.send_with(&mut |bytes| getrandom::fill(bytes).map_err(|_| Error::Crypto))
            }
        }
        .unwrap()
    }

    fn receive(&mut self, packet: &SendKey) {
        let check = |key: &[u8; 32]| {
            assert_eq!(key, packet.secret.as_ref());
            Ok(())
        };
        match self {
            Self::Hybrid(peer) => peer.receive(&packet.header, 0, check),
            Self::Sparse(peer) => peer.receive(&packet.header, 0, check),
        }
        .unwrap();
    }
}

#[test]
#[ignore = "explicit release-mode ratchet benchmark; excludes records, HTTP and attestation"]
fn bidirectional_recovery_cost() {
    let mut results = Vec::new();
    for repetition in 0..3 {
        for width in [32, 256, 1152] {
            let size = ChunkSize::new(width).unwrap();
            for burst in [1, 64] {
                for hybrid in [false, true] {
                    let mut peers = if hybrid {
                        let initial = InitialKey::generate().unwrap();
                        [
                            Endpoint::Hybrid(Box::new(Peer::initiator(
                                &[1; 32],
                                size,
                                initial.public_key(),
                            ))),
                            Endpoint::Hybrid(Box::new(Peer::responder(&[1; 32], size, initial))),
                        ]
                    } else {
                        [true, false].map(|alice| {
                            Endpoint::Sparse(Box::new(peer::Peer::new(
                                alice,
                                &[1; 32],
                                size,
                                Retention::Timed,
                            )))
                        })
                    };
                    let first = peers[0].send();
                    peers[1].receive(&first);
                    let mut packets = Vec::with_capacity(burst);
                    let mut header_bytes = 0;
                    let mut largest_epoch = 0;
                    let started = Instant::now();
                    for _ in 0..4096 / (2 * burst) {
                        for side in [1, 0] {
                            for _ in 0..burst {
                                let packet = peers[side].send();
                                header_bytes += packet.header.len();
                                let offset = if hybrid { 64 } else { 16 };
                                largest_epoch = largest_epoch.max(u64::from_be_bytes(
                                    packet.header[offset..offset + 8].try_into().unwrap(),
                                ));
                                packets.push(packet);
                            }
                            // Reverse delivery includes real delayed-key staging and consumption.
                            while let Some(packet) = packets.pop() {
                                peers[1 - side].receive(&packet);
                            }
                        }
                    }
                    let elapsed = started.elapsed();
                    assert!(largest_epoch > 1);
                    results.push(serde_json::json!({
                        "repetition": repetition,
                        "protocol": if hybrid { "triple" } else { "spqr" },
                        "chunk_bytes": width, "burst": burst, "messages": 4096,
                        "elapsed_ns": elapsed.as_nanos(), "header_bytes": header_bytes,
                        "largest_advertised_epoch": largest_epoch,
                    }));
                }
            }
        }
    }
    println!(
        "RATCHET_BENCHMARK={}",
        serde_json::to_string(&results).unwrap()
    );
}
