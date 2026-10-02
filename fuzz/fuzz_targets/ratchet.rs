#![no_main]

use libfuzzer_sys::fuzz_target;
use stogas_verifier::channel::{
    Error,
    ratchet::{ChunkSize, InitialKey, Peer, SendKey},
};

fuzz_target!(|input: &[u8]| {
    let width = [32, 34, 256, 1152][usize::from(input.first().copied().unwrap_or(0)) % 4];
    let size = ChunkSize::new(width).unwrap();
    let initial = InitialKey::generate().unwrap();
    let mut peers = [
        Peer::initiator(&[7; 32], size, initial.public_key()),
        Peer::responder(&[7; 32], size, initial),
    ];
    let first = peers[0].send().unwrap();
    peers[1]
        .receive(&first.header, 0, |secret| {
            assert_eq!(*secret, *first.secret);
            Ok(())
        })
        .unwrap();
    let mut packets: [Vec<SendKey>; 2] = [Vec::new(), Vec::new()];
    for (round, command) in input.chunks(4).take(128).enumerate() {
        let side = usize::from(command[0] & 1);
        if command[0] & 2 == 0 || packets[side].is_empty() {
            if packets[side].len() < 16 {
                packets[side].push(peers[side].send().unwrap());
            }
        } else {
            let index = usize::from(command.get(1).copied().unwrap_or(0)) % packets[side].len();
            let packet = packets[side].remove(index);
            let receiver = &mut peers[1 - side];
            let mut changed = packet.header.clone();
            let offset = usize::from(command.get(2).copied().unwrap_or(0)) % changed.len();
            changed[offset] ^= command.get(3).copied().unwrap_or(1);
            assert!(
                receiver
                    .receive::<()>(&changed, round as u64, |_| Err(Error::Authentication))
                    .is_err()
            );
            // This schedule fits within both retention limits. Forgery cannot
            // prevent a later authentic delivery or allow its replay.
            receiver
                .receive(&packet.header, round as u64, |secret| {
                    assert_eq!(*secret, *packet.secret);
                    Ok(())
                })
                .unwrap();
            assert!(
                receiver
                    .receive::<()>(&packet.header, round as u64, |_| panic!("replay"))
                    .is_err()
            );
        }
    }
    let _ = peers[0].receive::<()>(input, 0, |_| Err(Error::Authentication));
});
