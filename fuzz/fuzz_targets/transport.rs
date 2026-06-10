//! Fuzz transport intake on an established pair: arbitrary mutations of a
//! genuine datagram plus pure garbage, against live session state.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Encapsulated, Now, Received, StaticSecret, Tunnel};

fn establish() -> (Tunnel, Tunnel, DeterministicRng) {
    let mut rng = DeterministicRng::new(0xe57ab);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::new(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::new(Config::new(b_key, a_pub)).unwrap();
    let now = Now::new(0, 1_700_000_000, 0);
    let (mut w, mut s) = ([0u8; 2048], [0u8; 2048]);
    let init = a.initiate_handshake(now, &mut w, &mut rng).unwrap().to_vec();
    let resp = match b.decapsulate(now, b"", false, &init, &mut s, &mut rng).unwrap() {
        Received::Reply(r) => r.to_vec(),
        _ => unreachable!(),
    };
    a.decapsulate(now, b"", false, &resp, &mut s, &mut rng).unwrap();
    let data = match a.encapsulate(now, b"confirm", &mut w, &mut rng).unwrap() {
        Encapsulated::Transport(t) => t.to_vec(),
        _ => unreachable!(),
    };
    b.decapsulate(now, b"", false, &data, &mut s, &mut rng).unwrap();
    (a, b, rng)
}

fuzz_target!(|input: (u16, &[u8])| {
    let (mutation_seed, fuzz_bytes) = input;
    let (mut a, mut b, mut rng) = establish();
    let now = Now::new(1_000_000, 1_700_000_000, 0);

    // 1. A genuine datagram with fuzzer-chosen byte splices applied.
    let mut wire = [0u8; 2048];
    let genuine = match a.encapsulate(now, b"payload under test", &mut wire, &mut rng) {
        Ok(Encapsulated::Transport(t)) => t.to_vec(),
        _ => return,
    };
    let mut mutated = genuine.clone();
    for (i, &byte) in fuzz_bytes.iter().enumerate() {
        let pos = (usize::from(mutation_seed) + i * 7) % mutated.len();
        mutated[pos] ^= byte;
    }
    let mut out = vec![0xEEu8; 512];
    let r = b.decapsulate(now, b"", false, &mutated, &mut out, &mut rng);
    if mutated == genuine {
        assert!(r.is_ok(), "genuine datagram rejected");
    } else if r.is_err() {
        assert!(out.iter().all(|&x| x == 0xEE), "buffer dirtied on reject");
    }

    // 2. The raw fuzz input as a datagram in both directions.
    let mut out = vec![0u8; fuzz_bytes.len() + 256];
    let _ = b.decapsulate(now, b"", false, fuzz_bytes, &mut out, &mut rng);
    let _ = a.decapsulate(now, b"", false, fuzz_bytes, &mut out, &mut rng);
});
