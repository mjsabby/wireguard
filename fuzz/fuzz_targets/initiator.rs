//! Fuzz the initiator's response handling: a tunnel with an in-flight
//! initiation receives arbitrary datagrams (mutated responses, cookie
//! replies, garbage).
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Now, StaticSecret, Tunnel};

fuzz_target!(|datagram: &[u8]| {
    let mut rng = DeterministicRng::new(0x1717);
    let key = StaticSecret::generate(&mut rng).unwrap();
    let peer = StaticSecret::generate(&mut rng).unwrap().public_key();
    let mut tunnel = Tunnel::new(Config::new(key, peer)).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let mut wire = [0u8; 2048];
    tunnel.initiate_handshake(now, &mut wire, &mut rng).unwrap();

    let mut out = vec![0xEEu8; datagram.len() + 256];
    let r = tunnel.decapsulate(now, b"r", false, datagram, &mut out, &mut rng);
    if r.is_err() {
        assert!(out.iter().all(|&b| b == 0xEE));
    }
    // The tunnel must remain pollable whatever happened.
    let later = Now::new(10_000_000_000, 1_700_000_010, 0);
    let mut buf = [0u8; 2048];
    let _ = tunnel.poll(later, &mut buf, &mut rng);
});
