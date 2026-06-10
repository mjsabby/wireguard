//! Fuzz the responder's datagram intake: a fully-keyed tunnel fed
//! arbitrary datagrams (with arbitrary under-load flag and remote
//! address). Must never panic and must never write to the output buffer
//! on a rejected datagram.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Now, StaticSecret, Tunnel};

fuzz_target!(|input: (bool, u8, &[u8])| {
    let (under_load, remote_len, datagram) = input;
    let mut rng = DeterministicRng::new(0xf00d);
    let key = StaticSecret::generate(&mut rng).unwrap();
    let peer = StaticSecret::generate(&mut rng).unwrap().public_key();
    let mut tunnel = Tunnel::new(Config::new(key, peer)).unwrap();

    let now = Now::new(1_000_000_000, 1_700_000_000, 0);
    let remote = vec![0xabu8; usize::from(remote_len)];
    let mut out = vec![0xEEu8; datagram.len() + 256];
    let r = tunnel.decapsulate(now, &remote, under_load, datagram, &mut out, &mut rng);
    if r.is_err() {
        assert!(
            out.iter().all(|&b| b == 0xEE),
            "output buffer dirtied by rejected datagram"
        );
    }
});
