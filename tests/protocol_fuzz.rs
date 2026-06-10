//! Unguided deterministic protocol fuzzing: a randomized state-machine
//! exploration that runs under plain `cargo test` (no nightly, no
//! corpus). The guided libFuzzer twin of this harness lives in
//! `fuzz/fuzz_targets/session_ops.rs`.
//!
//! Two tunnels talk over a hostile simulated network that delays,
//! reorders, duplicates, drops and corrupts datagrams, while the clock
//! jumps erratically and both sides keep polling. Invariants:
//!
//! 1. nothing ever panics;
//! 2. every payload delivered as `Received::Data` is *exactly* one of the
//!    payloads the other side encapsulated (no corruption, no forgery);
//! 3. tunnels always recover: after the storm, with a clean network, a
//!    round-trip always succeeds again.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use std::collections::{HashSet, VecDeque};

use common::S;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Config, Encapsulated, EntropySource, Now, PollOutput, Received, StaticSecret, Tunnel,
};

/// splitmix64 driving all the *decisions* (kept separate from the
/// tunnels' entropy so the schedule is independent of key material).
struct Driver(u64);
impl Driver {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// Fingerprint of a payload, for exact-delivery accounting.
fn fingerprint(data: &[u8]) -> u64 {
    // FNV-1a, good enough for accounting.
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
    h ^ (data.len() as u64)
}

struct Endpoint {
    tunnel: Tunnel,
    rng: DeterministicRng,
    /// Fingerprints of every payload this endpoint has ever encapsulated
    /// (padded form, since the receiver sees padding).
    sent: HashSet<u64>,
    delivered: u64,
}

fn run_episode(seed: u64) {
    let mut drv = Driver(seed);
    // Key material comes from a stream disjoint from the driver's.
    let mut keyrng = DeterministicRng::new(seed ^ 0x6b65_7973);
    let a_key = StaticSecret::generate(&mut keyrng).unwrap();
    let b_key = StaticSecret::generate(&mut keyrng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();

    let mut a = Endpoint {
        tunnel: Tunnel::new(Config::new(a_key, b_pub)).unwrap(),
        rng: DeterministicRng::new(seed.wrapping_mul(3)),
        sent: HashSet::new(),
        delivered: 0,
    };
    let mut b = Endpoint {
        tunnel: Tunnel::new(Config::new(b_key, a_pub)).unwrap(),
        rng: DeterministicRng::new(seed.wrapping_mul(5)),
        sent: HashSet::new(),
        delivered: 0,
    };

    // The hostile network: queues of (deliver-to-a?, datagram).
    let mut to_a: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_b: VecDeque<Vec<u8>> = VecDeque::new();
    let mut mono: u64 = 0;
    let now = |mono: u64| Now::new(mono, 1_700_000_000 + mono / S, (mono % S) as u32);

    let steps = 400;
    for _ in 0..steps {
        match drv.below(10) {
            // Send data from A or B.
            0..=2 => {
                let from_a = drv.chance(50);
                let len = drv.below(700) as usize;
                let mut payload = vec![0u8; len];
                let (ep, queue) = if from_a {
                    (&mut a, &mut to_b)
                } else {
                    (&mut b, &mut to_a)
                };
                ep.rng.fill(&mut payload).unwrap();
                let mut wire = vec![0u8; 1024];
                match ep
                    .tunnel
                    .encapsulate(now(mono), &payload, &mut wire, &mut ep.rng)
                {
                    Ok(Encapsulated::Transport(w)) => {
                        // Account the padded form (receiver sees padding).
                        let mut padded = payload.clone();
                        padded.resize(len.div_ceil(16) * 16, 0);
                        ep.sent.insert(fingerprint(&padded));
                        queue.push_back(w.to_vec());
                    }
                    Ok(Encapsulated::HandshakeInitiation(w)) => queue.push_back(w.to_vec()),
                    Err(_) => {} // NotEstablished/rate-limited: fine
                }
            }
            // Deliver one datagram (possibly corrupted) to its target.
            3..=6 => {
                let deliver_to_a = if to_a.is_empty() {
                    false
                } else if to_b.is_empty() {
                    true
                } else {
                    drv.chance(50)
                };
                let queue = if deliver_to_a { &mut to_a } else { &mut to_b };
                // Pull from a random position: reordering.
                if queue.is_empty() {
                    continue;
                }
                let idx = drv.below(queue.len() as u64) as usize;
                let mut datagram = queue.remove(idx).unwrap();
                // Duplicate sometimes (replay attempts).
                if drv.chance(20) {
                    queue.push_back(datagram.clone());
                }
                // Corrupt sometimes.
                if drv.chance(25) && !datagram.is_empty() {
                    let pos = drv.below(datagram.len() as u64) as usize;
                    datagram[pos] ^= (drv.below(255) + 1) as u8;
                }
                // Truncate sometimes.
                if drv.chance(10) {
                    let keep = drv.below(datagram.len() as u64 + 1) as usize;
                    datagram.truncate(keep);
                }
                let (ep, peer, reply_queue) = if deliver_to_a {
                    (&mut a, &mut b, &mut to_b)
                } else {
                    (&mut b, &mut a, &mut to_a)
                };
                let mut out = vec![0u8; 2048];
                let under_load = drv.chance(10);
                match ep.tunnel.decapsulate(
                    now(mono),
                    b"fuzz-remote",
                    under_load,
                    &datagram,
                    &mut out,
                    &mut ep.rng,
                ) {
                    Ok(Received::Data(d)) => {
                        // INVARIANT: only payloads the peer really sent.
                        assert!(
                            peer.sent.contains(&fingerprint(d)),
                            "seed {seed}: delivered a payload never sent ({} bytes)",
                            d.len()
                        );
                        ep.delivered += 1;
                    }
                    Ok(Received::Reply(w)) => reply_queue.push_back(w.to_vec()),
                    Ok(_) | Err(_) => {}
                }
            }
            // Advance time: small jitter to multi-second jumps.
            7..=8 => {
                mono += match drv.below(4) {
                    0 => drv.below(50 * 1_000_000), // ≤50ms
                    1 => drv.below(2 * S),          // ≤2s
                    2 => drv.below(12 * S),         // ≤12s (crosses REKEY_TIMEOUT)
                    _ => drv.below(40 * S),         // ≤40s
                };
            }
            // Poll both sides, routing anything they emit.
            _ => {
                for (ep, queue) in [(&mut a, &mut to_b), (&mut b, &mut to_a)] {
                    loop {
                        let mut wire = vec![0u8; 1024];
                        match ep.tunnel.poll(now(mono), &mut wire, &mut ep.rng).unwrap() {
                            PollOutput::Send(w, _) => queue.push_back(w.to_vec()),
                            _ => break,
                        }
                        if queue.len() > 64 {
                            break;
                        }
                    }
                }
            }
        }
        // Network capacity bound (drops happen implicitly when an episode
        // ends with queued datagrams).
        while to_a.len() > 64 {
            to_a.pop_front();
        }
        while to_b.len() > 64 {
            to_b.pop_front();
        }
    }

    // RECOVERY INVARIANT: clean network, generous time → traffic flows.
    to_a.clear();
    to_b.clear();
    mono += 600 * S; // far past every give-up/discard timer
    let mut wires: VecDeque<(bool, Vec<u8>)> = VecDeque::new(); // (to_b, datagram)
    let mut delivered_after_storm = false;
    for round in 0..2400 {
        // A keeps trying to send; everything is delivered faithfully.
        let mut wire = vec![0u8; 1024];
        match a
            .tunnel
            .encapsulate(now(mono), b"recovery probe", &mut wire, &mut a.rng)
        {
            Ok(Encapsulated::Transport(w)) | Ok(Encapsulated::HandshakeInitiation(w)) => {
                wires.push_back((true, w.to_vec()));
            }
            Err(_) => {}
        }
        for (ep, q) in [(&mut a, false), (&mut b, true)] {
            let mut wire = vec![0u8; 1024];
            if let PollOutput::Send(w, _) =
                ep.tunnel.poll(now(mono), &mut wire, &mut ep.rng).unwrap()
            {
                wires.push_back((q, w.to_vec()));
            }
        }
        while let Some((to_b_side, datagram)) = wires.pop_front() {
            let ep = if to_b_side { &mut b } else { &mut a };
            let mut out = vec![0u8; 2048];
            match ep
                .tunnel
                .decapsulate(now(mono), b"r", false, &datagram, &mut out, &mut ep.rng)
            {
                Ok(Received::Reply(w)) => wires.push_back((!to_b_side, w.to_vec())),
                Ok(Received::Data(d)) if to_b_side && d.starts_with(b"recovery probe") => {
                    delivered_after_storm = true;
                }
                _ => {}
            }
        }
        if delivered_after_storm {
            break;
        }
        mono += S; // 1s per round: lets pacing/retransmit timers run
        assert!(
            round < 2399,
            "seed {seed}: tunnels failed to recover after the storm"
        );
    }
    assert!(delivered_after_storm);
}

#[test]
fn protocol_storm_episodes() {
    // 24 deterministic episodes × 400 hostile steps + recovery check.
    for seed in 0..24 {
        run_episode(seed * 0x9e37 + 7);
    }
}

#[test]
fn protocol_storm_long_episode() {
    // One long, distinct seed for depth.
    run_episode(0xdeadbeef);
}
