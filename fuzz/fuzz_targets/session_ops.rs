//! Structured, coverage-guided protocol fuzzing: the fuzzer drives two
//! real tunnels through an op interpreter (send / deliver / corrupt /
//! reorder / drop / advance time / poll / under-load), the corpus-guided
//! twin of `tests/protocol_fuzz.rs`.
//!
//! Invariant: every payload delivered as `Data` is byte-exact one that
//! the peer actually encapsulated.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashSet, VecDeque};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Encapsulated, Now, PollOutput, Received, StaticSecret, Tunnel};

#[derive(Arbitrary, Debug)]
enum Op {
    SendA { len: u16 },
    SendB { len: u16 },
    DeliverToA { pick: u8, corrupt_pos: u16, corrupt_val: u8, duplicate: bool },
    DeliverToB { pick: u8, corrupt_pos: u16, corrupt_val: u8, duplicate: bool },
    DropToA { pick: u8 },
    DropToB { pick: u8 },
    AdvanceMillis(u16),
    AdvanceSeconds(u8),
    PollA,
    PollB,
    InitiateA,
    ResetB,
}

fn fingerprint(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
    h ^ (data.len() as u64)
}

fuzz_target!(|ops: Vec<Op>| {
    if ops.len() > 256 {
        return;
    }
    let mut keyrng = DeterministicRng::new(0x6b6579);
    let a_key = StaticSecret::generate(&mut keyrng).unwrap();
    let b_key = StaticSecret::generate(&mut keyrng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::new(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::new(Config::new(b_key, a_pub)).unwrap();
    let mut rng_a = DeterministicRng::new(3);
    let mut rng_b = DeterministicRng::new(5);

    let mut sent_a: HashSet<u64> = HashSet::new(); // padded payload fps A sent
    let mut sent_b: HashSet<u64> = HashSet::new();
    let mut to_a: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_b: VecDeque<Vec<u8>> = VecDeque::new();
    let mut mono: u64 = 0;
    let now = |m: u64| Now::new(m, 1_700_000_000 + m / 1_000_000_000, 0);

    for op in ops {
        match op {
            Op::SendA { len } | Op::SendB { len } => {
                let from_a = matches!(op, Op::SendA { .. });
                let len = usize::from(len) % 1024;
                let mut payload = vec![0u8; len];
                let (tunnel, rng, sent, queue) = if from_a {
                    (&mut a, &mut rng_a, &mut sent_a, &mut to_b)
                } else {
                    (&mut b, &mut rng_b, &mut sent_b, &mut to_a)
                };
                use wireguard_sans_io::EntropySource;
                rng.fill(&mut payload).unwrap();
                let mut wire = vec![0u8; 2048];
                match tunnel.encapsulate(now(mono), &payload, &mut wire, rng) {
                    Ok(Encapsulated::Transport(w)) => {
                        let mut padded = payload.clone();
                        padded.resize(len.div_ceil(16) * 16, 0);
                        sent.insert(fingerprint(&padded));
                        queue.push_back(w.to_vec());
                    }
                    Ok(Encapsulated::HandshakeInitiation(w)) => queue.push_back(w.to_vec()),
                    Err(_) => {}
                }
            }
            Op::DeliverToA { pick, corrupt_pos, corrupt_val, duplicate }
            | Op::DeliverToB { pick, corrupt_pos, corrupt_val, duplicate } => {
                let to_a_side = matches!(op, Op::DeliverToA { .. });
                let queue = if to_a_side { &mut to_a } else { &mut to_b };
                if queue.is_empty() {
                    continue;
                }
                let idx = usize::from(pick) % queue.len();
                let mut datagram = queue.remove(idx).unwrap();
                if duplicate {
                    queue.push_back(datagram.clone());
                }
                if corrupt_val != 0 && !datagram.is_empty() {
                    let pos = usize::from(corrupt_pos) % datagram.len();
                    datagram[pos] ^= corrupt_val;
                }
                let (tunnel, rng, peer_sent, reply_queue) = if to_a_side {
                    (&mut a, &mut rng_a, &sent_b, &mut to_b)
                } else {
                    (&mut b, &mut rng_b, &sent_a, &mut to_a)
                };
                let mut out = vec![0xEEu8; datagram.len() + 256];
                match tunnel.decapsulate(now(mono), b"fz", false, &datagram, &mut out, rng) {
                    Ok(Received::Data(d)) => {
                        assert!(
                            peer_sent.contains(&fingerprint(d)),
                            "delivered a never-sent payload"
                        );
                    }
                    Ok(Received::Reply(w)) => reply_queue.push_back(w.to_vec()),
                    Ok(_) => {}
                    Err(_) => {
                        let dirty = out
                            .iter()
                            .rev()
                            .take(256)
                            .any(|&x| x != 0xEE);
                        // Only the tail canary is checked (the plaintext
                        // area length varies); rejected datagrams must
                        // never write past anything.
                        assert!(!dirty, "rejected datagram wrote into buffer tail");
                    }
                }
            }
            Op::DropToA { pick } => {
                if !to_a.is_empty() {
                    let idx = usize::from(pick) % to_a.len();
                    to_a.remove(idx);
                }
            }
            Op::DropToB { pick } => {
                if !to_b.is_empty() {
                    let idx = usize::from(pick) % to_b.len();
                    to_b.remove(idx);
                }
            }
            Op::AdvanceMillis(ms) => mono += u64::from(ms) * 1_000_000,
            Op::AdvanceSeconds(s) => mono += u64::from(s) * 1_000_000_000,
            Op::PollA | Op::PollB => {
                let on_a = matches!(op, Op::PollA);
                let (tunnel, rng, queue) = if on_a {
                    (&mut a, &mut rng_a, &mut to_b)
                } else {
                    (&mut b, &mut rng_b, &mut to_a)
                };
                for _ in 0..4 {
                    let mut wire = vec![0u8; 2048];
                    match tunnel.poll(now(mono), &mut wire, rng).unwrap() {
                        PollOutput::Send(w, _) => queue.push_back(w.to_vec()),
                        _ => break,
                    }
                }
            }
            Op::InitiateA => {
                let mut wire = vec![0u8; 2048];
                if let Ok(w) = a.initiate_handshake(now(mono), &mut wire, &mut rng_a) {
                    to_b.push_back(w.to_vec());
                }
            }
            Op::ResetB => {
                b.reset();
                sent_a.clear(); // queued/encrypted A-payloads may now never decrypt; fine
            }
        }
        while to_a.len() > 32 {
            to_a.pop_front();
        }
        while to_b.len() > 32 {
            to_b.pop_front();
        }
    }
});
