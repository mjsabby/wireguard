//! Performance and profiling harness (dependency-free).
//!
//! ```text
//! cargo run --release --example perf            # full run
//! cargo run --release --example perf -- --quick # CI smoke numbers
//! ```
//!
//! For profiling with full symbols:
//!
//! ```text
//! cargo build --profile profiling --example perf
//! perf record --call-graph dwarf -- target/profiling/examples/perf
//! perf report
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unreachable
)]

use std::hint::black_box;
use std::time::Instant;

use wireguard_sans_io::crypto::{aead, blake2s, chacha20, poly1305, x25519};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Encapsulated, Now, Received, StaticSecret, Tunnel};

fn now(mono: u64) -> Now {
    Now::new(mono, 1_700_000_000 + mono / 1_000_000_000, 0)
}

/// Measure `f` for ~`target_ms`, returning (iterations, seconds).
fn measure<F: FnMut()>(target_ms: u64, mut f: F) -> (u64, f64) {
    // Calibration pass.
    let t0 = Instant::now();
    let mut calib = 0u64;
    while t0.elapsed().as_millis() < 20 {
        f();
        calib += 1;
    }
    let per_iter = t0.elapsed().as_secs_f64() / calib as f64;
    let iters = ((target_ms as f64 / 1000.0) / per_iter).max(1.0) as u64;
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    (iters, t0.elapsed().as_secs_f64())
}

fn rate(label: &str, unit: &str, target_ms: u64, f: impl FnMut()) {
    let (iters, secs) = measure(target_ms, f);
    let per_sec = iters as f64 / secs;
    let us = secs / iters as f64 * 1e6;
    println!("{label:<46} {per_sec:>12.0} {unit}/s  ({us:>9.2} µs/{unit})");
}

fn throughput(label: &str, bytes_per_iter: usize, target_ms: u64, f: impl FnMut()) {
    let (iters, secs) = measure(target_ms, f);
    let mbps = iters as f64 * bytes_per_iter as f64 / secs / 1e6;
    println!(
        "{label:<46} {mbps:>12.1} MB/s   ({:>9.2} µs/op)",
        secs / iters as f64 * 1e6
    );
}

fn established_pair(rng: &mut DeterministicRng) -> (Tunnel, Tunnel) {
    let a_key = StaticSecret::generate(rng).unwrap();
    let b_key = StaticSecret::generate(rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::new(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::new(Config::new(b_key, a_pub)).unwrap();
    let t = now(0);
    let (mut w, mut s) = ([0u8; 2048], [0u8; 2048]);
    let init = a.initiate_handshake(t, &mut w, rng).unwrap().to_vec();
    let resp = match b.decapsulate(t, b"", false, &init, &mut s, rng).unwrap() {
        Received::Reply(r) => r.to_vec(),
        _ => unreachable!(),
    };
    a.decapsulate(t, b"", false, &resp, &mut s, rng).unwrap();
    let data = match a.encapsulate(t, b"confirm", &mut w, rng).unwrap() {
        Encapsulated::Transport(d) => d.to_vec(),
        _ => unreachable!(),
    };
    b.decapsulate(t, b"", false, &data, &mut s, rng).unwrap();
    (a, b)
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let ms = if quick { 60 } else { 400 };
    let mut rng = DeterministicRng::new(0xbe7c);

    println!("== crypto primitives ==");
    let key = [0x42u8; 32];
    let data_1k = [0xa5u8; 1024];
    let data_64 = [0xa5u8; 64];

    throughput("blake2s-256 (1 KiB)", 1024, ms, || {
        black_box(blake2s::hash(&[&data_1k]));
    });
    throughput("chacha20 keystream (1 KiB)", 1024, ms, {
        let mut buf = data_1k;
        move || chacha20::xor_in_place(&key, 0, &[0u8; 12], black_box(&mut buf))
    });
    throughput("poly1305 (1 KiB)", 1024, ms, || {
        black_box(poly1305::poly1305(&key, &data_1k));
    });
    throughput("chacha20poly1305 seal (1 KiB)", 1024, ms, {
        let mut out = [0u8; 1024 + 16];
        move || {
            aead::seal(&key, &aead::nonce_from_counter(1), &[], &data_1k, &mut out).unwrap();
        }
    });
    throughput("chacha20poly1305 seal (64 B)", 64, ms, {
        let mut out = [0u8; 64 + 16];
        move || {
            aead::seal(&key, &aead::nonce_from_counter(1), &[], &data_64, &mut out).unwrap();
        }
    });
    let scalar = x25519::clamp_scalar([7u8; 32]);
    let point = x25519::x25519_base(&[9u8; 32]);
    rate("x25519 scalar mult", "op", ms, || {
        black_box(x25519::x25519(&scalar, &point));
    });

    println!("\n== handshake ==");
    rate(
        "full 1-RTT handshake (both sides, 4 msgs)",
        "handshake",
        ms,
        || {
            let (a, b) = established_pair(&mut rng);
            black_box((a, b));
        },
    );

    println!("\n== transport ==");
    for (label, size) in [("64 B", 64usize), ("1420 B (typical MTU)", 1420)] {
        let (mut a, mut b) = established_pair(&mut rng);
        let payload = vec![0xddu8; size];
        let mut wire = vec![0u8; size + 64];
        let mut out = vec![0u8; size + 64];
        let mut mono = 1_000_000u64;
        throughput(&format!("encapsulate+decapsulate ({label})"), size, ms, {
            let rng = &mut rng;
            move || {
                mono += 1000;
                let t = now(mono);
                let n = match a.encapsulate(t, &payload, &mut wire, rng).unwrap() {
                    Encapsulated::Transport(w) => w.len(),
                    _ => unreachable!(),
                };
                match b
                    .decapsulate(t, b"", false, &wire[..n], &mut out, rng)
                    .unwrap()
                {
                    Received::Data(d) => {
                        black_box(d);
                    }
                    _ => unreachable!(),
                }
            }
        });
    }

    {
        let (mut a, _b) = established_pair(&mut rng);
        let payload = vec![0xddu8; 1420];
        let mut wire = vec![0u8; 2048];
        let mut mono = 1_000_000u64;
        throughput("encapsulate only (1420 B)", 1420, ms, {
            let rng = &mut rng;
            move || {
                mono += 1000;
                match a.encapsulate(now(mono), &payload, &mut wire, rng).unwrap() {
                    Encapsulated::Transport(w) => {
                        black_box(w);
                    }
                    _ => unreachable!(),
                }
            }
        });
    }
    {
        // Decapsulate-only: pre-encrypt a batch, then time pure decryption.
        let (mut a, mut b) = established_pair(&mut rng);
        let payload = vec![0xddu8; 1420];
        let mut batch = Vec::new();
        let mut mono = 1_000_000u64;
        for _ in 0..200_000 {
            mono += 1000;
            let mut w = vec![0u8; 2048];
            let n = match b
                .encapsulate(now(mono), &payload, &mut w, &mut rng)
                .unwrap()
            {
                Encapsulated::Transport(t) => t.len(),
                _ => unreachable!(),
            };
            w.truncate(n);
            batch.push(w);
        }
        let mut i = 0usize;
        let mut out = vec![0u8; 2048];
        throughput("decapsulate only (1420 B)", 1420, ms.min(150), {
            let rng = &mut rng;
            move || {
                if i < batch.len() {
                    let _ = a
                        .decapsulate(now(mono), b"", false, &batch[i], &mut out, rng)
                        .unwrap();
                    i += 1;
                }
            }
        });
    }

    println!("\n(buffers are stack/caller-owned; the library performed zero heap allocations)");
}
