//! Empirical (dudect-style) timing smoke tests for the constant-time
//! claims: Welch's t-test between two input classes that a variable-time
//! implementation would distinguish trivially.
//!
//! These are statistical wall-clock measurements: inherently noisy and
//! environment-dependent, so they are `#[ignore]`d by default and run
//! explicitly with
//! `cargo test --release --test constant_time -- --ignored`.
//! They are a tripwire, not a proof: a |t| in the hundreds (an early-exit
//! memcmp shows ~1000+) means a real problem, single digits are noise.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Instant;

use wireguard_sans_io::crypto::ct;
use wireguard_sans_io::crypto::x25519;

/// Welch's t statistic between two sample sets of nanosecond timings.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var = |v: &[f64], m: f64| {
        v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)
    };
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / ((va / a.len() as f64) + (vb / b.len() as f64)).sqrt()
}

/// Time two operations *interleaved* (the dudect discipline): running the
/// classes back-to-back lets CPU frequency drift between the blocks show
/// up as a bogus difference; alternating cancels it.
fn interleaved_samples<F, G>(mut f: F, mut g: G, rounds: usize) -> (Vec<f64>, Vec<f64>)
where
    F: FnMut() -> bool,
    G: FnMut() -> bool,
{
    let mut a = Vec::with_capacity(rounds);
    let mut b = Vec::with_capacity(rounds);
    for i in 0..rounds + 100 {
        let t0 = Instant::now();
        for _ in 0..32 {
            std::hint::black_box(f());
        }
        let dt_f = t0.elapsed().as_nanos() as f64;
        let t0 = Instant::now();
        for _ in 0..32 {
            std::hint::black_box(g());
        }
        let dt_g = t0.elapsed().as_nanos() as f64;
        if i >= 100 {
            a.push(dt_f);
            b.push(dt_g);
        }
    }
    (a, b)
}

#[test]
#[ignore = "statistical timing test; run explicitly in --release on a quiet machine"]
fn ct_eq_timing_independent_of_difference_position() {
    // Class A: differs in the first byte. Class B: differs in the last.
    // An early-exit comparison times these very differently. 4 KiB
    // buffers give the early exit thousands of bytes of head start.
    const N: usize = 4096;
    let base = vec![0x5au8; N];
    let mut first = base.clone();
    first[0] ^= 1;
    let mut last = base.clone();
    last[N - 1] ^= 1;

    let (a, b) = interleaved_samples(
        || ct::ct_eq(&base, &first),
        || ct::ct_eq(&base, &last),
        4000,
    );
    let t = welch_t(&a, &b);

    // Sanity: the harness CAN detect a leaky comparison — the standard
    // slice equality (libc memcmp, early exit).
    let (a, b) = interleaved_samples(
        || std::hint::black_box(&base[..]) == std::hint::black_box(&first[..]),
        || std::hint::black_box(&base[..]) == std::hint::black_box(&last[..]),
        4000,
    );
    let t_leaky = welch_t(&a, &b);
    assert!(
        t_leaky.abs() > 10.0,
        "harness failed to flag memcmp (|t| = {:.1}); \
         environment too noisy for this test to mean anything",
        t_leaky.abs()
    );
    assert!(
        t.abs() < 30.0,
        "ct_eq timing differs by position: |t| = {:.1} (leaky memcmp scored {:.1})",
        t.abs(),
        t_leaky.abs()
    );
}

#[test]
#[ignore = "statistical timing test; run explicitly in --release on a quiet machine"]
fn x25519_timing_independent_of_scalar_weight() {
    // Montgomery ladder: all-zero-ish scalars vs all-ones scalars. A
    // branch-on-bit ladder leaks the Hamming weight.
    let u = x25519::BASEPOINT;
    let light = [0u8; 32]; // clamping makes this a valid scalar
    let heavy = [0xffu8; 32];

    let (a, b) = interleaved_samples(
        || x25519::x25519(&light, &u) != [0u8; 32],
        || x25519::x25519(&heavy, &u) != [0u8; 32],
        100,
    );
    let t = welch_t(&a, &b);
    assert!(
        t.abs() < 30.0,
        "x25519 timing depends on scalar bits: |t| = {:.1}",
        t.abs()
    );
}
