//! Regression tests for security-audit findings (June 2026).
//! These previously demonstrated bugs; they now lock in the fixes.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Config, Encapsulated, EntropyError, EntropySource, Error, Now, PollOutput, Received,
    SendReason, StaticSecret, Tunnel,
};

/// An entropy source that succeeds N times, then fails forever.
struct CountdownRng {
    inner: DeterministicRng,
    remaining: usize,
}
impl EntropySource for CountdownRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if self.remaining == 0 {
            return Err(EntropyError);
        }
        self.remaining -= 1;
        self.inner.fill(buf)
    }
}

// ============================================================================
// H1 (fixed): jitter entropy failure must not strand a phantom in-flight
// handshake. The fix degrades jitter to 0 and commits state atomically.
// ============================================================================
#[test]
fn h1_entropy_failure_during_jitter_does_not_stall() {
    let mut rng = DeterministicRng::new(1);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let mut cfg = Config::new(a_key, b_key.public_key());
    cfg.persistent_keepalive = Some(core::num::NonZeroU16::new(25).unwrap());
    let mut a = Tunnel::new(cfg).unwrap();

    // index ok, eph ok, jitter draw FAILS:
    let mut bad_rng = CountdownRng {
        inner: DeterministicRng::new(2),
        remaining: 2,
    };
    let now = Now::new(0, 1_700_000_000, 0);
    let mut buf = [0u8; 2048];

    // With the fix, jitter degrades to 0 and the initiation is emitted.
    match a.poll(now, &mut buf, &mut bad_rng).unwrap() {
        PollOutput::Send(wire, SendReason::HandshakeInitiation) => {
            assert_eq!(wire.len(), 148);
        }
        other => panic!("expected initiation despite jitter-entropy failure, got {other:?}"),
    }
    // Retransmission is armed (jitter=0 ⇒ retransmit_at = now + 5s).
    assert_eq!(
        a.next_wake().map(|t| t.nanos()),
        Some(5_000_000_000),
        "retransmit_at must be armed even when jitter entropy failed"
    );
    // And a working rng can keep driving the state machine.
    let mut good = DeterministicRng::new(3);
    let later = Now::new(6_000_000_000, 1_700_000_006, 0);
    match a.poll(later, &mut buf, &mut good).unwrap() {
        PollOutput::Send(_, SendReason::HandshakeRetransmit) => {}
        other => panic!("expected retransmit, got {other:?}"),
    }
}

// ============================================================================
// M1 (fixed): a mac2 forged against the all-zero `previous` cookie secret
// must be rejected; the under-load responder must send a cookie reply, not
// run the full Noise handshake.
// ============================================================================
#[test]
fn m1_cookie_jar_rejects_all_zero_previous_forgery() {
    let mut rng = DeterministicRng::new(7);
    let _a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let b_pub = b_key.public_key();
    // A third party who knows the responder's pubkey but holds a different
    // static key.
    let m_key = StaticSecret::generate(&mut rng).unwrap();
    let m_pub = m_key.public_key();
    let mut responder = Tunnel::new(Config::new(b_key, m_pub)).unwrap();
    let mut mallory = Tunnel::new(Config::new(m_key, b_pub)).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let mut buf_m = [0u8; 2048];
    let mut buf_r = [0u8; 2048];
    let remote_m = b"198.51.100.7:1";

    // Step 1: prime the responder's cookie jar.
    let init1 = match mallory.encapsulate(now, b"x", &mut buf_m, &mut rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        _ => panic!(),
    };
    let r = responder
        .decapsulate(now, remote_m, true, &init1, &mut buf_r, &mut rng)
        .unwrap();
    assert!(matches!(r, Received::Reply(_)));
    assert_eq!(responder.stats().cookies_sent, 1);

    // Step 2: forge mac2 against the all-zero key, ignoring the cookie reply.
    let now2 = Now::new(6_000_000_000, 1_700_000_006, 0);
    let init2 = mallory
        .initiate_handshake(now2, &mut buf_m, &mut rng)
        .unwrap()
        .to_vec();
    let mut forged = init2.clone();
    let beta = &forged[..132];
    let forged_cookie = blake2s::mac(&[0u8; 32], &[remote_m.as_slice()]);
    let forged_mac2 = blake2s::mac(&forged_cookie, &[beta]);
    forged[132..148].copy_from_slice(&forged_mac2);

    // Step 3: under load, the forgery must be REJECTED → cookie reply,
    // not full handshake processing.
    let r = responder
        .decapsulate(now2, remote_m, true, &forged, &mut buf_r, &mut rng)
        .unwrap();
    assert!(
        matches!(r, Received::Reply(_)),
        "forged mac2 must not bypass under-load protection"
    );
    assert_eq!(
        responder.stats().cookies_sent,
        2,
        "responder must answer the forgery with a (cheap) cookie reply"
    );
}

// ============================================================================
// M2 (fixed): persistent keepalive must revive the tunnel after `gave_up`,
// backing off by one keepalive interval rather than going silent forever.
// ============================================================================
#[test]
fn m2_persistent_keepalive_revives_after_gave_up() {
    const S: u64 = 1_000_000_000;
    let mut rng = DeterministicRng::new(9);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let mut cfg = Config::new(a_key, b_key.public_key());
    cfg.persistent_keepalive = Some(core::num::NonZeroU16::new(25).unwrap());
    let mut a = Tunnel::new(cfg).unwrap();
    let mut buf = [0u8; 2048];

    // Drive a handshake attempt to exhaustion (peer never answers).
    let mut t = 0u64;
    let _ = a
        .initiate_handshake(Now::new(t, t / S, 0), &mut buf, &mut rng)
        .unwrap();
    let mut expired = false;
    while t <= 95 * S {
        t += S;
        loop {
            match a.poll(Now::new(t, t / S, 0), &mut buf, &mut rng).unwrap() {
                PollOutput::Idle => break,
                PollOutput::HandshakeExpired => {
                    expired = true;
                    break;
                }
                PollOutput::Send(_, _) => {} // retransmits; drop them
                other => panic!("unexpected {other:?}"),
            }
        }
        if expired {
            break;
        }
    }
    assert!(expired, "attempt must expire after REKEY_ATTEMPT_TIME");

    // After gave_up, next_wake must NOT be None: it must point at the
    // persistent-keepalive revival deadline.
    let wake = a.next_wake();
    assert!(
        wake.is_some(),
        "M2: persistent keepalive must keep a deadline armed after gave_up"
    );
    // And polling at/after that deadline must produce a fresh initiation.
    let revive_t = wake.unwrap().nanos().max(t);
    match a
        .poll(Now::new(revive_t, revive_t / S, 0), &mut buf, &mut rng)
        .unwrap()
    {
        PollOutput::Send(_, SendReason::HandshakeInitiation) => {}
        other => panic!("M2: expected revival initiation at {revive_t}, got {other:?}"),
    }
}

// ============================================================================
// L4 (fixed): handshake-response mac1 is verified before the index match,
// so an off-path attacker can't timing-probe the in-flight index.
// ============================================================================
#[test]
fn l4_response_mac1_checked_before_index() {
    let mut rng = DeterministicRng::new(11);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let mut a = Tunnel::new(Config::new(a_key, b_key.public_key())).unwrap();
    let now = Now::new(0, 0, 0);
    let mut buf = [0u8; 2048];
    // Put a handshake in flight so an index *could* match.
    let _ = a.initiate_handshake(now, &mut buf, &mut rng).unwrap();
    // A 92-byte response with garbage everywhere (mac1 invalid). With the
    // fix, this returns InvalidMac1 regardless of receiver_index.
    let mut resp = [0u8; 92];
    resp[0] = 2; // type
    let mut out = [0u8; 256];
    let r = a.decapsulate(now, &[], false, &resp, &mut out, &mut rng);
    assert_eq!(r.err(), Some(Error::InvalidMac1));
}
