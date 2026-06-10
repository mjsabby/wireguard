//! The whitepaper §6 timer state machine, exercised by time travel:
//! retransmissions, jitter bounds, attempt expiry, rekeys, reject/expiry,
//! keepalives (passive, confirming, persistent), discard, next_wake.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{MS, Pair, S, new_pair, new_pair_with};
use wireguard_sans_io::{
    Encapsulated, Error, PollOutput, Received, SendReason,
    consts::{
        KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECV,
        REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX, SESSION_DISCARD_TIME,
    },
};

/// Drain every action poll has at `now`, returning (wires, events).
fn drain(
    t: &mut wireguard_sans_io::Tunnel,
    now: wireguard_sans_io::Now,
    rng: &mut wireguard_sans_io::testing::DeterministicRng,
) -> (Vec<(Vec<u8>, SendReason)>, Vec<&'static str>) {
    let mut wires = Vec::new();
    let mut events = Vec::new();
    loop {
        let mut buf = [0u8; 2048];
        match t.poll(now, &mut buf, rng).unwrap() {
            PollOutput::Send(w, r) => wires.push((w.to_vec(), r)),
            PollOutput::HandshakeExpired => events.push("handshake_expired"),
            PollOutput::SessionsExpired => events.push("sessions_expired"),
            PollOutput::Idle => break,
        }
        assert!(wires.len() + events.len() < 16, "poll never stabilizes");
    }
    (wires, events)
}

#[test]
fn initiation_retransmits_on_schedule_until_attempt_expiry() {
    let mut p = new_pair(40);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let _ = p.a.initiate_handshake(now, &mut wire, &mut p.rng).unwrap();

    let mut sends = 1u32;
    let mut expired = false;
    // Walk poll forward via next_wake until the attempt is abandoned.
    for _ in 0..64 {
        let wake = p.a.next_wake().expect("retransmit timer armed");
        assert!(wake.nanos() > p.clock.mono_ns, "wake must be in the future");
        // Strictly before the deadline: nothing happens.
        let just_before = p.clock.advance(wake.nanos() - p.clock.mono_ns - 1);
        assert!(matches!(
            p.a.poll(just_before, &mut wire, &mut p.rng).unwrap(),
            PollOutput::Idle
        ));
        let at = p.clock.advance(1);
        match p.a.poll(at, &mut wire, &mut p.rng).unwrap() {
            PollOutput::Send(w, SendReason::HandshakeRetransmit) => {
                assert_eq!(w.len(), 148);
                sends += 1;
            }
            PollOutput::HandshakeExpired => {
                expired = true;
                break;
            }
            other => panic!("unexpected poll output {other:?}"),
        }
    }
    assert!(expired, "attempt must eventually give up");
    // Spec: retries every REKEY_TIMEOUT (+ ≤333ms jitter) for
    // REKEY_ATTEMPT_TIME (90s): 90/5 ≈ 18 sends, minus jitter slippage.
    assert!(
        (15..=18).contains(&sends),
        "saw {sends} initiation sends, expected ≈17"
    );
    assert!(
        p.clock.mono_ns >= REKEY_ATTEMPT_TIME,
        "gave up before Rekey-Attempt-Time"
    );
    // After giving up the tunnel is quiet: no armed wake-ups.
    let (wires, events) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert!(wires.is_empty() && events.is_empty());
    assert_eq!(p.a.next_wake(), None, "quiet after abandoning");
}

#[test]
fn retransmission_jitter_is_within_spec_bounds() {
    // Across many handshake attempts, the gap between sends must be in
    // [REKEY_TIMEOUT, REKEY_TIMEOUT + 333ms] and must actually vary.
    let mut p = new_pair(41);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let _ = p.a.initiate_handshake(now, &mut wire, &mut p.rng).unwrap();
    let mut last_send = p.clock.mono_ns;
    let mut gaps = Vec::new();
    for _ in 0..10 {
        let wake = p.a.next_wake().unwrap();
        let at = p.clock.advance(wake.nanos() - p.clock.mono_ns);
        match p.a.poll(at, &mut wire, &mut p.rng).unwrap() {
            PollOutput::Send(_, SendReason::HandshakeRetransmit) => {
                gaps.push(p.clock.mono_ns - last_send);
                last_send = p.clock.mono_ns;
            }
            PollOutput::HandshakeExpired => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(gaps.len() >= 8);
    for gap in &gaps {
        assert!(*gap >= REKEY_TIMEOUT, "gap {gap} below Rekey-Timeout");
        assert!(
            *gap <= REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX,
            "gap {gap} beyond jitter bound"
        );
    }
    assert!(
        gaps.iter().collect::<std::collections::HashSet<_>>().len() > 1,
        "jitter must vary: {gaps:?}"
    );
}

#[test]
fn initiation_pacing_is_global() {
    let mut p = new_pair(42);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let _ = p.a.initiate_handshake(now, &mut wire, &mut p.rng).unwrap();
    // Explicit re-initiation within 5s is rate limited.
    let soon = p.clock.advance(REKEY_TIMEOUT - 1);
    assert!(matches!(
        p.a.initiate_handshake(soon, &mut wire, &mut p.rng),
        Err(Error::HandshakeRateLimited)
    ));
    let ok_at = p.clock.advance(1);
    assert!(p.a.initiate_handshake(ok_at, &mut wire, &mut p.rng).is_ok());
}

#[test]
fn rekey_after_time_via_send_path() {
    let mut p = new_pair(43);
    p.establish();
    // Just before REKEY_AFTER_TIME: sending does not trigger a rekey.
    p.clock.advance(REKEY_AFTER_TIME - S);
    p.assert_roundtrip_a_to_b(b"young session");
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "no rekey yet: {wires:?}");
    // Cross the threshold: the next send marks rekey_due and poll emits a
    // fresh initiation (the initiator-only rule).
    p.clock.advance(2 * S);
    p.assert_roundtrip_a_to_b(b"aging session");
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1, "exactly one initiation");
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    assert_eq!(wires[0].0[0], 1);
    // The responder does NOT rekey on time (thundering-herd prevention).
    let wire = p.seal_from_b(b"responder traffic");
    let _ = p.open_at_a(&wire);
    let (wires, _) = drain(&mut p.b, p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "responder must not time-rekey: {wires:?}");
}

#[test]
fn rekey_on_receive_path_when_reject_approaches() {
    let mut p = new_pair(44);
    p.establish();
    // A (initiator) hears from B after 165s (= Reject − Keepalive −
    // Rekey): receive path must trigger A's rekey, once.
    p.clock.advance(REKEY_AFTER_TIME_RECV);
    let wire = p.seal_from_b(b"still here");
    let _ = p.open_at_a(&wire);
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    // Receiving more data does not double-trigger ("has not yet acted
    // upon this event" is latched).
    let wire = p.seal_from_b(b"more");
    let _ = p.open_at_a(&wire);
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert!(
        wires
            .iter()
            .all(|(_, r)| *r == SendReason::HandshakeRetransmit),
        "no second fresh initiation: {wires:?}"
    );
}

#[test]
fn reject_after_time_blocks_both_directions() {
    let mut p = new_pair(45);
    p.establish();
    let wire_before = p.seal_from_a(b"sent in time");
    p.clock.advance(REJECT_AFTER_TIME);
    // Sending: the expired session is unusable; encapsulate falls back to
    // a new handshake initiation.
    let now = p.clock.now();
    let mut buf = [0u8; 2048];
    assert!(matches!(
        p.a.encapsulate(now, b"too late", &mut buf, &mut p.rng)
            .unwrap(),
        Encapsulated::HandshakeInitiation(_)
    ));
    // Receiving: a datagram encrypted in time but delivered after the
    // deadline is rejected.
    let mut out = vec![0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wire_before, &mut out, &mut p.rng)
            .err(),
        Some(Error::Expired)
    );
}

#[test]
fn passive_keepalive_emitted_once_after_quiet_receive() {
    let mut p = new_pair(46);
    p.establish();
    // B receives data and never answers.
    let wire = p.seal_from_a(b"talk to me");
    let _ = p.open_at_b(&wire);
    // Just before Keepalive-Timeout: nothing.
    p.clock.advance(KEEPALIVE_TIMEOUT - 1);
    assert!(matches!(
        p.b.poll(p.clock.now(), &mut [0u8; 256], &mut p.rng)
            .unwrap(),
        PollOutput::Idle
    ));
    // At the deadline: exactly one keepalive.
    p.clock.advance(1);
    let (wires, _) = drain(&mut p.b, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::Keepalive);
    assert_eq!(wires[0].0.len(), 32);
    // A accepts it as a keepalive (not data).
    let now = p.clock.now();
    let mut out = [0u8; 64];
    assert!(matches!(
        p.a.decapsulate(now, b"", false, &wires[0].0, &mut out, &mut p.rng)
            .unwrap(),
        Received::Keepalive
    ));
    // No repeat keepalive without new inbound data.
    p.clock.advance(KEEPALIVE_TIMEOUT * 3);
    let (wires, _) = drain(&mut p.b, p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "{wires:?}");
}

#[test]
fn keepalives_do_not_arm_passive_keepalive() {
    let mut p = new_pair(47);
    p.establish();
    // B receives only a keepalive (not data): it owes no reply.
    let now = p.clock.now();
    let mut buf = [0u8; 2048];
    let ka = match p.a.encapsulate(now, b"", &mut buf, &mut p.rng).unwrap() {
        Encapsulated::Transport(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    let mut out = [0u8; 64];
    assert!(matches!(
        p.b.decapsulate(now, b"", false, &ka, &mut out, &mut p.rng)
            .unwrap(),
        Received::Keepalive
    ));
    p.clock.advance(KEEPALIVE_TIMEOUT * 2);
    let (wires, _) = drain(&mut p.b, p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "keepalive ping-pong loop: {wires:?}");
}

#[test]
fn dead_peer_triggers_new_handshake() {
    let mut p = new_pair(48);
    p.establish();
    // A sends data; B never receives it (network ate it). After
    // Keepalive-Timeout + Rekey-Timeout, A must start a new handshake.
    let _lost = p.seal_from_a(b"into the void");
    p.clock.advance(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT - 1);
    assert!(matches!(
        p.a.poll(p.clock.now(), &mut [0u8; 2048], &mut p.rng)
            .unwrap(),
        PollOutput::Idle
    ));
    p.clock.advance(1);
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    // A reply in time would have prevented it.
    let mut q = new_pair(49);
    q.establish();
    let wire = q.seal_from_a(b"hello?");
    let got = q.open_at_b(&wire);
    assert_eq!(&got[..6], b"hello?");
    let reply = q.seal_from_b(b"here!");
    let _ = q.open_at_a(&reply);
    q.clock.advance(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + S);
    let (wires, _) = drain(&mut q.a, q.clock.now(), &mut q.rng);
    assert!(wires.is_empty(), "{wires:?}");
}

#[test]
fn session_discard_after_three_reject_after_time() {
    let mut p = new_pair(50);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 1);
    assert!(matches!(
        p.a.poll(p.clock.now(), &mut [0u8; 2048], &mut p.rng)
            .unwrap(),
        PollOutput::Idle
    ));
    assert!(p.a.is_established());
    p.clock.advance(1);
    let (_, events) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(!p.a.is_established());
    assert_eq!(p.a.next_wake(), None, "fully quiet after discard");
    // The tunnel still works: a fresh handshake re-establishes.
    let mut wire = [0u8; 2048];
    let now = p.clock.now();
    assert!(p.a.initiate_handshake(now, &mut wire, &mut p.rng).is_ok());
}

#[test]
fn persistent_keepalive_keeps_link_warm_and_revives_dead_tunnels() {
    let mut p = new_pair_with(51, None, Some(25));
    p.establish();
    // Quiet link: at 25s the persistent keepalive fires.
    p.clock.advance(25 * S - 1);
    assert!(matches!(
        p.a.poll(p.clock.now(), &mut [0u8; 2048], &mut p.rng)
            .unwrap(),
        PollOutput::Idle
    ));
    p.clock.advance(1);
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::PersistentKeepalive);
    // Deliver to B so its counters move; then repeat period works too.
    let now = p.clock.now();
    let mut out = [0u8; 64];
    p.b.decapsulate(now, b"", false, &wires[0].0, &mut out, &mut p.rng)
        .unwrap();
    p.clock.advance(25 * S);
    let (wires, _) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::PersistentKeepalive);
}

#[test]
fn next_wake_never_misses_an_action() {
    // Property: polling strictly before next_wake is always Idle; the
    // armed deadline, when reached, yields an action (or re-arms a later
    // wake). Walked across an entire handshake-and-traffic lifecycle.
    let mut p = new_pair(52);
    p.establish();
    let wire = p.seal_from_a(b"prime the timers");
    let _ = p.open_at_b(&wire);

    for step in 0..40 {
        let Some(wake) = p.b.next_wake().or_else(|| p.a.next_wake()) else {
            break;
        };
        // Check the owner of the earliest wake.
        let (owner, name) = match (p.a.next_wake(), p.b.next_wake()) {
            (Some(a), Some(b)) if a <= b => (&mut p.a, "a"),
            (Some(_) | None, Some(_)) => (&mut p.b, "b"),
            (Some(_), None) => (&mut p.a, "a"),
            (None, None) => break,
        };
        let wake = wake.min(owner.next_wake().unwrap());
        if wake.nanos() > p.clock.mono_ns + 1 {
            let before = wireguard_sans_io::Now::new(
                wake.nanos() - 1,
                1_700_000_000 + (wake.nanos() - 1) / S,
                0,
            );
            p.clock.mono_ns = wake.nanos() - 1;
            let mut buf = [0u8; 2048];
            let r = owner.poll(before, &mut buf, &mut p.rng).unwrap();
            assert!(
                matches!(r, PollOutput::Idle),
                "step {step}: {name} acted {r:?} before its declared wake"
            );
        }
        p.clock.mono_ns = p.clock.mono_ns.max(wake.nanos());
        let now = p.clock.now();
        let mut buf = [0u8; 2048];
        let _ = owner.poll(now, &mut buf, &mut p.rng).unwrap();
        // No assertion on the action itself: re-arming with a later wake
        // is legal; the property is "never act earlier than announced".
    }
}

#[test]
fn encapsulate_resets_attempt_window() {
    // §6.4: explicit sends reset the 90s give-up counter.
    let mut p = new_pair(53);
    let mut wire = [0u8; 2048];
    let now = p.clock.now();
    let _ = p.a.initiate_handshake(now, &mut wire, &mut p.rng).unwrap();
    // 80s in (still within the window), the app tries to send again.
    p.clock.advance(80 * S);
    assert!(matches!(
        p.a.encapsulate(p.clock.now(), b"still trying", &mut wire, &mut p.rng),
        Err(Error::NotEstablished)
    ));
    // 30s later (110s after the first initiation — past the original 90s
    // window) retransmissions must STILL be running because the window
    // was reset at 80s.
    p.clock.advance(30 * S);
    let (wires, events) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert!(events.is_empty(), "gave up too early: window not reset");
    assert!(!wires.is_empty());
}

fn establish_at(p: &mut Pair) {
    p.establish();
}

#[test]
fn clock_jump_far_forward_is_handled() {
    // A caller that sleeps for an hour and polls once must see the
    // discard event exactly once and end quiet, not loop or panic.
    let mut p = new_pair(54);
    establish_at(&mut p);
    p.clock.advance(3600 * S);
    let (wires, events) = drain(&mut p.a, p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(wires.is_empty());
    assert_eq!(p.a.next_wake(), None);
}

#[test]
fn jitter_uses_entropy_but_failure_is_contained() {
    let mut p = new_pair(55);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let _ = p.a.initiate_handshake(now, &mut wire, &mut p.rng).unwrap();
    let wake = p.a.next_wake().unwrap();
    let at = p.clock.advance(wake.nanos() + MS);
    // Retransmission needs entropy (new ephemeral + jitter): with a dead
    // rng poll errors but the tunnel survives.
    let r =
        p.a.poll(at, &mut wire, &mut wireguard_sans_io::testing::FailingRng);
    assert!(matches!(r, Err(Error::EntropyFailure)));
    let r2 = p.a.poll(at, &mut wire, &mut p.rng).unwrap();
    assert!(matches!(
        r2,
        PollOutput::Send(_, SendReason::HandshakeRetransmit)
    ));
}
