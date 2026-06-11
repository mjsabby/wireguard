//! Regression tests for the June 2026 follow-up audit.
//!
//! M-1: `next_wake()` tested `current.is_some()` while `poll()` tested
//! `current_usable`; with `current` past Reject-After-Time and
//! `persistent_keepalive` set, `next_wake()` returned a stale deadline
//! that `poll()` could never satisfy → caller busy-looped at 100 % CPU.
//! Fixed by mirroring `usable_for_send(last_now)` in `next_wake()`.
//!
//! L-2: `next_wake()`'s discard horizon counted an unconfirmed `next`
//! that `poll()` drops at Reject-After-Time before computing its own
//! horizon, delaying `SessionsExpired` by up to 360 s. Fixed by adding
//! `next.created + REJECT_AFTER_TIME` as a wake candidate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{S, new_pair_with};
use wireguard_sans_io::PollOutput;

#[test]
fn next_wake_poll_busy_loop_when_current_unusable() {
    // A has persistent_keepalive=25s; B will go silent.
    let mut p = new_pair_with(0xb00b, None, Some(25));
    p.establish();

    // A sends data at t=119s so last_any_tx=last_data_tx=119s.
    p.clock.advance(119 * S);
    let _ = p.seal_from_a(b"last words");

    // From here B is dead. Drive A purely by next_wake()/poll() and
    // count how many times poll() returns Idle while next_wake() is
    // already in the past — each is one busy-loop iteration a real
    // caller would spin on.
    let mut idle_with_past_wake = 0u32;
    let mut iterations = 0u32;
    let mut buf = [0u8; 2048];

    while p.clock.mono_ns < 540 * S && iterations < 100_000 {
        iterations += 1;
        let Some(wake) = p.a.next_wake() else { break };
        // A real caller does: sleep_until(wake.max(now)); poll(now).
        if wake.nanos() > p.clock.mono_ns {
            p.clock.mono_ns = wake.nanos();
        }
        let now = p.clock.now();
        let r = p.a.poll(now, &mut buf, &mut p.rng).unwrap();
        if matches!(r, PollOutput::Idle)
            && p.a
                .next_wake()
                .is_some_and(|w| w.nanos() <= p.clock.mono_ns)
        {
            // Idle but next_wake didn't advance: the next loop
            // iteration would spin at the same instant — that IS the
            // bug. Count it and nudge 1 ns so the test itself doesn't
            // hang.
            idle_with_past_wake += 1;
            p.clock.mono_ns += 1;
        }
    }

    // Pre-fix this hit ~100k iterations (bounded only by the test's 1 ns
    // nudge; unbounded in production). Post-fix: zero.
    assert_eq!(
        idle_with_past_wake, 0,
        "M-1 regression: poll() returned Idle {idle_with_past_wake} times \
         while next_wake() was already in the past (caller busy-loops)"
    );
    // The tunnel did make progress (handshake attempts were emitted and
    // eventually expired) — i.e. we didn't just suppress all wake-ups.
    assert!(p.a.stats().handshakes_initiated > 1);
}

/// Control: with NO persistent keepalive the same scenario is quiet
/// (no busy-loop), confirming the persistent-keepalive branch is the
/// culprit.
#[test]
fn no_busy_loop_without_persistent_keepalive() {
    let mut p = new_pair_with(0xb00c, None, None);
    p.establish();
    p.clock.advance(119 * S);
    let _ = p.seal_from_a(b"x");

    let mut idle_with_past_wake = 0u32;
    let mut buf = [0u8; 2048];
    for _ in 0..100_000 {
        let Some(wake) = p.a.next_wake() else { break };
        if wake.nanos() > p.clock.mono_ns {
            p.clock.mono_ns = wake.nanos();
        }
        let r = p.a.poll(p.clock.now(), &mut buf, &mut p.rng).unwrap();
        if matches!(r, PollOutput::Idle)
            && p.a
                .next_wake()
                .is_some_and(|w| w.nanos() <= p.clock.mono_ns)
        {
            idle_with_past_wake += 1;
            p.clock.mono_ns += 1;
        }
        if p.clock.mono_ns > 600 * S {
            break;
        }
    }
    assert_eq!(idle_with_past_wake, 0);
}

/// L-2 regression: an unconfirmed `next` must not push the wipe of
/// `current`/`previous` past `current.created + 540 s`.
#[test]
fn unconfirmed_next_does_not_delay_session_discard() {
    use wireguard_sans_io::Received;
    use wireguard_sans_io::consts::SESSION_DISCARD_TIME;

    let mut p = common::new_pair(0xb00d);
    p.establish(); // current born at t = 0 on both sides.

    // At t = 300 s, B (acting as initiator) sends an initiation that A
    // answers — installing an unconfirmed `next` in A — but B never
    // confirms (response is dropped).
    let now300 = p.clock.advance(300 * S);
    let mut wb = [0u8; 2048];
    let init =
        p.b.initiate_handshake(now300, &mut wb, &mut p.rng)
            .unwrap()
            .to_vec();
    let mut wa = [0u8; 2048];
    match p
        .a
        .decapsulate(now300, b"b-addr", false, &init, &mut wa, &mut p.rng)
        .unwrap()
    {
        Received::Reply(_) => {} // A.next is now set, born at 300 s
        other => panic!("expected response, got {other:?}"),
    }

    // A's `current` (born t=0) must be wiped at 540 s. Pre-fix,
    // next_wake() returned 300+540 = 840 s and a sleep-until-wake
    // caller would not poll until then. Post-fix, next_wake() includes
    // 300+180 = 480 s (next-expiry), at which poll() drops `next` and
    // recomputes; the discard then fires at 540 s.
    let mut wiped_at = None;
    let mut buf = [0u8; 2048];
    for _ in 0..50 {
        let Some(wake) = p.a.next_wake() else { break };
        p.clock.mono_ns = p.clock.mono_ns.max(wake.nanos());
        loop {
            match p.a.poll(p.clock.now(), &mut buf, &mut p.rng).unwrap() {
                PollOutput::SessionsExpired => {
                    wiped_at = Some(p.clock.mono_ns);
                }
                PollOutput::Idle => break,
                _ => {}
            }
        }
        if wiped_at.is_some() {
            break;
        }
    }
    let wiped_at = wiped_at.expect("sessions must eventually be discarded");
    assert!(
        wiped_at <= SESSION_DISCARD_TIME,
        "L-2 regression: current (born t=0) wiped at {wiped_at} ns, \
         must be ≤ {SESSION_DISCARD_TIME} ns; unconfirmed `next` delayed it"
    );
}
