//! Replay protection and packet reordering over the wire, plus handshake
//! replay defences (timestamps, response one-shot).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::new_pair;
use wireguard_sans_io::{Error, Received};

#[test]
fn duplicate_transport_datagrams_rejected() {
    let mut p = new_pair(20);
    p.establish();
    let wire = p.seal_from_a(b"once only");
    let got = p.open_at_b(&wire);
    assert_eq!(&got[..9], b"once only");
    // Byte-identical replay: rejected by the replay window, even though
    // the AEAD would verify.
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wire, &mut out, &mut p.rng)
            .err(),
        Some(Error::Replay)
    );
    assert_eq!(p.b.stats().replays_dropped, 1);
    // And again later in time.
    p.clock.advance(common::S);
    let now = p.clock.now();
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wire, &mut out, &mut p.rng)
            .err(),
        Some(Error::Replay)
    );
}

#[test]
fn reordered_delivery_within_window_is_accepted() {
    let mut p = new_pair(21);
    p.establish();
    // Encrypt 64 datagrams, deliver them in reverse order.
    let wires: Vec<(usize, Vec<u8>)> = (0..64)
        .map(|i| {
            let payload = format!("packet number {i:03}");
            (i, p.seal_from_a(payload.as_bytes()))
        })
        .collect();
    for (i, wire) in wires.iter().rev() {
        let got = p.open_at_b(wire);
        assert_eq!(&got[..17], format!("packet number {i:03}").as_bytes());
    }
    // Every single one replayed afterwards is rejected.
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    for (_, wire) in &wires {
        assert_eq!(
            p.b.decapsulate(now, b"", false, wire, &mut out, &mut p.rng)
                .err(),
            Some(Error::Replay)
        );
    }
    assert_eq!(p.b.stats().replays_dropped, 64);
}

#[test]
fn counters_far_behind_the_window_are_rejected() {
    let mut p = new_pair(22);
    p.establish();
    let early = p.seal_from_a(b"very early");
    // Push the counter far past the window (2048).
    for _ in 0..2100 {
        let w = p.seal_from_a(b"filler");
        p.open_at_b(&w);
    }
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &early, &mut out, &mut p.rng)
            .err(),
        Some(Error::Replay),
        "counter 0 is far below the window and must be dropped"
    );
}

#[test]
fn replayed_initiation_is_rejected_by_timestamp() {
    let mut p = new_pair(23);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    // First copy: accepted, response produced.
    assert!(matches!(
        p.b.decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::Reply(_)
    ));
    // Byte-identical replay: timestamp is not strictly greater → rejected,
    // and crucially NO response is generated (whitepaper §5.1: replays
    // must not make the responder regenerate session state).
    assert_eq!(
        p.b.decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::ReplayedTimestamp)
    );
    // Same one hour later.
    let later = p.clock.advance(3600 * common::S);
    assert_eq!(
        p.b.decapsulate(later, b"", false, &init, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::ReplayedTimestamp)
    );
}

#[test]
fn older_timestamp_rejected_even_if_never_seen() {
    // Two initiations created at t0 and t1 > t0; deliver the newer one
    // first. The older one must then be rejected (monotonicity, not just
    // uniqueness).
    let mut p = new_pair(24);
    let now0 = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init_old =
        p.a.initiate_handshake(now0, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    // 30s later (well past whitening granularity and pacing).
    let now1 = p.clock.advance(30 * common::S);
    let init_new =
        p.a.initiate_handshake(now1, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    assert!(matches!(
        p.b.decapsulate(now1, b"", false, &init_new, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::Reply(_)
    ));
    assert_eq!(
        p.b.decapsulate(now1, b"", false, &init_old, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::ReplayedTimestamp)
    );
}

#[test]
fn handshake_response_is_single_use() {
    let mut p = new_pair(25);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let resp = match p
        .b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::HandshakeComplete
    ));
    // Replaying the response: no in-flight handshake matches any more.
    assert_eq!(
        p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::NoPendingHandshake)
    );
}

#[test]
fn response_to_superseded_initiation_is_rejected() {
    // A retransmits (new ephemeral + index); a response to the FIRST
    // initiation must no longer complete.
    let mut p = new_pair(26);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init1 =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let resp1 = match p
        .b
        .decapsulate(now, b"", false, &init1, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    // 5+s later the retransmission replaces the in-flight state.
    let later = p.clock.advance(6 * common::S);
    let _init2 =
        p.a.initiate_handshake(later, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    assert_eq!(
        p.a.decapsulate(later, b"", false, &resp1, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::NoPendingHandshake)
    );
}

#[test]
fn unknown_receiver_index_rejected() {
    let mut p = new_pair(27);
    p.establish();
    let mut wire = p.seal_from_a(b"hello");
    // Twiddle the receiver index.
    wire[4] ^= 0xff;
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wire, &mut out, &mut p.rng)
            .err(),
        Some(Error::UnknownReceiverIndex)
    );
}

#[test]
fn counter_at_reject_after_messages_dropped_before_decryption() {
    let mut p = new_pair(28);
    p.establish();
    let mut wire = p.seal_from_a(b"x");
    // Rewrite the counter field to ≥ REJECT_AFTER_MESSAGES. The AEAD
    // would fail anyway (nonce mismatch), but the counter check must trip
    // first and is the cheap pre-authentication path.
    wire[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wire, &mut out, &mut p.rng)
            .err(),
        Some(Error::Expired)
    );
}
