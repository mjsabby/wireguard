//! The DoS-mitigation cookie dance under load (whitepaper §5.3, §5.4.4,
//! §5.4.7, §6.6).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::new_pair;
use wireguard_sans_io::{Error, PollOutput, Received, SendReason, consts};

#[test]
fn full_cookie_dance_under_load() {
    let mut p = new_pair(30);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let remote = b"203.0.113.7:51820";

    // A initiates; B is under load and the initiation carries no mac2.
    let init1 =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let cookie_reply = match p
        .b
        .decapsulate(now, remote, true, &init1, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("expected cookie reply, got {other:?}"),
    };
    assert_eq!(cookie_reply.len(), consts::COOKIE_REPLY_LEN);
    assert_eq!(cookie_reply[0], 3);
    assert_eq!(p.b.stats().cookies_sent, 1);
    assert!(!p.b.is_established(), "no session state from a cookie path");

    // A stores the cookie quietly (§6.6: no immediate retransmission).
    assert!(matches!(
        p.a.decapsulate(now, remote, false, &cookie_reply, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::CookieStored
    ));
    assert_eq!(p.a.stats().cookies_received, 1);

    // The Rekey-Timeout retransmission now carries mac2 and B (still
    // under load) accepts and responds.
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(retry_at, &mut wire, &mut p.rng).unwrap() {
        PollOutput::Send(w, SendReason::HandshakeRetransmit) => w.to_vec(),
        other => panic!("expected retransmit, got {other:?}"),
    };
    let mac2 = &init2[consts::HANDSHAKE_INITIATION_LEN - 16..];
    assert!(mac2.iter().any(|&b| b != 0), "retry must carry mac2");
    let resp = match p
        .b
        .decapsulate(retry_at, remote, true, &init2, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("expected response, got {other:?}"),
    };
    assert!(matches!(
        p.a.decapsulate(retry_at, remote, false, &resp, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::HandshakeComplete
    ));
}

#[test]
fn mac2_is_bound_to_the_remote_address() {
    let mut p = new_pair(31);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);

    let init1 =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let cookie_reply = match p
        .b
        .decapsulate(now, b"1.2.3.4:1111", true, &init1, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    p.a.decapsulate(now, b"", false, &cookie_reply, &mut scratch, &mut p.rng)
        .unwrap();
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(retry_at, &mut wire, &mut p.rng).unwrap() {
        PollOutput::Send(w, _) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    // Same datagram "arriving" from a different source address: the
    // cookie (and thus mac2) no longer proves IP ownership → B answers
    // with a fresh cookie reply rather than doing the DH work.
    match p
        .b
        .decapsulate(
            retry_at,
            b"6.6.6.6:666",
            true,
            &init2,
            &mut scratch,
            &mut p.rng,
        )
        .unwrap()
    {
        Received::Reply(w) => assert_eq!(w[0], 3, "cookie reply, not response"),
        other => panic!("{other:?}"),
    }
    // From the right address it is processed.
    match p
        .b
        .decapsulate(
            retry_at,
            b"1.2.3.4:1111",
            true,
            &init2,
            &mut scratch,
            &mut p.rng,
        )
        .unwrap()
    {
        Received::Reply(w) => assert_eq!(w[0], 2, "handshake response"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn not_under_load_ignores_missing_mac2() {
    let mut p = new_pair(32);
    p.establish();
    p.assert_roundtrip_a_to_b(b"no cookies involved");
    assert_eq!(p.a.stats().cookies_received, 0);
    assert_eq!(p.b.stats().cookies_sent, 0);
}

#[test]
fn expired_cookies_stop_filling_mac2() {
    let mut p = new_pair(33);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init1 =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let cookie_reply = match p
        .b
        .decapsulate(now, b"r", true, &init1, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    p.a.decapsulate(now, b"r", false, &cookie_reply, &mut scratch, &mut p.rng)
        .unwrap();
    // Two minutes later the stored cookie has expired: a fresh initiation
    // goes out with mac2 = 0 again.
    let later = p.clock.advance(consts::COOKIE_LIFETIME);
    let init =
        p.a.initiate_handshake(later, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let mac2 = &init[consts::HANDSHAKE_INITIATION_LEN - 16..];
    assert!(
        mac2.iter().all(|&b| b == 0),
        "expired cookie must not be used"
    );
}

#[test]
fn forged_cookie_replies_are_rejected_and_change_nothing() {
    let mut p = new_pair(34);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let cookie_reply = match p
        .b
        .decapsulate(now, b"r", true, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    // Flip each byte of the encrypted section: all rejected.
    for byte in 8..consts::COOKIE_REPLY_LEN {
        let mut bad = cookie_reply.clone();
        bad[byte] ^= 1;
        assert_eq!(
            p.a.decapsulate(now, b"r", false, &bad, &mut scratch, &mut p.rng)
                .err(),
            Some(Error::InvalidCookie),
            "byte {byte}"
        );
    }
    assert_eq!(p.a.stats().cookies_received, 0);
    // A cookie reply for an unknown receiver index is rejected earlier.
    let mut bad = cookie_reply.clone();
    bad[4] ^= 0x55;
    assert_eq!(
        p.a.decapsulate(now, b"r", false, &bad, &mut scratch, &mut p.rng)
            .err(),
        Some(Error::UnknownReceiverIndex)
    );
    // The real one still works after all that.
    assert!(matches!(
        p.a.decapsulate(now, b"r", false, &cookie_reply, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::CookieStored
    ));
}

#[test]
fn under_load_initiations_with_valid_mac2_skip_the_dance() {
    // Once A has a fresh cookie, every handshake message it sends within
    // the cookie lifetime is processed by a loaded B on first delivery.
    let mut p = new_pair(35);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let remote = b"9.9.9.9:9";
    let init1 =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let reply = match p
        .b
        .decapsulate(now, remote, true, &init1, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    p.a.decapsulate(now, remote, false, &reply, &mut scratch, &mut p.rng)
        .unwrap();
    let t1 = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(t1, &mut wire, &mut p.rng).unwrap() {
        PollOutput::Send(w, _) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    let resp = match p
        .b
        .decapsulate(t1, remote, true, &init2, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    // Note: A consumes the response NOT under load. (A loaded receiver
    // would be entitled to demand mac2 on the response too — covered by
    // `loaded_initiator_cookies_responses`.)
    p.a.decapsulate(t1, remote, false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    assert!(p.a.is_established());
    assert_eq!(
        p.b.stats().cookies_sent,
        1,
        "only the first round needed a cookie"
    );
}

#[test]
fn loaded_initiator_cookies_responses() {
    // The under-load mac2 rule applies to handshake *responses* as well
    // (whitepaper §5.3: "either an initiation or a response handshake
    // message"): a loaded initiator answers a mac2-less response with a
    // cookie reply rather than finishing the handshake.
    let mut p = new_pair(36);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let resp = match p
        .b
        .decapsulate(now, b"b-addr", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    match p
        .a
        .decapsulate(now, b"b-addr", true, &resp, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => assert_eq!(w[0], 3, "cookie reply to the responder"),
        other => panic!("{other:?}"),
    }
    assert!(
        !p.a.is_established(),
        "handshake deliberately not completed"
    );
    // The in-flight handshake is still alive: the same response delivered
    // when no longer loaded completes it.
    assert!(matches!(
        p.a.decapsulate(now, b"b-addr", false, &resp, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::HandshakeComplete
    ));
}
