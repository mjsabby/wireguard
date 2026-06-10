//! Adversarial input battery: every datagram an attacker could craft must
//! be rejected without panicking, without leaking plaintext into output
//! buffers, and without corrupting tunnel state.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use common::new_pair;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Error, Received, StaticSecret, Tunnel};

/// Feed a hostile datagram; whatever happens must be an error, and the
/// output buffer must not receive any bytes.
fn must_reject(t: &mut Tunnel, now: wireguard_sans_io::Now, datagram: &[u8], what: &str) {
    let mut rng = DeterministicRng::new(0x6666);
    let mut out = vec![0xEEu8; datagram.len().max(256)];
    let r = t.decapsulate(now, b"attacker:1", false, datagram, &mut out, &mut rng);
    assert!(r.is_err(), "{what}: accepted {r:?}");
    assert!(
        out.iter().all(|&b| b == 0xEE),
        "{what}: output buffer was written on failure"
    );
}

#[test]
fn bit_flip_storm_on_every_message_type() {
    let mut p = new_pair(60);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);

    // Collect one pristine instance of each handshake message.
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

    // Every single-bit corruption of the initiation against a fresh
    // responder: all rejected (mac1 covers everything before the macs;
    // flips inside mac2 are ignored *only* when not under load, but the
    // replayed timestamp rule still rejects the duplicate).
    for byte in 0..init.len() {
        for bit in [0u8, 3, 7] {
            let mut bad = init.clone();
            bad[byte] ^= 1 << bit;
            if bad == *init {
                continue;
            }
            // mac2 is not covered by mac1 and is ignored off-load; a flip
            // confined there leaves a valid message that must then be
            // rejected as a timestamp replay (it was already consumed).
            must_reject(&mut p.b, now, &bad, &format!("init byte {byte} bit {bit}"));
        }
    }

    // Same for the response against the initiator — excluding the mac2
    // field: when not under load, mac2 is *ignored by design* (whitepaper
    // §5.4.4), so a flip confined there yields a message that correctly
    // completes the handshake. Everything covered by mac1 must reject.
    for byte in 0..resp.len() - 16 {
        for bit in [0u8, 4] {
            let mut bad = resp.clone();
            bad[byte] ^= 1 << bit;
            must_reject(&mut p.a, now, &bad, &format!("resp byte {byte} bit {bit}"));
        }
    }

    // The pristine response still completes the handshake: the storm did
    // not corrupt the in-flight state.
    assert!(matches!(
        p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::HandshakeComplete
    ));
}

#[test]
fn bit_flip_storm_on_transport_data() {
    let mut p = new_pair(61);
    p.establish();
    let wire = p.seal_from_a(b"super secret payload!");
    let now = p.clock.now();
    for byte in 0..wire.len() {
        for bit in [0u8, 7] {
            let mut bad = wire.clone();
            bad[byte] ^= 1 << bit;
            let mut out = vec![0xEEu8; 256];
            let mut rng = DeterministicRng::new(1);
            let r = p.b.decapsulate(now, b"", false, &bad, &mut out, &mut rng);
            assert!(r.is_err(), "byte {byte} bit {bit} accepted");
            assert!(
                out.iter().all(|&b| b == 0xEE),
                "byte {byte} bit {bit}: plaintext leaked to buffer on failure"
            );
        }
    }
    // Pristine datagram still decrypts: state survived ~700 forgeries.
    let got = p.open_at_b(&wire);
    assert_eq!(&got[..21], b"super secret payload!");
}

#[test]
fn truncation_and_extension_sweeps() {
    let mut p = new_pair(62);
    p.establish();
    let now = p.clock.now();
    let transport = p.seal_from_a(b"data");
    let mut messages: Vec<(&str, Vec<u8>)> = vec![("transport", transport)];
    let mut wire = [0u8; 2048];
    p.clock.advance(common::S * 6);
    let init =
        p.a.initiate_handshake(p.clock.now(), &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    messages.push(("initiation", init));

    for (name, msg) in &messages {
        for keep in 0..msg.len() {
            // Handshake messages of any wrong length are structurally
            // invalid; truncated transport is either structurally invalid
            // (< 32) or an AEAD forgery (≥ 32). All must reject.
            must_reject(
                &mut p.b,
                now,
                &msg[..keep],
                &format!("{name} truncated to {keep}"),
            );
        }
        let mut extended = msg.clone();
        extended.push(0);
        if *name != "transport" {
            must_reject(&mut p.b, now, &extended, &format!("{name} extended"));
        }
    }
}

#[test]
fn type_confusion_is_rejected() {
    let mut p = new_pair(63);
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
    // Relabel each message as every other type: length checks (and macs)
    // must kill all of them, on both ends.
    for (msg, target) in [(&init, &mut p.b), (&resp, &mut p.a)] {
        for t in [0u8, 2, 3, 4, 5, 9, 255] {
            let mut bad = msg.clone();
            if bad[0] == t {
                continue;
            }
            bad[0] = t;
            must_reject(target, now, &bad, &format!("relabelled as {t}"));
        }
    }
}

#[test]
fn initiation_from_unknown_but_valid_peer_is_rejected() {
    // Mallory KNOWS B's public key (so mac1 verifies, and the handshake
    // AEADs decrypt) but is not the configured peer: B must refuse after
    // authenticating the inner static key.
    let mut rng = DeterministicRng::new(64);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let mallory_key = StaticSecret::generate(&mut rng).unwrap();
    let b_pub = b_key.public_key();
    let mut b = Tunnel::new(Config::new(b_key, a_key.public_key())).unwrap();
    let mut mallory = Tunnel::new(Config::new(mallory_key, b_pub)).unwrap();

    let now = wireguard_sans_io::Now::new(0, 1_700_000_000, 0);
    let (mut wire, mut out) = ([0u8; 2048], [0u8; 2048]);
    let init = mallory
        .initiate_handshake(now, &mut wire, &mut rng)
        .unwrap();
    assert_eq!(
        b.decapsulate(now, b"", false, init, &mut out, &mut rng)
            .err(),
        Some(Error::UnknownPeer)
    );
    assert_eq!(b.stats().auth_failures, 1);
    assert!(!b.is_established());
}

#[test]
fn wrong_responder_initiation_fails_mac1_first() {
    // A initiation addressed to a *different* public key fails the cheap
    // mac1 check (counted separately from AEAD failures = the DoS path).
    let mut p = new_pair(65);
    let mut q = new_pair(66);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    let mut out = [0u8; 2048];
    assert_eq!(
        q.b.decapsulate(now, b"", false, &init, &mut out, &mut q.rng)
            .err(),
        Some(Error::InvalidMac1)
    );
    assert_eq!(q.b.stats().mac1_failures, 1);
    assert_eq!(q.b.stats().auth_failures, 0, "no expensive work was done");
}

#[test]
fn garbage_and_degenerate_datagrams() {
    let mut p = new_pair(67);
    p.establish();
    let now = p.clock.now();
    must_reject(&mut p.b, now, &[], "empty");
    must_reject(&mut p.b, now, &[1], "single byte");
    must_reject(&mut p.b, now, &[0; 4], "type zero");
    must_reject(&mut p.b, now, &[4, 0, 0], "truncated header");
    must_reject(&mut p.b, now, &[0xff; 4096], "4 KiB of 0xff");
    must_reject(&mut p.b, now, &[0x04; 31], "transport one byte short");
    // A datagram of zeros that parses as transport type … receiver 0.
    let mut zeros = vec![0u8; 64];
    zeros[0] = 4;
    must_reject(&mut p.b, now, &zeros, "all-zero transport");
    // Deterministic pseudo-random garbage, various lengths.
    let mut rng = DeterministicRng::new(0xbad5eed);
    for len in [5usize, 31, 32, 64, 92, 147, 148, 149, 1500] {
        for _ in 0..50 {
            let mut g = vec![0u8; len];
            use wireguard_sans_io::EntropySource;
            rng.fill(&mut g).unwrap();
            let mut out = vec![0u8; 2048];
            let mut r2 = DeterministicRng::new(1);
            // Must not panic; overwhelmingly rejects (a random 16-byte
            // mac1 forgery has probability 2^-128).
            let _ = p.b.decapsulate(now, b"", false, &g, &mut out, &mut r2);
        }
    }
    // Still fully functional afterwards.
    p.assert_roundtrip_a_to_b(b"survived the garbage storm");
}

#[test]
fn cross_tunnel_datagrams_do_not_confuse_state() {
    // Two independent pairs; datagrams from one delivered into the other.
    let mut p = new_pair(68);
    let mut q = new_pair(69);
    p.establish();
    q.establish();
    let p_wire = p.seal_from_a(b"for p only");
    let q_wire = q.seal_from_a(b"for q only");
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    let mut rng = DeterministicRng::new(2);
    // q.b sees p's datagram: unknown index or auth failure, never data.
    assert!(
        q.b.decapsulate(now, b"", false, &p_wire, &mut out, &mut rng)
            .is_err()
    );
    assert!(
        p.b.decapsulate(now, b"", false, &q_wire, &mut out, &mut rng)
            .is_err()
    );
    // Correct delivery still works.
    assert_eq!(&p.open_at_b(&p_wire)[..10], b"for p only");
    assert_eq!(&q.open_at_b(&q_wire)[..10], b"for q only");
}

#[test]
fn reflected_messages_are_rejected() {
    // Reflect every message straight back at its sender.
    let mut p = new_pair(70);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wire, &mut p.rng)
            .unwrap()
            .to_vec();
    // A's own initiation reflected to A: mac1 is keyed by B's public key,
    // A expects macs keyed by A's public key → InvalidMac1.
    must_reject(&mut p.a, now, &init, "reflected initiation");
    let resp = match p
        .b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    must_reject(&mut p.b, now, &resp, "reflected response");
    p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    // Established transport reflected to its sender: A never allocated
    // that receiver index (indices are random and independent), and even
    // a collision would fail the AEAD.
    let data = p.seal_from_a(b"boomerang");
    let mut out = vec![0xEEu8; 256];
    let r =
        p.a.decapsulate(now, b"", false, &data, &mut out, &mut p.rng);
    assert!(r.is_err(), "reflected transport accepted: {r:?}");
}

#[test]
fn errors_leave_tunnel_usable_under_interleaved_attack() {
    // Interleave valid traffic with attacks; the valid stream must be
    // completely unaffected.
    let mut p = new_pair(71);
    p.establish();
    let mut attacker_rng = DeterministicRng::new(0xa77ac);
    for i in 0..200u32 {
        let payload = format!("legit message {i}");
        p.assert_roundtrip_a_to_b(payload.as_bytes());
        // One attack per legit packet, cycling shapes.
        let now = p.clock.now();
        let mut out = vec![0u8; 512];
        let attack: Vec<u8> = match i % 4 {
            0 => {
                let mut g = vec![0u8; 148];
                use wireguard_sans_io::EntropySource;
                attacker_rng.fill(&mut g).unwrap();
                g[0] = 1;
                g[1] = 0;
                g[2] = 0;
                g[3] = 0;
                g
            }
            1 => {
                let mut t = p.seal_from_a(b"to corrupt");
                let len = t.len();
                t[len - 1] ^= 0xff;
                t
            }
            2 => vec![3u8, 0, 0, 0, 1, 2, 3, 4],
            _ => vec![2u8; 92],
        };
        let _ =
            p.b.decapsulate(now, b"x", false, &attack, &mut out, &mut attacker_rng);
    }
    let s = p.b.stats();
    assert_eq!(s.handshakes_completed, 1, "attacks must not force rekeys");
    assert!(s.auth_failures + s.mac1_failures + s.replays_dropped > 0);
}
