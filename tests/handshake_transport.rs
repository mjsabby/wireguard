//! Core protocol flows over the public API: handshake establishment,
//! bidirectional transport, padding, PSKs, buffers, stats.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use common::{new_pair, new_pair_with};
use wireguard_sans_io::{
    Encapsulated, Error, Received, consts, ip_packet_len, peek, transport_datagram_len,
};

#[test]
fn full_handshake_and_bidirectional_transport() {
    let mut p = new_pair(1);
    p.establish();
    // A → B and B → A, various sizes incl. boundary cases.
    for len in [1usize, 15, 16, 17, 64, 255, 1024, 1420] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        p.assert_roundtrip_a_to_b(&payload);
        let wire = p.seal_from_b(&payload);
        let got = p.open_at_a(&wire);
        assert_eq!(&got[..len], payload.as_slice());
    }
    let stats = p.a.stats();
    assert_eq!(stats.handshakes_completed, 1);
    assert!(stats.tx_transport > 8);
    assert_eq!(stats.auth_failures, 0);
}

#[test]
fn handshake_wire_messages_have_spec_sizes() {
    let mut p = new_pair(2);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    let init = match p
        .a
        .encapsulate(now, b"data", &mut wire, &mut p.rng)
        .unwrap()
    {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(init.len(), consts::HANDSHAKE_INITIATION_LEN);
    assert_eq!(init[0], 1);
    assert_eq!(&init[1..4], &[0, 0, 0]);

    let mut scratch = [0u8; 2048];
    let resp = match p
        .b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(resp.len(), consts::HANDSHAKE_RESPONSE_LEN);
    assert_eq!(resp[0], 2);

    // Keepalive datagram is exactly 32 bytes; data is padded to 16.
    p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    let ka = match p.a.encapsulate(now, b"", &mut wire, &mut p.rng).unwrap() {
        Encapsulated::Transport(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(ka.len(), consts::KEEPALIVE_LEN);
    let one = match p.a.encapsulate(now, b"x", &mut wire, &mut p.rng).unwrap() {
        Encapsulated::Transport(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(one.len(), 16 + 16 + 16); // header + padded(1)=16 + tag
    assert_eq!(one.len(), transport_datagram_len(1));
}

#[test]
fn payload_not_consumed_until_established() {
    let mut p = new_pair(3);
    let now = p.clock.now();
    let mut wire = [0u8; 2048];
    // First send: initiation comes back instead of a transport message.
    assert!(matches!(
        p.a.encapsulate(now, b"hello", &mut wire, &mut p.rng)
            .unwrap(),
        Encapsulated::HandshakeInitiation(_)
    ));
    // Second immediate send: handshake in flight, payload still pending.
    assert!(matches!(
        p.a.encapsulate(now, b"hello", &mut wire, &mut p.rng),
        Err(Error::NotEstablished)
    ));
    assert!(!p.a.is_established());
}

#[test]
fn responder_cannot_send_before_confirmation() {
    let mut p = new_pair(4);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init = match p.a.encapsulate(now, b"x", &mut wire, &mut p.rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    let resp = match p
        .b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    // B (responder) has an unconfirmed session: whitepaper §5.1 forbids
    // sending transport data on it. Encapsulating from B instead begins
    // B's own handshake (roles are symmetric).
    assert!(!p.b.is_established());
    assert!(matches!(
        p.b.encapsulate(now, b"reply", &mut wire, &mut p.rng)
            .unwrap(),
        Encapsulated::HandshakeInitiation(_)
    ));
    // A completes; A's first data confirms B's session.
    p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    let data = match p
        .a
        .encapsulate(now, b"ping", &mut wire, &mut p.rng)
        .unwrap()
    {
        Encapsulated::Transport(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        p.b.decapsulate(now, b"", false, &data, &mut scratch, &mut p.rng)
            .unwrap(),
        Received::Data(_)
    ));
    assert!(p.b.is_established());
    // Now B can answer over the tunnel.
    let reply = p.seal_from_b(b"pong");
    assert_eq!(&p.open_at_a(&reply)[..4], b"pong");
}

#[test]
fn psk_pairs_interoperate_and_mismatches_fail() {
    // Matching PSK works.
    let mut p = new_pair_with(5, Some([7u8; 32]), None);
    p.establish();
    p.assert_roundtrip_a_to_b(b"psk traffic");

    // Mismatched PSK: responder produces a response the initiator rejects
    // (the responder cannot detect it; psk2 only enters at the response).
    let mut rng = wireguard_sans_io::testing::DeterministicRng::new(6);
    let a_key = wireguard_sans_io::StaticSecret::generate(&mut rng).unwrap();
    let b_key = wireguard_sans_io::StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut cfg_a = wireguard_sans_io::Config::new(a_key, b_pub);
    cfg_a.psk = wireguard_sans_io::PresharedKey::from_bytes([1; 32]);
    let mut cfg_b = wireguard_sans_io::Config::new(b_key, a_pub);
    cfg_b.psk = wireguard_sans_io::PresharedKey::from_bytes([2; 32]);
    let mut a = wireguard_sans_io::Tunnel::new(cfg_a).unwrap();
    let mut b = wireguard_sans_io::Tunnel::new(cfg_b).unwrap();
    let now = wireguard_sans_io::Now::new(0, 1_700_000_000, 0);
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init = match a.encapsulate(now, b"x", &mut wire, &mut rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    let resp = match b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        a.decapsulate(now, b"", false, &resp, &mut scratch, &mut rng)
            .err(),
        Some(Error::AuthFailure)
    );
    assert!(!a.is_established());
    assert_eq!(a.stats().auth_failures, 1);
}

#[test]
fn padding_is_transparent_with_ip_length_helper() {
    let mut p = new_pair(7);
    p.establish();
    // A 21-byte "IPv4 packet": header claims total length 21.
    let mut packet = vec![0u8; 21];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&21u16.to_be_bytes());
    packet[20] = 0xfe;
    let wire = p.seal_from_a(&packet);
    let padded = p.open_at_b(&wire);
    assert_eq!(padded.len(), 32, "21 pads to 32");
    let inner = ip_packet_len(&padded).unwrap();
    assert_eq!(&padded[..inner], packet.as_slice());
}

#[test]
fn buffer_too_small_paths_are_total() {
    let mut p = new_pair(8);
    let now = p.clock.now();
    let mut tiny = [0u8; 32];
    // Handshake needs 148 bytes.
    assert!(matches!(
        p.a.encapsulate(now, b"x", &mut tiny, &mut p.rng),
        Err(Error::BufferTooSmall)
    ));
    p.establish();
    // Transport needs transport_datagram_len(payload).
    let mut tiny = [0u8; 47];
    assert!(matches!(
        p.a.encapsulate(now, b"0123456789abcdef", &mut tiny, &mut p.rng),
        Err(Error::BufferTooSmall)
    ));
    // Decapsulate of data into a too-small plaintext buffer.
    let wire = p.seal_from_a(&[9u8; 64]);
    let mut tiny = [0u8; 16];
    assert!(matches!(
        p.b.decapsulate(p.clock.now(), b"", false, &wire, &mut tiny, &mut p.rng),
        Err(Error::BufferTooSmall)
    ));
    // The datagram is still valid and decryptable with a real buffer —
    // BufferTooSmall is pre-verification and must not advance the replay
    // window.
    let got = p.open_at_b(&wire);
    assert_eq!(got.len(), 64);
}

#[test]
fn peek_routes_all_four_message_types() {
    let mut p = new_pair(9);
    let now = p.clock.now();
    let (mut wire, mut scratch) = ([0u8; 2048], [0u8; 2048]);
    let init = match p.a.encapsulate(now, b"x", &mut wire, &mut p.rng).unwrap() {
        Encapsulated::HandshakeInitiation(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        peek(&init).unwrap(),
        wireguard_sans_io::PacketKind::HandshakeInitiation { .. }
    ));
    let resp = match p
        .b
        .decapsulate(now, b"", false, &init, &mut scratch, &mut p.rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };
    match peek(&resp).unwrap() {
        wireguard_sans_io::PacketKind::HandshakeResponse {
            sender_index: _,
            receiver_index,
        } => {
            // The response routes back by our initiation's sender index.
            match peek(&init).unwrap() {
                wireguard_sans_io::PacketKind::HandshakeInitiation { sender_index } => {
                    assert_eq!(receiver_index, sender_index);
                }
                _ => unreachable!(),
            }
        }
        other => panic!("{other:?}"),
    }
    p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    let data = p.seal_from_a(b"zz");
    assert!(matches!(
        peek(&data).unwrap(),
        wireguard_sans_io::PacketKind::TransportData { counter: 0, .. }
    ));
    assert!(matches!(peek(&[]), Err(Error::InvalidPacket)));
}

#[test]
fn sessions_rotate_and_old_session_still_decrypts_in_flight_packets() {
    let mut p = new_pair(10);
    p.establish();
    // Capture a datagram on session 1, then rekey, then deliver it late.
    let old_wire = p.seal_from_a(b"in flight from session one");
    p.clock.advance(common::S * 10);
    // Force a second handshake (A initiates explicitly).
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
    p.a.decapsulate(now, b"", false, &resp, &mut scratch, &mut p.rng)
        .unwrap();
    // New session works A→B...
    p.assert_roundtrip_a_to_b(b"fresh session traffic");
    // ...and the late packet from the previous session still decrypts.
    let got = p.open_at_b(&old_wire);
    assert_eq!(&got[..26], b"in flight from session one");
    assert_eq!(p.b.stats().handshakes_completed, 2);
}
