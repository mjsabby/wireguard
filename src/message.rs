//! Wire formats: parsing and building the four WireGuard message types
//! (whitepaper §5.4).
//!
//! Parsing is strict — exact lengths for the fixed-size handshake
//! messages, minimum length for transport data, and the three reserved
//! bytes must be zero — and total: every input either parses or returns
//! [`Error::InvalidPacket`]; nothing panics, nothing is copied.

use crate::Error;
use crate::consts::{
    COOKIE_REPLY_LEN, HANDSHAKE_INITIATION_LEN, HANDSHAKE_RESPONSE_LEN, TRANSPORT_OVERHEAD,
};

/// Message type byte of a handshake initiation.
pub const TYPE_HANDSHAKE_INITIATION: u8 = 1;
/// Message type byte of a handshake response.
pub const TYPE_HANDSHAKE_RESPONSE: u8 = 2;
/// Message type byte of a cookie reply.
pub const TYPE_COOKIE_REPLY: u8 = 3;
/// Message type byte of transport data.
pub const TYPE_TRANSPORT_DATA: u8 = 4;

/// Bytes of `msg` covered by `mac1` (everything before the macs).
const INIT_ALPHA_LEN: usize = HANDSHAKE_INITIATION_LEN - 32;
const RESP_ALPHA_LEN: usize = HANDSHAKE_RESPONSE_LEN - 32;

/// A parsed handshake initiation (type 1, 148 bytes).
#[derive(Debug)]
pub struct HandshakeInitiation<'a> {
    /// The initiator's session index (`I_i`).
    pub sender_index: u32,
    /// Unencrypted ephemeral public key.
    pub ephemeral: &'a [u8; 32],
    /// `Aead(κ, 0, S_pub_i, H)`: 32 + 16 bytes.
    pub encrypted_static: &'a [u8; 48],
    /// `Aead(κ, 0, Timestamp(), H)`: 12 + 16 bytes.
    pub encrypted_timestamp: &'a [u8; 28],
    /// First MAC; keyed by `Hash(Label-Mac1 ∥ our_public)`.
    pub mac1: &'a [u8; 16],
    /// Second MAC; keyed by a cookie when under load, else zero.
    pub mac2: &'a [u8; 16],
    /// All bytes before `mac1` (the `msgα` MAC input).
    pub alpha: &'a [u8],
    /// All bytes before `mac2` (the `msgβ` MAC input).
    pub beta: &'a [u8],
}

/// A parsed handshake response (type 2, 92 bytes).
#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    /// The responder's session index (`I_r`).
    pub sender_index: u32,
    /// Echo of the initiator's session index (`I_i`).
    pub receiver_index: u32,
    /// Unencrypted ephemeral public key.
    pub ephemeral: &'a [u8; 32],
    /// `Aead(κ, 0, ε, H)`: just the 16-byte tag.
    pub encrypted_nothing: &'a [u8; 16],
    /// First MAC.
    pub mac1: &'a [u8; 16],
    /// Second MAC.
    pub mac2: &'a [u8; 16],
    /// All bytes before `mac1`.
    pub alpha: &'a [u8],
    /// All bytes before `mac2`.
    pub beta: &'a [u8],
}

/// A parsed cookie reply (type 3, 64 bytes).
#[derive(Debug)]
pub struct CookieReply<'a> {
    /// The index of the session/handshake this replies to.
    pub receiver_index: u32,
    /// Random XChaCha20 nonce.
    pub nonce: &'a [u8; 24],
    /// `Xaead(...)` of the 16-byte cookie: 16 + 16 bytes.
    pub encrypted_cookie: &'a [u8; 32],
}

/// A parsed transport data message (type 4, ≥ 32 bytes).
#[derive(Debug)]
pub struct TransportData<'a> {
    /// The receiver-side session index.
    pub receiver_index: u32,
    /// AEAD nonce counter.
    pub counter: u64,
    /// Ciphertext plus tag (≥ 16 bytes).
    pub ciphertext: &'a [u8],
}

/// Any well-formed WireGuard datagram.
#[derive(Debug)]
pub enum Packet<'a> {
    /// Type 1.
    HandshakeInitiation(HandshakeInitiation<'a>),
    /// Type 2.
    HandshakeResponse(HandshakeResponse<'a>),
    /// Type 3.
    CookieReply(CookieReply<'a>),
    /// Type 4.
    TransportData(TransportData<'a>),
}

/// Split off a fixed-size chunk, mapping failure to `InvalidPacket`.
#[inline]
fn take<const N: usize>(bytes: &[u8]) -> Result<(&[u8; N], &[u8]), Error> {
    bytes.split_first_chunk::<N>().ok_or(Error::InvalidPacket)
}

fn le_u32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// Parse a datagram into a typed view. Borrow-only, total, strict.
///
/// # Errors
/// [`Error::InvalidPacket`] for anything that is not a structurally valid
/// WireGuard message.
pub fn parse(datagram: &[u8]) -> Result<Packet<'_>, Error> {
    let (type_word, _) = take::<4>(datagram)?;
    // The first four bytes read as a little-endian u32 must equal the type
    // byte: the three reserved bytes are required to be zero.
    match le_u32(type_word) {
        t if t == u32::from(TYPE_HANDSHAKE_INITIATION) => {
            if datagram.len() != HANDSHAKE_INITIATION_LEN {
                return Err(Error::InvalidPacket);
            }
            let alpha = datagram.get(..INIT_ALPHA_LEN).ok_or(Error::InvalidPacket)?;
            let beta = datagram
                .get(..INIT_ALPHA_LEN + 16)
                .ok_or(Error::InvalidPacket)?;
            let rest = datagram.get(4..).ok_or(Error::InvalidPacket)?;
            let (sender, rest) = take::<4>(rest)?;
            let (ephemeral, rest) = take::<32>(rest)?;
            let (encrypted_static, rest) = take::<48>(rest)?;
            let (encrypted_timestamp, rest) = take::<28>(rest)?;
            let (mac1, rest) = take::<16>(rest)?;
            let (mac2, rest) = take::<16>(rest)?;
            if !rest.is_empty() {
                return Err(Error::Internal); // unreachable: length checked
            }
            Ok(Packet::HandshakeInitiation(HandshakeInitiation {
                sender_index: le_u32(sender),
                ephemeral,
                encrypted_static,
                encrypted_timestamp,
                mac1,
                mac2,
                alpha,
                beta,
            }))
        }
        t if t == u32::from(TYPE_HANDSHAKE_RESPONSE) => {
            if datagram.len() != HANDSHAKE_RESPONSE_LEN {
                return Err(Error::InvalidPacket);
            }
            let alpha = datagram.get(..RESP_ALPHA_LEN).ok_or(Error::InvalidPacket)?;
            let beta = datagram
                .get(..RESP_ALPHA_LEN + 16)
                .ok_or(Error::InvalidPacket)?;
            let rest = datagram.get(4..).ok_or(Error::InvalidPacket)?;
            let (sender, rest) = take::<4>(rest)?;
            let (receiver, rest) = take::<4>(rest)?;
            let (ephemeral, rest) = take::<32>(rest)?;
            let (encrypted_nothing, rest) = take::<16>(rest)?;
            let (mac1, rest) = take::<16>(rest)?;
            let (mac2, rest) = take::<16>(rest)?;
            if !rest.is_empty() {
                return Err(Error::Internal);
            }
            Ok(Packet::HandshakeResponse(HandshakeResponse {
                sender_index: le_u32(sender),
                receiver_index: le_u32(receiver),
                ephemeral,
                encrypted_nothing,
                mac1,
                mac2,
                alpha,
                beta,
            }))
        }
        t if t == u32::from(TYPE_COOKIE_REPLY) => {
            if datagram.len() != COOKIE_REPLY_LEN {
                return Err(Error::InvalidPacket);
            }
            let rest = datagram.get(4..).ok_or(Error::InvalidPacket)?;
            let (receiver, rest) = take::<4>(rest)?;
            let (nonce, rest) = take::<24>(rest)?;
            let (encrypted_cookie, rest) = take::<32>(rest)?;
            if !rest.is_empty() {
                return Err(Error::Internal);
            }
            Ok(Packet::CookieReply(CookieReply {
                receiver_index: le_u32(receiver),
                nonce,
                encrypted_cookie,
            }))
        }
        t if t == u32::from(TYPE_TRANSPORT_DATA) => {
            if datagram.len() < TRANSPORT_OVERHEAD {
                return Err(Error::InvalidPacket);
            }
            let rest = datagram.get(4..).ok_or(Error::InvalidPacket)?;
            let (receiver, rest) = take::<4>(rest)?;
            let (counter, ciphertext) = take::<8>(rest)?;
            Ok(Packet::TransportData(TransportData {
                receiver_index: le_u32(receiver),
                counter: u64::from_le_bytes(*counter),
                ciphertext,
            }))
        }
        _ => Err(Error::InvalidPacket),
    }
}

/// A cheap routing summary of a datagram, for callers that manage many
/// peers and need to demultiplex before involving any [`crate::Tunnel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// Handshake initiation: route by trying configured peers (the inner
    /// static key is only revealed by processing it).
    HandshakeInitiation {
        /// The initiator's chosen session index.
        sender_index: u32,
    },
    /// Handshake response: route to the tunnel whose in-flight initiation
    /// used `receiver_index`.
    HandshakeResponse {
        /// The responder's session index.
        sender_index: u32,
        /// Our in-flight handshake index.
        receiver_index: u32,
    },
    /// Cookie reply: route like a response.
    CookieReply {
        /// Our handshake/session index.
        receiver_index: u32,
    },
    /// Transport data: route to the tunnel owning `receiver_index`.
    TransportData {
        /// Our session index.
        receiver_index: u32,
        /// The transport counter (pre-authentication: informational only).
        counter: u64,
    },
}

/// Classify a datagram without copying or verifying anything.
///
/// # Errors
/// [`Error::InvalidPacket`] as for [`parse`].
pub fn peek(datagram: &[u8]) -> Result<PacketKind, Error> {
    Ok(match parse(datagram)? {
        Packet::HandshakeInitiation(m) => PacketKind::HandshakeInitiation {
            sender_index: m.sender_index,
        },
        Packet::HandshakeResponse(m) => PacketKind::HandshakeResponse {
            sender_index: m.sender_index,
            receiver_index: m.receiver_index,
        },
        Packet::CookieReply(m) => PacketKind::CookieReply {
            receiver_index: m.receiver_index,
        },
        Packet::TransportData(m) => PacketKind::TransportData {
            receiver_index: m.receiver_index,
            counter: m.counter,
        },
    })
}

/// Write a message header (type byte + three zero reserved bytes).
fn write_header(out: &mut [u8], msg_type: u8) -> Result<(), Error> {
    let (head, _) = out.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *head = [msg_type, 0, 0, 0];
    Ok(())
}

/// Assemble a handshake initiation into `out` (mac fields zeroed; the
/// cookie layer fills them). Returns the 148-byte message slice.
///
/// # Errors
/// [`Error::BufferTooSmall`].
pub fn build_initiation<'a>(
    out: &'a mut [u8],
    sender_index: u32,
    ephemeral: &[u8; 32],
    encrypted_static: &[u8; 48],
    encrypted_timestamp: &[u8; 28],
) -> Result<&'a mut [u8], Error> {
    let msg = out
        .get_mut(..HANDSHAKE_INITIATION_LEN)
        .ok_or(Error::BufferTooSmall)?;
    msg.fill(0);
    write_header(msg, TYPE_HANDSHAKE_INITIATION)?;
    let rest = msg.get_mut(4..).ok_or(Error::Internal)?;
    let (sender, rest) = rest.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *sender = sender_index.to_le_bytes();
    let (eph, rest) = rest.split_first_chunk_mut::<32>().ok_or(Error::Internal)?;
    *eph = *ephemeral;
    let (st, rest) = rest.split_first_chunk_mut::<48>().ok_or(Error::Internal)?;
    *st = *encrypted_static;
    let (ts, _macs) = rest.split_first_chunk_mut::<28>().ok_or(Error::Internal)?;
    *ts = *encrypted_timestamp;
    Ok(msg)
}

/// Assemble a handshake response into `out` (macs zeroed). Returns the
/// 92-byte message slice.
///
/// # Errors
/// [`Error::BufferTooSmall`].
pub fn build_response<'a>(
    out: &'a mut [u8],
    sender_index: u32,
    receiver_index: u32,
    ephemeral: &[u8; 32],
    encrypted_nothing: &[u8; 16],
) -> Result<&'a mut [u8], Error> {
    let msg = out
        .get_mut(..HANDSHAKE_RESPONSE_LEN)
        .ok_or(Error::BufferTooSmall)?;
    msg.fill(0);
    write_header(msg, TYPE_HANDSHAKE_RESPONSE)?;
    let rest = msg.get_mut(4..).ok_or(Error::Internal)?;
    let (sender, rest) = rest.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *sender = sender_index.to_le_bytes();
    let (receiver, rest) = rest.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *receiver = receiver_index.to_le_bytes();
    let (eph, rest) = rest.split_first_chunk_mut::<32>().ok_or(Error::Internal)?;
    *eph = *ephemeral;
    let (nothing, _macs) = rest.split_first_chunk_mut::<16>().ok_or(Error::Internal)?;
    *nothing = *encrypted_nothing;
    Ok(msg)
}

/// Assemble a cookie reply into `out`. Returns the 64-byte message slice.
///
/// # Errors
/// [`Error::BufferTooSmall`].
pub fn build_cookie_reply<'a>(
    out: &'a mut [u8],
    receiver_index: u32,
    nonce: &[u8; 24],
    encrypted_cookie: &[u8; 32],
) -> Result<&'a mut [u8], Error> {
    let msg = out
        .get_mut(..COOKIE_REPLY_LEN)
        .ok_or(Error::BufferTooSmall)?;
    msg.fill(0);
    write_header(msg, TYPE_COOKIE_REPLY)?;
    let rest = msg.get_mut(4..).ok_or(Error::Internal)?;
    let (receiver, rest) = rest.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *receiver = receiver_index.to_le_bytes();
    let (n, rest) = rest.split_first_chunk_mut::<24>().ok_or(Error::Internal)?;
    *n = *nonce;
    let (cookie, _) = rest.split_first_chunk_mut::<32>().ok_or(Error::Internal)?;
    *cookie = *encrypted_cookie;
    Ok(msg)
}

/// Write the 16-byte transport header; the ciphertext is sealed in place
/// after it.
///
/// # Errors
/// [`Error::BufferTooSmall`].
pub fn write_transport_header(
    out: &mut [u8],
    receiver_index: u32,
    counter: u64,
) -> Result<(), Error> {
    if out.len() < TRANSPORT_OVERHEAD {
        return Err(Error::BufferTooSmall);
    }
    write_header(out, TYPE_TRANSPORT_DATA)?;
    let rest = out.get_mut(4..).ok_or(Error::Internal)?;
    let (receiver, rest) = rest.split_first_chunk_mut::<4>().ok_or(Error::Internal)?;
    *receiver = receiver_index.to_le_bytes();
    let (ctr, _) = rest.split_first_chunk_mut::<8>().ok_or(Error::Internal)?;
    *ctr = counter.to_le_bytes();
    Ok(())
}

/// The two 16-byte MAC slots at the tail of a handshake message, mutable,
/// plus the `alpha`/`beta` lengths. Works for both initiation (148) and
/// response (92) messages.
///
/// # Errors
/// [`Error::InvalidPacket`] if `msg` is not handshake-message sized.
pub fn mac_slots(msg: &mut [u8]) -> Result<MacSlots<'_>, Error> {
    let len = msg.len();
    if len != HANDSHAKE_INITIATION_LEN && len != HANDSHAKE_RESPONSE_LEN {
        return Err(Error::InvalidPacket);
    }
    let beta_len = len.checked_sub(16).ok_or(Error::Internal)?;
    let alpha_len = len.checked_sub(32).ok_or(Error::Internal)?;
    let (body, mac2) = msg.split_at_mut_checked(beta_len).ok_or(Error::Internal)?;
    let (alpha, mac1) = body
        .split_at_mut_checked(alpha_len)
        .ok_or(Error::Internal)?;
    let mac1: &mut [u8; 16] = mac1.try_into().map_err(|_| Error::Internal)?;
    let mac2: &mut [u8; 16] = mac2.try_into().map_err(|_| Error::Internal)?;
    Ok(MacSlots { alpha, mac1, mac2 })
}

/// Mutable decomposition of a handshake message for MAC filling.
#[derive(Debug)]
pub struct MacSlots<'a> {
    /// Everything before `mac1` (the `msgα` input; `msgβ` is
    /// `alpha ∥ mac1`).
    pub alpha: &'a mut [u8],
    /// The `mac1` slot.
    pub mac1: &'a mut [u8; 16],
    /// The `mac2` slot.
    pub mac2: &'a mut [u8; 16],
}

/// Recover the true length of the IP packet at the start of a decrypted
/// transport payload, so WireGuard's zero padding (whitepaper §5.4.6) can
/// be trimmed: reads the IPv4 *Total Length* or IPv6 *Payload Length*
/// field. Returns `None` if the bytes are not a plausible IP packet (not
/// v4/v6, header truncated, or claimed length exceeding the payload).
#[must_use]
pub fn ip_packet_len(payload: &[u8]) -> Option<usize> {
    let version = payload.first()? >> 4;
    let claimed = match version {
        4 => {
            let (len_bytes, _) = payload.get(2..)?.split_first_chunk::<2>()?;
            let total = usize::from(u16::from_be_bytes(*len_bytes));
            (total >= 20).then_some(total)?
        }
        6 => {
            let (len_bytes, _) = payload.get(4..)?.split_first_chunk::<2>()?;
            usize::from(u16::from_be_bytes(*len_bytes)).checked_add(40)?
        }
        _ => return None,
    };
    (claimed <= payload.len()).then_some(claimed)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::panic
    )]
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn valid_initiation() -> Vec<u8> {
        let mut out = vec![0u8; HANDSHAKE_INITIATION_LEN];
        build_initiation(&mut out, 0x11223344, &[0xaa; 32], &[0xbb; 48], &[0xcc; 28]).unwrap();
        out
    }

    #[test]
    fn initiation_roundtrip() {
        let buf = valid_initiation();
        match parse(&buf).unwrap() {
            Packet::HandshakeInitiation(m) => {
                assert_eq!(m.sender_index, 0x11223344);
                assert_eq!(m.ephemeral, &[0xaa; 32]);
                assert_eq!(m.encrypted_static, &[0xbb; 48]);
                assert_eq!(m.encrypted_timestamp, &[0xcc; 28]);
                assert_eq!(m.mac1, &[0; 16]);
                assert_eq!(m.mac2, &[0; 16]);
                assert_eq!(m.alpha.len(), 116);
                assert_eq!(m.beta.len(), 132);
                assert_eq!(&m.beta[..116], m.alpha);
            }
            other => panic!("wrong variant {other:?}"),
        }
        assert_eq!(
            peek(&buf).unwrap(),
            PacketKind::HandshakeInitiation {
                sender_index: 0x11223344
            }
        );
    }

    #[test]
    fn response_roundtrip() {
        let mut out = vec![0u8; HANDSHAKE_RESPONSE_LEN];
        build_response(&mut out, 7, 9, &[0xee; 32], &[0xdd; 16]).unwrap();
        match parse(&out).unwrap() {
            Packet::HandshakeResponse(m) => {
                assert_eq!(m.sender_index, 7);
                assert_eq!(m.receiver_index, 9);
                assert_eq!(m.ephemeral, &[0xee; 32]);
                assert_eq!(m.encrypted_nothing, &[0xdd; 16]);
                assert_eq!(m.alpha.len(), 60);
                assert_eq!(m.beta.len(), 76);
            }
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn cookie_reply_roundtrip() {
        let mut out = vec![0u8; COOKIE_REPLY_LEN];
        build_cookie_reply(&mut out, 0xdeadbeef, &[9; 24], &[8; 32]).unwrap();
        match parse(&out).unwrap() {
            Packet::CookieReply(m) => {
                assert_eq!(m.receiver_index, 0xdeadbeef);
                assert_eq!(m.nonce, &[9; 24]);
                assert_eq!(m.encrypted_cookie, &[8; 32]);
            }
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn transport_roundtrip_and_min_length() {
        let mut out = vec![0u8; 64];
        write_transport_header(&mut out, 5, u64::MAX - 1).unwrap();
        match parse(&out).unwrap() {
            Packet::TransportData(m) => {
                assert_eq!(m.receiver_index, 5);
                assert_eq!(m.counter, u64::MAX - 1);
                assert_eq!(m.ciphertext.len(), 48);
            }
            other => panic!("wrong variant {other:?}"),
        }
        // Exactly 32 bytes (keepalive) parses; 31 does not.
        assert!(parse(&out[..32]).is_ok());
        assert!(matches!(parse(&out[..31]), Err(Error::InvalidPacket)));
    }

    #[test]
    fn reserved_bytes_must_be_zero() {
        for byte in 1..4 {
            let mut buf = valid_initiation();
            buf[byte] = 1;
            assert!(matches!(parse(&buf), Err(Error::InvalidPacket)), "{byte}");
        }
    }

    #[test]
    fn unknown_types_rejected() {
        for t in [0u8, 5, 6, 100, 255] {
            let mut buf = valid_initiation();
            buf[0] = t;
            assert!(matches!(parse(&buf), Err(Error::InvalidPacket)), "{t}");
        }
    }

    #[test]
    fn every_truncation_and_extension_rejected() {
        let init = valid_initiation();
        for keep in 0..init.len() {
            assert!(
                matches!(parse(&init[..keep]), Err(Error::InvalidPacket)),
                "truncation to {keep}"
            );
        }
        let mut extended = init.clone();
        extended.push(0);
        assert!(matches!(parse(&extended), Err(Error::InvalidPacket)));

        let mut resp = vec![0u8; HANDSHAKE_RESPONSE_LEN];
        build_response(&mut resp, 1, 2, &[0; 32], &[0; 16]).unwrap();
        for keep in 0..resp.len() {
            assert!(matches!(parse(&resp[..keep]), Err(Error::InvalidPacket)));
        }

        let mut cookie = vec![0u8; COOKIE_REPLY_LEN];
        build_cookie_reply(&mut cookie, 1, &[0; 24], &[0; 32]).unwrap();
        for keep in 0..cookie.len() {
            assert!(matches!(parse(&cookie[..keep]), Err(Error::InvalidPacket)));
        }
    }

    #[test]
    fn builders_report_small_buffers() {
        let mut tiny = [0u8; 10];
        assert!(matches!(
            build_initiation(&mut tiny, 0, &[0; 32], &[0; 48], &[0; 28]),
            Err(Error::BufferTooSmall)
        ));
        assert!(matches!(
            build_response(&mut tiny, 0, 0, &[0; 32], &[0; 16]),
            Err(Error::BufferTooSmall)
        ));
        assert!(matches!(
            build_cookie_reply(&mut tiny, 0, &[0; 24], &[0; 32]),
            Err(Error::BufferTooSmall)
        ));
        assert!(matches!(
            write_transport_header(&mut tiny, 0, 0),
            Err(Error::BufferTooSmall)
        ));
    }

    #[test]
    fn ip_packet_len_parses_v4_v6_and_rejects_junk() {
        // IPv4: version 4, IHL 5, total length 21, one padding byte after.
        let mut v4 = vec![0u8; 32];
        v4[0] = 0x45;
        v4[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert_eq!(ip_packet_len(&v4), Some(21));
        // IPv6: payload length 8 → 48 total.
        let mut v6 = vec![0u8; 64];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(ip_packet_len(&v6), Some(48));
        // Claimed length beyond the buffer: rejected.
        let mut lying = vec![0u8; 32];
        lying[0] = 0x45;
        lying[2..4].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(ip_packet_len(&lying), None);
        // v4 total length below the minimum header: rejected.
        let mut tiny = vec![0u8; 32];
        tiny[0] = 0x45;
        tiny[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(ip_packet_len(&tiny), None);
        // Not IP at all / empty / truncated headers.
        assert_eq!(ip_packet_len(&[]), None);
        assert_eq!(ip_packet_len(&[0x45]), None);
        assert_eq!(ip_packet_len(&[0x70; 16]), None);
        assert_eq!(ip_packet_len(&[0x60, 0, 0, 0, 9]), None);
    }

    #[test]
    fn mac_slots_decompose_correctly() {
        let mut init = valid_initiation();
        {
            let slots = mac_slots(&mut init).unwrap();
            assert_eq!(slots.alpha.len(), 116);
            slots.mac1.fill(0xaa);
            slots.mac2.fill(0xbb);
        }
        match parse(&init).unwrap() {
            Packet::HandshakeInitiation(m) => {
                assert_eq!(m.mac1, &[0xaa; 16]);
                assert_eq!(m.mac2, &[0xbb; 16]);
            }
            other => panic!("wrong variant {other:?}"),
        }
        let mut not_handshake = vec![0u8; 64];
        assert!(matches!(
            mac_slots(&mut not_handshake),
            Err(Error::InvalidPacket)
        ));
    }
}
