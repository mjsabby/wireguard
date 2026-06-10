//! The Noise IKpsk2 handshake, exactly as laid out in whitepaper
//! §5.4.2–§5.4.5.
//!
//! This module is pure key-schedule mechanics: it neither checks macs
//! (that is [`crate::cookie`]'s job, done *before* any function here runs)
//! nor enforces timestamp monotonicity, peer identity or rate limits
//! (the [`crate::tunnel`] layer does, on the results). Every byte of
//! intermediate secret state is wiped when the value is dropped.

use crate::Error;
use crate::consts::{CONSTRUCTION, HANDSHAKE_INITIATION_LEN, HANDSHAKE_RESPONSE_LEN, IDENTIFIER};
use crate::crypto::{aead, blake2s, ct, kdf, x25519};
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{self, HandshakeInitiation, HandshakeResponse};
use crate::time::Tai64N;

/// `Hash(Construction)` and `Hash(C0 ∥ Identifier)`: the same for every
/// handshake, computed once per [`crate::Tunnel`].
#[derive(Clone)]
pub(crate) struct HandshakeConstants {
    pub ck0: [u8; 32],
    pub h0: [u8; 32],
}

impl HandshakeConstants {
    pub(crate) fn new() -> Self {
        let ck0 = blake2s::hash(&[CONSTRUCTION]);
        let h0 = blake2s::hash(&[&ck0, IDENTIFIER]);
        Self { ck0, h0 }
    }
}

impl core::fmt::Debug for HandshakeConstants {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandshakeConstants")
    }
}

/// Initiator state held between sending an initiation and receiving the
/// matching response.
pub(crate) struct InFlightInitiation {
    pub local_index: u32,
    eph_secret: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
}

impl Drop for InFlightInitiation {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.eph_secret);
        ct::wipe_array(&mut self.chain);
        ct::wipe_array(&mut self.hash);
    }
}

impl core::fmt::Debug for InFlightInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InFlightInitiation(index={})", self.local_index)
    }
}

/// The transport keys a completed handshake yields (whitepaper §5.4.5).
pub(crate) struct SessionKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    pub local_index: u32,
    pub peer_index: u32,
    pub is_initiator: bool,
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.send);
        ct::wipe_array(&mut self.recv);
    }
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SessionKeys(local={}, peer={}, initiator={})",
            self.local_index, self.peer_index, self.is_initiator
        )
    }
}

/// `H := Hash(H ∥ part)`, the Noise mixHash operation.
fn mix_hash(h: &mut [u8; 32], part: &[u8]) {
    *h = blake2s::hash(&[h.as_slice(), part]);
}

/// Build a handshake initiation (whitepaper §5.4.2) into `out` with zeroed
/// mac fields. `eph_secret_raw` must be fresh entropy.
///
/// # Errors
/// `BufferTooSmall`; `InvalidPublicKey` if the configured peer key is
/// low-order (configuration error, no message emitted).
#[allow(clippy::too_many_arguments)] // internal plumbing; every argument is distinct state
pub(crate) fn create_initiation(
    constants: &HandshakeConstants,
    local_static: &StaticSecret,
    local_public: &PublicKey,
    peer_public: &PublicKey,
    local_index: u32,
    eph_secret_raw: [u8; 32],
    timestamp: Tai64N,
    out: &mut [u8],
) -> Result<InFlightInitiation, Error> {
    // Check buffer up front so we never compute secrets we then discard.
    if out.len() < HANDSHAKE_INITIATION_LEN {
        return Err(Error::BufferTooSmall);
    }

    let mut ck = constants.ck0;
    let mut h = constants.h0;
    mix_hash(&mut h, peer_public.as_bytes());

    let eph_secret = x25519::clamp_scalar(eph_secret_raw);
    let eph_public = x25519::x25519_base(&eph_secret);
    ck = kdf::kdf1(&ck, &eph_public);
    mix_hash(&mut h, &eph_public);

    // es
    let mut es = x25519::shared_secret(&eph_secret, peer_public.as_bytes())?;
    let (ck_next, mut k) = kdf::kdf2(&ck, &es);
    ck = ck_next;
    ct::wipe_array(&mut es);
    let mut encrypted_static = [0u8; 48];
    aead::seal(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        local_public.as_bytes(),
        &mut encrypted_static,
    )?;
    ct::wipe_array(&mut k);
    mix_hash(&mut h, &encrypted_static);

    // ss
    let mut ss = x25519::shared_secret(local_static.as_bytes(), peer_public.as_bytes())?;
    let (ck_next, mut k) = kdf::kdf2(&ck, &ss);
    ck = ck_next;
    ct::wipe_array(&mut ss);
    let mut encrypted_timestamp = [0u8; 28];
    aead::seal(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        timestamp.as_bytes(),
        &mut encrypted_timestamp,
    )?;
    ct::wipe_array(&mut k);
    mix_hash(&mut h, &encrypted_timestamp);

    message::build_initiation(
        out,
        local_index,
        &eph_public,
        &encrypted_static,
        &encrypted_timestamp,
    )?;

    Ok(InFlightInitiation {
        local_index,
        eph_secret,
        chain: ck,
        hash: h,
    })
}

/// Everything a verified-and-decrypted initiation tells the responder.
/// Consumed by [`create_response`].
pub(crate) struct ConsumedInitiation {
    /// The initiator's session index.
    pub peer_index: u32,
    /// Decrypted initiator static public key. The caller **must** verify
    /// this equals the configured peer before responding.
    pub static_public: [u8; 32],
    /// Decrypted TAI64N timestamp. The caller **must** enforce strict
    /// monotonicity per peer before responding.
    pub timestamp: Tai64N,
    eph_public: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
}

impl Drop for ConsumedInitiation {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.chain);
        ct::wipe_array(&mut self.hash);
    }
}

impl core::fmt::Debug for ConsumedInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConsumedInitiation(peer_index={})", self.peer_index)
    }
}

/// Process a received initiation (whitepaper §5.4.2, responder side).
/// Performs the two Diffie-Hellman operations and both decryptions; mac1
/// must already have been verified by the caller.
///
/// # Errors
/// `AuthFailure` if either AEAD fails (forgery / wrong responder);
/// `InvalidPublicKey` for low-order ephemeral or static keys.
pub(crate) fn consume_initiation(
    constants: &HandshakeConstants,
    local_static: &StaticSecret,
    local_public: &PublicKey,
    msg: &HandshakeInitiation<'_>,
) -> Result<ConsumedInitiation, Error> {
    let mut ck = constants.ck0;
    let mut h = constants.h0;
    mix_hash(&mut h, local_public.as_bytes());

    ck = kdf::kdf1(&ck, msg.ephemeral);
    mix_hash(&mut h, msg.ephemeral);

    // es (from the responder's side: DH(S_priv_r, E_pub_i)).
    let mut es = x25519::shared_secret(local_static.as_bytes(), msg.ephemeral)?;
    let (ck_next, mut k) = kdf::kdf2(&ck, &es);
    ck = ck_next;
    ct::wipe_array(&mut es);
    let mut static_public = [0u8; 32];
    let opened = aead::open(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        msg.encrypted_static,
        &mut static_public,
    );
    ct::wipe_array(&mut k);
    if opened != Ok(32) {
        return Err(Error::AuthFailure);
    }
    mix_hash(&mut h, msg.encrypted_static);

    // ss
    let mut ss = x25519::shared_secret(local_static.as_bytes(), &static_public)?;
    let (ck_next, mut k) = kdf::kdf2(&ck, &ss);
    ck = ck_next;
    ct::wipe_array(&mut ss);
    let mut timestamp = [0u8; 12];
    let opened = aead::open(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        msg.encrypted_timestamp,
        &mut timestamp,
    );
    ct::wipe_array(&mut k);
    if opened != Ok(12) {
        return Err(Error::AuthFailure);
    }
    mix_hash(&mut h, msg.encrypted_timestamp);

    Ok(ConsumedInitiation {
        peer_index: msg.sender_index,
        static_public,
        timestamp: Tai64N::from_bytes(timestamp),
        eph_public: *msg.ephemeral,
        chain: ck,
        hash: h,
    })
}

/// Build the handshake response (whitepaper §5.4.3) and derive transport
/// keys (§5.4.5), responder side. Consumes the initiation state.
///
/// # Errors
/// `BufferTooSmall`; `InvalidPublicKey` for low-order peer keys.
pub(crate) fn create_response(
    consumed: &ConsumedInitiation,
    psk: &PresharedKey,
    local_index: u32,
    eph_secret_raw: [u8; 32],
    out: &mut [u8],
) -> Result<SessionKeys, Error> {
    if out.len() < HANDSHAKE_RESPONSE_LEN {
        return Err(Error::BufferTooSmall);
    }

    let mut ck = consumed.chain;
    let mut h = consumed.hash;

    let eph_secret = x25519::clamp_scalar(eph_secret_raw);
    let eph_public = x25519::x25519_base(&eph_secret);
    ck = kdf::kdf1(&ck, &eph_public);
    mix_hash(&mut h, &eph_public);

    // ee
    let mut ee = x25519::shared_secret(&eph_secret, &consumed.eph_public)?;
    ck = kdf::kdf1(&ck, &ee);
    ct::wipe_array(&mut ee);
    // se (responder side: DH(E_priv_r, S_pub_i)).
    let mut se = x25519::shared_secret(&eph_secret, &consumed.static_public)?;
    ck = kdf::kdf1(&ck, &se);
    ct::wipe_array(&mut se);

    // psk2
    let (ck_next, mut tau, mut k) = kdf::kdf3(&ck, psk.as_bytes());
    ck = ck_next;
    mix_hash(&mut h, &tau);
    ct::wipe_array(&mut tau);

    let mut encrypted_nothing = [0u8; 16];
    aead::seal(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        &[],
        &mut encrypted_nothing,
    )?;
    ct::wipe_array(&mut k);
    mix_hash(&mut h, &encrypted_nothing);

    message::build_response(
        out,
        local_index,
        consumed.peer_index,
        &eph_public,
        &encrypted_nothing,
    )?;

    // (T_send_i = T_recv_r, T_recv_i = T_send_r) := Kdf2(C, ε)
    let (t_initiator, t_responder) = kdf::kdf2(&ck, &[]);
    ct::wipe_array(&mut ck);
    let mut eph_secret = eph_secret;
    ct::wipe_array(&mut eph_secret);

    Ok(SessionKeys {
        send: t_responder,
        recv: t_initiator,
        local_index,
        peer_index: consumed.peer_index,
        is_initiator: false,
    })
}

/// Process the handshake response (whitepaper §5.4.3, initiator side) and
/// derive transport keys. The caller has already matched
/// `msg.receiver_index` to `inflight.local_index` and verified mac1.
///
/// # Errors
/// `AuthFailure` if the final AEAD fails (wrong PSK, tampering, wrong
/// responder); `InvalidPublicKey` for a low-order responder ephemeral.
pub(crate) fn consume_response(
    inflight: &InFlightInitiation,
    local_static: &StaticSecret,
    psk: &PresharedKey,
    msg: &HandshakeResponse<'_>,
) -> Result<SessionKeys, Error> {
    let mut ck = inflight.chain;
    let mut h = inflight.hash;

    ck = kdf::kdf1(&ck, msg.ephemeral);
    mix_hash(&mut h, msg.ephemeral);

    // ee
    let mut ee = x25519::shared_secret(&inflight.eph_secret, msg.ephemeral)?;
    ck = kdf::kdf1(&ck, &ee);
    ct::wipe_array(&mut ee);
    // se (initiator side: DH(S_priv_i, E_pub_r)).
    let mut se = x25519::shared_secret(local_static.as_bytes(), msg.ephemeral)?;
    ck = kdf::kdf1(&ck, &se);
    ct::wipe_array(&mut se);

    // psk2
    let (ck_next, mut tau, mut k) = kdf::kdf3(&ck, psk.as_bytes());
    ck = ck_next;
    mix_hash(&mut h, &tau);
    ct::wipe_array(&mut tau);

    let mut nothing = [0u8; 0];
    let opened = aead::open(
        &k,
        &aead::nonce_from_counter(0),
        &h,
        msg.encrypted_nothing,
        &mut nothing,
    );
    ct::wipe_array(&mut k);
    if opened != Ok(0) {
        return Err(Error::AuthFailure);
    }
    mix_hash(&mut h, msg.encrypted_nothing);

    let (t_initiator, t_responder) = kdf::kdf2(&ck, &[]);
    ct::wipe_array(&mut ck);

    Ok(SessionKeys {
        send: t_initiator,
        recv: t_responder,
        local_index: inflight.local_index,
        peer_index: msg.sender_index,
        is_initiator: true,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::panic
    )]
    use super::*;
    use crate::EntropySource;
    use crate::message::{Packet, parse};
    use crate::testing::DeterministicRng;
    use std::vec;

    struct Party {
        secret: StaticSecret,
        public: PublicKey,
    }

    fn party(rng: &mut DeterministicRng) -> Party {
        let secret = StaticSecret::generate(rng).unwrap();
        let public = secret.public_key();
        Party { secret, public }
    }

    fn run_handshake(psk_i: &PresharedKey, psk_r: &PresharedKey) -> Result<(), Error> {
        let mut rng = DeterministicRng::new(0xabcdef);
        let constants = HandshakeConstants::new();
        let init = party(&mut rng);
        let resp = party(&mut rng);

        // Initiator → initiation.
        let mut wire1 = vec![0u8; HANDSHAKE_INITIATION_LEN];
        let inflight = create_initiation(
            &constants,
            &init.secret,
            &init.public,
            &resp.public,
            0x1111,
            rng.gen32().unwrap(),
            Tai64N::from_unix(1_700_000_000, 0),
            &mut wire1,
        )?;

        // Responder consumes and responds.
        let parsed = match parse(&wire1)? {
            Packet::HandshakeInitiation(m) => m,
            _ => return Err(Error::Internal),
        };
        let consumed = consume_initiation(&constants, &resp.secret, &resp.public, &parsed)?;
        assert_eq!(&consumed.static_public, init.public.as_bytes());
        assert_eq!(consumed.peer_index, 0x1111);
        assert_eq!(
            consumed.timestamp,
            Tai64N::from_unix(1_700_000_000, 0),
            "timestamp must round-trip"
        );

        let mut wire2 = vec![0u8; HANDSHAKE_RESPONSE_LEN];
        let resp_keys =
            create_response(&consumed, psk_r, 0x2222, rng.gen32().unwrap(), &mut wire2)?;

        // Initiator consumes the response.
        let parsed = match parse(&wire2)? {
            Packet::HandshakeResponse(m) => m,
            _ => return Err(Error::Internal),
        };
        assert_eq!(parsed.receiver_index, 0x1111);
        let init_keys = consume_response(&inflight, &init.secret, psk_i, &parsed)?;

        // Key agreement, direction-crossed.
        assert_eq!(init_keys.send, resp_keys.recv);
        assert_eq!(init_keys.recv, resp_keys.send);
        assert_ne!(init_keys.send, init_keys.recv, "directions must differ");
        assert!(init_keys.is_initiator && !resp_keys.is_initiator);
        assert_eq!(init_keys.peer_index, 0x2222);
        assert_eq!(resp_keys.peer_index, 0x1111);
        Ok(())
    }

    #[test]
    fn full_handshake_agrees_without_psk() {
        run_handshake(&PresharedKey::default(), &PresharedKey::default()).unwrap();
    }

    #[test]
    fn full_handshake_agrees_with_psk() {
        let psk = PresharedKey::from_bytes([0x42; 32]);
        run_handshake(&psk.clone(), &psk).unwrap();
    }

    #[test]
    fn psk_mismatch_fails_closed() {
        let a = PresharedKey::from_bytes([1; 32]);
        let b = PresharedKey::from_bytes([2; 32]);
        assert_eq!(run_handshake(&a, &b), Err(Error::AuthFailure));
        // Zero vs non-zero also fails (psk-mode mismatch).
        assert_eq!(
            run_handshake(&PresharedKey::default(), &PresharedKey::from_bytes([3; 32])),
            Err(Error::AuthFailure)
        );
    }

    #[test]
    fn initiation_for_wrong_responder_fails() {
        let mut rng = DeterministicRng::new(7);
        let constants = HandshakeConstants::new();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mallory = party(&mut rng);

        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        create_initiation(
            &constants,
            &init.secret,
            &init.public,
            &resp.public,
            1,
            rng.gen32().unwrap(),
            Tai64N::from_unix(0, 0),
            &mut wire,
        )
        .unwrap();
        let parsed = match parse(&wire).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        // Mallory (not the addressed responder) cannot decrypt it.
        assert_eq!(
            consume_initiation(&constants, &mallory.secret, &mallory.public, &parsed).err(),
            Some(Error::AuthFailure)
        );
    }

    #[test]
    fn tampered_initiation_fields_fail() {
        let mut rng = DeterministicRng::new(9);
        let constants = HandshakeConstants::new();
        let init = party(&mut rng);
        let resp = party(&mut rng);

        let mut wire = vec![0u8; HANDSHAKE_INITIATION_LEN];
        create_initiation(
            &constants,
            &init.secret,
            &init.public,
            &resp.public,
            1,
            rng.gen32().unwrap(),
            Tai64N::from_unix(0, 0),
            &mut wire,
        )
        .unwrap();
        // Flip one bit in every non-mac byte: consume must fail (macs are
        // checked at the tunnel layer; here even without them nothing
        // forged may pass the AEADs).
        for byte in 8..116 {
            let mut bad = wire.clone();
            bad[byte] ^= 1;
            let parsed = match parse(&bad).unwrap() {
                Packet::HandshakeInitiation(m) => m,
                _ => unreachable!(),
            };
            let r = consume_initiation(&constants, &resp.secret, &resp.public, &parsed);
            assert!(r.is_err(), "tamper at byte {byte} accepted");
        }
    }

    #[test]
    fn chain_constants_match_reference_implementations() {
        // These exact bytes appear as precomputed constants in BoringTun
        // (cloudflare/boringtun src/noise/handshake.rs: INITIAL_CHAIN_KEY
        // and INITIAL_CHAIN_HASH). Agreeing with them anchors our whole
        // BLAKE2s + construction-string pipeline to a third party.
        let c = HandshakeConstants::new();
        assert_eq!(
            c.ck0,
            [
                0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25,
                0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98,
                0x8b, 0x78, 0xcd, 0x36
            ]
        );
        assert_eq!(
            c.h0,
            [
                0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a,
                0xd5, 0x32, 0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65,
                0xba, 0x07, 0x9e, 0xf3
            ]
        );
    }

    #[test]
    fn fresh_entropy_gives_fresh_sessions() {
        // Two handshakes between the same parties must never share keys
        // (forward secrecy comes from the ephemerals).
        let mut rng = DeterministicRng::new(0x5151);
        let constants = HandshakeConstants::new();
        let init = party(&mut rng);
        let resp = party(&mut rng);
        let mut keys = vec![];
        for i in 0..2 {
            let mut w1 = vec![0u8; HANDSHAKE_INITIATION_LEN];
            let inflight = create_initiation(
                &constants,
                &init.secret,
                &init.public,
                &resp.public,
                i,
                rng.gen32().unwrap(),
                Tai64N::from_unix(i.into(), 0),
                &mut w1,
            )
            .unwrap();
            let parsed = match parse(&w1).unwrap() {
                Packet::HandshakeInitiation(m) => m,
                _ => unreachable!(),
            };
            let consumed =
                consume_initiation(&constants, &resp.secret, &resp.public, &parsed).unwrap();
            let mut w2 = vec![0u8; HANDSHAKE_RESPONSE_LEN];
            let _rk = create_response(
                &consumed,
                &PresharedKey::default(),
                i,
                rng.gen32().unwrap(),
                &mut w2,
            )
            .unwrap();
            let parsed = match parse(&w2).unwrap() {
                Packet::HandshakeResponse(m) => m,
                _ => unreachable!(),
            };
            let ik = consume_response(&inflight, &init.secret, &PresharedKey::default(), &parsed)
                .unwrap();
            keys.push((ik.send, ik.recv));
        }
        assert_ne!(keys[0], keys[1]);
    }
}
