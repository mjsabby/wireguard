//! Cookie MACs and the cookie reply message (whitepaper §5.3, §5.4.4,
//! §5.4.7): WireGuard's CPU-exhaustion (DoS) defence.
//!
//! * `mac1` is mandatory on every handshake message and is checked
//!   *before* any expensive Diffie-Hellman work, in constant time, and
//!   failures are dropped silently.
//! * `mac2` proves IP ownership when the receiver is under load, using a
//!   cookie minted from a rotating secret and the sender's endpoint, and
//!   delivered encrypted (XChaCha20-Poly1305) bound to the provoking
//!   message's `mac1`.

use crate::Error;
use crate::consts::{COOKIE_LIFETIME, COOKIE_REPLY_LEN, LABEL_COOKIE, LABEL_MAC1};
use crate::crypto::{aead, blake2s, ct};
use crate::entropy::EntropySource;
use crate::keys::PublicKey;
use crate::message::{self, CookieReply};
use crate::time::Ticks;

/// Per-peer precomputed MAC and cookie-encryption keys (whitepaper
/// §5.4.4/§5.4.7 note that these hashes "can be pre-computed").
#[derive(Clone)]
pub(crate) struct MacKeys {
    /// `Hash(Label-Mac1 ∥ peer_public)`: keys `mac1` on messages we send.
    pub mac1_send: [u8; 32],
    /// `Hash(Label-Mac1 ∥ our_public)`: verifies `mac1` on messages we
    /// receive.
    pub mac1_recv: [u8; 32],
    /// `Hash(Label-Cookie ∥ our_public)`: encrypts cookie replies we send.
    pub cookie_send: [u8; 32],
    /// `Hash(Label-Cookie ∥ peer_public)`: decrypts cookie replies we
    /// receive.
    pub cookie_recv: [u8; 32],
}

impl MacKeys {
    pub(crate) fn new(local_public: &PublicKey, peer_public: &PublicKey) -> Self {
        Self {
            mac1_send: blake2s::hash(&[LABEL_MAC1, peer_public.as_bytes()]),
            mac1_recv: blake2s::hash(&[LABEL_MAC1, local_public.as_bytes()]),
            cookie_send: blake2s::hash(&[LABEL_COOKIE, local_public.as_bytes()]),
            cookie_recv: blake2s::hash(&[LABEL_COOKIE, peer_public.as_bytes()]),
        }
    }
}

impl core::fmt::Debug for MacKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MacKeys")
    }
}

/// The most recent cookie a peer sent us (initiator side of the cookie
/// dance). Used to fill `mac2` while fresh (`< COOKIE_LIFETIME`).
#[derive(Clone)]
pub(crate) struct LastCookie {
    value: [u8; 16],
    received_at: Ticks,
}

impl LastCookie {
    pub(crate) fn new(value: [u8; 16], received_at: Ticks) -> Self {
        Self { value, received_at }
    }

    pub(crate) fn fresh_value(&self, now: Ticks) -> Option<&[u8; 16]> {
        (now.since(self.received_at) < COOKIE_LIFETIME).then_some(&self.value)
    }
}

impl Drop for LastCookie {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.value);
    }
}

impl core::fmt::Debug for LastCookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LastCookie")
    }
}

/// The responder's rotating cookie secret (`R_m`, whitepaper §5.4.7): a
/// random value that changes every two minutes. The previous secret is
/// kept so cookies minted just before a rotation stay verifiable for their
/// full advertised lifetime.
pub(crate) struct CookieJar {
    secret: [u8; 32],
    previous: [u8; 32],
    /// `previous` holds a real (random) secret. False until the *second*
    /// rotation, so the all-zero pre-prime value is never accepted.
    has_previous: bool,
    rotated_at: Ticks,
    primed: bool,
    /// 192-bit counter for XChaCha20 cookie-reply nonces. The XChaCha
    /// nonce needs only uniqueness under `cookie_send`, not
    /// unpredictability, so a counter avoids drawing 24 bytes of entropy
    /// per reply (which under flood becomes the dominant cost and can
    /// stall a constrained HWRNG).
    nonce_counter: [u64; 3],
}

impl CookieJar {
    pub(crate) const fn new() -> Self {
        Self {
            secret: [0u8; 32],
            previous: [0u8; 32],
            has_previous: false,
            rotated_at: Ticks::ZERO,
            primed: false,
            nonce_counter: [0u64; 3],
        }
    }

    fn rotate_if_needed(&mut self, now: Ticks, rng: &mut dyn EntropySource) -> Result<(), Error> {
        if !self.primed || now.since(self.rotated_at) >= COOKIE_LIFETIME {
            let fresh = rng.gen32().map_err(|_| Error::EntropyFailure)?;
            // Only after entropy succeeded: commit the rotation.
            self.previous = self.secret;
            self.has_previous = self.primed; // true from the second rotation on
            self.secret = fresh;
            self.rotated_at = now;
            if !self.primed {
                // First prime: also seed the nonce counter from entropy
                // so independent restarts don't replay nonces. Failure
                // here is harmless (counter starts at 0; the
                // `cookie_send` key is itself per-static-key, and
                // collisions across restarts only weaken the
                // authenticity of *attacker-discardable* cookie replies).
                let mut seed = [0u8; 24];
                if rng.fill(&mut seed).is_ok() {
                    let (a, rest) = seed.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
                    let (b, rest) = rest.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
                    let (c, _) = rest.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
                    self.nonce_counter =
                        [u64::from_le_bytes(*a), u64::from_le_bytes(*b), u64::from_le_bytes(*c)];
                }
            }
            self.primed = true;
        }
        Ok(())
    }

    /// Take the next unique 24-byte XChaCha20 nonce.
    fn next_nonce(&mut self) -> [u8; 24] {
        // 192-bit increment: practically inexhaustible.
        let [a, b, c] = self.nonce_counter;
        let (a, carry) = a.overflowing_add(1);
        let (b, carry) = b.overflowing_add(u64::from(carry));
        let c = c.wrapping_add(u64::from(carry));
        self.nonce_counter = [a, b, c];
        let mut out = [0u8; 24];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.nonce_counter.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// `τ := Mac(R_m, A_remote)`: the cookie for a remote endpoint.
    /// `remote` is the caller-encoded source IP and port.
    pub(crate) fn mint(
        &mut self,
        now: Ticks,
        rng: &mut dyn EntropySource,
        remote: &[u8],
    ) -> Result<[u8; 16], Error> {
        self.rotate_if_needed(now, rng)?;
        Ok(blake2s::mac(&self.secret, &[remote]))
    }

    /// Does `mac2` prove possession of a cookie we minted recently for
    /// `remote`? Checks the current and (if real) previous secret, in
    /// constant time.
    pub(crate) fn verify_mac2(&self, remote: &[u8], beta: &[u8], mac2: &[u8; 16]) -> bool {
        if !self.primed {
            return false;
        }
        let current = blake2s::mac(&blake2s::mac(&self.secret, &[remote]), &[beta]);
        let previous = blake2s::mac(&blake2s::mac(&self.previous, &[remote]), &[beta]);
        // Both arms always evaluated; `has_previous` masks the
        // pre-second-rotation all-zero secret so it is never accepted.
        let ok_current = ct::ct_eq(&current, mac2);
        let ok_previous = ct::ct_eq(&previous, mac2) & self.has_previous;
        ok_current | ok_previous
    }
}

impl Drop for CookieJar {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.secret);
        ct::wipe_array(&mut self.previous);
    }
}

impl core::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CookieJar")
    }
}

/// Fill the `mac1` and `mac2` slots of an outgoing handshake message
/// (whitepaper §5.4.4). Returns the `mac1` value, which the caller stores
/// to authenticate a possible cookie reply.
///
/// # Errors
/// `InvalidPacket` if `msg` is not a handshake message (internal misuse).
pub(crate) fn apply_macs(
    keys: &MacKeys,
    cookie: Option<&LastCookie>,
    now: Ticks,
    msg: &mut [u8],
) -> Result<[u8; 16], Error> {
    let slots = message::mac_slots(msg)?;
    let mac1 = blake2s::mac(&keys.mac1_send, &[slots.alpha]);
    *slots.mac1 = mac1;
    // msg.mac2 := Mac(L, msgβ) when the cookie is fresh, else 0^16.
    *slots.mac2 = match cookie.and_then(|c| c.fresh_value(now)) {
        Some(value) => blake2s::mac(value, &[slots.alpha, slots.mac1]),
        None => [0u8; 16],
    };
    Ok(mac1)
}

/// Verify `mac1` of a received handshake message, constant time.
pub(crate) fn verify_mac1(keys: &MacKeys, alpha: &[u8], mac1: &[u8; 16]) -> bool {
    let expected = blake2s::mac(&keys.mac1_recv, &[alpha]);
    ct::ct_eq(&expected, mac1)
}

/// Build a cookie reply (whitepaper §5.4.7) for a message whose `mac1`
/// validated but whose `mac2` did not while under load.
///
/// # Errors
/// `BufferTooSmall`, `EntropyFailure`.
#[allow(clippy::too_many_arguments)] // internal plumbing; every argument is distinct state
pub(crate) fn build_cookie_reply(
    keys: &MacKeys,
    jar: &mut CookieJar,
    now: Ticks,
    rng: &mut dyn EntropySource,
    peer_sender_index: u32,
    their_mac1: &[u8; 16],
    remote: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < COOKIE_REPLY_LEN {
        return Err(Error::BufferTooSmall);
    }
    let mut cookie = jar.mint(now, rng, remote)?;
    let nonce = jar.next_nonce();
    let mut encrypted = [0u8; 32];
    let sealed = aead::xseal(
        &keys.cookie_send,
        &nonce,
        their_mac1,
        &cookie,
        &mut encrypted,
    );
    ct::wipe_array(&mut cookie);
    if sealed != Ok(32) {
        return Err(Error::Internal);
    }
    message::build_cookie_reply(out, peer_sender_index, &nonce, &encrypted)?;
    Ok(COOKIE_REPLY_LEN)
}

/// Decrypt and authenticate a received cookie reply against the `mac1` of
/// the last handshake message we sent (whitepaper §5.4.7: the AEAD's
/// additional data binds the reply to our message).
///
/// # Errors
/// `InvalidCookie` if authentication fails.
pub(crate) fn consume_cookie_reply(
    keys: &MacKeys,
    last_sent_mac1: &[u8; 16],
    msg: &CookieReply<'_>,
    now: Ticks,
) -> Result<LastCookie, Error> {
    let mut cookie = [0u8; 16];
    let opened = aead::xopen(
        &keys.cookie_recv,
        msg.nonce,
        last_sent_mac1,
        msg.encrypted_cookie,
        &mut cookie,
    );
    if opened != Ok(16) {
        return Err(Error::InvalidCookie);
    }
    Ok(LastCookie::new(cookie, now))
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
    use crate::StaticSecret;
    use crate::consts::HANDSHAKE_INITIATION_LEN;
    use crate::message::{Packet, parse};
    use crate::testing::DeterministicRng;
    use std::vec;

    fn keypairs() -> (MacKeys, MacKeys) {
        let mut rng = DeterministicRng::new(0xc00c1e);
        let a = StaticSecret::generate(&mut rng).unwrap().public_key();
        let b = StaticSecret::generate(&mut rng).unwrap().public_key();
        (MacKeys::new(&a, &b), MacKeys::new(&b, &a))
    }

    fn blank_initiation() -> std::vec::Vec<u8> {
        let mut msg = vec![0u8; HANDSHAKE_INITIATION_LEN];
        message::build_initiation(&mut msg, 7, &[1; 32], &[2; 48], &[3; 28]).unwrap();
        msg
    }

    #[test]
    fn mac1_roundtrip_and_direction() {
        let (ours, theirs) = keypairs();
        let mut msg = blank_initiation();
        apply_macs(&ours, None, Ticks::ZERO, &mut msg).unwrap();
        let parsed = match parse(&msg).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        // The receiver (them) verifies with their recv key.
        assert!(verify_mac1(&theirs, parsed.alpha, parsed.mac1));
        // We cannot verify our own sent mac1 (it is keyed by their pub).
        assert!(!verify_mac1(&ours, parsed.alpha, parsed.mac1));
        // mac2 is zero without a cookie.
        assert_eq!(parsed.mac2, &[0u8; 16]);
        // Any body tamper breaks mac1.
        for byte in 0..116 {
            let mut bad = msg.clone();
            bad[byte] ^= 0x80;
            let p = match parse(&bad) {
                Ok(Packet::HandshakeInitiation(m)) => m,
                _ => continue, // header tampering may fail parsing: fine
            };
            assert!(!verify_mac1(&theirs, p.alpha, p.mac1), "byte {byte}");
        }
    }

    #[test]
    fn cookie_reply_dance_end_to_end() {
        // "We" are the loaded responder; "peer" sent an initiation with a
        // valid mac1 and no mac2.
        let mut rng = DeterministicRng::new(0xfeed);
        let (peer_keys, our_keys) = keypairs();
        let now = Ticks::from_secs(100);
        let remote = b"192.0.2.33:51820";

        let mut init = blank_initiation();
        let peer_mac1 = apply_macs(&peer_keys, None, now, &mut init).unwrap();

        // Under load: we answer with a cookie reply instead of processing.
        let mut jar = CookieJar::new();
        let mut reply = vec![0u8; COOKIE_REPLY_LEN];
        let n = build_cookie_reply(
            &our_keys, &mut jar, now, &mut rng, 7, &peer_mac1, remote, &mut reply,
        )
        .unwrap();
        assert_eq!(n, COOKIE_REPLY_LEN);

        // Peer consumes the reply...
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        let cookie = consume_cookie_reply(&peer_keys, &peer_mac1, &parsed, now).unwrap();

        // ...and retransmits with mac2 filled.
        let mut retry = blank_initiation();
        apply_macs(&peer_keys, Some(&cookie), now.add_nanos(1), &mut retry).unwrap();
        let parsed = match parse(&retry).unwrap() {
            Packet::HandshakeInitiation(m) => m,
            _ => unreachable!(),
        };
        assert_ne!(parsed.mac2, &[0u8; 16]);
        assert!(verify_mac1(&our_keys, parsed.alpha, parsed.mac1));
        assert!(jar.verify_mac2(remote, parsed.beta, parsed.mac2));

        // mac2 does not verify for a different remote address (IP
        // ownership proof) nor for tampered bodies.
        assert!(!jar.verify_mac2(b"198.51.100.9:7", parsed.beta, parsed.mac2));
        let mut other_beta = parsed.beta.to_vec();
        other_beta[10] ^= 1;
        assert!(!jar.verify_mac2(remote, &other_beta, parsed.mac2));
    }

    #[test]
    fn forged_cookie_replies_rejected() {
        let mut rng = DeterministicRng::new(3);
        let (peer_keys, our_keys) = keypairs();
        let now = Ticks::ZERO;
        let mac1 = [0xaa; 16];
        let mut jar = CookieJar::new();
        let mut reply = vec![0u8; COOKIE_REPLY_LEN];
        build_cookie_reply(
            &our_keys, &mut jar, now, &mut rng, 1, &mac1, b"r", &mut reply,
        )
        .unwrap();

        // Wrong binding mac1 (attacker did not see our message).
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        assert_eq!(
            consume_cookie_reply(&peer_keys, &[0xbb; 16], &parsed, now).err(),
            Some(Error::InvalidCookie)
        );
        // Bit flips anywhere in nonce or ciphertext.
        for byte in 8..COOKIE_REPLY_LEN {
            let mut bad = reply.clone();
            bad[byte] ^= 1;
            let parsed = match parse(&bad).unwrap() {
                Packet::CookieReply(m) => m,
                _ => unreachable!(),
            };
            assert!(
                consume_cookie_reply(&peer_keys, &mac1, &parsed, now).is_err(),
                "byte {byte}"
            );
        }
        // The genuine reply with the right binding works.
        let parsed = match parse(&reply).unwrap() {
            Packet::CookieReply(m) => m,
            _ => unreachable!(),
        };
        assert!(consume_cookie_reply(&peer_keys, &mac1, &parsed, now).is_ok());
    }

    #[test]
    fn cookies_expire_and_secrets_rotate() {
        let mut rng = DeterministicRng::new(11);
        let now = Ticks::from_secs(1000);
        let cookie = LastCookie::new([7; 16], now);
        assert!(cookie.fresh_value(now).is_some());
        assert!(
            cookie
                .fresh_value(now.add_nanos(COOKIE_LIFETIME - 1))
                .is_some()
        );
        assert!(cookie.fresh_value(now.add_nanos(COOKIE_LIFETIME)).is_none());

        // Jar: a cookie minted now verifies now and within one rotation,
        // but not after two.
        let mut jar = CookieJar::new();
        let remote = b"10.0.0.1:1";
        let beta = b"some message beta bytes";
        let c = jar.mint(now, &mut rng, remote).unwrap();
        let mac2 = blake2s::mac(&c, &[beta.as_slice()]);
        assert!(jar.verify_mac2(remote, beta, &mac2));
        // Force one rotation: old secret moves to `previous`, still valid.
        let _ = jar
            .mint(now.add_nanos(COOKIE_LIFETIME), &mut rng, remote)
            .unwrap();
        assert!(jar.verify_mac2(remote, beta, &mac2), "previous secret");
        // Second rotation: gone.
        let _ = jar
            .mint(now.add_nanos(2 * COOKIE_LIFETIME), &mut rng, remote)
            .unwrap();
        assert!(!jar.verify_mac2(remote, beta, &mac2), "two rotations");
    }

    #[test]
    fn unprimed_jar_rejects_all_mac2() {
        let jar = CookieJar::new();
        assert!(!jar.verify_mac2(b"r", b"beta", &[0u8; 16]));
        // All-zero mac2 (the "no cookie" wire value) must never verify.
        let mut rng = DeterministicRng::new(1);
        let mut jar = CookieJar::new();
        let _ = jar.mint(Ticks::ZERO, &mut rng, b"r").unwrap();
        assert!(!jar.verify_mac2(b"r", b"beta", &[0u8; 16]));
    }

    /// Regression: after the first rotation `previous` is the all-zero
    /// pre-prime value, which an attacker can key against without any
    /// secret knowledge. `has_previous` must mask it.
    #[test]
    fn jar_rejects_mac2_keyed_on_all_zero_previous() {
        let mut rng = DeterministicRng::new(0xa7);
        let mut jar = CookieJar::new();
        let _ = jar.mint(Ticks::ZERO, &mut rng, b"x").unwrap();
        let remote = b"203.0.113.5:51820";
        let beta = b"some 116- or 76-byte msg-beta prefix the attacker built";
        let forged_cookie = blake2s::mac(&[0u8; 32], &[remote.as_slice()]);
        let forged_mac2 = blake2s::mac(&forged_cookie, &[beta.as_slice()]);
        assert!(
            !jar.verify_mac2(remote, beta, &forged_mac2),
            "all-zero `previous` must never be accepted as a mac2 key"
        );
        // After a real second rotation, the (now random) previous works.
        let c = jar.mint(Ticks::ZERO, &mut rng, remote).unwrap();
        let real_mac2 = blake2s::mac(&c, &[beta.as_slice()]);
        let _ = jar
            .mint(Ticks::ZERO.add_nanos(COOKIE_LIFETIME), &mut rng, remote)
            .unwrap();
        assert!(jar.verify_mac2(remote, beta, &real_mac2), "real previous");
    }

    #[test]
    fn cookie_reply_nonces_are_unique_and_entropy_free() {
        // Two replies under load draw no per-reply entropy and never
        // repeat a nonce.
        let mut rng = DeterministicRng::new(5);
        let mut jar = CookieJar::new();
        let _ = jar.mint(Ticks::ZERO, &mut rng, b"r").unwrap(); // primes
        let n1 = jar.next_nonce();
        let n2 = jar.next_nonce();
        assert_ne!(n1, n2);
        // 192-bit carry across word boundaries.
        let mut jar2 = CookieJar::new();
        jar2.nonce_counter = [u64::MAX, u64::MAX, 0];
        jar2.primed = true;
        let n = jar2.next_nonce();
        assert_eq!(jar2.nonce_counter, [0, 0, 1]);
        assert_eq!(&n[16..], 1u64.to_le_bytes());
    }
}
