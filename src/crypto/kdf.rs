//! HMAC-BLAKE2s and the `Kdf_n` chain (whitepaper §5.4).
//!
//! `Kdf_n(key, input)` is HKDF (RFC 5869) instantiated with HMAC-BLAKE2s:
//! `τ0 = Hmac(key, input)`, `τ1 = Hmac(τ0, 0x1)`,
//! `τi = Hmac(τ0, τ(i−1) ∥ i)`, returning `(τ1, …, τn)`.

use crate::crypto::blake2s::Blake2s256;
use crate::crypto::ct;

/// BLAKE2s block size, the HMAC padding width.
const BLOCK: usize = 64;

/// `Hmac(key, parts[0] ∥ parts[1] ∥ …)` per RFC 2104 over BLAKE2s-256.
///
/// All protocol keys are 32 bytes; keys longer than the 64-byte block are
/// hashed first (defensive totality, the protocol never hits that branch).
#[must_use]
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Blake2s256::new();
        h.update(key);
        let digest = h.finalize();
        for (d, s) in k_block.iter_mut().zip(digest.iter()) {
            *d = *s;
        }
    } else {
        for (d, s) in k_block.iter_mut().zip(key.iter()) {
            *d = *s;
        }
    }

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k_block.iter()) {
        *i = k ^ 0x36;
        *o = k ^ 0x5c;
    }

    let mut inner = Blake2s256::new();
    inner.update(&ipad);
    for part in parts {
        inner.update(part);
    }
    let mut inner_digest = inner.finalize();

    let mut outer = Blake2s256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let out = outer.finalize();

    ct::wipe(&mut k_block);
    ct::wipe(&mut ipad);
    ct::wipe(&mut opad);
    ct::wipe_array(&mut inner_digest);
    out
}

/// `Kdf1(key, input)` (whitepaper §5.4): returns `τ1`.
#[must_use]
pub fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[0x01]]);
    ct::wipe_array(&mut t0);
    t1
}

/// `Kdf2(key, input)`: returns `(τ1, τ2)`.
#[must_use]
pub fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[0x01]]);
    let t2 = hmac(&t0, &[&t1, &[0x02]]);
    ct::wipe_array(&mut t0);
    (t1, t2)
}

/// `Kdf3(key, input)`: returns `(τ1, τ2, τ3)`.
#[must_use]
pub fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[0x01]]);
    let t2 = hmac(&t0, &[&t1, &[0x02]]);
    let t3 = hmac(&t0, &[&t2, &[0x03]]);
    ct::wipe_array(&mut t0);
    (t1, t2, t3)
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
    use crate::crypto::blake2s;

    #[test]
    fn hmac_matches_manual_construction() {
        // Recompute HMAC from its definition with explicit concatenation
        // buffers and compare.
        let key = [0x0bu8; 32];
        let msg = b"Hi There, this is a wireguard kdf test message";
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&key);
        let mut ip = [0u8; 64];
        let mut op = [0u8; 64];
        for i in 0..64 {
            ip[i] = k[i] ^ 0x36;
            op[i] = k[i] ^ 0x5c;
        }
        let inner = blake2s::hash(&[&ip, msg]);
        let expected = blake2s::hash(&[&op, &inner]);
        assert_eq!(hmac(&key, &[msg]), expected);
        // Multi-part input == concatenated input.
        assert_eq!(hmac(&key, &[&msg[..7], &msg[7..]]), expected);
    }

    #[test]
    fn hmac_long_key_is_hashed() {
        let long = [0x77u8; 100];
        let short = blake2s::hash(&[&long]);
        assert_eq!(hmac(&long, &[b"m"]), hmac(&short, &[b"m"]));
    }

    #[test]
    fn kdf_chain_is_consistent() {
        // kdf1/kdf2/kdf3 must be prefixes of one another and follow the
        // τ chain definition exactly.
        let key = [7u8; 32];
        let input = [9u8; 32];
        let a = kdf1(&key, &input);
        let (b1, b2) = kdf2(&key, &input);
        let (c1, c2, c3) = kdf3(&key, &input);
        assert_eq!(a, b1);
        assert_eq!(b1, c1);
        assert_eq!(b2, c2);
        let t0 = hmac(&key, &[&input]);
        assert_eq!(c1, hmac(&t0, &[&[1u8]]));
        assert_eq!(c2, hmac(&t0, &[&c1, &[2u8]]));
        assert_eq!(c3, hmac(&t0, &[&c2, &[3u8]]));
        // Distinctness.
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);
    }

    #[test]
    fn kdf_handles_empty_input() {
        // Transport key derivation uses Kdf2(C, ε).
        let key = [3u8; 32];
        let (t1, t2) = kdf2(&key, &[]);
        assert_ne!(t1, t2);
        assert_eq!(kdf1(&key, &[]), t1);
    }
}
