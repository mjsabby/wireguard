//! X25519 Diffie-Hellman (RFC 7748) — whitepaper `DH()`.
//!
//! Field arithmetic over GF(2^255 − 19) in radix 2^51: five `u64` limbs,
//! products accumulated in `u128`. The Montgomery ladder runs a fixed 255
//! iterations with arithmetic conditional swaps; there are no
//! secret-dependent branches or memory indices anywhere.
//!
//! # Limb bound discipline
//!
//! Every operation documents its input/output bounds; the invariants are:
//!
//! * `from_bytes`, `mul`, `square`, `mul_small` produce *weakly reduced*
//!   elements: limbs `< 2^51 + 2^13`.
//! * `add` and `sub` accept weakly reduced inputs and produce limbs
//!   `< 2^53`, which `mul`/`square` accept (their `u128` accumulators take
//!   inputs up to `2^54` without overflow).
//! * `to_bytes` accepts weakly reduced elements and emits the unique
//!   canonical encoding, in constant time.

use crate::Error;
use crate::crypto::ct;

/// 51-bit limb mask.
const MASK: u64 = (1 << 51) - 1;

/// `(p - 2) mod 2^51` style constants for limbwise subtraction: adding
/// `2·p` (limbwise `2^52 − 38, 2^52 − 2, …`) before subtracting keeps every
/// limb positive for any weakly reduced operand.
const TWO_P0: u64 = 0x000f_ffff_ffff_ffda;
const TWO_P1234: u64 = 0x000f_ffff_ffff_fffe;

/// Widening u64 multiply. u64×u64 cannot overflow u128, so this is total.
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x).wrapping_mul(u128::from(y))
}

/// A field element.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl core::fmt::Debug for Fe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Limbs may carry secret-derived state during the ladder.
        f.write_str("Fe(REDACTED)")
    }
}

impl Fe {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Decode 32 little-endian bytes, masking bit 255 (RFC 7748 §5).
    /// Output limbs `<= MASK`.
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut q = [0u64; 4];
        for (qi, chunk) in q.iter_mut().zip(bytes.chunks_exact(8)) {
            *qi = u64::from_le_bytes(<[u8; 8]>::try_from(chunk).unwrap_or([0; 8]));
        }
        let [t0, t1, t2, t3] = q;
        Self([
            t0 & MASK,
            ((t0 >> 51) | (t1 << 13)) & MASK,
            ((t1 >> 38) | (t2 << 26)) & MASK,
            ((t2 >> 25) | (t3 << 39)) & MASK,
            (t3 >> 12) & MASK,
        ])
    }

    /// Canonical constant-time encoding. Accepts weakly reduced input
    /// (limbs `< 2^52`).
    fn to_bytes(self) -> [u8; 32] {
        let [mut l0, mut l1, mut l2, mut l3, mut l4] = self.0;

        // One carry pass (with the 19-fold) to tighten limbs below
        // 2^51 + 2^13.
        let mut c;
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);
        c = l1 >> 51;
        l1 &= MASK;
        l2 = l2.wrapping_add(c);
        c = l2 >> 51;
        l2 &= MASK;
        l3 = l3.wrapping_add(c);
        c = l3 >> 51;
        l3 &= MASK;
        l4 = l4.wrapping_add(c);
        c = l4 >> 51;
        l4 &= MASK;
        l0 = l0.wrapping_add(c.wrapping_mul(19));
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);

        // q = 1 iff the value is >= p (computed as the bit-255 carry of
        // value + 19); adding 19·q and dropping bit 255 then subtracts p
        // exactly when needed. Constant time.
        let mut q = l0.wrapping_add(19) >> 51;
        q = l1.wrapping_add(q) >> 51;
        q = l2.wrapping_add(q) >> 51;
        q = l3.wrapping_add(q) >> 51;
        q = l4.wrapping_add(q) >> 51;

        l0 = l0.wrapping_add(q.wrapping_mul(19));
        c = l0 >> 51;
        l0 &= MASK;
        l1 = l1.wrapping_add(c);
        c = l1 >> 51;
        l1 &= MASK;
        l2 = l2.wrapping_add(c);
        c = l2 >> 51;
        l2 &= MASK;
        l3 = l3.wrapping_add(c);
        c = l3 >> 51;
        l3 &= MASK;
        l4 = l4.wrapping_add(c);
        l4 &= MASK;

        let o0 = l0 | (l1 << 51);
        let o1 = (l1 >> 13) | (l2 << 38);
        let o2 = (l2 >> 26) | (l3 << 25);
        let o3 = (l3 >> 39) | (l4 << 12);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(8).zip([o0, o1, o2, o3].iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Limbwise sum; no reduction (outputs `< 2^53` for weakly reduced
    /// inputs, fine as `mul`/`square` input).
    fn add(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self([
            a0.wrapping_add(b0),
            a1.wrapping_add(b1),
            a2.wrapping_add(b2),
            a3.wrapping_add(b3),
            a4.wrapping_add(b4),
        ])
    }

    /// `self − rhs`, computed as `self + 2p − rhs` limbwise so nothing
    /// underflows for weakly reduced `rhs` (limbs `< 2^52 − 38`).
    fn sub(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self([
            a0.wrapping_add(TWO_P0).wrapping_sub(b0),
            a1.wrapping_add(TWO_P1234).wrapping_sub(b1),
            a2.wrapping_add(TWO_P1234).wrapping_sub(b2),
            a3.wrapping_add(TWO_P1234).wrapping_sub(b3),
            a4.wrapping_add(TWO_P1234).wrapping_sub(b4),
        ])
    }

    /// Schoolbook multiplication mod p with the 19-fold on high cross
    /// terms. Inputs may have limbs up to `2^53` (the largest the ladder
    /// ever produces is < 2^52.6 via `add`/`sub`); output is weakly
    /// reduced. Accumulators stay below 2^113 « 2^128.
    fn mul(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        let b1_19 = b1.wrapping_mul(19);
        let b2_19 = b2.wrapping_mul(19);
        let b3_19 = b3.wrapping_mul(19);
        let b4_19 = b4.wrapping_mul(19);

        // u64×u64 in u128 can never overflow; the 5-term sums stay below
        // 2^115 (see the bound discipline note), so the wrapping ops never
        // actually wrap.
        let t0 = m(a0, b0)
            .wrapping_add(m(a1, b4_19))
            .wrapping_add(m(a2, b3_19))
            .wrapping_add(m(a3, b2_19))
            .wrapping_add(m(a4, b1_19));
        let t1 = m(a0, b1)
            .wrapping_add(m(a1, b0))
            .wrapping_add(m(a2, b4_19))
            .wrapping_add(m(a3, b3_19))
            .wrapping_add(m(a4, b2_19));
        let t2 = m(a0, b2)
            .wrapping_add(m(a1, b1))
            .wrapping_add(m(a2, b0))
            .wrapping_add(m(a3, b4_19))
            .wrapping_add(m(a4, b3_19));
        let t3 = m(a0, b3)
            .wrapping_add(m(a1, b2))
            .wrapping_add(m(a2, b1))
            .wrapping_add(m(a3, b0))
            .wrapping_add(m(a4, b4_19));
        let t4 = m(a0, b4)
            .wrapping_add(m(a1, b3))
            .wrapping_add(m(a2, b2))
            .wrapping_add(m(a3, b1))
            .wrapping_add(m(a4, b0));

        Self::carry(t0, t1, t2, t3, t4)
    }

    /// Squaring with the symmetric-term shortcuts; same bounds as `mul`.
    ///
    /// With `a = Σ aᵢ·2^(51·i)`, the product coefficients fold (×19) from
    /// positions 5..9 back onto 0..4:
    ///
    /// ```text
    /// t0 = a0²        + 19·(2·a1·a4 + 2·a2·a3)
    /// t1 = 2·a0·a1    + 19·(2·a2·a4 +   a3²)
    /// t2 = 2·a0·a2 + a1² + 19·(2·a3·a4)
    /// t3 = 2·a0·a3 + 2·a1·a2 + 19·a4²
    /// t4 = 2·a0·a4 + 2·a1·a3 + a2²
    /// ```
    fn square(self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let d0 = a0.wrapping_mul(2);
        let d1 = a1.wrapping_mul(2);
        let d2 = a2.wrapping_mul(2);
        let d3 = a3.wrapping_mul(2);
        let a3_19 = a3.wrapping_mul(19);
        let a4_19 = a4.wrapping_mul(19);

        let t0 = m(a0, a0)
            .wrapping_add(m(d1, a4_19))
            .wrapping_add(m(d2, a3_19));
        let t1 = m(d0, a1)
            .wrapping_add(m(d2, a4_19))
            .wrapping_add(m(a3, a3_19));
        let t2 = m(d0, a2).wrapping_add(m(a1, a1)).wrapping_add(m(d3, a4_19));
        let t3 = m(d0, a3).wrapping_add(m(d1, a2)).wrapping_add(m(a4, a4_19));
        let t4 = m(d0, a4).wrapping_add(m(d1, a3)).wrapping_add(m(a2, a2));

        Self::carry(t0, t1, t2, t3, t4)
    }

    /// Shared carry chain from `u128` accumulators back to weakly reduced
    /// limbs.
    fn carry(t0: u128, t1: u128, t2: u128, t3: u128, t4: u128) -> Self {
        // Accumulators are < 2^115, so adding a < 2^64 carry never wraps.
        let t1 = t1.wrapping_add(t0 >> 51);
        let r0 = (t0 as u64) & MASK;
        let t2 = t2.wrapping_add(t1 >> 51);
        let r1 = (t1 as u64) & MASK;
        let t3 = t3.wrapping_add(t2 >> 51);
        let r2 = (t2 as u64) & MASK;
        let t4 = t4.wrapping_add(t3 >> 51);
        let r3 = (t3 as u64) & MASK;
        let c4 = (t4 >> 51) as u64;
        let r4 = (t4 as u64) & MASK;
        let r0 = r0.wrapping_add(c4.wrapping_mul(19));
        let c = r0 >> 51;
        let r0 = r0 & MASK;
        let r1 = r1.wrapping_add(c);
        Self([r0, r1, r2, r3, r4])
    }

    /// Multiply by a small constant (121665 = (A−2)/4). Output weakly
    /// reduced.
    fn mul_small(self, k: u32) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let k = u64::from(k);
        Self::carry(m(a0, k), m(a1, k), m(a2, k), m(a3, k), m(a4, k))
    }

    /// `self^(p−2) = self^−1` (and `0 ↦ 0`), classic addition chain.
    fn invert(self) -> Self {
        fn nsquare(mut x: Fe, n: u32) -> Fe {
            for _ in 0..n {
                x = x.square();
            }
            x
        }
        let z = self;
        let z2 = z.square(); // 2
        let z9 = nsquare(z2, 2).mul(z); // 9
        let z11 = z9.mul(z2); // 11
        let z_5_0 = z11.square().mul(z9); // 31 = 2^5 − 1
        let z_10_0 = nsquare(z_5_0, 5).mul(z_5_0); // 2^10 − 1
        let z_20_0 = nsquare(z_10_0, 10).mul(z_10_0); // 2^20 − 1
        let z_40_0 = nsquare(z_20_0, 20).mul(z_20_0); // 2^40 − 1
        let z_50_0 = nsquare(z_40_0, 10).mul(z_10_0); // 2^50 − 1
        let z_100_0 = nsquare(z_50_0, 50).mul(z_50_0); // 2^100 − 1
        let z_200_0 = nsquare(z_100_0, 100).mul(z_100_0); // 2^200 − 1
        let z_250_0 = nsquare(z_200_0, 50).mul(z_50_0); // 2^250 − 1
        nsquare(z_250_0, 5).mul(z11) // 2^255 − 21
    }

    /// Constant-time conditional swap: exchanges `a` and `b` iff
    /// `swap == 1`. `swap` must be 0 or 1.
    fn cswap(swap: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(core::hint::black_box(swap));
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}

/// RFC 7748 §5 scalar clamping.
#[must_use]
pub fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    if let Some(first) = scalar.first_mut() {
        *first &= 248;
    }
    if let Some(last) = scalar.last_mut() {
        *last &= 127;
        *last |= 64;
    }
    scalar
}

/// The X25519 function: scalar multiplication on the Montgomery curve.
/// `scalar` is clamped internally; bit 255 of `u` is ignored (RFC 7748).
#[must_use]
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = clamp_scalar(*scalar);
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    let mut t = 255usize;
    while t > 0 {
        t = t.wrapping_sub(1);
        let byte = k.get(t >> 3).copied().unwrap_or(0);
        let bit = u64::from((byte >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(swap, &mut x2, &mut x3);
        Fe::cswap(swap, &mut z2, &mut z3);
        swap = bit;

        // RFC 7748 §5 ladder step.
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    Fe::cswap(swap, &mut x2, &mut x3);
    Fe::cswap(swap, &mut z2, &mut z3);

    // z2 == 0 (low-order input) inverts to 0 and yields an all-zero
    // output, which `shared_secret` rejects.
    x2.mul(z2.invert()).to_bytes()
}

/// The X25519 base point (u = 9).
pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Derive the public key for a private key.
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASEPOINT)
}

/// Diffie-Hellman with mandatory contributory-behaviour check: an all-zero
/// shared secret (low-order or zero `peer_public`) is rejected, in
/// constant time, exactly like the kernel implementation.
///
/// # Errors
/// [`Error::InvalidPublicKey`] if the shared secret is all-zero.
pub fn shared_secret(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut out = x25519(private, peer_public);
    if ct::ct_is_zero(&out) {
        ct::wipe_array(&mut out);
        return Err(Error::InvalidPublicKey);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::string_slice,
        clippy::panic
    )]
    use super::*;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// splitmix64 for deterministic property tests.
    struct Rng(u64);
    impl Rng {
        fn next32(&mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in out.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
            }
            out
        }
    }

    #[test]
    fn rfc7748_vector_1() {
        let scalar = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = arr("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_vector_2() {
        // u has its high bit set: must be masked, not rejected.
        let scalar = arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = arr("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_iterated() {
        // RFC 7748 §5.2: k = u = base point, iterate k := X25519(k, u).
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000u32 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    arr("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            arr("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.1.
        let alice_priv = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub = arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = arr("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_base(&alice_priv), alice_pub);
        assert_eq!(x25519_base(&bob_priv), bob_pub);
        assert_eq!(x25519(&alice_priv, &bob_pub), shared);
        assert_eq!(x25519(&bob_priv, &alice_pub), shared);
        assert_eq!(shared_secret(&alice_priv, &bob_pub).unwrap(), shared);
    }

    #[test]
    fn dh_commutes_on_random_keys() {
        let mut rng = Rng(0x5eed);
        for _ in 0..24 {
            let a = rng.next32();
            let b = rng.next32();
            let ga = x25519_base(&a);
            let gb = x25519_base(&b);
            assert_eq!(x25519(&a, &gb), x25519(&b, &ga));
        }
    }

    #[test]
    fn square_equals_mul_self_and_inverse_works() {
        let mut rng = Rng(0xfeed);
        for _ in 0..64 {
            let bytes = rng.next32();
            let z = Fe::from_bytes(&bytes);
            assert_eq!(z.square().to_bytes(), z.mul(z).to_bytes());
            // x · x^(p−2) ≡ 1 for x ≠ 0.
            let inv = z.invert();
            assert_eq!(z.mul(inv).to_bytes(), Fe::ONE.to_bytes());
        }
        // Sub/add/mul_small consistency: (a + b) − b ≡ a.
        for _ in 0..64 {
            let a = Fe::from_bytes(&rng.next32());
            let b = Fe::from_bytes(&rng.next32());
            // Normalize through mul by one to exercise carry paths.
            let lhs = a.add(b).sub(b).mul(Fe::ONE).to_bytes();
            assert_eq!(lhs, a.mul(Fe::ONE).to_bytes());
            // 121665·a == a · fe(121665)
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&121_665u32.to_le_bytes());
            assert_eq!(
                a.mul_small(121_665).to_bytes(),
                a.mul(Fe::from_bytes(&k)).to_bytes()
            );
        }
    }

    #[test]
    fn canonical_encoding_of_noncanonical_inputs() {
        // p ≡ 0, p+1 ≡ 1, 2^255−1 ≡ 18 (mod p): from_bytes+to_bytes must
        // produce the canonical representative.
        let p = arr("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let p1 = arr("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let all = arr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 32]);
        assert_eq!(Fe::from_bytes(&p1).to_bytes(), Fe::ONE.to_bytes());
        let mut eighteen = [0u8; 32];
        eighteen[0] = 18;
        assert_eq!(Fe::from_bytes(&all).to_bytes(), eighteen);
    }

    #[test]
    fn low_order_points_rejected_by_shared_secret() {
        let priv_key = Rng(7).next32();
        // u = 0 and u = 1 are low order; u = p−1 has order 4.
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        let pm1 = arr("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        for u in [&zero, &one, &pm1] {
            assert_eq!(x25519(&priv_key, u), [0u8; 32], "u={u:02x?}");
            assert_eq!(
                shared_secret(&priv_key, u),
                Err(Error::InvalidPublicKey),
                "u={u:02x?}"
            );
        }
        // A valid point is accepted.
        assert!(shared_secret(&priv_key, &BASEPOINT).is_ok());
    }

    #[test]
    fn clamping() {
        let c = clamp_scalar([0xffu8; 32]);
        assert_eq!(c[0] & 7, 0);
        assert_eq!(c[31] & 128, 0);
        assert_eq!(c[31] & 64, 64);
        // Clamping is idempotent.
        assert_eq!(clamp_scalar(c), c);
        // The ladder clamps internally: passing clamped or unclamped gives
        // the same result.
        let mut rng = Rng(0xc1a3);
        for _ in 0..8 {
            let s = rng.next32();
            assert_eq!(x25519_base(&s), x25519_base(&clamp_scalar(s)));
        }
    }
}
