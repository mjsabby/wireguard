//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Classic "donna" radix-2^26 implementation: five 26-bit limbs held in
//! `u32`s, products accumulated in `u64`s. The shapes of all operations are
//! fixed; there are no secret-dependent branches or indices.

use crate::crypto::ct;

/// 26-bit limb mask.
const M26: u64 = 0x03ff_ffff;

/// Read up to 8 little-endian bytes at `offset`, zero-padding past the end.
/// Total for every input; all call sites stay in bounds anyway.
#[inline]
fn le64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut tmp = [0u8; 8];
    let src = bytes.get(offset..).unwrap_or(&[]);
    for (d, s) in tmp.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    u64::from_le_bytes(tmp)
}

/// Read up to 4 little-endian bytes at `offset`, zero-padding past the end.
#[inline]
fn le32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut tmp = [0u8; 4];
    let src = bytes.get(offset..).unwrap_or(&[]);
    for (d, s) in tmp.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    u32::from_le_bytes(tmp)
}

/// Streaming Poly1305.
#[derive(Clone)]
pub struct Poly1305 {
    /// Clamped `r`, radix 2^26.
    r: [u32; 5],
    /// Accumulator, radix 2^26.
    h: [u32; 5],
    /// The `s` half of the key.
    pad: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    /// Key in the standard `r ∥ s` layout. The caller must never reuse a
    /// key across messages (the AEAD derives a fresh one per nonce).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r (RFC 8439 §2.5: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff).
        let t0 = le64_at(key, 0) & 0x0fff_fffc_0fff_ffff;
        let t1 = le64_at(key, 8) & 0x0fff_fffc_0fff_fffc;
        let r = [
            (t0 & M26) as u32,
            ((t0 >> 26) & M26) as u32,
            (((t0 >> 52) | (t1 << 12)) & M26) as u32,
            ((t1 >> 14) & M26) as u32,
            ((t1 >> 40) & M26) as u32,
        ];
        let pad = [
            le32_at(key, 16),
            le32_at(key, 20),
            le32_at(key, 24),
            le32_at(key, 28),
        ];
        Self {
            r,
            h: [0u32; 5],
            pad,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    /// Absorb one 16-byte block. `hibit` is `1 << 24` for full blocks and
    /// `0` for the already-0x01-terminated final partial block.
    fn process_block(&mut self, block: &[u8; 16], hibit: u32) {
        let t0 = le64_at(block.as_slice(), 0);
        let t1 = le64_at(block.as_slice(), 8);

        let [h0, h1, h2, h3, h4] = self.h;
        // h += block (with the high bit appended). Limbs stay < 2^27.
        let h0 = u64::from(h0).wrapping_add(t0 & M26);
        let h1 = u64::from(h1).wrapping_add((t0 >> 26) & M26);
        let h2 = u64::from(h2).wrapping_add(((t0 >> 52) | (t1 << 12)) & M26);
        let h3 = u64::from(h3).wrapping_add((t1 >> 14) & M26);
        let h4 = u64::from(h4).wrapping_add((t1 >> 40) | u64::from(hibit));

        // h *= r (mod 2^130 - 5).
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let s1 = r1.wrapping_mul(5);
        let s2 = r2.wrapping_mul(5);
        let s3 = r3.wrapping_mul(5);
        let s4 = r4.wrapping_mul(5);

        // Bounds: h0..h4 < 2^27 (h1 may carry an extra 2^10 from the
        // previous round's wrap-around fold, still < 2^27), r < 2^26,
        // s < 2^29 ⇒ each product < 2^56 and each 5-term sum < 2^58.4,
        // well inside u64.
        let m = u64::wrapping_mul;
        let d0 = m(h0, r0)
            .wrapping_add(m(h1, s4))
            .wrapping_add(m(h2, s3))
            .wrapping_add(m(h3, s2))
            .wrapping_add(m(h4, s1));
        let d1 = m(h0, r1)
            .wrapping_add(m(h1, r0))
            .wrapping_add(m(h2, s4))
            .wrapping_add(m(h3, s3))
            .wrapping_add(m(h4, s2));
        let d2 = m(h0, r2)
            .wrapping_add(m(h1, r1))
            .wrapping_add(m(h2, r0))
            .wrapping_add(m(h3, s4))
            .wrapping_add(m(h4, s3));
        let d3 = m(h0, r3)
            .wrapping_add(m(h1, r2))
            .wrapping_add(m(h2, r1))
            .wrapping_add(m(h3, r0))
            .wrapping_add(m(h4, s4));
        let d4 = m(h0, r4)
            .wrapping_add(m(h1, r3))
            .wrapping_add(m(h2, r2))
            .wrapping_add(m(h3, r1))
            .wrapping_add(m(h4, r0));

        // Carry chain back to < 2^26 (+ epsilon) limbs.
        let mut c = d0 >> 26;
        let h0 = d0 & M26;
        let d1 = d1.wrapping_add(c);
        c = d1 >> 26;
        let h1 = d1 & M26;
        let d2 = d2.wrapping_add(c);
        c = d2 >> 26;
        let h2 = d2 & M26;
        let d3 = d3.wrapping_add(c);
        c = d3 >> 26;
        let h3 = d3 & M26;
        let d4 = d4.wrapping_add(c);
        c = d4 >> 26;
        let h4 = d4 & M26;
        let h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        let h0 = h0 & M26;
        let h1 = h1.wrapping_add(c);

        self.h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
    }

    /// Absorb message bytes.
    pub fn update(&mut self, mut data: &[u8]) -> &mut Self {
        // Top up a partial block first.
        if self.buf_len > 0 {
            let space = self.buf.get_mut(self.buf_len..).unwrap_or(&mut []);
            let take = space.len().min(data.len());
            for (d, s) in space.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            self.buf_len = self.buf_len.saturating_add(take);
            data = data.get(take..).unwrap_or(&[]);
            if self.buf_len < 16 {
                // `data` is exhausted; the partial block stays buffered.
                return self;
            }
            let block = self.buf;
            self.process_block(&block, 1 << 24);
            self.buf_len = 0;
        }
        // Whole blocks straight from the input.
        let mut chunks = data.chunks_exact(16);
        for chunk in chunks.by_ref() {
            let mut block = [0u8; 16];
            for (d, s) in block.iter_mut().zip(chunk.iter()) {
                *d = *s;
            }
            self.process_block(&block, 1 << 24);
        }
        // Stash the tail.
        let rem = chunks.remainder();
        for (d, s) in self.buf.iter_mut().zip(rem.iter()) {
            *d = *s;
        }
        self.buf_len = rem.len();
        self
    }

    /// Absorb `data` and then zero bytes up to the next 16-byte boundary
    /// (the AEAD's `pad16`). Calls must themselves start on a block
    /// boundary, which the AEAD construction guarantees.
    pub fn update_padded(&mut self, data: &[u8]) -> &mut Self {
        debug_assert_eq!(
            self.buf_len, 0,
            "update_padded must be entered on a block boundary"
        );
        self.update(data);
        let rem = data.len() % 16;
        if rem != 0 {
            let zeros = [0u8; 16];
            self.update(zeros.get(rem..).unwrap_or(&[]));
        }
        self
    }

    /// Finish and produce the tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            // Final partial block: append 0x01, zero-fill, no high bit.
            let mut block = [0u8; 16];
            for (d, s) in block.iter_mut().zip(self.buf.iter().take(self.buf_len)) {
                *d = *s;
            }
            if let Some(slot) = block.get_mut(self.buf_len) {
                *slot = 1;
            }
            self.process_block(&block, 0);
        }

        // Fully reduce h mod 2^130 - 5, constant time.
        let [h0, h1, h2, h3, h4] = self.h.map(u64::from);
        let mut c = h1 >> 26;
        let h1 = h1 & M26;
        let h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        let h2 = h2 & M26;
        let h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        let h3 = h3 & M26;
        let h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        let h4 = h4 & M26;
        let h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        let h0 = h0 & M26;
        let h1 = h1.wrapping_add(c);

        // g = h + 5 - 2^130; select g when h >= p (i.e. no borrow).
        let g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        let g0 = g0 & M26;
        let g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        let g1 = g1 & M26;
        let g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        let g2 = g2 & M26;
        let g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        let g3 = g3 & M26;
        let g4 = h4.wrapping_add(c).wrapping_sub(1u64 << 26);

        // mask = all-ones iff g4's sign bit (bit 63 after the wrapping
        // subtraction) is clear, i.e. h >= p.
        let mask = (g4 >> 63).wrapping_sub(1);
        let h0 = (h0 & !mask) | (g0 & mask);
        let h1 = (h1 & !mask) | (g1 & mask);
        let h2 = (h2 & !mask) | (g2 & mask);
        let h3 = (h3 & !mask) | (g3 & mask);
        let h4 = (h4 & !mask) | (g4 & mask & M26);

        // Repack to four 32-bit words (h mod 2^128).
        let w0 = (h0 | (h1 << 26)) as u32;
        let w1 = ((h1 >> 6) | (h2 << 20)) as u32;
        let w2 = ((h2 >> 12) | (h3 << 14)) as u32;
        let w3 = ((h3 >> 18) | (h4 << 8)) as u32;

        // tag = (h + s) mod 2^128.
        let [p0, p1, p2, p3] = self.pad;
        let mut f = u64::from(w0).wrapping_add(u64::from(p0));
        let o0 = f as u32;
        f = u64::from(w1)
            .wrapping_add(u64::from(p1))
            .wrapping_add(f >> 32);
        let o1 = f as u32;
        f = u64::from(w2)
            .wrapping_add(u64::from(p2))
            .wrapping_add(f >> 32);
        let o2 = f as u32;
        f = u64::from(w3)
            .wrapping_add(u64::from(p3))
            .wrapping_add(f >> 32);
        let o3 = f as u32;

        let mut tag = [0u8; 16];
        for (chunk, word) in tag.chunks_exact_mut(4).zip([o0, o1, o2, o3].iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        // Key-derived state is wiped by `Drop` below.
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Wipe everything key-derived whether or not `finalize` ran, so
        // a `Poly1305` abandoned mid-stream leaves nothing behind.
        self.r = [0; 5];
        self.h = [0; 5];
        self.pad = [0; 4];
        ct::wipe(&mut self.buf);
        core::hint::black_box(self);
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly1305 { .. }")
    }
}

/// One-shot tag over a single byte string.
#[must_use]
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(data);
    p.finalize()
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
    use std::vec;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_basic_vector() {
        // RFC 8439 §2.5.2.
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.as_slice(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    // ----- slow reference implementation ---------------------------------
    // Schoolbook arithmetic in base 2^32 with explicit reduction mod
    // 2^130-5: deliberately naive so it is easy to audit, used to verify
    // the limb implementation on adversarial inputs.

    /// Little-endian base-2^32 digits.
    type Big = Vec<u64>;

    fn big_from_le_bytes(bytes: &[u8]) -> Big {
        let mut digits = vec![0u64; bytes.len().div_ceil(4)];
        for (i, b) in bytes.iter().enumerate() {
            digits[i / 4] |= u64::from(*b) << (8 * (i % 4));
        }
        digits
    }

    fn big_normalize(a: &mut Big) {
        let mut carry = 0u64;
        for d in a.iter_mut() {
            let v = *d + carry;
            *d = v & 0xffff_ffff;
            carry = v >> 32;
        }
        while carry > 0 {
            a.push(carry & 0xffff_ffff);
            carry >>= 32;
        }
        while a.last() == Some(&0) {
            a.pop();
        }
    }

    fn big_add(a: &Big, b: &Big) -> Big {
        let mut out = vec![0u64; a.len().max(b.len())];
        for (i, o) in out.iter_mut().enumerate() {
            *o = a.get(i).copied().unwrap_or(0) + b.get(i).copied().unwrap_or(0);
        }
        big_normalize(&mut out);
        out
    }

    fn big_mul(a: &Big, b: &Big) -> Big {
        if a.is_empty() || b.is_empty() {
            return Vec::new();
        }
        let mut acc = vec![0u128; a.len() + b.len()];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                acc[i + j] += u128::from(*x) * u128::from(*y);
            }
        }
        // Propagate 128-bit columns into 32-bit digits.
        let mut out = vec![0u64; acc.len() + 2];
        let mut carry = 0u128;
        for (i, col) in acc.iter().enumerate() {
            let v = col + carry;
            out[i] = (v & 0xffff_ffff) as u64;
            carry = v >> 32;
        }
        let mut i = acc.len();
        while carry > 0 {
            out[i] = (carry & 0xffff_ffff) as u64;
            carry >>= 32;
            i += 1;
        }
        big_normalize(&mut out);
        out
    }

    fn big_bit_len(a: &Big) -> usize {
        match a.last() {
            None => 0,
            Some(top) => (a.len() - 1) * 32 + (64 - top.leading_zeros() as usize),
        }
    }

    fn big_shift_right_130(a: &Big) -> Big {
        // floor(a / 2^130): drop 4 whole digits (128 bits) then 2 more bits.
        let mut out: Big = a.iter().skip(4).copied().collect();
        let mut prev = 0u64;
        for d in out.iter_mut().rev() {
            let v = *d;
            *d = (v >> 2) | ((prev & 0b11) << 30);
            prev = v;
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn big_low_130(a: &Big) -> Big {
        let mut out: Big = a.iter().take(5).copied().collect();
        if let Some(top) = out.get_mut(4) {
            *top &= 0b11; // keep bits 128..130
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn big_ge(a: &Big, b: &Big) -> bool {
        if a.len() != b.len() {
            return a.len() > b.len();
        }
        for (x, y) in a.iter().rev().zip(b.iter().rev()) {
            if x != y {
                return x > y;
            }
        }
        true
    }

    fn big_sub(a: &Big, b: &Big) -> Big {
        // requires a >= b
        let mut out = vec![0u64; a.len()];
        let mut borrow = 0i64;
        for (i, o) in out.iter_mut().enumerate() {
            let mut v = a[i] as i64 - b.get(i).copied().unwrap_or(0) as i64 - borrow;
            if v < 0 {
                v += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            *o = v as u64;
        }
        assert_eq!(borrow, 0);
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }

    fn p130() -> Big {
        // 2^130 - 5
        let mut p = vec![0u64; 5];
        p[4] = 0b100;
        let five = vec![5u64];
        big_sub(&p, &five)
    }

    fn big_mod_p(mut a: Big) -> Big {
        let p = p130();
        let five = vec![5u64];
        while big_bit_len(&a) > 130 {
            let hi = big_shift_right_130(&a);
            let lo = big_low_130(&a);
            a = big_add(&lo, &big_mul(&hi, &five));
        }
        while !a.is_empty() && big_ge(&a, &p) {
            a = big_sub(&a, &p);
        }
        a
    }

    fn poly1305_slow(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut r_bytes: [u8; 16] = key[..16].try_into().unwrap();
        // clamp
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;
        let r = big_from_le_bytes(&r_bytes);
        let s = big_from_le_bytes(&key[16..]);

        let mut acc: Big = Vec::new();
        for chunk in msg.chunks(16) {
            let mut n = chunk.to_vec();
            n.push(0x01);
            let n = big_from_le_bytes(&n);
            acc = big_mod_p(big_mul(&big_add(&acc, &n), &r));
        }
        let mut acc = big_add(&acc, &s);
        acc.resize(4, 0); // truncate mod 2^128 / pad
        let mut tag = [0u8; 16];
        for (i, d) in acc.iter().take(4).enumerate() {
            tag[i * 4..i * 4 + 4].copy_from_slice(&(*d as u32).to_le_bytes());
        }
        tag
    }

    #[test]
    fn slow_model_reproduces_rfc_vector() {
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = poly1305_slow(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.as_slice(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    /// Deterministic test PRNG (splitmix64).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                for (d, s) in chunk.iter_mut().zip(v.iter()) {
                    *d = *s;
                }
            }
        }
    }

    #[test]
    fn fast_matches_slow_model_on_random_and_adversarial_inputs() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        // Random keys/messages at every length 0..=64 plus longer ones.
        for len in (0..=64).chain([65, 127, 128, 255, 1024]) {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            let mut msg = vec![0u8; len];
            rng.fill(&mut msg);
            assert_eq!(poly1305(&key, &msg), poly1305_slow(&key, &msg), "len={len}");
        }
        // Adversarial corners: maximal r/s/message bytes, zero key, sparse
        // patterns that maximize carries.
        let specials: [[u8; 32]; 4] = [
            [0xff; 32],
            [0x00; 32],
            {
                let mut k = [0u8; 32];
                k[0] = 0xff;
                k[15] = 0xff;
                k[16] = 0xff;
                k[31] = 0xff;
                k
            },
            {
                let mut k = [0xffu8; 32];
                k[..16].copy_from_slice(&[0x02; 16]);
                k
            },
        ];
        for key in &specials {
            for msg_byte in [0x00u8, 0x01, 0xfe, 0xff] {
                for len in [0usize, 1, 15, 16, 17, 32, 48, 64, 96] {
                    let msg = vec![msg_byte; len];
                    assert_eq!(
                        poly1305(key, &msg),
                        poly1305_slow(key, &msg),
                        "key={key:02x?} byte={msg_byte:02x} len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn streaming_equals_oneshot() {
        let mut rng = Rng(42);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut msg = [0u8; 100];
        rng.fill(&mut msg);
        let oneshot = poly1305(&key, &msg);
        for split in 0..=100 {
            let mut p = Poly1305::new(&key);
            p.update(&msg[..split]).update(&msg[split..]);
            assert_eq!(p.finalize(), oneshot, "split={split}");
        }
        // Byte at a time.
        let mut p = Poly1305::new(&key);
        for b in &msg {
            p.update(core::slice::from_ref(b));
        }
        assert_eq!(p.finalize(), oneshot);
    }

    #[test]
    fn update_padded_pads_to_block_boundary() {
        let key = [9u8; 32];
        let data = [0xabu8; 21];
        let mut a = Poly1305::new(&key);
        a.update_padded(&data);
        let mut b = Poly1305::new(&key);
        b.update(&data).update(&[0u8; 11]);
        assert_eq!(a.finalize(), b.finalize());
        // Already aligned: no padding added.
        let data = [0xabu8; 32];
        let mut a = Poly1305::new(&key);
        a.update_padded(&data);
        let mut b = Poly1305::new(&key);
        b.update(&data);
        assert_eq!(a.finalize(), b.finalize());
    }
}
