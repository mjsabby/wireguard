//! BLAKE2s (RFC 7693): the only hash function WireGuard uses.
//!
//! WireGuard needs three shapes of it (whitepaper §5.4):
//!
//! * `Hash(input)` — plain BLAKE2s with 32-byte output: [`Blake2s256`] /
//!   [`hash`].
//! * `Mac(key, input)` — *keyed* BLAKE2s with 16-byte output: [`Blake2sMac`]
//!   / [`mac`].
//! * `Hmac(key, input)` — plain BLAKE2s-256 wrapped in the HMAC
//!   construction: see [`crate::crypto::kdf`].
//!
//! The implementation is streaming (so concatenations like
//! `Hash(a ∥ b ∥ c)` never need a scratch buffer), allocation-free and
//! panic-free.

use crate::crypto::ct;

/// BLAKE2s initialization vector (RFC 7693 §2.6; the SHA-256 IV).
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Message word schedule (RFC 7693 §2.7).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The G mixing function (RFC 7693 §3.1).
#[inline(always)]
#[allow(clippy::indexing_slicing)] // PANIC-FREEDOM: callers pass literal
// indices < 16 into a [u32; 16]; see `compress`.
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// The compression function F (RFC 7693 §3.2).
#[allow(clippy::indexing_slicing)] // PANIC-FREEDOM: every index below is a
// compile-time constant < 16 (literals and SIGMA entries, which are all in
// 0..16) used on [u32; 16] arrays; none can be out of bounds.
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (mi, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *mi = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap_or([0; 4]));
    }

    let mut v = [0u32; 16];
    let (lo, hi) = v.split_at_mut(8);
    lo.copy_from_slice(h.as_slice());
    hi.copy_from_slice(IV.as_slice());
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }

    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    let (v_lo, v_hi) = v.split_at(8);
    for ((hi, a), b) in h.iter_mut().zip(v_lo).zip(v_hi) {
        *hi ^= a ^ b;
    }
}

/// Shared streaming core for both output lengths.
#[derive(Clone)]
struct Core {
    h: [u32; 8],
    /// Bytes fed to `compress` so far.
    t: u64,
    buf: [u8; 64],
    /// Valid prefix of `buf`, `0..=64`.
    buf_len: usize,
}

impl Core {
    /// `out_len` and `key.len()` must both be `<= 32`; the public wrappers
    /// guarantee it.
    fn new(out_len: usize, key: &[u8]) -> Self {
        let mut h = IV;
        let h0 = h.first_mut();
        if let Some(h0) = h0 {
            *h0 ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ (out_len as u32);
        }
        let mut core = Self {
            h,
            t: 0,
            buf: [0u8; 64],
            buf_len: 0,
        };
        if !key.is_empty() {
            // Keyed mode: the key, zero-padded to a full block, becomes the
            // first message block (RFC 7693 §2.9).
            for (d, s) in core.buf.iter_mut().zip(key.iter()) {
                *d = *s;
            }
            core.buf_len = 64;
        }
        core
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == 64 {
                // Only compress a buffered block once we know more input
                // follows: the final block must go through `compress` with
                // the `last` flag instead.
                self.t = self.t.wrapping_add(64);
                compress(&mut self.h, &self.buf, self.t, false);
                self.buf_len = 0;
            }
            let space = self.buf.get_mut(self.buf_len..).unwrap_or(&mut []);
            let take = space.len().min(data.len());
            for (d, s) in space.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            self.buf_len = self.buf_len.saturating_add(take);
            data = data.get(take..).unwrap_or(&[]);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        self.t = self.t.wrapping_add(self.buf_len as u64);
        for b in self.buf.get_mut(self.buf_len..).unwrap_or(&mut []) {
            *b = 0;
        }
        compress(&mut self.h, &self.buf, self.t, true);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        // State is wiped by `Drop` below.
        out
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // The state may have absorbed secret material (keys, chaining
        // values); wipe it whether or not `finalize` ran, so a hasher
        // abandoned mid-stream on an error path leaves nothing behind.
        for word in &mut self.h {
            *word = 0;
        }
        ct::wipe(&mut self.buf);
        core::hint::black_box(&mut *self);
    }
}

/// Streaming BLAKE2s with 32-byte output — WireGuard's `Hash()`.
#[derive(Clone)]
pub struct Blake2s256 {
    core: Core,
}

impl Blake2s256 {
    /// Start a new unkeyed 32-byte-output hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: Core::new(32, &[]),
        }
    }

    /// Absorb `data`; returns `&mut self` so concatenated inputs chain
    /// naturally.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.core.update(data);
        self
    }

    /// Finish and return the 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.core.finalize()
    }
}

impl Default for Blake2s256 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Blake2s256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print absorbed (possibly secret) state.
        f.write_str("Blake2s256 { .. }")
    }
}

/// Streaming *keyed* BLAKE2s with 16-byte output — WireGuard's
/// `Mac(key, input)`.
#[derive(Clone)]
pub struct Blake2sMac {
    core: Core,
}

impl Blake2sMac {
    /// Start a keyed MAC. WireGuard uses 32-byte keys (`mac1`) and 16-byte
    /// keys (`mac2`/cookies); any length up to 32 is accepted. Longer keys
    /// are hashed down to 32 bytes first (defensive totality — the protocol
    /// never does this).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        if key.len() > 32 {
            let mut shortened = Blake2s256::new();
            shortened.update(key);
            let mut digest = shortened.finalize();
            let mac = Self {
                core: Core::new(16, &digest),
            };
            ct::wipe_array(&mut digest);
            mac
        } else {
            Self {
                core: Core::new(16, key),
            }
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.core.update(data);
        self
    }

    /// Finish and return the 16-byte tag.
    #[must_use]
    pub fn finalize(self) -> [u8; 16] {
        let full = self.core.finalize();
        let mut out = [0u8; 16];
        for (d, s) in out.iter_mut().zip(full.iter()) {
            *d = *s;
        }
        out
    }
}

impl core::fmt::Debug for Blake2sMac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Blake2sMac { .. }")
    }
}

/// One-shot `Hash(parts[0] ∥ parts[1] ∥ …)` (whitepaper `Hash`).
#[must_use]
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

/// One-shot `Mac(key, parts[0] ∥ parts[1] ∥ …)` (whitepaper `Mac`).
#[must_use]
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = Blake2sMac::new(key);
    for part in parts {
        m.update(part);
    }
    m.finalize()
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
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc7693_abc() {
        // RFC 7693 Appendix B.
        let digest = hash(&[b"abc"]);
        assert_eq!(
            digest.as_slice(),
            unhex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    #[test]
    fn empty_input() {
        let digest = hash(&[]);
        assert_eq!(
            digest.as_slice(),
            unhex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    #[test]
    fn official_kat_keyed() {
        // First two entries of the official BLAKE2s keyed test vectors
        // (https://github.com/BLAKE2/BLAKE2, blake2s-kat): key = 00..1f,
        // message = empty and [0x00].
        let key: Vec<u8> = (0u8..32).collect();
        let m = Blake2s256_keyed(&key);
        let d0 = m.finalize();
        assert_eq!(
            d0.as_slice(),
            unhex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
        );
        let mut m = Blake2s256_keyed(&key);
        m.core.update(&[0u8]);
        assert_eq!(
            m.finalize().as_slice(),
            unhex("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1")
        );
    }

    /// Keyed BLAKE2s with 32-byte output, only needed to check the official
    /// KAT (the protocol itself only uses keyed-16).
    #[allow(non_snake_case)]
    fn Blake2s256_keyed(key: &[u8]) -> Blake2s256 {
        Blake2s256 {
            core: Core::new(32, key),
        }
    }

    #[test]
    fn incremental_equals_oneshot_at_every_split() {
        // 0..=200-byte messages, split at every possible position, plus
        // byte-at-a-time feeding: all must agree with the one-shot digest.
        let msg: Vec<u8> = (0..200u16).map(|i| (i as u8).wrapping_mul(31)).collect();
        for len in [0usize, 1, 31, 32, 63, 64, 65, 127, 128, 129, 200] {
            let oneshot = hash(&[&msg[..len]]);
            for split in 0..=len {
                let mut h = Blake2s256::new();
                h.update(&msg[..split]).update(&msg[split..len]);
                assert_eq!(h.finalize(), oneshot, "len={len} split={split}");
            }
            let mut h = Blake2s256::new();
            for b in &msg[..len] {
                h.update(core::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), oneshot, "byte-at-a-time len={len}");
        }
    }

    #[test]
    fn mac_is_keyed_and_16_bytes() {
        let t1 = mac(&[1u8; 32], &[b"hello"]);
        let t2 = mac(&[2u8; 32], &[b"hello"]);
        let t3 = mac(&[1u8; 32], &[b"hellp"]);
        assert_ne!(t1, t2);
        assert_ne!(t1, t3);
        // 16-byte keyed output must NOT be a truncation of the 32-byte
        // keyed output (the parameter block differs).
        let mut k32 = Blake2s256_keyed(&[1u8; 32]);
        k32.update(b"hello");
        assert_ne!(&k32.finalize()[..16], t1.as_slice());
        // Multi-part == concatenated.
        assert_eq!(mac(&[1u8; 32], &[b"he", b"llo"]), t1);
    }

    #[test]
    fn long_keys_are_hashed_down_not_panicking() {
        let long_key = [0xabu8; 100];
        let t = mac(&long_key, &[b"x"]);
        let reduced = hash(&[&long_key]);
        assert_eq!(t, mac(&reduced, &[b"x"]));
    }

    #[test]
    fn counter_crosses_block_boundaries() {
        // Exactly 64 and 128 bytes exercise the "hold last block back"
        // logic; compare against splits to ensure t-accounting matches.
        let msg = [0x5au8; 128];
        for len in [63, 64, 65, 127, 128] {
            let oneshot = hash(&[&msg[..len]]);
            let mut h = Blake2s256::new();
            h.update(&msg[..len / 2]).update(&msg[len / 2..len]);
            assert_eq!(h.finalize(), oneshot);
        }
    }
}
