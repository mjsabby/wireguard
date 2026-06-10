//! ChaCha20 stream cipher (RFC 8439) and HChaCha20
//! (draft-irtf-cfrg-xchacha), the cores of WireGuard's two AEADs.

/// "expand 32-byte k", the ChaCha constant words.
const C0: u32 = 0x6170_7865;
const C1: u32 = 0x3320_646e;
const C2: u32 = 0x7962_2d32;
const C3: u32 = 0x6b20_6574;

/// Load 8 little-endian words from a 32-byte key.
#[inline]
fn key_words(key: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (wi, chunk) in w.iter_mut().zip(key.chunks_exact(4)) {
        *wi = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap_or([0; 4]));
    }
    w
}

/// The 20-round ChaCha permutation on a full state, *without* the final
/// feed-forward addition. Shared verbatim by the block function and
/// HChaCha20.
#[inline]
fn permute(state: &[u32; 16]) -> [u32; 16] {
    let [
        mut x0,
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
    ] = *state;

    macro_rules! qr {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(16);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(12);
            $a = $a.wrapping_add($b);
            $d = ($d ^ $a).rotate_left(8);
            $c = $c.wrapping_add($d);
            $b = ($b ^ $c).rotate_left(7);
        };
    }

    // 10 double rounds = 20 rounds.
    for _ in 0..10 {
        qr!(x0, x4, x8, x12);
        qr!(x1, x5, x9, x13);
        qr!(x2, x6, x10, x14);
        qr!(x3, x7, x11, x15);
        qr!(x0, x5, x10, x15);
        qr!(x1, x6, x11, x12);
        qr!(x2, x7, x8, x13);
        qr!(x3, x4, x9, x14);
    }

    [
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
    ]
}

/// One 64-byte keystream block (RFC 8439 §2.3).
#[must_use]
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let k = key_words(key);
    let [k0, k1, k2, k3, k4, k5, k6, k7] = k;
    let mut n = [0u32; 3];
    for (ni, chunk) in n.iter_mut().zip(nonce.chunks_exact(4)) {
        *ni = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap_or([0; 4]));
    }
    let [n0, n1, n2] = n;
    let state = [
        C0, C1, C2, C3, k0, k1, k2, k3, k4, k5, k6, k7, counter, n0, n1, n2,
    ];
    let worked = permute(&state);
    let mut out = [0u8; 64];
    for ((o, w), s) in out.chunks_exact_mut(4).zip(worked.iter()).zip(state.iter()) {
        o.copy_from_slice(&w.wrapping_add(*s).to_le_bytes());
    }
    out
}

/// XOR the ChaCha20 keystream into `data` in place, starting at block
/// `counter` (RFC 8439 §2.4). Encryption and decryption are the same
/// operation.
///
/// The 32-bit block counter wraps per RFC 8439 semantics; a single message
/// would need to exceed 256 GiB to get there, far beyond any datagram this
/// crate touches.
pub fn xor_in_place(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): derive a subkey from a key
/// and a 16-byte nonce; the building block of XChaCha20-Poly1305.
#[must_use]
pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let [k0, k1, k2, k3, k4, k5, k6, k7] = key_words(key);
    let mut n = [0u32; 4];
    for (ni, chunk) in n.iter_mut().zip(input.chunks_exact(4)) {
        *ni = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap_or([0; 4]));
    }
    let [n0, n1, n2, n3] = n;
    let state = [
        C0, C1, C2, C3, k0, k1, k2, k3, k4, k5, k6, k7, n0, n1, n2, n3,
    ];
    let worked = permute(&state);
    // Output = working words 0..4 and 12..16, no feed-forward.
    let [w0, w1, w2, w3, .., w12, w13, w14, w15] = worked;
    let mut out = [0u8; 32];
    for (o, w) in out
        .chunks_exact_mut(4)
        .zip([w0, w1, w2, w3, w12, w13, w14, w15].iter())
    {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
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

    fn rfc_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2.
        let key = rfc_key();
        let nonce: [u8; 12] = unhex("000000090000004a00000000").try_into().unwrap();
        let ks = block(&key, 1, &nonce);
        let expected = unhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(ks.as_slice(), expected);
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: the "sunscreen" plaintext, counter starts at 1.
        let key = rfc_key();
        let nonce: [u8; 12] = unhex("000000000000004a00000000").try_into().unwrap();
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = plaintext.to_vec();
        xor_in_place(&key, 1, &nonce, &mut data);
        let expected = unhex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(data, expected);
        // Round-trip.
        xor_in_place(&key, 1, &nonce, &mut data);
        assert_eq!(data.as_slice(), plaintext);
    }

    #[test]
    fn keystream_continuity_across_chunking() {
        // Encrypting in one call must equal encrypting in pieces with
        // manually advanced counters.
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut whole = [0xa5u8; 256];
        xor_in_place(&key, 5, &nonce, &mut whole);
        let mut parts = [0xa5u8; 256];
        let (a, b) = parts.split_at_mut(64);
        let (b, c) = b.split_at_mut(128);
        xor_in_place(&key, 5, &nonce, a);
        xor_in_place(&key, 6, &nonce, b);
        xor_in_place(&key, 8, &nonce, c);
        assert_eq!(whole, parts);
    }

    #[test]
    fn hchacha20_consistent_with_block_function() {
        // Independent structural check: by construction, HChaCha20(k, n)
        // equals the ChaCha20 working state (block output minus the
        // feed-forward of the input state) at words 0..4 and 12..16, where
        // the 16-byte input supplies words 12..16 (counter ∥ nonce). This
        // pins HChaCha20 to the RFC-validated block function.
        let key = rfc_key();
        let input: [u8; 16] = unhex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let counter = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let nonce: [u8; 12] = input[4..16].try_into().unwrap();
        let blk = block(&key, counter, &nonce);

        let key_w = {
            let mut w = [0u32; 8];
            for (wi, c) in w.iter_mut().zip(key.chunks_exact(4)) {
                *wi = u32::from_le_bytes(c.try_into().unwrap());
            }
            w
        };
        let input_state: [u32; 16] = [
            C0,
            C1,
            C2,
            C3,
            key_w[0],
            key_w[1],
            key_w[2],
            key_w[3],
            key_w[4],
            key_w[5],
            key_w[6],
            key_w[7],
            counter,
            u32::from_le_bytes(input[4..8].try_into().unwrap()),
            u32::from_le_bytes(input[8..12].try_into().unwrap()),
            u32::from_le_bytes(input[12..16].try_into().unwrap()),
        ];
        let mut expected = [0u8; 32];
        for (i, slot) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
            let word = u32::from_le_bytes(blk[slot * 4..slot * 4 + 4].try_into().unwrap())
                .wrapping_sub(input_state[*slot]);
            expected[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(hchacha20(&key, &input), expected);
    }

    #[test]
    fn hchacha20_draft_vector() {
        // draft-irtf-cfrg-xchacha-03 §2.2.1 (verified against
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt).
        let key = rfc_key();
        let input: [u8; 16] = unhex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let expected = unhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        assert_eq!(hchacha20(&key, &input).as_slice(), expected);
    }
}
