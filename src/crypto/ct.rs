//! Constant-time comparison and best-effort wiping of secrets.

/// Constant-time equality of two byte strings whose *lengths are public*.
///
/// Returns `false` immediately on length mismatch (the length of every
/// comparison in this crate is fixed by the protocol, so this branch never
/// depends on a secret). Otherwise the comparison touches every byte
/// exactly once with no data-dependent branches.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Optimization barrier: deny the compiler the knowledge it would need
    // to turn the fold into an early-exit comparison.
    core::hint::black_box(diff) == 0
}

/// Constant-time check that a byte string is all zero.
///
/// Used to reject low-order Diffie-Hellman results without leaking, via
/// timing, which prefix of the result was non-zero.
#[must_use]
pub fn ct_is_zero(a: &[u8]) -> bool {
    let mut acc = 0u8;
    for x in a {
        acc |= x;
    }
    core::hint::black_box(acc) == 0
}

/// Best-effort wipe of secret material.
///
/// Safe Rust offers no guaranteed-volatile write, so this zeroes the bytes
/// and then routes the reference through [`core::hint::black_box`], forcing
/// the compiler to assume the zeroed memory is observed (and therefore not
/// elide the stores). This is a hardening measure, not a guarantee: copies
/// the compiler already spilled elsewhere (moved values, registers) are out
/// of reach — as they are for every zeroization strategy.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(bytes);
}

/// [`wipe`] for fixed-size arrays.
pub fn wipe_array<const N: usize>(bytes: &mut [u8; N]) {
    wipe(bytes.as_mut_slice());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn eq_detects_single_bit_differences_at_every_position() {
        let a = [0x5au8; 64];
        for byte in 0..64 {
            for bit in 0..8 {
                let mut b = a;
                if let Some(v) = b.get_mut(byte) {
                    *v ^= 1u8 << bit;
                }
                assert!(!ct_eq(&a, &b), "flip at byte {byte} bit {bit} missed");
            }
        }
    }

    #[test]
    fn is_zero() {
        assert!(ct_is_zero(b""));
        assert!(ct_is_zero(&[0u8; 32]));
        let mut x = [0u8; 32];
        for i in 0..32 {
            x.fill(0);
            if let Some(v) = x.get_mut(i) {
                *v = 1;
            }
            assert!(!ct_is_zero(&x), "non-zero byte at {i} missed");
        }
    }

    #[test]
    fn wipe_zeroes() {
        let mut secret = [0xffu8; 48];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 48]);
        let mut arr = *b"0123456789abcdef0123456789abcdef";
        wipe_array(&mut arr);
        assert!(ct_is_zero(&arr));
    }
}
