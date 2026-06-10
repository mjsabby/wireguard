//! ChaCha20-Poly1305 (RFC 8439 §2.8) and XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha) AEADs — whitepaper `Aead()` and `Xaead()`.
//!
//! Decryption is strictly *verify-then-decrypt*: the Poly1305 tag is
//! checked (in constant time) over the ciphertext before a single byte of
//! plaintext is produced, so a forgery can never leave attacker-controlled
//! bytes in the caller's buffer.

use crate::Error;
use crate::crypto::chacha20;
use crate::crypto::ct;
use crate::crypto::poly1305::Poly1305;

/// Poly1305 tag length appended to every ciphertext.
pub const TAG_LEN: usize = 16;
/// AEAD key length.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (whitepaper `Xaead` uses a random
/// 24-byte nonce).
pub const XNONCE_LEN: usize = 24;

/// Build the 12-byte nonce WireGuard uses for handshake and transport
/// AEADs: 32 bits of zeros followed by the little-endian counter
/// (whitepaper §5.4).
#[must_use]
pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let [c0, c1, c2, c3, c4, c5, c6, c7] = counter.to_le_bytes();
    [0, 0, 0, 0, c0, c1, c2, c3, c4, c5, c6, c7]
}

/// Copy `src` into `dst` if the lengths match exactly. The explicit check
/// makes the operation total (and the panic in `copy_from_slice`
/// unreachable).
fn copy_exact(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::Internal);
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// Poly1305 tag over `aad` and `ciphertext` per RFC 8439 §2.8: both parts
/// zero-padded to 16 bytes, followed by their lengths as little-endian
/// 64-bit words.
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(otk);
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

/// One-time Poly1305 key: the first 32 bytes of ChaCha20 block 0
/// (RFC 8439 §2.6).
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20::block(key, 0, nonce);
    let mut otk = [0u8; 32];
    for (d, s) in otk.iter_mut().zip(block.iter()) {
        *d = *s;
    }
    otk
}

/// Encrypt `plaintext` with `aad`, writing `ciphertext ∥ tag` into `out`.
///
/// Returns the number of bytes written (`plaintext.len() + TAG_LEN`).
///
/// # Errors
/// [`Error::BufferTooSmall`] if `out` cannot hold the result.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(Error::BufferTooSmall)?;
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let (ct_part, tag_part) = out
        .split_at_mut_checked(plaintext.len())
        .ok_or(Error::Internal)?;

    copy_exact(ct_part, plaintext)?;
    chacha20::xor_in_place(key, 1, nonce, ct_part);

    let mut otk = poly_key(key, nonce);
    let tag = compute_tag(&otk, aad, ct_part);
    ct::wipe_array(&mut otk);
    copy_exact(tag_part, &tag)?;
    Ok(total)
}

/// Verify and decrypt `ciphertext ∥ tag` with `aad`, writing the plaintext
/// into `out`. Returns the plaintext length.
///
/// # Errors
/// * [`Error::AuthFailure`] if the input is shorter than a tag or the tag
///   does not verify — `out` is untouched in both cases.
/// * [`Error::BufferTooSmall`] if `out` cannot hold the plaintext.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let ct_len = ciphertext_and_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::AuthFailure)?;
    let (ciphertext, tag) = ciphertext_and_tag
        .split_at_checked(ct_len)
        .ok_or(Error::Internal)?;
    let out = out.get_mut(..ct_len).ok_or(Error::BufferTooSmall)?;

    let mut otk = poly_key(key, nonce);
    let expected = compute_tag(&otk, aad, ciphertext);
    ct::wipe_array(&mut otk);
    if !ct::ct_eq(&expected, tag) {
        return Err(Error::AuthFailure);
    }

    copy_exact(out, ciphertext)?;
    chacha20::xor_in_place(key, 1, nonce, out);
    Ok(ct_len)
}

/// Encrypt `buf[..pt_len]` in place and append the tag at
/// `buf[pt_len..pt_len + TAG_LEN]`: the zero-copy variant used for
/// transport data, where plaintext is staged directly in the outgoing
/// datagram buffer.
///
/// # Errors
/// [`Error::BufferTooSmall`] if `buf` is shorter than `pt_len + TAG_LEN`.
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let total = pt_len.checked_add(TAG_LEN).ok_or(Error::BufferTooSmall)?;
    let buf = buf.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let (ct_part, tag_part) = buf.split_at_mut_checked(pt_len).ok_or(Error::Internal)?;

    chacha20::xor_in_place(key, 1, nonce, ct_part);
    let mut otk = poly_key(key, nonce);
    let tag = compute_tag(&otk, aad, ct_part);
    ct::wipe_array(&mut otk);
    copy_exact(tag_part, &tag)?;
    Ok(total)
}

/// `Xaead` encryption: XChaCha20-Poly1305 with a 24-byte nonce.
///
/// # Errors
/// As [`seal`].
pub fn xseal(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let (subkey, sub_nonce) = xchacha_derive(key, nonce);
    let mut subkey = subkey;
    let r = seal(&subkey, &sub_nonce, aad, plaintext, out);
    ct::wipe_array(&mut subkey);
    r
}

/// `Xaead` decryption.
///
/// # Errors
/// As [`open`].
pub fn xopen(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let (subkey, sub_nonce) = xchacha_derive(key, nonce);
    let mut subkey = subkey;
    let r = open(&subkey, &sub_nonce, aad, ciphertext_and_tag, out);
    ct::wipe_array(&mut subkey);
    r
}

/// HChaCha20 subkey + derived 12-byte nonce (4 zero bytes ∥ last 8 nonce
/// bytes) per draft-irtf-cfrg-xchacha §2.3.
fn xchacha_derive(key: &[u8; 32], nonce: &[u8; XNONCE_LEN]) -> ([u8; 32], [u8; 12]) {
    let mut hin = [0u8; 16];
    for (d, s) in hin.iter_mut().zip(nonce.iter()) {
        *d = *s;
    }
    let subkey = chacha20::hchacha20(key, &hin);
    let mut sub_nonce = [0u8; 12];
    for (d, s) in sub_nonce.iter_mut().skip(4).zip(nonce.iter().skip(16)) {
        *d = *s;
    }
    (subkey, sub_nonce)
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

    const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 §2.8.2.
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let mut out = [0u8; 256];
        let n = seal(&key, &nonce, &aad, SUNSCREEN, &mut out).unwrap();
        assert_eq!(n, SUNSCREEN.len() + 16);
        let expected_ct = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected_tag = unhex("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(&out[..SUNSCREEN.len()], expected_ct.as_slice());
        assert_eq!(&out[SUNSCREEN.len()..n], expected_tag.as_slice());

        // And the inverse direction.
        let mut pt = [0u8; 256];
        let m = open(&key, &nonce, &aad, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], SUNSCREEN);
    }

    #[test]
    fn roundtrip_various_lengths() {
        let key = [0x42u8; 32];
        for len in 0..130usize {
            let nonce = nonce_from_counter(len as u64);
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let aad = [0xaau8; 7];
            let mut sealed = vec![0u8; len + TAG_LEN];
            let n = seal(&key, &nonce, &aad, &pt, &mut sealed).unwrap();
            assert_eq!(n, len + TAG_LEN);
            let mut opened = vec![0u8; len];
            let m = open(&key, &nonce, &aad, &sealed, &mut opened).unwrap();
            assert_eq!(m, len);
            assert_eq!(opened, pt);
        }
    }

    #[test]
    fn forgery_rejected_and_output_untouched() {
        let key = [7u8; 32];
        let nonce = nonce_from_counter(1);
        let mut sealed = [0u8; 64 + TAG_LEN];
        let n = seal(&key, &nonce, b"aad", &[0x55u8; 64], &mut sealed).unwrap();
        // Flip every single bit; every mutation must fail and must leave
        // the output buffer exactly as it was.
        for byte in 0..n {
            for bit in 0..8 {
                let mut corrupt = sealed;
                corrupt[byte] ^= 1 << bit;
                let mut out = [0xeeu8; 64];
                let r = open(&key, &nonce, b"aad", &corrupt[..n], &mut out);
                assert_eq!(r, Err(Error::AuthFailure), "byte {byte} bit {bit}");
                assert_eq!(out, [0xeeu8; 64], "output dirtied at byte {byte} bit {bit}");
            }
        }
        // Wrong AAD, wrong nonce, wrong key: all rejected.
        let mut out = [0u8; 64];
        assert_eq!(
            open(&key, &nonce, b"aax", &sealed[..n], &mut out),
            Err(Error::AuthFailure)
        );
        assert_eq!(
            open(&key, &nonce_from_counter(2), b"aad", &sealed[..n], &mut out),
            Err(Error::AuthFailure)
        );
        assert_eq!(
            open(&[8u8; 32], &nonce, b"aad", &sealed[..n], &mut out),
            Err(Error::AuthFailure)
        );
    }

    #[test]
    fn truncated_inputs_rejected() {
        let key = [7u8; 32];
        let nonce = nonce_from_counter(1);
        let mut sealed = [0u8; 32 + TAG_LEN];
        let n = seal(&key, &nonce, &[], &[0x55u8; 32], &mut sealed).unwrap();
        let mut out = [0u8; 64];
        for keep in 0..n {
            let r = open(&key, &nonce, &[], &sealed[..keep], &mut out);
            assert!(r.is_err(), "truncation to {keep} accepted");
        }
        // Empty and sub-tag-length inputs.
        assert_eq!(
            open(&key, &nonce, &[], &[], &mut out),
            Err(Error::AuthFailure)
        );
        assert_eq!(
            open(&key, &nonce, &[], &[0u8; 15], &mut out),
            Err(Error::AuthFailure)
        );
    }

    #[test]
    fn buffer_too_small_is_reported_not_panicked() {
        let key = [1u8; 32];
        let nonce = nonce_from_counter(0);
        let mut tiny = [0u8; 8];
        assert_eq!(
            seal(&key, &nonce, &[], &[0u8; 16], &mut tiny),
            Err(Error::BufferTooSmall)
        );
        let mut sealed = [0u8; 16 + TAG_LEN];
        seal(&key, &nonce, &[], &[0u8; 16], &mut sealed).unwrap();
        let mut tiny = [0u8; 8];
        assert_eq!(
            open(&key, &nonce, &[], &sealed, &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn empty_plaintext_is_just_a_tag() {
        // Keepalives are AEAD(key, counter, ε, ε): 16 bytes on the wire.
        let key = [3u8; 32];
        let nonce = nonce_from_counter(9);
        let mut sealed = [0u8; TAG_LEN];
        let n = seal(&key, &nonce, &[], &[], &mut sealed).unwrap();
        assert_eq!(n, TAG_LEN);
        let mut out = [0u8; 0];
        assert_eq!(open(&key, &nonce, &[], &sealed, &mut out), Ok(0));
    }

    #[test]
    fn xaead_roundtrip_and_nonce_separation() {
        let key = [0x99u8; 32];
        let mut n1 = [0u8; 24];
        let mut n2 = [0u8; 24];
        n2[23] = 1;
        let mut a = [0u8; 32 + TAG_LEN];
        let mut b = [0u8; 32 + TAG_LEN];
        xseal(&key, &n1, b"ad", &[0x11u8; 32], &mut a).unwrap();
        xseal(&key, &n2, b"ad", &[0x11u8; 32], &mut b).unwrap();
        assert_ne!(a, b, "different nonces must give different ciphertexts");
        // Differences confined to the HChaCha16-byte prefix also matter.
        n1[0] ^= 1;
        let mut c = [0u8; 32 + TAG_LEN];
        xseal(&key, &n1, b"ad", &[0x11u8; 32], &mut c).unwrap();
        assert_ne!(b, c);

        let mut out = [0u8; 32];
        let m = xopen(&key, &n1, b"ad", &c, &mut out).unwrap();
        assert_eq!(m, 32);
        assert_eq!(out, [0x11u8; 32]);
        // Cross-nonce decryption fails.
        assert_eq!(
            xopen(&key, &n2, b"ad", &c, &mut out),
            Err(Error::AuthFailure)
        );
    }

    #[test]
    fn xchacha_draft_aead_vector() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1 (same plaintext/AAD as the RFC
        // 8439 vector, 24-byte nonce 40..57, key 80..9f).
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let mut out = [0u8; 256];
        let n = xseal(&key, &nonce, &aad, SUNSCREEN, &mut out).unwrap();
        let expected_ct = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        );
        let expected_tag = unhex("c0875924c1c7987947deafd8780acf49");
        assert_eq!(&out[..SUNSCREEN.len()], expected_ct.as_slice());
        assert_eq!(&out[SUNSCREEN.len()..n], expected_tag.as_slice());
    }

    #[test]
    fn seal_in_place_matches_seal() {
        let key = [0x21u8; 32];
        for len in [0usize, 1, 15, 16, 17, 64, 200] {
            let nonce = nonce_from_counter(len as u64);
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut copied = vec![0u8; len + TAG_LEN];
            let n1 = seal(&key, &nonce, b"ad", &pt, &mut copied).unwrap();
            let mut inplace = vec![0u8; len + TAG_LEN];
            inplace[..len].copy_from_slice(&pt);
            let n2 = seal_in_place(&key, &nonce, b"ad", len, &mut inplace).unwrap();
            assert_eq!(n1, n2);
            assert_eq!(copied, inplace, "len={len}");
            // And it opens.
            let mut out = vec![0u8; len];
            assert_eq!(open(&key, &nonce, b"ad", &inplace, &mut out), Ok(len));
            assert_eq!(out, pt);
        }
        // Too-small buffer reports, not panics.
        let mut tiny = [0u8; 10];
        assert_eq!(
            seal_in_place(&key, &nonce_from_counter(0), &[], 8, &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn nonce_from_counter_layout() {
        assert_eq!(nonce_from_counter(0), [0u8; 12]);
        assert_eq!(
            nonce_from_counter(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            nonce_from_counter(u64::MAX),
            [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }
}
