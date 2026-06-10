//! Property-fuzz the crypto layer: seal/open round-trips, in-place vs
//! copying agreement, forgery rejection, and X25519 commutativity, all on
//! fuzzer-chosen inputs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wireguard_sans_io::crypto::{aead, x25519};

fuzz_target!(|input: ([u8; 32], [u8; 32], u64, &[u8], &[u8])| {
    let (key, key2, counter, aad, plaintext) = input;
    if plaintext.len() > 4096 {
        return;
    }
    let nonce = aead::nonce_from_counter(counter);

    // seal → open round-trip.
    let mut sealed = vec![0u8; plaintext.len() + aead::TAG_LEN];
    let n = aead::seal(&key, &nonce, aad, plaintext, &mut sealed).unwrap();
    assert_eq!(n, sealed.len());
    let mut opened = vec![0u8; plaintext.len()];
    assert_eq!(
        aead::open(&key, &nonce, aad, &sealed, &mut opened),
        Ok(plaintext.len())
    );
    assert_eq!(opened, plaintext);

    // In-place sealing must agree byte-for-byte.
    let mut inplace = vec![0u8; plaintext.len() + aead::TAG_LEN];
    inplace[..plaintext.len()].copy_from_slice(plaintext);
    aead::seal_in_place(&key, &nonce, aad, plaintext.len(), &mut inplace).unwrap();
    assert_eq!(inplace, sealed);

    // A different key or nonce must not open it.
    if key2 != key {
        let mut out = vec![0u8; plaintext.len()];
        assert!(aead::open(&key2, &nonce, aad, &sealed, &mut out).is_err());
    }
    let other_nonce = aead::nonce_from_counter(counter.wrapping_add(1));
    let mut out = vec![0u8; plaintext.len()];
    assert!(aead::open(&key, &other_nonce, aad, &sealed, &mut out).is_err());

    // Tag truncation must fail.
    assert!(aead::open(&key, &nonce, aad, &sealed[..sealed.len() - 1], &mut out).is_err());

    // X25519: commutativity on fuzzer keys (the core algebraic property),
    // plus clamping idempotence.
    let ga = x25519::x25519_base(&key);
    let gb = x25519::x25519_base(&key2);
    assert_eq!(x25519::x25519(&key, &gb), x25519::x25519(&key2, &ga));
    let clamped = x25519::clamp_scalar(key);
    assert_eq!(x25519::clamp_scalar(clamped), clamped);
    assert_eq!(x25519::x25519_base(&clamped), ga);
});
