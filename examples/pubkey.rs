//! `wg pubkey` equivalent: read a base64 private key on stdin, print the
//! base64 public key. Used by `scripts/interop_wg_tool.sh` to cross-check
//! our X25519 against wireguard-tools.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::io::Read;

use wireguard_sans_io::crypto::x25519;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().as_bytes();
    if s.len() != 44 || s[43] != b'=' {
        return None;
    }
    let val = |c: u8| -> Option<u32> { B64.iter().position(|&b| b == c).map(|p| p as u32) };
    let mut out = [0u8; 32];
    let mut o = 0usize;
    for chunk in s[..43].chunks(4) {
        let mut acc = 0u32;
        let mut bits = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
            bits += 6;
        }
        while bits >= 8 {
            bits -= 8;
            if o < 32 {
                out[o] = ((acc >> bits) & 0xff) as u8;
                o += 1;
            }
        }
    }
    (o == 32).then_some(out)
}

fn b64_encode_32(data: &[u8; 32]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut acc = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            acc |= u32::from(b) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((acc >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let private = b64_decode_32(&input).expect("stdin must be a 44-char base64 key");
    let public = x25519::x25519_base(&private);
    println!("{}", b64_encode_32(&public));
}
