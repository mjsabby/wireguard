//! In-tree cryptographic primitives.
//!
//! Everything WireGuard needs — BLAKE2s (plain, keyed, HMAC, and the HKDF
//! chain), ChaCha20, Poly1305, the ChaCha20-Poly1305 and
//! XChaCha20-Poly1305 AEADs, and X25519 — implemented in safe, panic-free,
//! allocation-free Rust with no dependencies.
//!
//! # Hazardous materials
//!
//! These modules are exported so that tests, fuzz targets and benchmarks
//! can exercise them directly, and because auditable primitives are useful.
//! They are **hard to use correctly in isolation** (nonce discipline, key
//! separation, etc. are the caller's problem at this layer). Use
//! [`crate::Tunnel`] unless you know exactly why you need these.
//!
//! # Constant-time discipline
//!
//! No secret-dependent branches and no secret-dependent memory indexing
//! anywhere in this module tree. Comparisons of secret material go through
//! [`ct`]. Limb arithmetic uses fixed-shape operations on `u64`/`u128`,
//! which lower to constant-time instructions on mainstream targets. (As
//! with every constant-time claim in any language, the compiler has the
//! last word; [`ct`] uses `core::hint::black_box` as a best-effort
//! optimization barrier, and the dudect-style test in
//! `tests/constant_time.rs` spot-checks the result empirically.)

pub mod aead;
pub mod blake2s;
pub mod chacha20;
pub mod ct;
pub mod kdf;
pub mod poly1305;
pub mod x25519;
