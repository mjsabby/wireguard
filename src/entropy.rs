//! Caller-supplied randomness, sans-I/O style.
//!
//! The library never talks to an OS RNG. Operations that need randomness
//! (ephemeral keys, session indices, cookie nonces, retransmission jitter)
//! take a `&mut dyn EntropySource`.

use core::fmt;

/// The entropy source failed to produce bytes.
///
/// Surfaced to callers as [`crate::Error::EntropyFailure`]; the operation
/// that needed randomness is aborted without emitting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("entropy source failed")
    }
}

impl core::error::Error for EntropyError {}

/// A source of cryptographically secure random bytes.
///
/// # Security
///
/// Everything rests on this. Ephemeral X25519 secrets come straight from
/// [`fill`](Self::fill); predictable output breaks forward secrecy
/// entirely. In `std` environments implement this on top of the operating
/// system RNG (`getrandom`, `rand::rngs::OsRng`, …); in embedded
/// environments use the hardware TRNG, seeded and health-checked per its
/// documentation.
///
/// Implementations should return `Err(EntropyError)` rather than produce
/// weak bytes; the library treats that as a hard failure of the operation
/// at hand and stays in a consistent state.
pub trait EntropySource {
    /// Fill `buf` completely with secure random bytes.
    ///
    /// # Errors
    /// [`EntropyError`] if secure bytes cannot be produced; `buf` contents
    /// are then unspecified and will not be used.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError>;

    /// Convenience: a random 32-byte array.
    ///
    /// # Errors
    /// As [`fill`](Self::fill).
    fn gen32(&mut self) -> Result<[u8; 32], EntropyError> {
        let mut out = [0u8; 32];
        self.fill(&mut out)?;
        Ok(out)
    }
}

impl fmt::Debug for dyn EntropySource + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn EntropySource")
    }
}
