//! Typed key material.
//!
//! Distinct types for static secrets, public keys and pre-shared keys make
//! it impossible to pass one where another is expected. Secret-bearing
//! types redact their `Debug` output and wipe themselves on drop (best
//! effort, see [`crate::crypto::ct::wipe`]).

use core::fmt;

use crate::crypto::ct;
use crate::crypto::x25519;
use crate::entropy::EntropySource;
use crate::error::Error;

/// Render 32 bytes as lowercase hex (for `PublicKey`'s Debug only —
/// public information by definition).
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// A WireGuard interface's static Curve25519 private key.
#[derive(Clone)]
pub struct StaticSecret([u8; 32]);

impl StaticSecret {
    /// Generate a fresh private key.
    ///
    /// # Errors
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(rng: &mut dyn EntropySource) -> Result<Self, Error> {
        let bytes = rng.gen32().map_err(|_| Error::EntropyFailure)?;
        Ok(Self(x25519::clamp_scalar(bytes)))
    }

    /// Wrap an existing 32-byte private key (e.g. from `wg genkey`).
    /// Clamping is applied internally wherever the key is used, so both
    /// clamped and unclamped encodings work.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519::x25519_base(&self.0))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for StaticSecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticSecret(REDACTED)")
    }
}

impl Drop for StaticSecret {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

/// A peer's static Curve25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wrap an existing 32-byte public key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// An optional pre-shared 256-bit key (whitepaper §5.2).
///
/// The all-zero default is exactly the protocol's "no PSK" mode (`Q = 0³²`).
#[derive(Clone, Default)]
pub struct PresharedKey([u8; 32]);

impl PresharedKey {
    /// Wrap an existing 32-byte pre-shared key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random PSK (the `wg genpsk` operation).
    ///
    /// # Errors
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(rng: &mut dyn EntropySource) -> Result<Self, Error> {
        Ok(Self(rng.gen32().map_err(|_| Error::EntropyFailure)?))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PresharedKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(REDACTED)")
    }
}

impl Drop for PresharedKey {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::testing::{DeterministicRng, FailingRng};
    use std::format;

    #[test]
    fn public_key_derivation_matches_rfc7748() {
        // RFC 7748 §6.1 Alice keypair.
        let secret = StaticSecret::from_bytes([
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ]);
        let public = secret.public_key();
        assert_eq!(
            public.as_bytes(),
            &[
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
                0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
                0xaa, 0x9b, 0x4e, 0x6a
            ]
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut rng = DeterministicRng::new(7);
        let secret = StaticSecret::generate(&mut rng).unwrap();
        let psk = PresharedKey::generate(&mut rng).unwrap();
        assert_eq!(format!("{secret:?}"), "StaticSecret(REDACTED)");
        assert_eq!(format!("{psk:?}"), "PresharedKey(REDACTED)");
        // Public keys are not secret and print fully.
        let rendered = format!("{:?}", secret.public_key());
        assert!(rendered.starts_with("PublicKey(") && rendered.len() > 70);
    }

    #[test]
    fn generation_uses_and_propagates_entropy() {
        let mut rng = DeterministicRng::new(7);
        let a = StaticSecret::generate(&mut rng).unwrap();
        let b = StaticSecret::generate(&mut rng).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_eq!(
            StaticSecret::generate(&mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        assert_eq!(
            PresharedKey::generate(&mut FailingRng).map(|_| ()),
            Err(Error::EntropyFailure)
        );
    }

    #[test]
    fn default_psk_is_all_zero() {
        assert_eq!(PresharedKey::default().as_bytes(), &[0u8; 32]);
    }
}
