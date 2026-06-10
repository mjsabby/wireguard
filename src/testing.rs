//! Deterministic helpers for tests, fuzzing and benchmarks.
//!
//! # ⚠️ Not for production
//!
//! [`DeterministicRng`] is fully deterministic given its seed. That is the
//! entire point — reproducible protocol tests and fuzz cases — and exactly
//! what makes it catastrophically unsuitable as a real
//! [`crate::EntropySource`] outside of tests.

use crate::crypto::chacha20;
use crate::entropy::{EntropyError, EntropySource};

/// A ChaCha20-keystream PRNG with a fixed, seed-derived key.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    key: [u8; 32],
    counter: u32,
    block: [u8; 64],
    used: usize,
}

impl DeterministicRng {
    /// Create a generator whose entire output is determined by `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut key = [0u8; 32];
        for (chunk, i) in key.chunks_exact_mut(8).zip(1u64..) {
            chunk.copy_from_slice(&seed.wrapping_mul(i).to_le_bytes());
        }
        Self {
            key,
            counter: 0,
            block: [0u8; 64],
            used: 64,
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.used >= 64 {
            self.block = chacha20::block(&self.key, self.counter, &[0u8; 12]);
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let b = self.block.get(self.used).copied().unwrap_or(0);
        self.used = self.used.saturating_add(1);
        b
    }

    /// A deterministic `u64`, handy for sizing/choice decisions in tests.
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        for b in &mut bytes {
            *b = self.next_byte();
        }
        u64::from_le_bytes(bytes)
    }
}

impl EntropySource for DeterministicRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        for b in buf.iter_mut() {
            *b = self.next_byte();
        }
        Ok(())
    }
}

/// An [`EntropySource`] that always fails — for exercising the
/// [`crate::Error::EntropyFailure`] paths.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailingRng;

impl EntropySource for FailingRng {
    fn fill(&mut self, _buf: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn deterministic_and_seed_sensitive() {
        let mut a = DeterministicRng::new(1);
        let mut b = DeterministicRng::new(1);
        let mut c = DeterministicRng::new(2);
        let (mut xa, mut xb, mut xc) = ([0u8; 100], [0u8; 100], [0u8; 100]);
        a.fill(&mut xa).unwrap();
        b.fill(&mut xb).unwrap();
        c.fill(&mut xc).unwrap();
        assert_eq!(xa, xb);
        assert_ne!(xa, xc);
        // Streams continue rather than repeat.
        let mut ya = [0u8; 100];
        a.fill(&mut ya).unwrap();
        assert_ne!(xa, ya);
    }

    #[test]
    fn failing_rng_fails() {
        assert!(FailingRng.fill(&mut [0u8; 4]).is_err());
        assert!(FailingRng.gen32().is_err());
    }
}
