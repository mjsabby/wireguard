//! Anti-replay sliding window for transport counters (whitepaper §5.4.6,
//! RFC 6479 style bitmap).
//!
//! Checked only *after* AEAD authentication succeeds, so only the
//! legitimate peer can advance it; a cheap read-only pre-check
//! ([`ReplayWindow::check`]) lets the caller drop obvious replays before
//! paying for AEAD verification.

use crate::consts::REJECT_AFTER_MESSAGES;

/// Window width in bits. 2048 tolerates extreme reordering (the kernel
/// uses 8192, wireguard-go 2048; anything ≥ the bandwidth-delay packet
/// count is fine).
pub const WINDOW_BITS: u64 = 2048;
/// One redundant word beyond the window: when the top slides into a new
/// word, that word is cleared, and without the spare word the clear would
/// erase bits of counters still inside the window (RFC 6479's
/// "bitmap minus one word" rule, same layout as wireguard-go).
const WORDS: usize = (WINDOW_BITS / 64) as usize + 1;

/// Sliding bitmap of received counters.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// Highest accepted counter (the window covers
    /// `greatest − WINDOW_BITS + 1 ..= greatest`).
    greatest: u64,
    /// `true` once any counter has been accepted (so counter 0 works).
    primed: bool,
    bitmap: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window: everything below `REJECT_AFTER_MESSAGES` is new.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            greatest: 0,
            primed: false,
            bitmap: [0u64; WORDS],
        }
    }

    /// Would `counter` be accepted right now? Read-only; counters at or
    /// above `REJECT_AFTER_MESSAGES`, already-seen counters, and counters
    /// older than the window are rejected.
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if !self.primed || counter > self.greatest {
            return true;
        }
        if self.greatest.wrapping_sub(counter) >= WINDOW_BITS {
            return false; // too old
        }
        !self.bit(counter)
    }

    /// Record `counter` as received. Must be called only after [`Self::check`]
    /// returned `true` *and* the packet authenticated; returns `false`
    /// (and changes nothing) if the counter would not be accepted, as a
    /// defensive double-check.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        if !self.primed {
            self.primed = true;
            self.greatest = counter;
            self.bitmap = [0u64; WORDS];
            self.set_bit(counter);
            return true;
        }
        if counter > self.greatest {
            // Slide forward: clear every word the jump skips over.
            let advance = counter.wrapping_sub(self.greatest);
            if advance >= WINDOW_BITS {
                self.bitmap = [0u64; WORDS];
            } else {
                // Words are used modulo WORDS; clear the words between the
                // old and new top, exclusive-old / inclusive-new.
                let old_word = self.greatest >> 6;
                let new_word = counter >> 6;
                let mut w = old_word.wrapping_add(1);
                while w <= new_word {
                    if let Some(slot) = self.bitmap.get_mut((w as usize) % WORDS) {
                        *slot = 0;
                    }
                    w = w.wrapping_add(1);
                }
            }
            self.greatest = counter;
        }
        self.set_bit(counter);
        true
    }

    /// Highest counter accepted so far (0 if none).
    #[must_use]
    pub fn greatest(&self) -> u64 {
        if self.primed { self.greatest } else { 0 }
    }

    fn bit(&self, counter: u64) -> bool {
        let word = ((counter >> 6) as usize) % WORDS;
        let mask = 1u64 << (counter & 63);
        self.bitmap.get(word).is_some_and(|w| w & mask != 0)
    }

    fn set_bit(&mut self, counter: u64) {
        let word = ((counter >> 6) as usize) % WORDS;
        let mask = 1u64 << (counter & 63);
        if let Some(w) = self.bitmap.get_mut(word) {
            *w |= mask;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
    use super::*;
    use std::collections::HashSet;
    use std::vec::Vec;

    #[test]
    fn fresh_window_accepts_zero_once() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        assert!(w.accept(0));
        assert!(!w.check(0), "duplicate of counter 0 must be rejected");
        assert!(!w.accept(0));
        assert!(w.accept(1));
    }

    #[test]
    fn in_order_and_duplicates() {
        let mut w = ReplayWindow::new();
        for c in 0..1000u64 {
            assert!(w.accept(c), "fresh {c}");
            assert!(!w.accept(c), "dup {c}");
        }
        assert_eq!(w.greatest(), 999);
    }

    #[test]
    fn reordering_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5000));
        // Everything within the window, in reverse, never seen: accepted.
        for c in (5000 - (WINDOW_BITS - 1)..5000).rev() {
            assert!(w.accept(c), "{c}");
        }
        // All now duplicates.
        for c in 5000 - (WINDOW_BITS - 1)..=5000 {
            assert!(!w.accept(c), "{c}");
        }
        // One past the window's left edge: too old.
        assert!(!w.accept(5000 - WINDOW_BITS));
    }

    #[test]
    fn window_edges_exactly() {
        let mut w = ReplayWindow::new();
        let top = 100_000u64;
        assert!(w.accept(top));
        assert!(w.check(top - (WINDOW_BITS - 1)), "oldest in-window");
        assert!(!w.check(top - WINDOW_BITS), "first out-of-window");
        assert!(w.accept(top - (WINDOW_BITS - 1)));
    }

    #[test]
    fn giant_jumps_clear_the_bitmap() {
        let mut w = ReplayWindow::new();
        for c in 0..100u64 {
            assert!(w.accept(c));
        }
        assert!(w.accept(1_000_000));
        // Everything in the new window that wasn't seen is fresh, even
        // where stale bits would have lived without clearing.
        for c in 1_000_000 - 200..1_000_000 {
            assert!(w.accept(c), "{c}");
        }
        // Old counters far below: rejected as too old.
        assert!(!w.accept(50));
    }

    #[test]
    fn reject_after_messages_limit() {
        let mut w = ReplayWindow::new();
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
        assert!(!w.accept(REJECT_AFTER_MESSAGES + 1));
        assert!(!w.accept(u64::MAX));
        assert!(w.accept(REJECT_AFTER_MESSAGES - 1));
        // Greatest is at the cliff edge; older traffic in-window still ok.
        assert!(w.accept(REJECT_AFTER_MESSAGES - 2));
    }

    /// splitmix64.
    fn mix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn model_based_random_sequences() {
        // Compare against a trivially-correct model: a set of seen
        // counters plus the window rule.
        let mut state = 0x1234_5678u64;
        for _case in 0..50 {
            let mut w = ReplayWindow::new();
            let mut seen: HashSet<u64> = HashSet::new();
            let mut greatest: Option<u64> = None;
            // Mix of local jitter around a rising base and occasional
            // big jumps.
            let mut base = 0u64;
            let counters: Vec<u64> = (0..600)
                .map(|_| {
                    let r = mix(&mut state);
                    if r % 19 == 0 {
                        base = base.wrapping_add(r % 100_000);
                    } else {
                        base = base.wrapping_add(r % 7);
                    }
                    let jitter = mix(&mut state) % (WINDOW_BITS * 2);
                    base.saturating_sub(jitter)
                })
                .collect();
            for c in counters {
                let model_ok = c < REJECT_AFTER_MESSAGES
                    && !seen.contains(&c)
                    && greatest.is_none_or(|g| c > g || g - c < WINDOW_BITS);
                assert_eq!(w.check(c), model_ok, "check({c}) greatest={greatest:?}");
                assert_eq!(w.accept(c), model_ok, "accept({c})");
                if model_ok {
                    seen.insert(c);
                    greatest = Some(greatest.map_or(c, |g| g.max(c)));
                }
            }
        }
    }
}
