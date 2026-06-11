//! Caller-supplied time, sans-I/O style.
//!
//! The library never reads a clock. Every API call that can depend on time
//! takes a [`Now`], which carries both a monotonic instant ([`Ticks`], used
//! for all whitepaper §6 timers) and a wall-clock reading (used only to
//! build the TAI64N handshake timestamp, [`Tai64N`]).

use core::fmt;

/// A monotonic instant in nanoseconds since an arbitrary caller-chosen
/// epoch (e.g. `std::time::Instant` elapsed-since-start).
///
/// `Ticks` must never decrease across calls into the same
/// [`crate::Tunnel`]. All arithmetic is saturating, so even a hostile clock
/// cannot cause a panic — a decreasing clock merely degrades timer
/// behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Ticks(u64);

impl Ticks {
    /// The zero instant.
    pub const ZERO: Self = Self(0);

    /// Construct from nanoseconds since the caller's epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Construct from seconds since the caller's epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// Nanoseconds since the caller's epoch.
    #[must_use]
    pub const fn nanos(self) -> u64 {
        self.0
    }

    /// This instant plus a duration in nanoseconds (saturating).
    #[must_use]
    pub const fn add_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    /// Nanoseconds elapsed from `earlier` to `self`; zero if `earlier` is
    /// in the future (saturating).
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// The earlier of two instants.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }
}

/// A complete caller-supplied reading of "now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Monotonic time, drives every protocol timer.
    pub ticks: Ticks,
    /// Wall-clock seconds since the Unix epoch. Only used to build the
    /// TAI64N timestamp inside handshake initiations; it must be (roughly)
    /// real **and non-decreasing**: the library clamps `ticks` against
    /// regression but cannot clamp the wall clock, so a backwards step
    /// here makes the peer reject our initiations as
    /// [`crate::Error::ReplayedTimestamp`] until the clock catches up.
    pub unix_secs: u64,
    /// Sub-second nanoseconds of the wall clock, `< 1_000_000_000`
    /// (defensively clamped, never panics).
    pub unix_nanos: u32,
}

impl Now {
    /// Build a `Now` from monotonic nanoseconds and a Unix wall-clock
    /// reading. `unix_nanos` is clamped to `999_999_999`.
    #[must_use]
    pub const fn new(mono_nanos: u64, unix_secs: u64, unix_nanos: u32) -> Self {
        let unix_nanos = if unix_nanos > 999_999_999 {
            999_999_999
        } else {
            unix_nanos
        };
        Self {
            ticks: Ticks::from_nanos(mono_nanos),
            unix_secs,
            unix_nanos,
        }
    }

    /// The TAI64N timestamp for this wall-clock reading.
    #[must_use]
    pub const fn tai64n(&self) -> Tai64N {
        Tai64N::from_unix(self.unix_secs, self.unix_nanos)
    }
}

/// A TAI64N timestamp (whitepaper §5.1): 8 bytes big-endian seconds since
/// the TAI epoch, then 4 bytes big-endian nanoseconds.
///
/// Big-endian layout means plain lexicographic byte comparison orders
/// timestamps chronologically; the derived `Ord` on the inner array does
/// exactly that. Timestamps are not secret, so a variable-time comparison
/// is fine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tai64N([u8; 12]);

/// TAI64 label of the Unix epoch as used by existing WireGuard
/// implementations (`2^62 + 10`).
const TAI64_UNIX_BASE: u64 = 0x4000_0000_0000_000a;

/// The whitepaper (§5.1) permits truncating 24 bits of the nanoseconds to
/// avoid leaking fine-grained clock readings; in-tree implementations do,
/// and so do we.
const NANOS_WHITENER_MASK: u32 = !0x00ff_ffff;

impl Tai64N {
    /// Build the (whitened) TAI64N timestamp for a Unix wall-clock reading.
    #[must_use]
    pub const fn from_unix(unix_secs: u64, unix_nanos: u32) -> Self {
        let secs = TAI64_UNIX_BASE.saturating_add(unix_secs);
        let nanos = (unix_nanos & NANOS_WHITENER_MASK) % 1_000_000_000;
        let [s0, s1, s2, s3, s4, s5, s6, s7] = secs.to_be_bytes();
        let [n0, n1, n2, n3] = nanos.to_be_bytes();
        Self([s0, s1, s2, s3, s4, s5, s6, s7, n0, n1, n2, n3])
    }

    /// Interpret 12 raw bytes as a TAI64N timestamp.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// The wire encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl fmt::Debug for Tai64N {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tai64N({:02x?})", self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn ticks_arithmetic_saturates() {
        assert_eq!(Ticks::from_nanos(u64::MAX).add_nanos(1).nanos(), u64::MAX);
        assert_eq!(Ticks::from_secs(u64::MAX).nanos(), u64::MAX);
        assert_eq!(Ticks::from_nanos(5).since(Ticks::from_nanos(9)), 0);
        assert_eq!(Ticks::from_nanos(9).since(Ticks::from_nanos(5)), 4);
        assert_eq!(
            Ticks::from_nanos(3).min(Ticks::from_nanos(7)),
            Ticks::from_nanos(3)
        );
    }

    #[test]
    fn tai64n_layout_and_base() {
        // Unix epoch exactly.
        let t = Tai64N::from_unix(0, 0);
        assert_eq!(
            t.as_bytes(),
            &[0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0],
            "TAI64 label of the Unix epoch must be 2^62 + 10"
        );
        // Seconds land in the first 8 bytes, big-endian.
        let t = Tai64N::from_unix(1, 0);
        assert_eq!(&t.as_bytes()[..8], &[0x40, 0, 0, 0, 0, 0, 0, 0x0b]);
    }

    #[test]
    fn tai64n_orders_chronologically() {
        let a = Tai64N::from_unix(100, 0);
        let b = Tai64N::from_unix(100, 999_999_999);
        let c = Tai64N::from_unix(101, 0);
        assert!(a < b && b < c);
        // Equal after whitening: nanos differing only in the low 24 bits
        // compare equal -- callers (the handshake) rely on strict "greater"
        // so this must be Equal, not Less.
        let d = Tai64N::from_unix(100, 0x0100_0000);
        let e = Tai64N::from_unix(100, 0x01ff_ffff);
        assert_eq!(d, e);
    }

    #[test]
    fn tai64n_whitening_truncates_low_24_bits() {
        let t = Tai64N::from_unix(0, 0x0123_4567);
        assert_eq!(&t.as_bytes()[8..], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tai64n_never_panics_on_extreme_inputs() {
        let _ = Tai64N::from_unix(u64::MAX, u32::MAX);
        let _ = Now::new(u64::MAX, u64::MAX, u32::MAX);
        assert_eq!(Now::new(0, 0, u32::MAX).unix_nanos, 999_999_999);
    }
}
