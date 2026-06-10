//! A sans-I/O implementation of the WireGuard® protocol.
//!
//! This crate implements the complete WireGuard protocol logic — the
//! Noise IKpsk2 handshake, cookie-based DoS mitigation, transport data
//! encryption with replay protection, and the whitepaper §6 timer state
//! machine — without performing any I/O, taking any locks, reading any
//! clocks, or allocating any memory.
//!
//! # Design rules
//!
//! * **Sans-I/O**: the library never touches sockets or clocks. Callers feed
//!   in datagrams, buffers, the current time ([`Now`]) and entropy
//!   ([`EntropySource`]); the library hands back datagrams to send and
//!   plaintext that was received. This makes every protocol state — including
//!   every timer expiry — reachable and assertable from deterministic tests.
//! * **`#![no_std]`, no allocator**: all state lives in [`Tunnel`] (a plain
//!   value) and in caller-provided buffers. The crate does not link `alloc`,
//!   so it *cannot* allocate.
//! * **`#![forbid(unsafe_code)]`** — enforced at the crate root and in CI;
//!   there are no dependencies, so the guarantee covers every line of code
//!   involved, including all cryptography.
//! * **Panic-free**: all reachable panic sites are forbidden by `clippy`
//!   lints (no indexing, no unchecked arithmetic, no `unwrap`); release
//!   objects are additionally scanned for `core::panicking` references in CI.
//! * **Defensive**: incoming data is authenticated before it is parsed any
//!   further or allowed to mutate state; plaintext is never written to the
//!   caller's buffer unless authentication succeeded; secret material is
//!   compared in constant time and wiped on drop (best effort, see
//!   [`crypto::ct`]).
//!
//! # Quick start
//!
//! See [`Tunnel`] for a complete two-peer example.
//!
//! WireGuard is a registered trademark of Jason A. Donenfeld. This crate is
//! an independent implementation of the published protocol.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod consts;
mod cookie;
pub mod crypto;
mod entropy;
mod error;
mod keys;
pub mod message;
mod noise;
pub mod replay;
mod session;
pub mod testing;
mod time;
mod timers;
mod tunnel;

pub use entropy::{EntropyError, EntropySource};
pub use error::Error;
pub use keys::{PresharedKey, PublicKey, StaticSecret};
pub use message::{PacketKind, ip_packet_len, peek};
pub use time::{Now, Tai64N, Ticks};
pub use tunnel::{
    Config, Encapsulated, PollOutput, Received, SendReason, Stats, Tunnel, transport_datagram_len,
};
