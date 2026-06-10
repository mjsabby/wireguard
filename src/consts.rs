//! Protocol constants from the WireGuard whitepaper (§5.4, §6.1).
//!
//! All values are protocol-fixed; changing any of them breaks
//! interoperability. Durations are expressed in nanoseconds to match
//! [`crate::Ticks`].

/// Noise construction name (whitepaper §5.4): hashed into the initial
/// chaining key.
pub const CONSTRUCTION: &[u8; 37] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// WireGuard identifier string (whitepaper §5.4): hashed into the initial
/// handshake hash.
pub const IDENTIFIER: &[u8; 34] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// Label for deriving the `mac1` key from a static public key.
pub const LABEL_MAC1: &[u8; 8] = b"mac1----";
/// Label for deriving the cookie-reply encryption key from a static public
/// key.
pub const LABEL_COOKIE: &[u8; 8] = b"cookie--";

/// After sending this many transport messages on a session, initiate a new
/// handshake (whitepaper §6.1: 2^60).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Hard limit: refuse to encrypt once the sending counter would reach this
/// value, and reject received counters at or above it (whitepaper §6.1:
/// 2^64 − 2^13 − 1).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// One second, in nanoseconds.
const SECOND: u64 = 1_000_000_000;

/// Initiator rekeys a session this old when traffic is sent (whitepaper
/// §6.1: 120 s).
pub const REKEY_AFTER_TIME: u64 = 120 * SECOND;
/// Sessions this old refuse to send or receive (whitepaper §6.1: 180 s).
pub const REJECT_AFTER_TIME: u64 = 180 * SECOND;
/// Handshake retransmission gives up after this long (whitepaper §6.1:
/// 90 s).
pub const REKEY_ATTEMPT_TIME: u64 = 90 * SECOND;
/// Handshake initiations are retransmitted (and never sent more often than)
/// once per this interval (whitepaper §6.1: 5 s).
pub const REKEY_TIMEOUT: u64 = 5 * SECOND;
/// Passive keepalive interval (whitepaper §6.1: 10 s).
pub const KEEPALIVE_TIMEOUT: u64 = 10 * SECOND;
/// Maximum jitter added to timer-driven initiations (whitepaper §6.1;
/// 333 ms, matching the kernel implementation).
pub const REKEY_TIMEOUT_JITTER_MAX: u64 = 333_000_000;
/// Received cookies are usable for this long, and the responder's cookie
/// secret rotates at this interval (whitepaper §5.4.4, §5.4.7: 120 s).
pub const COOKIE_LIFETIME: u64 = 120 * SECOND;
/// All session and handshake state is discarded and wiped if no new session
/// is created for this long (whitepaper §6.3: Reject-After-Time × 3).
pub const SESSION_DISCARD_TIME: u64 = REJECT_AFTER_TIME * 3;
/// On the receive path, the initiator of a session this old starts a new
/// handshake (whitepaper §6.2: Reject-After-Time − Keepalive-Timeout −
/// Rekey-Timeout = 165 s).
pub const REKEY_AFTER_TIME_RECV: u64 = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
/// If we sent data but heard nothing back for this long, the session is
/// presumed dead and a new handshake is initiated (whitepaper §6.5:
/// Keepalive-Timeout + Rekey-Timeout = 15 s).
pub const DEAD_PEER_TIMEOUT: u64 = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

/// Wire size of a handshake initiation message (type 1).
pub const HANDSHAKE_INITIATION_LEN: usize = 148;
/// Wire size of a handshake response message (type 2).
pub const HANDSHAKE_RESPONSE_LEN: usize = 92;
/// Wire size of a cookie reply message (type 3).
pub const COOKIE_REPLY_LEN: usize = 64;
/// Bytes of overhead on a transport message (type 4): 16 bytes of header
/// plus the 16-byte Poly1305 tag.
pub const TRANSPORT_OVERHEAD: usize = 32;
/// Wire size of a keepalive: a transport message with an empty payload.
pub const KEEPALIVE_LEN: usize = TRANSPORT_OVERHEAD;
/// Plaintext is zero-padded to a multiple of this before encryption
/// (whitepaper §5.4.6).
pub const PADDING_MULTIPLE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitepaper_values() {
        // Whitepaper §6.1 table, exactly.
        assert_eq!(REKEY_AFTER_MESSAGES, 1_152_921_504_606_846_976); // 2^60
        assert_eq!(REJECT_AFTER_MESSAGES, 18_446_744_073_709_543_423); // 2^64-2^13-1
        assert_eq!(REKEY_AFTER_TIME, 120_000_000_000);
        assert_eq!(REJECT_AFTER_TIME, 180_000_000_000);
        assert_eq!(REKEY_ATTEMPT_TIME, 90_000_000_000);
        assert_eq!(REKEY_TIMEOUT, 5_000_000_000);
        assert_eq!(KEEPALIVE_TIMEOUT, 10_000_000_000);
        assert_eq!(REKEY_AFTER_TIME_RECV, 165_000_000_000);
        assert_eq!(SESSION_DISCARD_TIME, 540_000_000_000);
        assert_eq!(CONSTRUCTION.len(), 37);
        assert_eq!(IDENTIFIER.len(), 34);
    }
}
