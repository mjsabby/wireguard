//! Error types.

use core::fmt;

/// Every way an operation on a [`crate::Tunnel`] can fail.
///
/// Errors are split into two informal classes, documented per variant:
///
/// * **Attacker-triggerable** (`InvalidPacket`, `InvalidMac1`, `AuthFailure`,
///   `Replay`, …): returned while processing an incoming datagram. The packet
///   has been rejected and **no state was modified and nothing must be sent
///   in response** — WireGuard stays silent toward unauthenticated peers.
///   Callers should drop the datagram and may count the event.
/// * **Caller errors** (`BufferTooSmall`, `NotEstablished`, …): local
///   conditions the caller can act upon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The provided output buffer is too small for the message that needs to
    /// be written. Caller error; see [`crate::transport_datagram_len`].
    BufferTooSmall,
    /// No established session exists, so the payload cannot be encrypted
    /// yet. Caller error; a handshake may have been emitted in its place,
    /// retry after the handshake completes.
    NotEstablished,
    /// The datagram is structurally not a WireGuard message (bad length,
    /// unknown type, non-zero reserved bytes). Attacker-triggerable.
    InvalidPacket,
    /// The `mac1` field of a handshake message is wrong, meaning the sender
    /// does not know our public key. Attacker-triggerable; must be dropped
    /// silently per whitepaper §5.3.
    InvalidMac1,
    /// AEAD or handshake authentication failed. Attacker-triggerable. No
    /// plaintext has been written to the output buffer.
    AuthFailure,
    /// A handshake initiation authenticated correctly but was created by a
    /// static key other than the configured peer. Attacker-triggerable (by
    /// other legitimate holders of our public key).
    UnknownPeer,
    /// A handshake initiation carried a TAI64N timestamp not greater than
    /// one we already accepted: a replayed or reordered initiation.
    /// Attacker-triggerable; whitepaper §5.1.
    ReplayedTimestamp,
    /// A transport or handshake message referenced a receiver index that
    /// does not match any live session or in-flight handshake.
    /// Attacker-triggerable.
    UnknownReceiverIndex,
    /// The transport counter was already received or is too old for the
    /// replay window (whitepaper §5.4.6). Attacker-triggerable.
    Replay,
    /// The session hit `REJECT_AFTER_TIME` / `REJECT_AFTER_MESSAGES`
    /// (whitepaper §6.2) and refuses further traffic until rekeyed.
    Expired,
    /// A handshake response or cookie reply arrived but no matching
    /// handshake is in flight. Attacker-triggerable (e.g. replayed
    /// response).
    NoPendingHandshake,
    /// A cookie reply failed to decrypt or did not match the `mac1` of the
    /// last handshake message we sent. Attacker-triggerable.
    InvalidCookie,
    /// An explicit handshake was requested more often than once per
    /// `REKEY_TIMEOUT` (whitepaper §6.1: "Under no circumstances will
    /// WireGuard send an initiation message more than once every
    /// Rekey-Timeout."). Caller error.
    HandshakeRateLimited,
    /// The configured [`crate::EntropySource`] reported failure. Caller
    /// environment error; the operation was aborted, no message was
    /// produced.
    EntropyFailure,
    /// A Diffie-Hellman operation involved a low-order/invalid public key
    /// (the shared secret would be all-zero). Attacker-triggerable on the
    /// receive path; a configuration error on the send path.
    InvalidPublicKey,
    /// An internal invariant did not hold. This is a defensive replacement
    /// for `panic!`: it should never be observed, and observing it
    /// indicates a bug in this crate. The tunnel remains in a safe state.
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::BufferTooSmall => "output buffer too small",
            Self::NotEstablished => "no established session yet",
            Self::InvalidPacket => "not a structurally valid WireGuard message",
            Self::InvalidMac1 => "handshake message has invalid mac1",
            Self::AuthFailure => "authentication failed",
            Self::UnknownPeer => "authenticated initiation from a different static key",
            Self::ReplayedTimestamp => "handshake initiation timestamp not newer than last",
            Self::UnknownReceiverIndex => "receiver index does not match any session",
            Self::Replay => "transport counter outside replay window",
            Self::Expired => "session exceeded reject-after limits",
            Self::NoPendingHandshake => "no matching in-flight handshake",
            Self::InvalidCookie => "cookie reply failed authentication",
            Self::HandshakeRateLimited => "initiation rate limited to one per REKEY_TIMEOUT",
            Self::EntropyFailure => "entropy source failed",
            Self::InvalidPublicKey => "Diffie-Hellman result was the all-zero point",
            Self::Internal => "internal invariant violated (bug in wireguard-sans-io)",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_is_total_and_distinct() {
        use std::collections::HashSet;
        use std::string::ToString;
        let all = [
            Error::BufferTooSmall,
            Error::NotEstablished,
            Error::InvalidPacket,
            Error::InvalidMac1,
            Error::AuthFailure,
            Error::UnknownPeer,
            Error::ReplayedTimestamp,
            Error::UnknownReceiverIndex,
            Error::Replay,
            Error::Expired,
            Error::NoPendingHandshake,
            Error::InvalidCookie,
            Error::HandshakeRateLimited,
            Error::EntropyFailure,
            Error::InvalidPublicKey,
            Error::Internal,
        ];
        let rendered: HashSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(rendered.len(), all.len(), "error messages must be unique");
    }
}
