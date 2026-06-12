//! The top-level sans-I/O WireGuard state machine for one peer pair.
//!
//! [`Tunnel`] owns every piece of per-peer protocol state — handshake,
//! sessions, cookies, timers — and exposes exactly four operations, none
//! of which performs I/O, reads a clock, or allocates:
//!
//! * [`Tunnel::encapsulate`]: plaintext in → transport datagram out (or a
//!   handshake initiation when no session exists yet).
//! * [`Tunnel::decapsulate`]: received datagram in → plaintext out, or a
//!   datagram that must be sent back (handshake response / cookie reply),
//!   or a state-change notification.
//! * [`Tunnel::poll`]: produces any timer-driven message that is due
//!   (retransmissions, keepalives, rekeys, expiries).
//! * [`Tunnel::next_wake`]: the earliest instant at which [`Tunnel::poll`]
//!   could have something to do.
//!
//! The caller owns sockets, clocks and scheduling; drive the tunnel with
//! datagrams as they arrive and call `poll` whenever `next_wake` falls
//! due.

use core::num::NonZeroU16;

use crate::consts::{
    HANDSHAKE_INITIATION_LEN, HANDSHAKE_RESPONSE_LEN, PADDING_MULTIPLE, REJECT_AFTER_MESSAGES,
    REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECV,
    REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX, SESSION_DISCARD_TIME, TRANSPORT_OVERHEAD,
};
use crate::cookie::{self, CookieJar, LastCookie, MacKeys};
use crate::crypto::x25519;
use crate::crypto::{aead, ct};
use crate::entropy::EntropySource;
use crate::error::Error;
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{self, Packet, TransportData};
use crate::noise::{self, HandshakeConstants, InFlightInitiation};
use crate::session::Session;
use crate::time::{Now, Tai64N, Ticks};
use crate::timers::Timers;

/// Static configuration of a [`Tunnel`].
#[derive(Debug)]
pub struct Config {
    /// Our interface's static private key.
    pub local_static: StaticSecret,
    /// The peer's static public key.
    pub peer_public: PublicKey,
    /// Optional pre-shared key (whitepaper §5.2); all-zero default means
    /// "no PSK".
    pub psk: PresharedKey,
    /// Optional persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<NonZeroU16>,
}

impl Config {
    /// Configuration with no PSK and no persistent keepalive.
    #[must_use]
    pub fn new(local_static: StaticSecret, peer_public: PublicKey) -> Self {
        Self {
            local_static,
            peer_public,
            psk: PresharedKey::default(),
            persistent_keepalive: None,
        }
    }
}

/// Result of [`Tunnel::encapsulate`].
#[derive(Debug)]
pub enum Encapsulated<'a> {
    /// The payload was encrypted; send this datagram to the peer.
    Transport(&'a [u8]),
    /// No usable session: a handshake initiation was produced instead and
    /// **the payload was not consumed**. Send this datagram, keep the
    /// payload buffered, and retry after the handshake completes (watch
    /// for [`Received::HandshakeComplete`]).
    HandshakeInitiation(&'a [u8]),
}

/// Result of [`Tunnel::decapsulate`].
#[derive(Debug)]
pub enum Received<'a> {
    /// Decrypted transport payload. WireGuard pads plaintext to 16 bytes,
    /// so this may carry up to 15 trailing padding bytes (zero from a
    /// conformant peer; the padding is authenticated but its content is
    /// not verified here). [`crate::message::ip_packet_len`] recovers
    /// the inner length.
    Data(&'a [u8]),
    /// An (authenticated) keepalive arrived. Nothing to deliver.
    Keepalive,
    /// The datagram was a handshake message that requires this reply
    /// (handshake response or cookie reply). Send it to the peer.
    Reply(&'a [u8]),
    /// A handshake we initiated just completed; data may now flow in both
    /// directions. If no data is sent promptly, [`Tunnel::poll`] emits a
    /// confirming keepalive so the responder can use the session too.
    HandshakeComplete,
    /// A cookie reply was accepted; handshake retransmissions will carry
    /// `mac2` until the cookie expires. No message is sent now
    /// (whitepaper §6.6).
    CookieStored,
}

/// Result of [`Tunnel::poll`].
#[derive(Debug)]
pub enum PollOutput<'a> {
    /// Send this datagram to the peer.
    Send(&'a [u8], SendReason),
    /// The current handshake attempt exceeded `REKEY_ATTEMPT_TIME` and was
    /// abandoned (whitepaper §6.4). A later send will start a new one.
    HandshakeExpired,
    /// All session and handshake state was discarded and wiped after
    /// `3 × REJECT_AFTER_TIME` of no new sessions (whitepaper §6.3).
    SessionsExpired,
    /// Nothing to do until [`Tunnel::next_wake`].
    Idle,
}

/// Why [`Tunnel::poll`] produced a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReason {
    /// A fresh handshake initiation (rekey, dead-peer recovery, or
    /// persistent-keepalive revival).
    HandshakeInitiation,
    /// Retransmission of the in-flight initiation (whitepaper §6.4).
    HandshakeRetransmit,
    /// Passive keepalive (whitepaper §6.5) or handshake-confirming
    /// keepalive.
    Keepalive,
    /// Configured persistent keepalive.
    PersistentKeepalive,
}

/// Observability counters. All values are cumulative since construction.
///
/// # ⚠️ Sensitivity
///
/// The per-failure counters (`mac1_failures`, `auth_failures`,
/// `replays_dropped`, `cookies_sent`) are **attacker-influenceable** and,
/// if exposed unaggregated to an untrusted observer (e.g. an
/// unauthenticated metrics endpoint), act as exact oracles: an attacker
/// can confirm this endpoint's static public key by watching
/// `mac1_failures`, probe load state via `cookies_sent`, and inflate
/// `replays_dropped` for free. Treat them as you would a debug log:
/// aggregate before publishing, or restrict who can read them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Transport messages sent (including keepalives).
    pub tx_transport: u64,
    /// Transport messages received and authenticated (incl. keepalives).
    pub rx_transport: u64,
    /// Plaintext payload bytes sent (before padding).
    pub tx_bytes: u64,
    /// Plaintext payload bytes received (after padding, before trimming).
    pub rx_bytes: u64,
    /// Keepalives sent.
    pub tx_keepalives: u64,
    /// Keepalives received.
    pub rx_keepalives: u64,
    /// Handshake initiations sent (including retransmissions).
    pub handshakes_initiated: u64,
    /// Handshake responses sent (initiations we accepted).
    pub handshakes_responded: u64,
    /// Sessions established (as initiator or responder-confirmed).
    pub handshakes_completed: u64,
    /// Datagrams rejected for failed authentication (any kind).
    pub auth_failures: u64,
    /// Handshake messages dropped for bad `mac1`.
    pub mac1_failures: u64,
    /// Transport messages dropped by the anti-replay window.
    pub replays_dropped: u64,
    /// Cookie replies accepted.
    pub cookies_received: u64,
    /// Cookie replies sent while under load.
    pub cookies_sent: u64,
    /// Monotonic instant of the last completed handshake.
    pub last_handshake_at: Option<Ticks>,
}

/// Which slot a session lives in (whitepaper §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Previous,
    Current,
    Next,
}

/// `DH(S_priv_local, S_pub_peer)`: never changes for the life of a
/// `Tunnel`, computed once at construction (audit L-1/L-2). Wiped on drop.
struct StaticStaticSecret([u8; 32]);

impl Drop for StaticStaticSecret {
    fn drop(&mut self) {
        ct::wipe_array(&mut self.0);
    }
}

/// A sans-I/O WireGuard tunnel to a single peer.
///
/// # Buffers
///
/// All output buffers are caller-provided. `encapsulate` needs
/// `max(148, transport_datagram_len(payload.len()))` bytes; `decapsulate`
/// needs `max(92, datagram.len() − 32)`; `poll` needs at least 148.
/// [`transport_datagram_len`] does the padding arithmetic.
///
/// # Example
///
/// ```
/// use wireguard_sans_io::{Config, Now, StaticSecret, Tunnel};
/// use wireguard_sans_io::{Encapsulated, Received};
/// use wireguard_sans_io::testing::DeterministicRng;
///
/// // ⚠ use a real entropy source outside of tests/examples.
/// let mut rng = DeterministicRng::new(42);
/// let a_key = StaticSecret::generate(&mut rng)?;
/// let b_key = StaticSecret::generate(&mut rng)?;
/// let a_pub = a_key.public_key();
/// let b_pub = b_key.public_key();
///
/// let mut a = Tunnel::new(Config::new(a_key, b_pub))?;
/// let mut b = Tunnel::new(Config::new(b_key, a_pub))?;
///
/// // Caller-owned clock and buffers (sans-I/O: no sockets, no clocks).
/// let now = Now::new(0, 1_700_000_000, 0);
/// let mut buf_a = [0u8; 2048];
/// let mut buf_b = [0u8; 2048];
///
/// // A has data but no session: encapsulate hands back an initiation.
/// let init = match a.encapsulate(now, b"ping", &mut buf_a, &mut rng)? {
///     Encapsulated::HandshakeInitiation(wire) => wire,
///     _ => unreachable!(),
/// };
/// // "Network": feed it to B, which answers with a response.
/// let resp = match b.decapsulate(now, &[], false, init, &mut buf_b, &mut rng)? {
///     Received::Reply(wire) => wire,
///     _ => unreachable!(),
/// };
/// // A completes the handshake and can now retry the payload.
/// let mut buf_a2 = [0u8; 2048];
/// assert!(matches!(
///     a.decapsulate(now, &[], false, resp, &mut buf_a2, &mut rng)?,
///     Received::HandshakeComplete
/// ));
/// let data = match a.encapsulate(now, b"ping", &mut buf_a, &mut rng)? {
///     Encapsulated::Transport(wire) => wire,
///     _ => unreachable!(),
/// };
/// // B decrypts (and pads back off with the IP-length helper in real use).
/// match b.decapsulate(now, &[], false, data, &mut buf_b, &mut rng)? {
///     Received::Data(plain) => assert_eq!(&plain[..4], b"ping"),
///     _ => unreachable!(),
/// }
/// # Ok::<(), wireguard_sans_io::Error>(())
/// ```
pub struct Tunnel {
    local_static: StaticSecret,
    local_public: PublicKey,
    peer_public: PublicKey,
    psk: PresharedKey,
    persistent_keepalive: Option<NonZeroU16>,
    constants: HandshakeConstants,
    mac_keys: MacKeys,
    /// Precomputed `DH(local_static, peer_public)` (audit L-1/L-2).
    precomputed_ss: StaticStaticSecret,

    inflight: Option<InFlightInitiation>,
    /// `mac1` of the last initiation we sent (cookie-reply AAD).
    last_init_mac1: Option<[u8; 16]>,
    /// `mac1` of the last response we sent (cookie-reply AAD).
    last_resp_mac1: Option<[u8; 16]>,
    cookie: Option<LastCookie>,
    cookie_jar: CookieJar,
    greatest_timestamp: Option<Tai64N>,
    /// TAI64N of the last initiation we sent: outbound timestamps are
    /// ratcheted strictly past this so a frozen caller wall clock cannot
    /// stall the handshake via peer-side `ReplayedTimestamp` (audit L-4).
    last_sent_tai64n: Option<Tai64N>,

    previous: Option<Session>,
    current: Option<Session>,
    next: Option<Session>,

    timers: Timers,
    /// §6.2 receive-path rekey fired for the current session already.
    recv_rekey_done: bool,
    /// Monotonicity clamp for hostile/buggy caller clocks.
    last_now: Ticks,

    stats: Stats,
}

impl core::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Tunnel(peer={:?}, established={}, inflight={})",
            self.peer_public,
            self.current.is_some(),
            self.inflight.is_some()
        )
    }
}

/// Datagram size for a payload: 16-byte header + zero-padded payload +
/// 16-byte tag (whitepaper §5.4.6).
#[must_use]
pub const fn transport_datagram_len(payload_len: usize) -> usize {
    let padded = match payload_len.checked_add(PADDING_MULTIPLE - 1) {
        Some(v) => v & !(PADDING_MULTIPLE - 1),
        None => usize::MAX & !(PADDING_MULTIPLE - 1),
    };
    padded.saturating_add(TRANSPORT_OVERHEAD)
}

impl Tunnel {
    /// Build a tunnel from its configuration.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if the peer's public key equals our own
    /// public key, or is a low-order / all-zero point (a configuration
    /// mix-up the protocol cannot work with — rejected here rather than on
    /// the first `encapsulate`; audit L-1).
    pub fn new(config: Config) -> Result<Self, Error> {
        let Config {
            local_static,
            peer_public,
            psk,
            persistent_keepalive,
        } = config;
        let local_public = local_static.public_key();
        if ct::ct_eq(local_public.as_bytes(), peer_public.as_bytes()) {
            return Err(Error::InvalidPublicKey);
        }
        // Precompute the static-static DH once (audit L-2). This also
        // rejects low-order `peer_public` up front (audit L-1):
        // `shared_secret` returns `InvalidPublicKey` for an all-zero
        // result.
        let precomputed_ss = StaticStaticSecret(x25519::shared_secret(
            local_static.as_bytes(),
            peer_public.as_bytes(),
        )?);
        let mac_keys = MacKeys::new(&local_public, &peer_public);
        Ok(Self {
            local_static,
            local_public,
            peer_public,
            psk,
            persistent_keepalive,
            constants: HandshakeConstants::new(),
            mac_keys,
            precomputed_ss,
            inflight: None,
            last_init_mac1: None,
            last_resp_mac1: None,
            cookie: None,
            cookie_jar: CookieJar::new(),
            greatest_timestamp: None,
            last_sent_tai64n: None,
            previous: None,
            current: None,
            next: None,
            timers: Timers::default(),
            recv_rekey_done: false,
            last_now: Ticks::ZERO,
            stats: Stats::default(),
        })
    }

    /// Encrypt `payload` into `out` as a transport datagram, or produce a
    /// handshake initiation when no usable session exists (see
    /// [`Encapsulated`]). An empty payload encodes a keepalive.
    ///
    /// # Errors
    /// * [`Error::NotEstablished`] — no session and a handshake is already
    ///   in flight (or rate-limited); the payload was not consumed.
    /// * [`Error::BufferTooSmall`], [`Error::EntropyFailure`],
    ///   [`Error::Expired`].
    pub fn encapsulate<'a>(
        &mut self,
        now: Now,
        payload: &[u8],
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Encapsulated<'a>, Error> {
        let now = self.clamp_now(now);
        let usable = self
            .current
            .as_ref()
            .is_some_and(|s| s.usable_for_send(now.ticks));

        if !usable {
            // §6.4: an explicit attempt to send fresh data resets the
            // Rekey-Attempt-Time window.
            self.timers.gave_up = false;
            if self.inflight.is_some() {
                self.timers.attempt_started = Some(now.ticks);
                return Err(Error::NotEstablished);
            }
            if !self.timers.initiation_allowed(now.ticks) {
                return Err(Error::NotEstablished);
            }
            self.timers.attempt_started = None;
            let n = self.send_initiation(now, out, rng, false)?;
            let wire = out.get(..n).ok_or(Error::Internal)?;
            return Ok(Encapsulated::HandshakeInitiation(wire));
        }

        let total = transport_datagram_len(payload.len());
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let padded = total
            .checked_sub(TRANSPORT_OVERHEAD)
            .ok_or(Error::Internal)?;

        let session = self.current.as_mut().ok_or(Error::Internal)?;
        let counter = session.next_counter()?;
        message::write_transport_header(out, session.keys.peer_index, counter)?;
        // Stage plaintext + zero padding directly in the outgoing buffer,
        // then seal in place.
        let body = out
            .get_mut(16..16usize.saturating_add(padded))
            .ok_or(Error::Internal)?;
        let (data_part, pad_part) = body
            .split_at_mut_checked(payload.len())
            .ok_or(Error::Internal)?;
        data_part.copy_from_slice(payload);
        pad_part.fill(0);
        let sealed = aead::seal_in_place(
            &session.keys.send,
            &aead::nonce_from_counter(counter),
            &[],
            padded,
            out.get_mut(16..).ok_or(Error::Internal)?,
        )?;
        if sealed.saturating_add(16) != total {
            return Err(Error::Internal);
        }

        // Timer + rekey bookkeeping (whitepaper §6.2, send path).
        if payload.is_empty() {
            self.timers.note_keepalive_tx(now.ticks);
            self.stats.tx_keepalives = self.stats.tx_keepalives.saturating_add(1);
        } else {
            self.timers.note_data_tx(now.ticks);
        }
        self.stats.tx_transport = self.stats.tx_transport.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(payload.len() as u64);
        let session = self.current.as_ref().ok_or(Error::Internal)?;
        if session.send_counter >= REKEY_AFTER_MESSAGES
            || (session.keys.is_initiator && session.age(now.ticks) >= REKEY_AFTER_TIME)
        {
            self.timers.rekey_due = true;
        }

        let wire = out.get(..total).ok_or(Error::Internal)?;
        Ok(Encapsulated::Transport(wire))
    }

    /// Process one received datagram.
    ///
    /// `remote` is the caller-encoded source address (IP + port bytes, any
    /// stable encoding) — used only by the cookie subsystem. `under_load`
    /// is the caller's own load signal (e.g. socket queue depth); when
    /// `true`, handshake messages without a valid `mac2` get a cookie
    /// reply instead of processing (whitepaper §5.3).
    ///
    /// # Caller obligations (DoS posture)
    ///
    /// WireGuard's design lets anyone who knows this endpoint's *public*
    /// key force at least one X25519 operation per handshake message when
    /// `under_load == false`. The library has no internal rate limiter
    /// (sans-I/O); **the caller must** assert `under_load` and/or apply an
    /// external per-source rate limit when handshake volume is high,
    /// exactly as the kernel implementation does with `ratelimiter.c`.
    ///
    /// # Errors
    /// All attacker-triggerable errors mean "drop the datagram silently";
    /// no protocol state was changed and nothing must be sent. See
    /// [`Error`].
    pub fn decapsulate<'a>(
        &mut self,
        now: Now,
        remote: &[u8],
        under_load: bool,
        datagram: &[u8],
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Received<'a>, Error> {
        let now = self.clamp_now(now);
        match message::parse(datagram) {
            Ok(Packet::HandshakeInitiation(m)) => {
                if !cookie::verify_mac1(&self.mac_keys, m.alpha, m.mac1) {
                    self.stats.mac1_failures = self.stats.mac1_failures.saturating_add(1);
                    return Err(Error::InvalidMac1);
                }
                if under_load && !self.cookie_jar.verify_mac2(remote, m.beta, m.mac2) {
                    let n = cookie::build_cookie_reply(
                        &self.mac_keys,
                        &mut self.cookie_jar,
                        now.ticks,
                        rng,
                        m.sender_index,
                        m.mac1,
                        remote,
                        out,
                    )?;
                    self.stats.cookies_sent = self.stats.cookies_sent.saturating_add(1);
                    let wire = out.get(..n).ok_or(Error::Internal)?;
                    return Ok(Received::Reply(wire));
                }
                // Expensive part begins only after the cheap MACs passed.
                let consumed = match noise::consume_initiation(
                    &self.constants,
                    &self.local_static,
                    &self.local_public,
                    &m,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                        return Err(e);
                    }
                };
                if !ct::ct_eq(&consumed.static_public, self.peer_public.as_bytes()) {
                    self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                    return Err(Error::UnknownPeer);
                }
                if self
                    .greatest_timestamp
                    .is_some_and(|t| consumed.timestamp <= t)
                {
                    return Err(Error::ReplayedTimestamp);
                }
                let local_index = self.fresh_index(rng)?;
                let eph = rng.gen32().map_err(|_| Error::EntropyFailure)?;
                let keys = noise::create_response(&consumed, &self.psk, local_index, eph, out)?;
                let msg = out
                    .get_mut(..HANDSHAKE_RESPONSE_LEN)
                    .ok_or(Error::Internal)?;
                let mac1 =
                    cookie::apply_macs(&self.mac_keys, self.cookie.as_ref(), now.ticks, msg)?;
                // Commit only now that nothing can fail.
                self.last_resp_mac1 = Some(mac1);
                self.greatest_timestamp = Some(consumed.timestamp);
                self.next = Some(Session::new(keys, now.ticks));
                self.stats.handshakes_responded = self.stats.handshakes_responded.saturating_add(1);
                let wire = out.get(..HANDSHAKE_RESPONSE_LEN).ok_or(Error::Internal)?;
                Ok(Received::Reply(wire))
            }
            Ok(Packet::HandshakeResponse(m)) => {
                // Cheap mac1 first (consistent with the initiation path),
                // then the index match — avoids a sub-µs timing probe of
                // the in-flight index.
                if !cookie::verify_mac1(&self.mac_keys, m.alpha, m.mac1) {
                    self.stats.mac1_failures = self.stats.mac1_failures.saturating_add(1);
                    return Err(Error::InvalidMac1);
                }
                let inflight = self
                    .inflight
                    .as_ref()
                    .filter(|i| i.local_index == m.receiver_index)
                    .ok_or(Error::NoPendingHandshake)?;
                if under_load && !self.cookie_jar.verify_mac2(remote, m.beta, m.mac2) {
                    let n = cookie::build_cookie_reply(
                        &self.mac_keys,
                        &mut self.cookie_jar,
                        now.ticks,
                        rng,
                        m.sender_index,
                        m.mac1,
                        remote,
                        out,
                    )?;
                    self.stats.cookies_sent = self.stats.cookies_sent.saturating_add(1);
                    let wire = out.get(..n).ok_or(Error::Internal)?;
                    return Ok(Received::Reply(wire));
                }
                let keys =
                    match noise::consume_response(inflight, &self.local_static, &self.psk, &m) {
                        Ok(keys) => keys,
                        Err(e) => {
                            self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                            return Err(e);
                        }
                    };
                // Commit: the new session becomes current (whitepaper §6.3).
                self.inflight = None;
                self.previous = self.current.take();
                self.current = Some(Session::new(keys, now.ticks));
                self.recv_rekey_done = false;
                self.timers.note_handshake_complete();
                self.timers.confirm_keepalive_due = true;
                self.stats.handshakes_completed = self.stats.handshakes_completed.saturating_add(1);
                self.stats.last_handshake_at = Some(now.ticks);
                Ok(Received::HandshakeComplete)
            }
            Ok(Packet::CookieReply(m)) => {
                let known = self
                    .inflight
                    .as_ref()
                    .is_some_and(|i| i.local_index == m.receiver_index)
                    || self.session_with_index(m.receiver_index).is_some();
                if !known {
                    return Err(Error::UnknownReceiverIndex);
                }
                // The reply is sealed with AAD = mac1 of the message that
                // provoked it; that may have been our last initiation OR
                // our last response, so try both.
                let try_open = |mac1: &Option<[u8; 16]>| {
                    mac1.as_ref().and_then(|m1| {
                        cookie::consume_cookie_reply(&self.mac_keys, m1, &m, now.ticks).ok()
                    })
                };
                let cookie = match try_open(&self.last_init_mac1)
                    .or_else(|| try_open(&self.last_resp_mac1))
                {
                    Some(c) => c,
                    None if self.last_init_mac1.is_none() && self.last_resp_mac1.is_none() => {
                        return Err(Error::NoPendingHandshake);
                    }
                    None => {
                        self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                        return Err(Error::InvalidCookie);
                    }
                };
                self.cookie = Some(cookie);
                self.stats.cookies_received = self.stats.cookies_received.saturating_add(1);
                Ok(Received::CookieStored)
            }
            Ok(Packet::TransportData(m)) => self.handle_transport(now, &m, out),
            Err(e) => Err(e),
        }
    }

    /// Timer-driven work: handshake retransmission and expiry, rekeys,
    /// keepalives, session discard. Call whenever `now` reaches
    /// [`Tunnel::next_wake`]; each call performs at most one action, so
    /// loop until [`PollOutput::Idle`].
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] (need ≥ 148 bytes),
    /// [`Error::EntropyFailure`].
    pub fn poll<'a>(
        &mut self,
        now: Now,
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<PollOutput<'a>, Error> {
        let now = self.clamp_now(now);
        let t = now.ticks;

        // An unconfirmed responder session in `next` cannot indefinitely
        // postpone wiping of `previous`/`current`: age it out on the
        // same Reject-After-Time horizon as any other keypair.
        if self
            .next
            .as_ref()
            .is_some_and(|s| s.age(t) >= REJECT_AFTER_TIME)
        {
            self.next = None;
        }

        // §6.3: discard everything after 3 × Reject-After-Time without a
        // new session.
        if let Some(newest) = self.newest_session_created() {
            if t.since(newest) >= SESSION_DISCARD_TIME {
                self.discard_all_sessions();
                return Ok(PollOutput::SessionsExpired);
            }
        }

        // §6.4: retransmit or abandon the in-flight handshake.
        if self.inflight.is_some() && self.timers.retransmit_at.is_some_and(|at| t >= at) {
            if self.timers.attempt_exhausted(t) {
                self.inflight = None;
                self.timers.note_gave_up();
                return Ok(PollOutput::HandshakeExpired);
            }
            let n = self.send_initiation(now, out, rng, true)?;
            let wire = out.get(..n).ok_or(Error::Internal)?;
            return Ok(PollOutput::Send(wire, SendReason::HandshakeRetransmit));
        }

        // §6.2: traffic-limit rekey.
        if self.timers.rekey_due {
            if self.inflight.is_some() {
                // A handshake is already running; the flag is satisfied.
                self.timers.rekey_due = false;
            } else if self.timers.initiation_allowed(t) {
                self.timers.attempt_started = None;
                let n = self.send_initiation(now, out, rng, true)?;
                let wire = out.get(..n).ok_or(Error::Internal)?;
                return Ok(PollOutput::Send(wire, SendReason::HandshakeInitiation));
            }
            // else: paced; next_wake covers the pacing deadline.
        }

        // §6.5 second half: dead-peer detection → new handshake.
        if self.inflight.is_none()
            && self.timers.dead_peer_due(t)
            && self.timers.initiation_allowed(t)
        {
            self.timers.attempt_started = None;
            let n = self.send_initiation(now, out, rng, true)?;
            let wire = out.get(..n).ok_or(Error::Internal)?;
            return Ok(PollOutput::Send(wire, SendReason::HandshakeInitiation));
        }

        let current_usable = self.current.as_ref().is_some_and(|s| s.usable_for_send(t));

        // Confirmation keepalive right after an initiator handshake.
        if self.timers.confirm_keepalive_due {
            if current_usable {
                let wire = self.send_keepalive(now, out)?;
                return Ok(PollOutput::Send(wire, SendReason::Keepalive));
            }
            self.timers.confirm_keepalive_due = false;
        }

        // §6.5 first half: passive keepalive.
        if self.timers.passive_keepalive_due(t) {
            if current_usable {
                let wire = self.send_keepalive(now, out)?;
                return Ok(PollOutput::Send(wire, SendReason::Keepalive));
            }
            // Session died before we could answer; disarm.
            self.timers.last_data_rx = None;
        }

        // Persistent keepalive.
        if let Some(interval) = self.persistent_keepalive {
            let interval_ns = u64::from(interval.get()).saturating_mul(1_000_000_000);
            if current_usable {
                let base = self
                    .timers
                    .last_any_tx
                    .or_else(|| self.current.as_ref().map(|s| s.created))
                    .unwrap_or(Ticks::ZERO);
                if t.since(base) >= interval_ns {
                    let wire = self.send_keepalive(now, out)?;
                    return Ok(PollOutput::Send(wire, SendReason::PersistentKeepalive));
                }
            } else if self.inflight.is_none()
                && self.timers.initiation_allowed(t)
                && self.timers.persistent_revive_allowed(t, interval_ns)
            {
                // Keep the tunnel alive even with nothing to send.
                // Persistent-keepalive deliberately survives `gave_up`
                // (its whole purpose is unconditional liveness across
                // peer reboots / NAT expiry), but after a failed attempt
                // it backs off by one keepalive interval rather than
                // hammering every Rekey-Timeout.
                self.timers.gave_up = false;
                self.timers.attempt_started = None;
                let n = self.send_initiation(now, out, rng, true)?;
                let wire = out.get(..n).ok_or(Error::Internal)?;
                return Ok(PollOutput::Send(wire, SendReason::HandshakeInitiation));
            }
        }

        Ok(PollOutput::Idle)
    }

    /// The earliest instant at which [`Tunnel::poll`] may have work.
    /// `None` means no timers are armed. A returned instant may already be
    /// in the past — poll immediately then.
    #[must_use]
    pub fn next_wake(&self) -> Option<Ticks> {
        let pacing_at = self
            .timers
            .last_initiation_tx
            .map_or(Ticks::ZERO, |last| last.add_nanos(REKEY_TIMEOUT));

        let immediate = (self.timers.rekey_due && self.inflight.is_none())
            .then_some(pacing_at)
            .or_else(|| self.timers.confirm_keepalive_due.then_some(Ticks::ZERO));

        let retransmit = if self.inflight.is_some() {
            self.timers.retransmit_at
        } else {
            None
        };

        let dead_peer = if self.inflight.is_none() {
            self.timers.dead_peer_at().map(|at| at.max(pacing_at))
        } else {
            None
        };

        let passive = self.timers.passive_keepalive_at();

        let discard = self
            .newest_session_created()
            .map(|c| c.add_nanos(SESSION_DISCARD_TIME));

        // An unconfirmed `next` is dropped by `poll` at Reject-After-Time
        // (line ~628); waking for that lets the discard horizon recompute
        // without `next` instead of being masked by it. (Audit L-2.)
        let next_expire = self
            .next
            .as_ref()
            .map(|s| s.created.add_nanos(REJECT_AFTER_TIME));

        let persistent = self.persistent_keepalive.and_then(|interval| {
            let interval_ns = u64::from(interval.get()).saturating_mul(1_000_000_000);
            // Mirror `poll`'s `current_usable` test, not just `is_some()`:
            // when `current` exists but is past Reject-After-Time (or
            // counter-exhausted), `poll` cannot send the keepalive and must
            // fall through to the revival branch — so must this deadline,
            // or the caller busy-loops on a stale `last_any_tx + interval`
            // that `poll` can never satisfy. (Audit M-1.)
            match &self.current {
                Some(s) if s.usable_for_send(self.last_now) => {
                    let base = self.timers.last_any_tx.unwrap_or(s.created);
                    Some(base.add_nanos(interval_ns))
                }
                _ if self.inflight.is_none() => {
                    // No usable session: wake at the pacing deadline, or
                    // — if the last attempt gave up — one keepalive
                    // interval after the last initiation.
                    Some(if self.timers.gave_up {
                        self.timers
                            .last_initiation_tx
                            .map_or(Ticks::ZERO, |last| last.add_nanos(interval_ns))
                    } else {
                        pacing_at
                    })
                }
                _ => None, // inflight: the retransmit candidate covers it
            }
        });

        [
            immediate,
            retransmit,
            dead_peer,
            passive,
            discard,
            next_expire,
            persistent,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Explicitly start (or restart) a handshake now, e.g. on
    /// configuration. Respects the global once-per-`REKEY_TIMEOUT` pacing.
    ///
    /// # Errors
    /// [`Error::HandshakeRateLimited`], [`Error::BufferTooSmall`],
    /// [`Error::EntropyFailure`].
    pub fn initiate_handshake<'a>(
        &mut self,
        now: Now,
        out: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<&'a [u8], Error> {
        let now = self.clamp_now(now);
        if !self.timers.initiation_allowed(now.ticks) {
            return Err(Error::HandshakeRateLimited);
        }
        self.timers.gave_up = false;
        self.timers.attempt_started = None;
        let n = self.send_initiation(now, out, rng, false)?;
        out.get(..n).ok_or(Error::Internal)
    }

    /// Is there a confirmed session ready to encrypt outgoing data?
    ///
    /// `false` once the current session is past `REJECT_AFTER_TIME` or
    /// `REJECT_AFTER_MESSAGES` (audit M-1: this used to test only
    /// `current.is_some()`, which stayed `true` for an unusable session).
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.current
            .as_ref()
            .is_some_and(|s| s.usable_for_send(self.last_now))
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Drop and wipe all sessions, in-flight handshakes and cookies.
    ///
    /// Timestamp replay protection (`greatest_timestamp`) is **retained**:
    /// this is deliberate so a captured initiation cannot be replayed
    /// across a reset. The consequence is that if the peer once sent an
    /// initiation with a far-future wall clock (NTP attack, VM snapshot,
    /// operator error), `reset()` cannot un-poison the tunnel — every
    /// subsequent legitimate initiation will be
    /// [`Error::ReplayedTimestamp`] until real time catches up. To
    /// recover from that, drop this `Tunnel` and create a fresh one with
    /// [`Tunnel::new`].
    pub fn reset(&mut self) {
        self.discard_all_sessions();
    }

    // ----- internals ------------------------------------------------------

    /// Defend timer arithmetic against a non-monotonic caller clock: time
    /// never goes backwards from the tunnel's perspective.
    fn clamp_now(&mut self, now: Now) -> Now {
        if now.ticks < self.last_now {
            return Now {
                ticks: self.last_now,
                unix_secs: now.unix_secs,
                unix_nanos: now.unix_nanos,
            };
        }
        self.last_now = now.ticks;
        now
    }

    fn newest_session_created(&self) -> Option<Ticks> {
        [&self.previous, &self.current, &self.next]
            .into_iter()
            .filter_map(|s| s.as_ref().map(|s| s.created))
            .max()
    }

    fn discard_all_sessions(&mut self) {
        self.previous = None;
        self.current = None;
        self.next = None;
        self.inflight = None;
        self.cookie = None;
        // Audit L-3: clear the last-sent-mac1 cache too so "discard wipes
        // everything ephemeral" holds literally. (Non-secret on-wire
        // values, but unreachable after the index slots above are gone,
        // so there is no reason to keep them.)
        self.last_init_mac1 = None;
        self.last_resp_mac1 = None;
        self.recv_rekey_done = false;
        self.timers = Timers {
            last_initiation_tx: self.timers.last_initiation_tx,
            ..Timers::default()
        };
    }

    fn session_with_index(&self, index: u32) -> Option<Slot> {
        if self
            .next
            .as_ref()
            .is_some_and(|s| s.keys.local_index == index)
        {
            return Some(Slot::Next);
        }
        if self
            .current
            .as_ref()
            .is_some_and(|s| s.keys.local_index == index)
        {
            return Some(Slot::Current);
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|s| s.keys.local_index == index)
        {
            return Some(Slot::Previous);
        }
        None
    }

    fn slot_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match slot {
            Slot::Next => self.next.as_mut(),
            Slot::Current => self.current.as_mut(),
            Slot::Previous => self.previous.as_mut(),
        }
    }

    /// A random session index distinct from every live one.
    fn fresh_index(&self, rng: &mut dyn EntropySource) -> Result<u32, Error> {
        for _ in 0..32 {
            let mut bytes = [0u8; 4];
            rng.fill(&mut bytes).map_err(|_| Error::EntropyFailure)?;
            let index = u32::from_le_bytes(bytes);
            let clash = self.session_with_index(index).is_some()
                || self
                    .inflight
                    .as_ref()
                    .is_some_and(|i| i.local_index == index);
            if !clash {
                return Ok(index);
            }
        }
        // 32 straight collisions: the entropy source is not random.
        Err(Error::EntropyFailure)
    }

    /// Create, mac and account a handshake initiation in `out`.
    fn send_initiation(
        &mut self,
        now: Now,
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        timer_driven: bool,
    ) -> Result<usize, Error> {
        let local_index = self.fresh_index(rng)?;
        let eph = rng.gen32().map_err(|_| Error::EntropyFailure)?;
        // §6.1 jitter (≤ 333 ms, timer-driven only). Drawn — and on
        // failure degraded to 0 — *before* any state is committed, so an
        // entropy hiccup here can never strand a phantom `inflight`.
        let jitter = if timer_driven {
            let mut j = [0u8; 8];
            match rng.fill(&mut j) {
                Ok(()) => u64::from_le_bytes(j)
                    .checked_rem(REKEY_TIMEOUT_JITTER_MAX.saturating_add(1))
                    .unwrap_or(0),
                Err(_) => 0, // jitter is non-security-critical: degrade, don't stall
            }
        } else {
            0
        };
        // Audit L-4: ratchet the outbound TAI64N strictly past the last one
        // we sent, so a frozen/regressed caller wall clock cannot make the
        // peer reject every retransmission as `ReplayedTimestamp`. The
        // ratchet adds 1 to the (already-whitened) low nanosecond bits and
        // so leaks nothing the previous timestamp did not.
        let timestamp = match self.last_sent_tai64n {
            Some(last) if now.tai64n() <= last => last.tick(),
            _ => now.tai64n(),
        };
        let inflight = noise::create_initiation(
            &self.constants,
            &self.local_public,
            &self.peer_public,
            &self.precomputed_ss.0,
            local_index,
            eph,
            timestamp,
            out,
        )?;
        let msg = out
            .get_mut(..HANDSHAKE_INITIATION_LEN)
            .ok_or(Error::Internal)?;
        let mac1 = cookie::apply_macs(&self.mac_keys, self.cookie.as_ref(), now.ticks, msg)?;
        // Commit: nothing below can fail.
        self.last_sent_tai64n = Some(timestamp);
        self.last_init_mac1 = Some(mac1);
        self.inflight = Some(inflight);
        self.timers.note_initiation_tx(now.ticks, jitter);
        self.stats.handshakes_initiated = self.stats.handshakes_initiated.saturating_add(1);
        Ok(HANDSHAKE_INITIATION_LEN)
    }

    /// Encrypt an empty payload on the current session.
    fn send_keepalive<'a>(&mut self, now: Now, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if out.len() < TRANSPORT_OVERHEAD {
            return Err(Error::BufferTooSmall);
        }
        let session = self.current.as_mut().ok_or(Error::Internal)?;
        let counter = session.next_counter()?;
        message::write_transport_header(out, session.keys.peer_index, counter)?;
        aead::seal_in_place(
            &session.keys.send,
            &aead::nonce_from_counter(counter),
            &[],
            0,
            out.get_mut(16..).ok_or(Error::Internal)?,
        )?;
        self.timers.note_keepalive_tx(now.ticks);
        self.stats.tx_keepalives = self.stats.tx_keepalives.saturating_add(1);
        self.stats.tx_transport = self.stats.tx_transport.saturating_add(1);
        // §6.2 send-path rekey applies to keepalives too: a keepalive-only
        // initiator session must not coast past Rekey-After-Time.
        let session = self.current.as_ref().ok_or(Error::Internal)?;
        if session.send_counter >= REKEY_AFTER_MESSAGES
            || (session.keys.is_initiator && session.age(now.ticks) >= REKEY_AFTER_TIME)
        {
            self.timers.rekey_due = true;
        }
        out.get(..TRANSPORT_OVERHEAD).ok_or(Error::Internal)
    }

    fn handle_transport<'a>(
        &mut self,
        now: Now,
        msg: &TransportData<'_>,
        out: &'a mut [u8],
    ) -> Result<Received<'a>, Error> {
        let t = now.ticks;
        // Cheap pre-authentication rejects (DoS posture): unknown index,
        // out-of-range counter, expired session, replayed counter.
        let slot = self
            .session_with_index(msg.receiver_index)
            .ok_or(Error::UnknownReceiverIndex)?;
        if msg.counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::Expired);
        }
        let ciphertext = msg.ciphertext;
        let session = self.slot_mut(slot).ok_or(Error::Internal)?;
        if session.age(t) >= REJECT_AFTER_TIME {
            return Err(Error::Expired);
        }
        if !session.replay.check(msg.counter) {
            self.stats.replays_dropped = self.stats.replays_dropped.saturating_add(1);
            return Err(Error::Replay);
        }

        // Authenticate-and-decrypt; out remains untouched on failure.
        let n = match aead::open(
            &session.keys.recv,
            &aead::nonce_from_counter(msg.counter),
            &[],
            ciphertext,
            out,
        ) {
            Ok(n) => n,
            // Audit M-3: a too-small caller buffer is a local error, not
            // an authentication failure — don't pollute the
            // attacker-influenceable `auth_failures` counter with it.
            Err(Error::BufferTooSmall) => return Err(Error::BufferTooSmall),
            Err(e) => {
                self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
                return Err(e);
            }
        };

        // Only an authenticated counter may advance the replay window.
        if !session.replay.accept(msg.counter) {
            return Err(Error::Internal);
        }
        let confirms = !session.confirmed;
        session.confirmed = true;

        if confirms && slot == Slot::Next {
            // First authenticated transport on a responder session:
            // promote next → current (whitepaper §6.3).
            self.previous = self.current.take();
            self.current = self.next.take();
            self.recv_rekey_done = false;
            // Audit M-2: a confirmed session in either role satisfies any
            // in-flight handshake of our own and any pending rekey — clear
            // them so a simultaneous-open or a rekey raced by the peer's
            // initiation doesn't keep retransmitting redundantly for up
            // to 90 s. Mirrors the initiator-side commit above.
            self.inflight = None;
            self.timers.note_handshake_complete();
            self.stats.handshakes_completed = self.stats.handshakes_completed.saturating_add(1);
            self.stats.last_handshake_at = Some(t);
        }

        // §6.2 receive path: the initiator rekeys an aging current session.
        if !self.recv_rekey_done {
            if let Some(current) = &self.current {
                if current.keys.is_initiator && current.age(t) >= REKEY_AFTER_TIME_RECV {
                    self.timers.rekey_due = true;
                    self.recv_rekey_done = true;
                }
            }
        }

        let is_keepalive = n == 0;
        self.timers.note_rx(t, is_keepalive);
        self.stats.rx_transport = self.stats.rx_transport.saturating_add(1);
        self.stats.rx_bytes = self.stats.rx_bytes.saturating_add(n as u64);
        if is_keepalive {
            self.stats.rx_keepalives = self.stats.rx_keepalives.saturating_add(1);
            Ok(Received::Keepalive)
        } else {
            let plain = out.get(..n).ok_or(Error::Internal)?;
            Ok(Received::Data(plain))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::testing::{DeterministicRng, FailingRng};

    fn pair() -> (Tunnel, Tunnel, DeterministicRng) {
        let mut rng = DeterministicRng::new(0x7eb7);
        let a_key = StaticSecret::generate(&mut rng).unwrap();
        let b_key = StaticSecret::generate(&mut rng).unwrap();
        let a_pub = a_key.public_key();
        let b_pub = b_key.public_key();
        let a = Tunnel::new(Config::new(a_key, b_pub)).unwrap();
        let b = Tunnel::new(Config::new(b_key, a_pub)).unwrap();
        (a, b, rng)
    }

    #[test]
    fn transport_datagram_len_padding() {
        assert_eq!(transport_datagram_len(0), 32); // keepalive
        assert_eq!(transport_datagram_len(1), 48);
        assert_eq!(transport_datagram_len(16), 48);
        assert_eq!(transport_datagram_len(17), 64);
        assert_eq!(transport_datagram_len(1420), 1420 + 32 + 4);
        // Saturates instead of overflowing.
        let _ = transport_datagram_len(usize::MAX);
    }

    #[test]
    fn self_peering_rejected() {
        let mut rng = DeterministicRng::new(1);
        let key = StaticSecret::generate(&mut rng).unwrap();
        let public = key.public_key();
        assert!(matches!(
            Tunnel::new(Config::new(key, public)),
            Err(Error::InvalidPublicKey)
        ));
    }

    /// Audit L-1: a low-order/zero peer public key is rejected at
    /// construction, not on the first encapsulate.
    #[test]
    fn low_order_peer_public_rejected_at_construction() {
        let mut rng = DeterministicRng::new(1);
        let key = StaticSecret::generate(&mut rng).unwrap();
        for bad in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            assert!(matches!(
                Tunnel::new(Config::new(key.clone(), PublicKey::from_bytes(bad))),
                Err(Error::InvalidPublicKey)
            ));
        }
    }

    /// Audit M-1: `is_established()` must reflect actual usability.
    #[test]
    fn is_established_false_for_expired_current() {
        let (mut a, mut b, mut rng) = pair();
        let now = Now::new(0, 1_700_000_000, 0);
        let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
        let init = match a.encapsulate(now, b"x", &mut wa, &mut rng).unwrap() {
            Encapsulated::HandshakeInitiation(w) => w.to_vec(),
            _ => panic!(),
        };
        let resp = match b
            .decapsulate(now, &[], false, &init, &mut wb, &mut rng)
            .unwrap()
        {
            Received::Reply(w) => w.to_vec(),
            _ => panic!(),
        };
        a.decapsulate(now, &[], false, &resp, &mut wa, &mut rng)
            .unwrap();
        assert!(a.is_established());
        // Past Reject-After-Time: current still occupies its slot but is
        // no longer usable for sending.
        let late = Now::new(REJECT_AFTER_TIME, 1_700_000_180, 0);
        let _ = a.poll(late, &mut wa, &mut rng); // bump last_now
        assert!(
            !a.is_established(),
            "expired current must not report established"
        );
    }

    /// Audit L-4: a frozen wall clock must not produce identical TAI64N
    /// timestamps on retransmitted initiations.
    #[test]
    fn outbound_tai64n_is_ratcheted_past_frozen_wall_clock() {
        let (mut a, mut b, mut rng) = pair();
        // Wall clock frozen at one value; only mono advances.
        let frozen = |mono| Now::new(mono, 1_700_000_000, 0);
        let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
        let init1 = a
            .initiate_handshake(frozen(0), &mut wa, &mut rng)
            .unwrap()
            .to_vec();
        // B accepts the first.
        assert!(matches!(
            b.decapsulate(frozen(0), &[], false, &init1, &mut wb, &mut rng)
                .unwrap(),
            Received::Reply(_)
        ));
        // 6 s later (mono), wall clock STILL 1_700_000_000: retransmit.
        let init2 = a
            .initiate_handshake(frozen(6_000_000_000), &mut wa, &mut rng)
            .unwrap()
            .to_vec();
        // Without the ratchet, B would reject as ReplayedTimestamp.
        assert!(matches!(
            b.decapsulate(frozen(6_000_000_000), &[], false, &init2, &mut wb, &mut rng)
                .unwrap(),
            Received::Reply(_)
        ));
    }

    /// Audit M-2: confirming a responder session clears any in-flight
    /// handshake of our own.
    #[test]
    fn responder_promotion_clears_own_inflight() {
        let (mut a, mut b, mut rng) = pair();
        let now = Now::new(0, 1_700_000_000, 0);
        let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
        // B starts its OWN handshake (so b.inflight is set).
        let _b_init = b.initiate_handshake(now, &mut wb, &mut rng).unwrap();
        // Meanwhile A initiates; B responds (next set, inflight still set).
        let a_init = a
            .initiate_handshake(now, &mut wa, &mut rng)
            .unwrap()
            .to_vec();
        let resp = match b
            .decapsulate(now, &[], false, &a_init, &mut wb, &mut rng)
            .unwrap()
        {
            Received::Reply(w) => w.to_vec(),
            _ => panic!(),
        };
        a.decapsulate(now, &[], false, &resp, &mut wa, &mut rng)
            .unwrap();
        // A's first transport confirms B's `next` → promotion.
        let data = match a.encapsulate(now, b"hi", &mut wa, &mut rng).unwrap() {
            Encapsulated::Transport(w) => w.to_vec(),
            _ => panic!(),
        };
        b.decapsulate(now, &[], false, &data, &mut wb, &mut rng)
            .unwrap();
        // B's own inflight handshake must now be cleared: poll at the
        // retransmit deadline produces no HandshakeRetransmit.
        let later = Now::new(6_000_000_000, 1_700_000_006, 0);
        let r = b.poll(later, &mut wb, &mut rng).unwrap();
        assert!(
            !matches!(r, PollOutput::Send(_, SendReason::HandshakeRetransmit)),
            "M-2: stale inflight retransmitted after promotion: {r:?}"
        );
        assert!(b.inflight.is_none());
    }

    /// Audit M-3: a caller-side BufferTooSmall on transport receive must
    /// not count as an authentication failure.
    #[test]
    fn buffer_too_small_does_not_count_as_auth_failure() {
        let (mut a, mut b, mut rng) = pair();
        let now = Now::new(0, 1_700_000_000, 0);
        let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
        let init = match a.encapsulate(now, b"x", &mut wa, &mut rng).unwrap() {
            Encapsulated::HandshakeInitiation(w) => w.to_vec(),
            _ => panic!(),
        };
        let resp = match b
            .decapsulate(now, &[], false, &init, &mut wb, &mut rng)
            .unwrap()
        {
            Received::Reply(w) => w.to_vec(),
            _ => panic!(),
        };
        a.decapsulate(now, &[], false, &resp, &mut wa, &mut rng)
            .unwrap();
        let data = match a.encapsulate(now, &[7u8; 64], &mut wa, &mut rng).unwrap() {
            Encapsulated::Transport(w) => w.to_vec(),
            _ => panic!(),
        };
        let mut tiny = [0u8; 8];
        assert_eq!(
            b.decapsulate(now, &[], false, &data, &mut tiny, &mut rng)
                .err(),
            Some(Error::BufferTooSmall)
        );
        assert_eq!(
            b.stats().auth_failures,
            0,
            "BufferTooSmall is a caller error, not an auth failure"
        );
    }

    #[test]
    fn entropy_failure_is_contained() {
        let (mut a, _b, _rng) = pair();
        let now = Now::new(0, 0, 0);
        let mut buf = [0u8; 2048];
        assert!(matches!(
            a.encapsulate(now, b"x", &mut buf, &mut FailingRng),
            Err(Error::EntropyFailure)
        ));
        // The tunnel is still functional with a working rng.
        let mut rng = DeterministicRng::new(2);
        assert!(a.encapsulate(now, b"x", &mut buf, &mut rng).is_ok());
    }

    #[test]
    fn clock_regression_is_clamped() {
        let (mut a, _b, mut rng) = pair();
        let mut buf = [0u8; 2048];
        let _ = a
            .encapsulate(Now::new(1_000_000_000, 5, 0), b"x", &mut buf, &mut rng)
            .unwrap();
        // Time "goes backwards": pacing still measured from the later
        // instant — a second initiation is NOT allowed at t=0.
        let r = a.encapsulate(Now::new(0, 5, 0), b"x", &mut buf, &mut rng);
        assert!(matches!(r, Err(Error::NotEstablished)));
        assert_eq!(a.stats().handshakes_initiated, 1);
    }

    #[test]
    fn fresh_index_with_broken_rng_fails_cleanly() {
        // An rng that always returns the same bytes forces collisions.
        struct ConstRng;
        impl crate::EntropySource for ConstRng {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), crate::EntropyError> {
                buf.fill(0xab);
                Ok(())
            }
        }
        let (mut a, mut b, mut rng) = pair();
        let now = Now::new(0, 0, 0);
        let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
        // Establish a session whose local index is the constant value.
        let init = match a.encapsulate(now, b"x", &mut wa, &mut ConstRng).unwrap() {
            Encapsulated::HandshakeInitiation(w) => w,
            _ => panic!(),
        };
        let resp = match b
            .decapsulate(now, &[], false, init, &mut wb, &mut rng)
            .unwrap()
        {
            Received::Reply(w) => w,
            _ => panic!(),
        };
        let mut wa2 = [0u8; 2048];
        a.decapsulate(now, &[], false, resp, &mut wa2, &mut rng)
            .unwrap();
        // Forcing another handshake with the colliding rng must error,
        // not loop or panic.
        let later = Now::new(REKEY_TIMEOUT, 1, 0);
        assert!(matches!(
            a.initiate_handshake(later, &mut wa2, &mut ConstRng),
            Err(Error::EntropyFailure)
        ));
    }
}
