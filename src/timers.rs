//! Timer bookkeeping for whitepaper §6: pure state plus deadline
//! arithmetic, no clocks.
//!
//! The [`Timers`] struct records *when things last happened*; the tunnel
//! asks it *what is due* at a caller-supplied instant and reports the
//! earliest future deadline through [`Timers::next_wake`].

use crate::consts::{
    DEAD_PEER_TIMEOUT, KEEPALIVE_TIMEOUT, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT,
    REKEY_TIMEOUT_JITTER_MAX,
};
use crate::time::Ticks;

/// Traffic timestamps and armed deadlines.
#[derive(Debug, Default, Clone)]
pub(crate) struct Timers {
    /// Last transport *data* (non-keepalive) we sent.
    pub last_data_tx: Option<Ticks>,
    /// Last transport data (non-keepalive) we received.
    pub last_data_rx: Option<Ticks>,
    /// Last transport message of any kind we sent (incl. keepalives).
    pub last_any_tx: Option<Ticks>,
    /// Last transport message of any kind we received.
    pub last_any_rx: Option<Ticks>,
    /// When the in-flight handshake attempt started (Rekey-Attempt-Time
    /// window).
    pub attempt_started: Option<Ticks>,
    /// When the next retransmission of the in-flight initiation is due
    /// (Rekey-Timeout + jitter after the last send).
    pub retransmit_at: Option<Ticks>,
    /// When we last sent *any* initiation (global once-per-Rekey-Timeout
    /// pacing; whitepaper §6.1).
    pub last_initiation_tx: Option<Ticks>,
    /// Traffic-limit rekey wanted (set on the send/receive paths, §6.2).
    pub rekey_due: bool,
    /// An initiator handshake just completed and nothing has been sent on
    /// the new session yet: emit a keepalive so the responder confirms.
    pub confirm_keepalive_due: bool,
    /// The last handshake attempt ran out of Rekey-Attempt-Time. Timer
    /// triggers stay quiet until the next explicit data event (§6.4: the
    /// attempt counter "is reset when a peer explicitly attempts to send a
    /// new transport data message").
    pub gave_up: bool,
}

impl Timers {
    /// Record a data-bearing transport send.
    pub fn note_data_tx(&mut self, now: Ticks) {
        self.last_data_tx = Some(now);
        self.last_any_tx = Some(now);
        self.confirm_keepalive_due = false;
        self.gave_up = false;
    }

    /// Record a keepalive send.
    pub fn note_keepalive_tx(&mut self, now: Ticks) {
        self.last_any_tx = Some(now);
        self.confirm_keepalive_due = false;
    }

    /// Record an authenticated inbound transport message.
    pub fn note_rx(&mut self, now: Ticks, is_keepalive: bool) {
        self.last_any_rx = Some(now);
        if !is_keepalive {
            self.last_data_rx = Some(now);
        }
        self.gave_up = false;
    }

    /// Record that an initiation went out: starts/continues the attempt
    /// window, arms the retransmission deadline with jitter, and applies
    /// pacing.
    pub fn note_initiation_tx(&mut self, now: Ticks, jitter: u64) {
        if self.attempt_started.is_none() {
            self.attempt_started = Some(now);
        }
        self.last_initiation_tx = Some(now);
        self.retransmit_at = Some(
            now.add_nanos(REKEY_TIMEOUT)
                .add_nanos(jitter.min(REKEY_TIMEOUT_JITTER_MAX)),
        );
        self.rekey_due = false;
    }

    /// Handshake completed: clear the attempt machinery.
    pub fn note_handshake_complete(&mut self) {
        self.attempt_started = None;
        self.retransmit_at = None;
        self.rekey_due = false;
        self.gave_up = false;
    }

    /// Abandon the current attempt (Rekey-Attempt-Time exhausted).
    pub fn note_gave_up(&mut self) {
        self.attempt_started = None;
        self.retransmit_at = None;
        self.rekey_due = false;
        self.gave_up = true;
    }

    /// Is the attempt window exhausted at `now`? (§6.4)
    pub fn attempt_exhausted(&self, now: Ticks) -> bool {
        self.attempt_started
            .is_some_and(|t0| now.since(t0) >= REKEY_ATTEMPT_TIME)
    }

    /// May another initiation be sent at `now`? Never more than one per
    /// Rekey-Timeout, under any circumstances (§6.1).
    pub fn initiation_allowed(&self, now: Ticks) -> bool {
        self.last_initiation_tx
            .is_none_or(|t| now.since(t) >= REKEY_TIMEOUT)
    }

    /// Passive keepalive due (§6.5): we received data and sent nothing
    /// back for Keepalive-Timeout.
    pub fn passive_keepalive_due(&self, now: Ticks) -> bool {
        match self.last_data_rx {
            None => false,
            Some(rx) => {
                let unanswered = self.last_any_tx.is_none_or(|tx| tx < rx);
                unanswered && now.since(rx) >= KEEPALIVE_TIMEOUT
            }
        }
    }

    /// The instant a passive keepalive becomes due, if armed.
    pub fn passive_keepalive_at(&self) -> Option<Ticks> {
        let rx = self.last_data_rx?;
        let unanswered = self.last_any_tx.is_none_or(|tx| tx < rx);
        unanswered.then(|| rx.add_nanos(KEEPALIVE_TIMEOUT))
    }

    /// Dead-peer detection (§6.5): we sent data and heard *nothing* back
    /// for Keepalive-Timeout + Rekey-Timeout.
    pub fn dead_peer_due(&self, now: Ticks) -> bool {
        if self.gave_up {
            return false;
        }
        match self.last_data_tx {
            None => false,
            Some(tx) => {
                let unanswered = self.last_any_rx.is_none_or(|rx| rx < tx);
                unanswered && now.since(tx) >= DEAD_PEER_TIMEOUT
            }
        }
    }

    /// May persistent-keepalive start a fresh handshake attempt at `now`?
    /// Always when not given-up; after `gave_up`, only once a full
    /// keepalive interval has elapsed since the last initiation, so a
    /// dead peer is probed once per interval rather than continuously.
    pub fn persistent_revive_allowed(&self, now: Ticks, interval_ns: u64) -> bool {
        if !self.gave_up {
            return true;
        }
        self.last_initiation_tx
            .is_none_or(|t| now.since(t) >= interval_ns)
    }

    pub fn dead_peer_at(&self) -> Option<Ticks> {
        if self.gave_up {
            return None;
        }
        let tx = self.last_data_tx?;
        let unanswered = self.last_any_rx.is_none_or(|rx| rx < tx);
        unanswered.then(|| tx.add_nanos(DEAD_PEER_TIMEOUT))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::consts::KEEPALIVE_TIMEOUT;

    const S: u64 = 1_000_000_000;

    #[test]
    fn initiation_pacing() {
        let mut t = Timers::default();
        assert!(t.initiation_allowed(Ticks::from_secs(0)));
        t.note_initiation_tx(Ticks::from_secs(0), 0);
        assert!(!t.initiation_allowed(Ticks::from_nanos(REKEY_TIMEOUT - 1)));
        assert!(t.initiation_allowed(Ticks::from_nanos(REKEY_TIMEOUT)));
    }

    #[test]
    fn retransmit_with_clamped_jitter() {
        let mut t = Timers::default();
        t.note_initiation_tx(Ticks::ZERO, u64::MAX);
        assert_eq!(
            t.retransmit_at,
            Some(Ticks::from_nanos(REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX))
        );
        // Attempt window persists across retransmissions.
        t.note_initiation_tx(Ticks::from_nanos(REKEY_TIMEOUT), 0);
        assert_eq!(t.attempt_started, Some(Ticks::ZERO));
        assert!(!t.attempt_exhausted(Ticks::from_nanos(REKEY_ATTEMPT_TIME - 1)));
        assert!(t.attempt_exhausted(Ticks::from_nanos(REKEY_ATTEMPT_TIME)));
    }

    #[test]
    fn passive_keepalive_arming() {
        let mut t = Timers::default();
        assert!(!t.passive_keepalive_due(Ticks::from_secs(100)));
        // Receive data at t=10 with no reply: due at t=20.
        t.note_rx(Ticks::from_secs(10), false);
        assert!(!t.passive_keepalive_due(Ticks::from_secs(19)));
        assert!(t.passive_keepalive_due(Ticks::from_secs(20)));
        // Any send disarms.
        t.note_keepalive_tx(Ticks::from_secs(20));
        assert!(!t.passive_keepalive_due(Ticks::from_secs(40)));
        // Keepalives received do NOT arm it (only data does).
        let mut t = Timers::default();
        t.note_rx(Ticks::from_secs(10), true);
        assert!(!t.passive_keepalive_due(Ticks::from_secs(100)));
    }

    #[test]
    fn dead_peer_arming() {
        let mut t = Timers::default();
        t.note_data_tx(Ticks::from_secs(10));
        assert!(!t.dead_peer_due(Ticks::from_nanos(10 * S + DEAD_PEER_TIMEOUT - 1)));
        assert!(t.dead_peer_due(Ticks::from_nanos(10 * S + DEAD_PEER_TIMEOUT)));
        // A reply disarms.
        t.note_rx(Ticks::from_secs(12), true);
        assert!(!t.dead_peer_due(Ticks::from_secs(60)));
        // Giving up suppresses it until the next data event.
        let mut t = Timers::default();
        t.note_data_tx(Ticks::from_secs(10));
        t.note_gave_up();
        assert!(!t.dead_peer_due(Ticks::from_secs(60)));
        t.note_data_tx(Ticks::from_secs(70));
        assert!(t.dead_peer_due(Ticks::from_nanos(70 * S + DEAD_PEER_TIMEOUT)));
    }

    #[test]
    fn deadline_accessors_match_due_predicates() {
        let mut t = Timers::default();
        assert_eq!(t.passive_keepalive_at(), None);
        assert_eq!(t.dead_peer_at(), None);
        t.note_rx(Ticks::from_secs(10), false);
        let at = t.passive_keepalive_at().unwrap();
        assert_eq!(at, Ticks::from_nanos(10 * S + KEEPALIVE_TIMEOUT));
        assert!(!t.passive_keepalive_due(at.add_nanos(0).min(Ticks::from_nanos(at.nanos() - 1))));
        assert!(t.passive_keepalive_due(at));
        t.note_data_tx(Ticks::from_secs(11));
        let at = t.dead_peer_at().unwrap();
        assert_eq!(at, Ticks::from_nanos(11 * S + DEAD_PEER_TIMEOUT));
        assert!(t.dead_peer_due(at));
        assert!(!t.dead_peer_due(Ticks::from_nanos(at.nanos() - 1)));
    }
}
