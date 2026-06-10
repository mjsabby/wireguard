//! A secure session: one keypair derived from one completed handshake,
//! with its counters and replay window (whitepaper §5.4.5, §6.2, §6.3).

use crate::Error;
use crate::consts::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME};
use crate::noise::SessionKeys;
use crate::replay::ReplayWindow;
use crate::time::Ticks;

/// One live keypair. Created on handshake completion, rotated through the
/// previous/current/next slots of the tunnel, wiped on drop (via
/// [`SessionKeys`]'s `Drop`).
pub(crate) struct Session {
    pub keys: SessionKeys,
    pub send_counter: u64,
    pub replay: ReplayWindow,
    pub created: Ticks,
    /// Whether transport data may be *sent* on this session. Initiator
    /// sessions are confirmed at creation; responder sessions only once
    /// the first authenticated transport message arrives (whitepaper §5.1:
    /// KEA+C confirmation).
    pub confirmed: bool,
}

impl Session {
    pub(crate) fn new(keys: SessionKeys, created: Ticks) -> Self {
        let confirmed = keys.is_initiator;
        Self {
            keys,
            send_counter: 0,
            replay: ReplayWindow::new(),
            created,
            confirmed,
        }
    }

    /// Age in nanoseconds at `now`.
    pub(crate) fn age(&self, now: Ticks) -> u64 {
        now.since(self.created)
    }

    /// May we encrypt outgoing data on this session right now?
    /// (whitepaper §6.2: Reject-After-Time / Reject-After-Messages, plus
    /// the confirmation rule.)
    pub(crate) fn usable_for_send(&self, now: Ticks) -> bool {
        self.confirmed
            && self.send_counter < REJECT_AFTER_MESSAGES
            && self.age(now) < REJECT_AFTER_TIME
    }

    /// Take the next sending counter, refusing at the reject limit.
    pub(crate) fn next_counter(&mut self) -> Result<u64, Error> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::Expired);
        }
        let counter = self.send_counter;
        self.send_counter = self.send_counter.checked_add(1).ok_or(Error::Internal)?;
        Ok(counter)
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Session(local={}, peer={}, initiator={}, confirmed={}, sent={})",
            self.keys.local_index,
            self.keys.peer_index,
            self.keys.is_initiator,
            self.confirmed,
            self.send_counter
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::noise::SessionKeys;

    fn keys(initiator: bool) -> SessionKeys {
        SessionKeys {
            send: [1; 32],
            recv: [2; 32],
            local_index: 10,
            peer_index: 20,
            is_initiator: initiator,
        }
    }

    #[test]
    fn confirmation_rules() {
        let now = Ticks::from_secs(5);
        let s = Session::new(keys(true), now);
        assert!(s.confirmed && s.usable_for_send(now));
        let s = Session::new(keys(false), now);
        assert!(!s.confirmed && !s.usable_for_send(now));
    }

    #[test]
    fn reject_after_time() {
        let born = Ticks::from_secs(100);
        let s = Session::new(keys(true), born);
        assert!(s.usable_for_send(born.add_nanos(REJECT_AFTER_TIME - 1)));
        assert!(!s.usable_for_send(born.add_nanos(REJECT_AFTER_TIME)));
    }

    #[test]
    fn counter_exhaustion() {
        let mut s = Session::new(keys(true), Ticks::ZERO);
        s.send_counter = REJECT_AFTER_MESSAGES - 1;
        assert_eq!(s.next_counter().unwrap(), REJECT_AFTER_MESSAGES - 1);
        assert_eq!(s.next_counter(), Err(Error::Expired));
        assert!(!s.usable_for_send(Ticks::ZERO));
    }
}
