//! Shared harness for the integration test battery: a deterministic
//! clock, tunnel pairs, and handshake/transport pumps — all through the
//! public API only.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Config, Encapsulated, Now, PollOutput, PresharedKey, Received, SendReason, StaticSecret, Tunnel,
};

pub const S: u64 = 1_000_000_000;
pub const MS: u64 = 1_000_000;

/// A deterministic, manually-advanced clock. Sans-I/O makes every timer
/// reachable instantly: tests jump straight to the interesting instants.
pub struct Clock {
    pub mono_ns: u64,
    base_unix: u64,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            mono_ns: 0,
            base_unix: 1_700_000_000,
        }
    }

    pub fn now(&self) -> Now {
        Now::new(
            self.mono_ns,
            self.base_unix + self.mono_ns / S,
            (self.mono_ns % S) as u32,
        )
    }

    pub fn advance(&mut self, ns: u64) -> Now {
        self.mono_ns += ns;
        self.now()
    }
}

pub struct Pair {
    pub a: Tunnel,
    pub b: Tunnel,
    pub rng: DeterministicRng,
    pub clock: Clock,
}

pub fn new_pair_with(seed: u64, psk: Option<[u8; 32]>, keepalive_secs: Option<u16>) -> Pair {
    let mut rng = DeterministicRng::new(seed);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut cfg_a = Config::new(a_key, b_pub);
    let mut cfg_b = Config::new(b_key, a_pub);
    if let Some(psk) = psk {
        cfg_a.psk = PresharedKey::from_bytes(psk);
        cfg_b.psk = PresharedKey::from_bytes(psk);
    }
    if let Some(secs) = keepalive_secs {
        cfg_a.persistent_keepalive = core::num::NonZeroU16::new(secs);
    }
    Pair {
        a: Tunnel::new(cfg_a).unwrap(),
        b: Tunnel::new(cfg_b).unwrap(),
        rng,
        clock: Clock::new(),
    }
}

pub fn new_pair(seed: u64) -> Pair {
    new_pair_with(seed, None, None)
}

impl Pair {
    /// Run a full handshake (A initiates) and confirm it with A's
    /// keepalive so both directions are usable. Returns the number of
    /// wire datagrams exchanged.
    pub fn establish(&mut self) -> usize {
        let now = self.clock.now();
        let mut wire = [0u8; 2048];
        let mut scratch = [0u8; 2048];

        let init: Vec<u8> = match self
            .a
            .encapsulate(now, b"", &mut wire, &mut self.rng)
            .unwrap()
        {
            Encapsulated::HandshakeInitiation(w) => w.to_vec(),
            Encapsulated::Transport(_) => panic!("session already established"),
        };
        let resp: Vec<u8> = match self
            .b
            .decapsulate(now, b"a-addr", false, &init, &mut scratch, &mut self.rng)
            .unwrap()
        {
            Received::Reply(w) => w.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };
        match self
            .a
            .decapsulate(now, b"b-addr", false, &resp, &mut scratch, &mut self.rng)
            .unwrap()
        {
            Received::HandshakeComplete => {}
            other => panic!("expected completion, got {other:?}"),
        }
        // A's confirmation keepalive lets B promote + use the session.
        let ka: Vec<u8> = match self.a.poll(now, &mut wire, &mut self.rng).unwrap() {
            PollOutput::Send(w, SendReason::Keepalive) => w.to_vec(),
            other => panic!("expected confirm keepalive, got {other:?}"),
        };
        match self
            .b
            .decapsulate(now, b"a-addr", false, &ka, &mut scratch, &mut self.rng)
            .unwrap()
        {
            Received::Keepalive => {}
            other => panic!("expected keepalive, got {other:?}"),
        }
        assert!(self.a.is_established() && self.b.is_established());
        4
    }

    /// Encrypt `payload` from one side, returning the wire datagram.
    pub fn seal_from_a(&mut self, payload: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        let mut wire = vec![0u8; 64 + payload.len() + 64];
        match self
            .a
            .encapsulate(now, payload, &mut wire, &mut self.rng)
            .unwrap()
        {
            Encapsulated::Transport(w) => w.to_vec(),
            other => panic!("expected transport, got {other:?}"),
        }
    }

    pub fn seal_from_b(&mut self, payload: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        let mut wire = vec![0u8; 64 + payload.len() + 64];
        match self
            .b
            .encapsulate(now, payload, &mut wire, &mut self.rng)
            .unwrap()
        {
            Encapsulated::Transport(w) => w.to_vec(),
            other => panic!("expected transport, got {other:?}"),
        }
    }

    /// Deliver a wire datagram to B, expecting decrypted data back.
    pub fn open_at_b(&mut self, wire: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        let mut out = vec![0u8; wire.len().max(256)];
        match self
            .b
            .decapsulate(now, b"a-addr", false, wire, &mut out, &mut self.rng)
            .unwrap()
        {
            Received::Data(d) => d.to_vec(),
            other => panic!("expected data, got {other:?}"),
        }
    }

    pub fn open_at_a(&mut self, wire: &[u8]) -> Vec<u8> {
        let now = self.clock.now();
        let mut out = vec![0u8; wire.len().max(256)];
        match self
            .a
            .decapsulate(now, b"b-addr", false, wire, &mut out, &mut self.rng)
            .unwrap()
        {
            Received::Data(d) => d.to_vec(),
            other => panic!("expected data, got {other:?}"),
        }
    }

    /// Round-trip a payload A→B and assert it arrives intact (modulo the
    /// protocol's zero padding, which is asserted too).
    pub fn assert_roundtrip_a_to_b(&mut self, payload: &[u8]) {
        let wire = self.seal_from_a(payload);
        let got = self.open_at_b(&wire);
        assert!(got.len() >= payload.len());
        assert_eq!(&got[..payload.len()], payload);
        assert!(
            got[payload.len()..].iter().all(|&b| b == 0),
            "padding must be zeros"
        );
        assert_eq!(got.len() % 16, 0, "padded length must be 16-aligned");
    }
}
