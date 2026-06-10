# wireguard-sans-io

A **sans-I/O**, **`#![no_std]`**, **zero-allocation**, **zero-dependency**,
**panic-free** implementation of the WireGuard® protocol in Rust 2024.

The library implements the complete protocol — the Noise IKpsk2 handshake,
cookie-based DoS mitigation, transport encryption with replay protection,
and the whitepaper §6 timer state machine — without ever touching a socket,
reading a clock, spawning a thread, or allocating a byte. Callers feed in
datagrams, buffers, the current time and entropy; the library hands back
datagrams to send and plaintext that was received.

```rust
use wireguard_sans_io::{Config, Encapsulated, Now, Received, StaticSecret, Tunnel};

let mut tunnel = Tunnel::new(Config::new(local_secret, peer_public))?;

// Send path: plaintext in, datagram out (or a handshake initiation if no
// session exists yet — the payload is then not consumed).
match tunnel.encapsulate(now, packet, &mut buf, &mut rng)? {
    Encapsulated::Transport(wire) => socket.send(wire)?,
    Encapsulated::HandshakeInitiation(wire) => socket.send(wire)?, // retry later
}

// Receive path: datagram in; plaintext, a reply, or a state change out.
match tunnel.decapsulate(now, remote_addr, under_load, datagram, &mut buf, &mut rng)? {
    Received::Data(plain) => deliver(plain),
    Received::Reply(wire) => socket.send(wire)?, // handshake response / cookie
    Received::Keepalive | Received::HandshakeComplete | Received::CookieStored => {}
}

// Timers: poll whenever `tunnel.next_wake()` falls due.
while let PollOutput::Send(wire, _why) = tunnel.poll(now, &mut buf, &mut rng)? {
    socket.send(wire)?;
}
```

A complete runnable two-peer example lives in the `Tunnel` rustdoc (and is
exercised as a doctest).

## Design rules

| Rule | Enforcement |
|---|---|
| No I/O, no clocks, no global state | API shape: time (`Now`) and entropy (`EntropySource`) are arguments; outputs go to caller buffers |
| `#![no_std]`, no `alloc` | The crate cannot allocate — verified by building for a core-only target (`x86_64-unknown-uefi`) |
| No `unsafe` | `#![forbid(unsafe_code)]` + **zero dependencies**, so the guarantee covers every line involved, including all cryptography |
| No panics | Clippy deny-wall (`indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, …) **and** `scripts/check_no_panic.sh`, which scans the optimized rlib for `core::panicking` references — there are none |
| Defensive | mac1 verified before any expensive work; verify-then-decrypt AEAD (forgeries never touch output buffers); replay window advanced only post-authentication; constant-time comparisons; secrets wiped on drop; monotonicity clamp on hostile clocks; internal invariant failures surface as `Error::Internal`, never as panics |

## Protocol coverage

Everything in the whitepaper §5–§6:

* **Handshake**: Noise IKpsk2 (Curve25519, ChaCha20-Poly1305, BLAKE2s),
  optional pre-shared key, TAI64N timestamps (with the §5.1-sanctioned
  24-bit nanosecond whitening), strict per-peer timestamp monotonicity,
  initiator-identity verification, low-order-point rejection.
* **Cookies** (§5.3, §5.4.4, §5.4.7): mandatory constant-time `mac1`,
  under-load `mac2` with rotating cookie secret (current + previous),
  XChaCha20-Poly1305 cookie replies bound to the provoking `mac1`,
  cookie expiry, §6.6 "wait for the retransmission timer" behaviour.
* **Transport** (§5.4.6): counter nonces, zero padding to 16 bytes,
  RFC 6479-style 2048-bit sliding replay window (with the extra redundant
  word), keepalives, in-place encryption (zero copies beyond the caller's
  buffer).
* **Timers** (§6): retransmission every `REKEY_TIMEOUT` with jittered
  deadlines, `REKEY_ATTEMPT_TIME` give-up, global once-per-`REKEY_TIMEOUT`
  initiation pacing, send/receive-path rekey rules (initiator-only),
  `REJECT_AFTER_*` enforcement both directions, passive keepalive,
  dead-peer re-initiation, persistent keepalive, previous/current/next
  session rotation with responder confirmation, 3×`REJECT_AFTER_TIME`
  discard-and-wipe. `next_wake()` reports the earliest armed deadline so
  embedders can sleep exactly the right amount.

Multi-peer routing stays with the embedder (it inherently needs maps):
`peek()` classifies datagrams by receiver index without copying so callers
can demultiplex to the right `Tunnel`. Per-IP rate limiting (token buckets)
is likewise an embedder concern, as it requires per-source tables.

## Testing

Around 9,600 lines of code, more than half of it tests. `cargo test` runs
152 tests; everything below is deterministic (a seeded ChaCha20 PRNG plays
the entropy source) and instant, because time is just a number.

* **Crypto vectors**: RFC 7693 (BLAKE2s + official keyed KATs), RFC 8439
  (ChaCha20 block/encrypt, Poly1305, AEAD), RFC 7748 (X25519 ×2, iterated
  ×1000, DH), draft-irtf-cfrg-xchacha (HChaCha20 §2.2.1, AEAD §A.3.1).
* **Cross-validation**: X25519 agrees with the system `wg(8)` tool on
  random keys (`scripts/interop_wg_tool.sh`); the handshake's initial
  chain constants match BoringTun's published values byte-for-byte.
* **Property tests**: Poly1305 against a naive big-integer model on
  adversarial inputs; field `square ≡ mul(a,a)`; `x·x⁻¹ ≡ 1`; DH
  commutativity; HChaCha20 derived structurally from the RFC-validated
  block function; replay window against a set-based model.
* **Protocol suites** (`tests/`): handshake/transport flows, PSK
  mismatch, padding + IP-length trimming, replay/reordering (counter and
  timestamp), cookie dance under load (including mac2↔source-address
  binding and loaded-initiator behaviour), the full timer lifecycle by
  time travel, and a `next_wake` "never act earlier than announced"
  property walk.
* **Adversarial suites**: single-bit-flip storms over every byte of every
  message type (with the mac2-is-ignored-off-load subtlety asserted),
  truncation/extension sweeps, type confusion, reflection, cross-tunnel
  confusion, unknown-peer initiations with valid mac1, garbage storms —
  all asserting *rejected, buffer untouched, state intact*.
* **Unguided protocol fuzz** (`tests/protocol_fuzz.rs`): 25 deterministic
  episodes of two tunnels over a hostile network (reorder/drop/duplicate/
  corrupt/under-load/clock-jumps) with exact-delivery and
  always-recovers invariants.
* **Guided fuzzing** (`fuzz/`, libFuzzer): six targets — `parse`,
  `responder`, `initiator`, `transport`, structured `session_ops`, and
  `crypto_roundtrip`. A 100 s/target campaign executed **63 million runs
  with zero findings** (debug assertions and overflow checks enabled).
  `scripts/fuzz_all.sh` reproduces it.
* **Timing tripwires** (`tests/constant_time.rs`, `--ignored`):
  interleaved dudect-style Welch t-tests on `ct_eq` and the X25519
  ladder, with a deliberately leaky memcmp as harness sanity check.
* **Coverage**: `scripts/coverage.sh` (rustup llvm-tools, no plugins) —
  currently **95.5 % regions / 96.2 % lines**; most uncovered regions are
  defensive `Error::Internal` branches that are unreachable by
  construction.

```sh
cargo test                                        # everything, < 1 s
cargo test --release --test constant_time -- --ignored   # timing tripwires
scripts/coverage.sh                               # coverage table
scripts/check_no_panic.sh                         # object-code panic scan
scripts/fuzz_all.sh 120                           # 6 × 120 s guided fuzz
scripts/interop_wg_tool.sh 64                     # vs wireguard-tools
cargo run --release --example perf                # benchmarks
```

## Performance

Measured by `examples/perf.rs` on this machine (x86_64, single core,
safe/serial code — no SIMD, no unsafe):

```
blake2s-256 (1 KiB)                          665 MB/s
chacha20 keystream (1 KiB)                   860 MB/s
poly1305 (1 KiB)                            2549 MB/s
chacha20poly1305 seal (1 KiB)                619 MB/s
x25519 scalar mult                         41269 op/s   (24.2 µs)
full 1-RTT handshake (both sides)           2815 /s     (355 µs)
encapsulate only (1420 B)                    607 MB/s   (≈ 4.9 Gbit/s)
decapsulate only (1420 B)                    602 MB/s
```

For profiling: `cargo build --profile profiling --example perf`, then
`perf record --call-graph dwarf -- target/profiling/examples/perf`.

## Security model & limitations

* **Trust the math, then verify**: every primitive is pinned by official
  test vectors *and* an independent anchor (wg(8) for the curve, BoringTun
  constants for the hash pipeline, a naive bignum model for Poly1305).
  Still, this implementation has not been independently audited.
* **Constant time is best-effort**, as in every high-level language:
  there are no secret-dependent branches or indices in the source, fixed
  ladder shape, `core::hint::black_box` barriers, and empirical timing
  tripwires — but the compiler has the last word.
* **Wiping is best-effort**: safe Rust has no guaranteed-volatile writes;
  drop-time zeroization goes through `black_box` and cannot reach copies
  the compiler spilled.
* **Entropy is the caller's responsibility** (`EntropySource`): feed it
  OS randomness; everything rests on it.
* The whitepaper's per-IP token-bucket rate limiter and multi-peer
  cryptokey routing are embedder concerns (they require allocation).

WireGuard is a registered trademark of Jason A. Donenfeld. This crate is an
independent implementation of the published protocol and is not affiliated
with or endorsed by the WireGuard project.

## License

MIT OR Apache-2.0.
