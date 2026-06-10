#!/usr/bin/env bash
# Cross-validate this crate's X25519 public-key derivation against the
# reference `wg` tool (wireguard-tools), if installed.
#
# `wg pubkey` performs the exact Curve25519 base-point multiplication a
# real WireGuard deployment uses; agreeing with it on random keys is an
# end-to-end check of our scalar clamping, field arithmetic, ladder and
# byte encoding against an independent implementation.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v wg >/dev/null 2>&1; then
    echo "SKIP: wg tool not installed"
    exit 0
fi

ROUNDS="${1:-32}"
cargo build --quiet --example pubkey

fail=0
for _ in $(seq "$ROUNDS"); do
    priv="$(wg genkey)"
    theirs="$(printf '%s' "$priv" | wg pubkey)"
    ours="$(printf '%s' "$priv" | ./target/debug/examples/pubkey)"
    if [ "$theirs" != "$ours" ]; then
        echo "MISMATCH for private key $priv: wg=$theirs ours=$ours"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "OK: $ROUNDS random keys agree with wg(8)"
else
    exit 1
fi
