#!/usr/bin/env bash
# Run every libFuzzer target for a bounded time (default 120s each).
# Requires: rustup nightly toolchain + cargo-fuzz.
#
#   scripts/fuzz_all.sh [seconds-per-target] [extra libfuzzer args...]
set -euo pipefail
cd "$(dirname "$0")/.."

SECS="${1:-120}"
shift || true

TARGETS=(parse responder initiator transport session_ops crypto_roundtrip)
for t in "${TARGETS[@]}"; do
    echo "==== fuzzing $t for ${SECS}s ===="
    cargo +nightly fuzz run "$t" -- -max_total_time="$SECS" "$@"
done
echo "All targets completed without findings."
