#!/usr/bin/env bash
# Verify panic-freedom at the object-code level.
#
# Builds the library alone in release mode and scans the resulting rlib
# for undefined references to core's panic machinery
# (core::panicking::*, unwrap/expect failure shims, bounds-check
# helpers). If the optimizer could not prove every panic site dead, a
# symbol shows up here and the check fails.
#
# This complements (not replaces) the clippy lint wall: lints stop panics
# at the source level; this catches anything that slipped through via
# library calls.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building release rlib..."
cargo build --release --lib --quiet

RLIB=$(ls -t target/release/libwireguard_sans_io*.rlib | head -1)
if [ -z "$RLIB" ]; then
    echo "FAIL: rlib not found"
    exit 1
fi
echo "Scanning $RLIB"

# Undefined symbols referencing panic plumbing.
PANIC_SYMS=$(nm -u "$RLIB" 2>/dev/null | grep -E 'panicking|unwrap_failed|expect_failed|slice_index|bounds_check|division_by_zero' | sort -u || true)

if [ -n "$PANIC_SYMS" ]; then
    echo "FAIL: panic machinery referenced by the release library:"
    echo "$PANIC_SYMS" | while read -r sym; do
        echo "    $sym"
    done
    exit 1
fi

echo "PASS: no references to core::panicking in the optimized library."
