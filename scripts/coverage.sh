#!/usr/bin/env bash
# Source-based code coverage via -C instrument-coverage and the
# rustup llvm-tools component (no extra cargo plugins needed).
#
#   scripts/coverage.sh           # summary table
#   scripts/coverage.sh show      # annotated per-line report for src/
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-report}"

# Locate llvm-profdata/llvm-cov from the rustup component.
SYSROOT=$(rustc --print sysroot)
TOOLS=$(find "$SYSROOT" -name llvm-profdata -path '*bin*' 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
if [ -z "$TOOLS" ]; then
    echo "llvm-tools not found; installing the rustup component..."
    rustup component add llvm-tools
    TOOLS=$(find "$SYSROOT" -name llvm-profdata -path '*bin*' | head -1 | xargs dirname)
fi
PROFDATA="$TOOLS/llvm-profdata"
LLVMCOV="$TOOLS/llvm-cov"

COVDIR="target/coverage"
rm -rf "$COVDIR"
mkdir -p "$COVDIR"

echo "Running instrumented test suite..."
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$PWD/$COVDIR/wg-%p-%m.profraw"
cargo test --tests --quiet >/dev/null

echo "Merging profiles..."
"$PROFDATA" merge -sparse "$COVDIR"/*.profraw -o "$COVDIR/wg.profdata"

# Collect the test executables that produced the profiles.
OBJECTS=$(cargo test --tests --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        continue
    exe = m.get("executable")
    if exe and m.get("profile", {}).get("test"):
        print("-object", exe)
')

# shellcheck disable=SC2086
"$LLVMCOV" "$MODE" \
    --instr-profile="$COVDIR/wg.profdata" \
    --ignore-filename-regex='(registry|rustc/|/tests/)' \
    $OBJECTS \
    ${MODE_FLAGS:-} | tee "$COVDIR/coverage.txt"

echo
echo "Report saved to $COVDIR/coverage.txt"
