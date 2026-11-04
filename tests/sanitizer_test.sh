#!/bin/sh
# INV-394: host-only diagnostic instrumentation; never the shipped binary.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
CC=${CC:-cc}

command -v "$CC" >/dev/null 2>&1 || { printf 'FAIL: compiler not found: %s\n' "$CC" >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-sanitize.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -I$ROOT -I$ROOT/../.."
if [ "$(uname -m)" = x86_64 ]; then
    FLAGS="$FLAGS -msha -msse4.1 -mssse3"
fi
if [ "$(uname -s)" = Darwin ]; then
    FLAGS="$FLAGS -DBASM_NO_PROC_SELF_EXE"
fi
if [ "$(uname -s)" = Linux ]; then
    for flag in -Wno-misleading-indentation -Wno-stringop-truncation -Wno-format-truncation; do
        if "$CC" "$flag" -Werror -x c -c /dev/null -o /dev/null >/dev/null 2>&1; then
            FLAGS="$FLAGS $flag"
        fi
    done
fi

# shellcheck disable=SC2086
"$CC" $FLAGS -o "$TMP/basm-sanitized" \
    "$ROOT/basm.c" "$ROOT/sign.c" "$ROOT/../../crypto/ed25519.c"

# INV-589: compile-time exclusions must pass host -Werror and sanitizer too.
# shellcheck disable=SC2086
"$CC" $FLAGS -DBASM_PUBLIC_ONLY=1 -o "$TMP/basm-public-sanitized" \
    "$ROOT/basm.c" "$ROOT/sign.c" "$ROOT/../../crypto/ed25519.c"

ASAN_OPTIONS=halt_on_error=1
if [ "$(uname -s)" = Linux ]; then
    ASAN_OPTIONS="$ASAN_OPTIONS:detect_leaks=1"
fi
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
export ASAN_OPTIONS UBSAN_OPTIONS

BASM="$TMP/basm-sanitized" sh "$ROOT/tests/expression_cache_capacity_test.sh"
BASM="$TMP/basm-sanitized" sh "$ROOT/tests/text_capacity_test.sh"
BASM="$TMP/basm-sanitized" sh "$ROOT/tests/preprocessor_limits_test.sh"

# INV-584: the hardened surface (fuzz shapes, layout farms, coverage
# corpus, Rel8 escrow incl. concurrency, batch isolation, dup labels,
# atomic publish) runs clean under ASan/UBSan. Leak reports on die()
# paths are out of scope: die() exits without unwinding by design and
# all long-lived state is static or arena-owned.
BASM="$TMP/basm-sanitized" BASM_FUZZ_SEED=11 BASM_FUZZ_COUNT=250 \
    bash "$ROOT/tests/fuzz_differential.sh" >/dev/null
BASM="$TMP/basm-sanitized" BASM_LAYOUT_SEED=11 BASM_LAYOUT_COUNT=120 \
    bash "$ROOT/tests/layout_torture.sh" >/dev/null
BASM="$TMP/basm-sanitized" ELFTOOL="$ROOT/elftool" bash "$ROOT/tests/encoding_coverage.sh" >/dev/null
BASM="$TMP/basm-sanitized" ELFTOOL="$ROOT/elftool" sh "$ROOT/tests/rel8_escrow_test.sh" >/dev/null
BASM="$TMP/basm-sanitized" ELFTOOL="$ROOT/elftool" sh "$ROOT/tests/batch_test.sh" >/dev/null
BASM="$TMP/basm-sanitized" sh "$ROOT/tests/atomic_publish_test.sh" >/dev/null
BASM="$TMP/basm-sanitized" bash "$ROOT/tests/critical_regression_test.sh" >/dev/null
BASM="$TMP/basm-sanitized" PUBLIC="$TMP/basm-public-sanitized" \
    sh "$ROOT/tests/target_profiles_test.sh"
BASM="$TMP/basm-sanitized" ELFTOOL="$ROOT/elftool" \
    sh "$ROOT/tests/target_profile_proof_test.sh"
BASM="$TMP/basm-sanitized" sh "$ROOT/tests/intent_encoding_test.sh"
for binary in "$TMP/basm-sanitized" "$TMP/basm-public-sanitized"; do
    BASM="$binary" sh "$ROOT/tests/intent_trace_test.sh"
    BASM="$binary" sh "$ROOT/tests/intent_cfg_test.sh"
done
INTENT_CFG_UNIT_ONLY=1 INTENT_CFG_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
    sh "$ROOT/tests/intent_cfg_test.sh"

printf 'PASS ASan/UBSan capacity suite\n'
