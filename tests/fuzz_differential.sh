#!/usr/bin/env bash
# W1/INV-578: differential fuzz gate, BearBasm vs NASM over generated cases.
# Same seed always replays the same stream. Any divergence fails loudly
# with the replayable case saved under $TMP (and printed with its seed).
set -euo pipefail
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
SEED=${BASM_FUZZ_SEED:-1}
COUNT=${BASM_FUZZ_COUNT:-1500}
command -v "$NASM" >/dev/null 2>&1 || { echo "FAIL: nasm not found" >&2; exit 1; }
[ -x "$BASM" ] || { echo "FAIL: missing basm: $BASM" >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-fuzz.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
perl "$ROOT/tests/fuzz/generate.pl" "$SEED" "$COUNT" >"$TMP/stream.asm"

pass=0; agree_reject=0; fail=0
idx=0
csplit -s -f "$TMP/case-" -b "%04d.basm" "$TMP/stream.asm" '/^%%CASE%%$/' '{*}' 2>/dev/null || true
sed -i '/^%%CASE%%$/d' "$TMP"/case-*.basm 2>/dev/null || true
for src in "$TMP"/case-*.basm; do
    [ -f "$src" ] || continue
    idx=$((idx + 1))
    set +e
    "$BASM" -f elf64 -o "$TMP/b.o" "$src" >"$TMP/b.log" 2>&1; brc=$?
    "$NASM" -f elf64 -o "$TMP/n.o" "$src" >"$TMP/n.log" 2>&1; nrc=$?
    set -e
    if [ "$brc" -ne 0 ] && [ "$nrc" -ne 0 ]; then
        agree_reject=$((agree_reject + 1)); continue
    fi
    if [ "$brc" -ne "$nrc" ]; then
        fail=$((fail + 1))
        echo "DIVERGE accept/reject case=$idx seed=$SEED basm_rc=$brc nasm_rc=$nrc"
        cp "$src" "$TMP/diverge-$idx.basm"
        [ "$fail" -ge 5 ] && break
        continue
    fi
    if ! "$ELFTOOL" diff "$TMP/b.o" "$TMP/n.o" >/dev/null 2>&1; then
        fail=$((fail + 1))
        echo "DIVERGE bytes case=$idx seed=$SEED"
        cp "$src" "$TMP/diverge-$idx.basm"
        "$ELFTOOL" diff "$TMP/b.o" "$TMP/n.o" 2>&1 | head -5 || true
        [ "$fail" -ge 5 ] && break
        continue
    fi
    pass=$((pass + 1))
done
total=$((pass + agree_reject + fail))
echo "fuzz differential: seed=$SEED cases=$total pass=$pass agree_reject=$agree_reject diverge=$fail"
[ "$fail" -eq 0 ] || { echo "FAIL: $fail divergent cases (see diverge-*.basm)"; exit 1; }
echo "PASS fuzz differential ($total cases, seed=$SEED)"
