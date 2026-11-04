#!/usr/bin/env bash
# W4: branch-farm torture. Padding sweeps the rel8/rel32 boundary, so any
# fixpoint under/overshoot lands on a wrong symbolic target. Dual accept
# requires normalized equality (mnemonics + symbolic targets + immediates;
# branch widths may differ per INV-545). Any other delta is a miscompile.
# INV-581: this test proves normalized branch targets, not a product-code change.
set -euo pipefail
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
SEED=${BASM_LAYOUT_SEED:-1}
COUNT=${BASM_LAYOUT_COUNT:-400}
command -v "$NASM" >/dev/null 2>&1 || { echo "FAIL: nasm not found" >&2; exit 1; }
[ -x "$BASM" ] || { echo "FAIL: missing basm: $BASM" >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-layout-torture.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
perl "$ROOT/tests/layout/generate.pl" "$SEED" "$COUNT" >"$TMP/stream.asm"
norm_obj() {
    objdump -d --no-show-raw-insn "$1" 2>/dev/null | sed -E -e '/:\t/!d' \
        -e 's/^[[:space:]]*[0-9a-f]+:[[:space:]]+//' -e 's/[[:space:]]+#.*//' \
        -e 's/\b[0-9a-f]+ </</g'
}
csplit -s -f "$TMP/case-" -b "%04d.basm" "$TMP/stream.asm" '/^%%CASE%%$/' '{*}' 2>/dev/null || true
sed -i '/^%%CASE%%$/d' "$TMP"/case-*.basm 2>/dev/null || true
pass=0; equiv=0; agree_reject=0; fail=0; idx=0
for src in "$TMP"/case-*.basm; do
    [ -f "$src" ] || continue
    idx=$((idx + 1))
    set +e
    "$BASM" -f elf64 -o "$TMP/b.o" "$src" >"$TMP/b.log" 2>&1; brc=$?
    "$NASM" -f elf64 -o "$TMP/n.o" "$src" >"$TMP/n.log" 2>&1; nrc=$?
    set -e
    if [ "$brc" -ne 0 ] || [ "$nrc" -ne 0 ]; then
        if [ "$brc" -ne "$nrc" ]; then
            fail=$((fail + 1))
            echo "DIVERGE accept/reject case=$idx seed=$SEED basm_rc=$brc nasm_rc=$nrc"
            cp "$src" "$TMP/diverge-$idx.basm"
            [ "$fail" -ge 5 ] && break
        else
            agree_reject=$((agree_reject + 1))
        fi
        continue
    fi
    if "$ELFTOOL" diff "$TMP/b.o" "$TMP/n.o" >/dev/null 2>&1; then
        pass=$((pass + 1)); continue
    fi
    norm_obj "$TMP/b.o" >"$TMP/b.norm"
    norm_obj "$TMP/n.o" >"$TMP/n.norm"
    if cmp -s "$TMP/b.norm" "$TMP/n.norm"; then
        equiv=$((equiv + 1)); continue
    fi
    fail=$((fail + 1))
    echo "DIVERGE semantics case=$idx seed=$SEED"
    cp "$src" "$TMP/diverge-$idx.basm"
    [ "$fail" -ge 5 ] && break
done
total=$((pass + equiv + agree_reject + fail))
echo "layout torture: seed=$SEED cases=$total identical=$pass branch_equiv=$equiv agree_reject=$agree_reject diverge=$fail"
[ "$fail" -eq 0 ] || { echo "FAIL: $fail divergent farms"; exit 1; }
echo "PASS layout torture ($total farms, seed=$SEED)"
