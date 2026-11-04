#!/usr/bin/env bash
# W3/INV-580: every repo .basm must agree with NASM (accept+bytes), unless
# the file is a registered subset extension (allowlist). A basm-only
# rejection where NASM accepts is a missing feature (GAP); byte divergence
# on dual accept is a miscompile (BUG). Both fail loudly.
# quarantine/ holds frozen rejected prototypes, not a parity surface.
set -euo pipefail
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
REPO=$(CDPATH= cd "$ROOT/../.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
ALLOW=${ALLOW:-$ROOT/tests/encoding_subset_allowlist.txt}
command -v "$NASM" >/dev/null 2>&1 || { echo "FAIL: nasm not found" >&2; exit 1; }
[ -x "$BASM" ] || { echo "FAIL: missing basm: $BASM" >&2; exit 1; }
touch "$ALLOW"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-enccov.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
# Branch-width-normalized comparison: same mnemonics, symbolic targets and
# immediates; addresses and encodings abstracted away. BearBasm converges to
# minimal-stable branches while stock NASM keeps near-boundary forward
# branches long (INV-545) — byte-identical is preferred, this proves the
# residual is width-only, never a wrong target or immediate.
norm_obj() {
    objdump -d --no-show-raw-insn "$1" 2>/dev/null | sed -E -e '/:\t/!d' \
        -e 's/^[[:space:]]*[0-9a-f]+:[[:space:]]+//' -e 's/[[:space:]]+#.*//' \
        -e 's/\b[0-9a-f]+ </</g'
}
same=0; equiv=0; agree_reject=0; allowed=0; bugs=0; gaps=0
while IFS= read -r src; do
    rel=${src#"$REPO"/}
    set +e
    "$BASM" -f elf64 -o "$TMP/b.o" "$src" >"$TMP/b.log" 2>&1; brc=$?
    "$NASM" -f elf64 -o "$TMP/n.o" "$src" >"$TMP/n.log" 2>&1; nrc=$?
    set -e
    if [ "$brc" -eq 0 ] && [ "$nrc" -eq 0 ]; then
        if "$ELFTOOL" diff "$TMP/b.o" "$TMP/n.o" >/dev/null 2>&1; then
            same=$((same + 1)); continue
        fi
        norm_obj "$TMP/b.o" >"$TMP/b.norm"
        norm_obj "$TMP/n.o" >"$TMP/n.norm"
        if cmp -s "$TMP/b.norm" "$TMP/n.norm"; then
            equiv=$((equiv + 1))
            echo "EQUIV branch-width-only: $rel"
            continue
        fi
        bugs=$((bugs + 1))
        echo "BUG bytes-differ: $rel"
        continue
    fi
    if [ "$brc" -ne 0 ] && [ "$nrc" -ne 0 ]; then
        agree_reject=$((agree_reject + 1)); continue
    fi
    if [ "$brc" -eq 0 ]; then
        if grep -qxF "$rel" "$ALLOW"; then
            allowed=$((allowed + 1)); continue
        fi
        gaps=$((gaps + 1))
        echo "GAP basm-only-accepts (needs allowlist or encoder fix): $rel"
        continue
    fi
    gaps=$((gaps + 1))
    echo "GAP basm-rejects-nasm-accepts: $rel"
    head -3 "$TMP/b.log" | sed 's/^/    basm: /'
done < <(find "$REPO/ring0" "$REPO/boot" "$REPO/toolchain" -name '*.basm' \
    -not -name '._*' -not -path '*/quarantine/*' | sort)
total=$((same + equiv + agree_reject + allowed + bugs + gaps))
echo "encoding coverage: files=$total identical=$same branch_equiv=$equiv agree_reject=$agree_reject allowed_subset=$allowed bugs=$bugs gaps=$gaps"
[ "$bugs" -eq 0 ] || { echo "FAIL: $bugs byte divergences"; exit 1; }
[ "$gaps" -eq 0 ] || { echo "FAIL: $gaps coverage gaps"; exit 1; }
echo "PASS encoding coverage ($total files)"
