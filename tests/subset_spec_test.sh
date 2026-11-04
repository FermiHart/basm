#!/bin/sh
# INV-587: the normative instruction inventory and executable dispatcher
# cannot drift independently.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/modules/02_encoding.inc"
SPEC="$ROOT/SUPPORTED-SUBSET.md"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-subset.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

perl -ne '
    if (/^\w+\t(\w+)\t.*\tsse_\w+\t64$/) { print "$1\n" unless $sse{$1}++; }
    $active = 1 if /g_insn_names\[\]\s*=/;
    while ($active && /I\(([a-z0-9_]+)\)/g) {
        print "$1\n" unless $1 eq "name";
    }
    $active = 0 if /#undef I/;
' "$SRC" "$ROOT/isa/forms.tsv" | LC_ALL=C sort -u >"$TMP/source"

awk '
    /BEGIN INSTRUCTION INVENTORY/ { active=1; next }
    /END INSTRUCTION INVENTORY/ { active=0 }
    active && /^[a-z0-9_]+$/ { print }
' "$SPEC" | LC_ALL=C sort >"$TMP/spec"

cmp -s "$TMP/source" "$TMP/spec" || {
    printf 'FAIL subset spec: instruction inventory drift\n' >&2
    diff -u "$TMP/spec" "$TMP/source" >&2 || true
    exit 1
}
grep -q 'SUPPORTED-SUBSET.md' "$ROOT/README.md" || {
    printf 'FAIL subset spec: README does not link the contract\n' >&2
    exit 1
}
grep -q 'SUPPORTED-SUBSET.md' "$ROOT/POLITICA-BASM.md" || {
    printf 'FAIL subset spec: dialect policy does not link the contract\n' >&2
    exit 1
}
count=$(wc -l <"$TMP/spec")
[ "$count" -gt 0 ] || { printf 'FAIL subset spec: empty inventory\n' >&2; exit 1; }
printf 'PASS supported subset specification (%d mnemonics)\n' "$count"
