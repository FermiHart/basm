#!/bin/sh
# INV-586: the shipped basm binary stays lean. A BSS/text regression like
# the 78MiB custom-section blowup (INV-547) must turn the gate red instead
# of shipping silently. Linux `size` format; other hosts report and skip.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/basm}
[ -x "$BIN" ] || { printf 'FAIL: missing basm: %s\n' "$BIN" >&2; exit 1; }
if [ "$(uname -s)" != Linux ]; then
    printf 'binary budget: non-Linux size format, skipping\n'
    exit 0
fi
# W1.2 re-baseline (owner decision 2026-09-10): 750000 base + 7000 for the
# proof-carrying object emitter (NOTE serializer only runs with the opt-in
# flag; default bytes are proven identical). BSS unchanged.
TEXT_MAX=757000
BSS_MAX=8000000
set -- $(size "$BIN" | tail -1)
text=$1
bss=$3
[ "$text" -le "$TEXT_MAX" ] || {
    printf 'FAIL binary budget: text %d > %d\n' "$text" "$TEXT_MAX" >&2
    exit 1
}
[ "$bss" -le "$BSS_MAX" ] || {
    printf 'FAIL binary budget: bss %d > %d\n' "$bss" "$BSS_MAX" >&2
    exit 1
}
printf 'PASS binary budget (text=%d bss=%d)\n' "$text" "$bss"
