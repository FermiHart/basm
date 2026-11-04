#!/bin/sh
# INV-559: authenticated cached outputs are content-bound; tampering is fail-closed.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
NASM=${NASM:-nasm}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-rel8.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
CACHE="$TMP/escrow"

dd if=/dev/zero of="$TMP/key.seed" bs=32 count=1 status=none
cat >"$TMP/input.basm" <<'EOF'
bits 64
section .text
global _start
_start:
    mov rax, rbx
    add rax, 7
    ret
EOF

"$BASM" --rel8-escrow "$CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/cold.o" "$TMP/input.basm" 2>"$TMP/cold.log"
! grep -q 'rel8 escrow hit' "$TMP/cold.log" || { printf 'FAIL rel8: cold run reported hit\n' >&2; exit 1; }
"$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/input.basm"
"$ELFTOOL" diff "$TMP/cold.o" "$TMP/nasm.o" >/dev/null

"$BASM" --rel8-escrow "$CACHE" --rel8-key "$TMP/key.seed" \
    --emit-attestation "$TMP/hit.basmproof" -f elf64 -o "$TMP/hit.o" "$TMP/input.basm" 2>"$TMP/hit.log"
grep -q 'rel8 escrow hit' "$TMP/hit.log" || { printf 'FAIL rel8: warm run missed\n' >&2; exit 1; }
cmp -s "$TMP/cold.o" "$TMP/hit.o" || { printf 'FAIL rel8: hit changed object\n' >&2; exit 1; }
"$BASM" --verify-attestation "$TMP/hit.basmproof"

set -- "$CACHE"/*.o
object=$1
printf X | dd of="$object" bs=1 seek=0 conv=notrunc status=none
rm -f "$TMP/rejected.o"
set +e
"$BASM" --rel8-escrow "$CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/rejected.o" "$TMP/input.basm" 2>"$TMP/rejected.log"
rc=$?
set -e
[ "$rc" -ne 0 ] && grep -q 'receipt rejected' "$TMP/rejected.log" || {
    printf 'FAIL rel8: tampered object was not rejected\n' >&2
    exit 1
}
[ ! -e "$TMP/rejected.o" ] || { printf 'FAIL rel8: rejected object was published\n' >&2; exit 1; }

PAYLOAD_CACHE="$TMP/payload-escrow"
printf 'first payload' >"$TMP/payload.bin"
cat >"$TMP/payload.basm" <<EOF
bits 64
section .rodata
incbin "$TMP/payload.bin"
EOF
"$BASM" --rel8-escrow "$PAYLOAD_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/payload-first.o" "$TMP/payload.basm" 2>"$TMP/payload-first.log"
"$BASM" --rel8-escrow "$PAYLOAD_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/payload-hit.o" "$TMP/payload.basm" 2>"$TMP/payload-hit.log"
grep -q 'rel8 escrow hit' "$TMP/payload-hit.log" || { printf 'FAIL rel8: incbin warm run missed\n' >&2; exit 1; }
printf 'second payload' >"$TMP/payload.bin"
"$BASM" --rel8-escrow "$PAYLOAD_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/payload-second.o" "$TMP/payload.basm" 2>"$TMP/payload-second.log"
! grep -q 'rel8 escrow hit' "$TMP/payload-second.log" || { printf 'FAIL rel8: changed incbin hit stale entry\n' >&2; exit 1; }
cmp -s "$TMP/payload-first.o" "$TMP/payload-second.o" && {
    printf 'FAIL rel8: changed incbin retained old object\n' >&2
    exit 1
}
"$NASM" -f elf64 -o "$TMP/payload-nasm.o" "$TMP/payload.basm"
"$ELFTOOL" diff "$TMP/payload-second.o" "$TMP/payload-nasm.o" >/dev/null

cat >"$TMP/string.basm" <<'EOF'
bits 64
section .rodata
db "incbin missing-payload.bin"
EOF
"$BASM" --rel8-escrow "$TMP/string-escrow" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/string.o" "$TMP/string.basm" 2>"$TMP/string.log"

cp "$BASM" "$TMP/identity-basm"
chmod +x "$TMP/identity-basm"
cp -p "$TMP/identity-basm" "$TMP/identity-time-reference"
"$TMP/identity-basm" --rel8-escrow "$TMP/identity-escrow" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/identity-first.o" "$TMP/input.basm" 2>"$TMP/identity-first.log"
size=$(wc -c <"$TMP/identity-basm")
printf X | dd of="$TMP/identity-basm" bs=1 seek=$((size - 1)) conv=notrunc status=none
touch -r "$TMP/identity-time-reference" "$TMP/identity-basm"
"$TMP/identity-basm" --rel8-escrow "$TMP/identity-escrow" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/identity-second.o" "$TMP/input.basm" 2>"$TMP/identity-second.log"
! grep -q 'rel8 escrow hit' "$TMP/identity-second.log" || {
    printf 'FAIL rel8: changed executable content reused stale cache\n' >&2
    exit 1
}

# INV-583: eight concurrent publishers on one escrow must all succeed
# with byte-identical outputs (a mid-race half entry heals as a miss,
# never fails the build and never poisons bytes).
RACE_CACHE="$TMP/race-escrow"
i=0
pids=""
while [ "$i" -lt 8 ]; do
    "$BASM" --rel8-escrow "$RACE_CACHE" --rel8-key "$TMP/key.seed" \
        -f elf64 -o "$TMP/race-$i.o" "$TMP/input.basm" \
        >"$TMP/race-$i.log" 2>&1 &
    pids="$pids $!"
    i=$((i + 1))
done
for pid in $pids; do
    wait "$pid" || { printf 'FAIL rel8: concurrent publisher failed (pid %s)\n' "$pid" >&2; exit 1; }
done
i=0
while [ "$i" -lt 8 ]; do
    cmp -s "$TMP/cold.o" "$TMP/race-$i.o" || {
        printf 'FAIL rel8: racy publish diverged (job %d)\n' "$i" >&2
        exit 1
    }
    i=$((i + 1))
done

"$BASM" --rel8-escrow "$RACE_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/race-restored.o" "$TMP/input.basm" 2>"$TMP/race-restored.log"
grep -q 'rel8 escrow hit' "$TMP/race-restored.log"
cmp -s "$TMP/cold.o" "$TMP/race-restored.o"

# INV-583: a half-present entry (receipt lost) heals via rebuild.
HALF_CACHE="$TMP/half-escrow"
"$BASM" --rel8-escrow "$HALF_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/half-first.o" "$TMP/input.basm" 2>"$TMP/half-first.log"
grep -q 'rel8 escrow hit' "$TMP/half-first.log" && {
    printf 'FAIL rel8: first half-cache run reported hit\n' >&2
    exit 1
}
rm -f "$HALF_CACHE"/*.receipt
"$BASM" --rel8-escrow "$HALF_CACHE" --rel8-key "$TMP/key.seed" \
    -f elf64 -o "$TMP/half-second.o" "$TMP/input.basm" 2>"$TMP/half-second.log"
! grep -q 'receipt rejected' "$TMP/half-second.log" || {
    printf 'FAIL rel8: half entry failed closed instead of healing\n' >&2
    exit 1
}
cmp -s "$TMP/cold.o" "$TMP/half-second.o" || {
    printf 'FAIL rel8: healed rebuild diverged\n' >&2
    exit 1
}

printf 'PASS rel8 escrow (authenticated hit + attestation + tamper rejection + incbin invalidation + race + heal)\n'
