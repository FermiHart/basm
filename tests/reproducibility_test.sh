#!/bin/sh
# INV-585: identical invocation => bit-identical object and, with a fixed
# SOURCE_DATE_EPOCH, bit-identical attestation across time. The STT_FILE
# symbol and proof carry input/output paths as given, like NASM/proof v2.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
[ -x "$BASM" ] || { printf 'FAIL: missing basm: %s\n' "$BASM" >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-repro.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cat >"$TMP/in.basm" <<'EOF'
bits 64
section .text
global _start
_start:
    mov rax, rbx
    add rax, 7
    cmp rax, 100
    jne .done
    nop
.done:
    ret
section .rodata
val: dq 0x12345678
EOF
"$BASM" -f elf64 -o "$TMP/a.o" "$TMP/in.basm"
sleep 2
"$BASM" -f elf64 -o "$TMP/b.o" "$TMP/in.basm"
cmp -s "$TMP/a.o" "$TMP/b.o" || { printf 'FAIL repro: identical builds differ\n' >&2; exit 1; }
"$BASM" -f bin -o "$TMP/a.bin" "$TMP/in.basm" 2>/dev/null || true
if [ -f "$TMP/a.bin" ]; then
    sleep 1
    "$BASM" -f bin -o "$TMP/b.bin" "$TMP/in.basm" 2>/dev/null || true
    [ -f "$TMP/b.bin" ] && cmp -s "$TMP/a.bin" "$TMP/b.bin" || {
        printf 'FAIL repro: identical flat builds differ\n' >&2; exit 1; }
fi
SOURCE_DATE_EPOCH=1700000000 "$BASM" -f elf64 -o "$TMP/attested.o" \
    --emit-attestation "$TMP/a.proof" "$TMP/in.basm"
sleep 2
SOURCE_DATE_EPOCH=1700000000 "$BASM" -f elf64 -o "$TMP/attested.o" \
    --emit-attestation "$TMP/b.proof" "$TMP/in.basm"
cmp -s "$TMP/a.proof" "$TMP/b.proof" || {
    printf 'FAIL repro: fixed-epoch attestations differ\n' >&2
    exit 1
}
grep -q '^build_epoch: 1700000000$' "$TMP/a.proof" || {
    printf 'FAIL repro: attestation ignored SOURCE_DATE_EPOCH\n' >&2
    exit 1
}
printf 'PASS reproducibility (bit-identical objects + fixed-epoch proofs)\n'
