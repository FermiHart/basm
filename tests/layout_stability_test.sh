#!/bin/sh
# INV-545: final bytes require a stable layout, symbol table and EQU values.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-layout-stability.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/contextual-equ.basm" <<'EOF'
bits 64
section .text
times 127 db 0x90
add eax, X
X equ $-$$
dd X
EOF

cat >"$TMP/late-extern.basm" <<'EOF'
bits 64
section .text
jmp target
jmp ext
times 125 db 0x90
target:
ret
extern ext
EOF

cat >"$TMP/forward-symbols.basm" <<'EOF'
bits 64
section .text
call callee
loop loop_target
mov rax, [rel payload]
callee:
ret
loop_target:
ret
section .rodata
payload: times 2 dq 1
EOF

for name in contextual-equ late-extern forward-symbols; do
    "$BASM" -f elf64 -o "$TMP/$name.basm.o" "$TMP/$name.basm"
    "$NASM" -f elf64 -o "$TMP/$name.nasm.o" "$TMP/$name.basm"
    "$ELFTOOL" audit "$TMP/$name.basm.o" >/dev/null
    "$ELFTOOL" diff "$TMP/$name.basm.o" "$TMP/$name.nasm.o" >/dev/null || {
        printf 'FAIL layout stability: %s differs from NASM\n' "$name" >&2
        exit 1
    }
done

printf 'PASS layout stability (contextual EQU + late extern + forward symbols)\n'
