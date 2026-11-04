#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}

command -v "$NASM" >/dev/null 2>&1 || { echo "FAIL: nasm not found" >&2; exit 1; }
[ -x "$BASM" ] || { echo "FAIL: missing basm: $BASM" >&2; exit 1; }
[ -x "$ELFTOOL" ] || { echo "FAIL: missing elftool: $ELFTOOL" >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-critical.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/prefixes.basm" <<'ASM'
bits 64
section .text
_start:
    sete r8b
    rdrand rax
    rdseed rax
    rep insw
    rep outsw
    invpcid rdi, [rsp]
    fldcw [r8]
    ldmxcsr [r9]
    stmxcsr [r10]
    mov r8w, r9w
    add r15w, r8w
    o64 push rax
ASM

"$NASM" -f elf64 -o "$TMP/prefixes.n.o" "$TMP/prefixes.basm"
"$BASM" -f elf64 -o "$TMP/prefixes.b.o" "$TMP/prefixes.basm"
"$ELFTOOL" diff "$TMP/prefixes.b.o" "$TMP/prefixes.n.o" >/dev/null

perl -e 'print "a" x 300, ":\nret\n"' >"$TMP/long-label.basm"
if "$BASM" -f elf64 -o "$TMP/long-label.o" "$TMP/long-label.basm" >/dev/null 2>&1; then
    echo "FAIL: long label accepted" >&2
    exit 1
fi

cat >"$TMP/flat-reloc.basm" <<'ASM'
bits 64
section .text
extern ext_target
    call ext_target
ASM
if "$BASM" -f bin -o "$TMP/flat-reloc.bin" "$TMP/flat-reloc.basm" >/dev/null 2>&1; then
    echo "FAIL: flat binary with relocation accepted" >&2
    exit 1
fi

cat >"$TMP/sign.basm" <<'ASM'
bits 64
section .text
_start:
    ret
ASM
if "$BASM" -f elf64 -o "$TMP/sign.o" --emit-attestation "$TMP/sign.proof" --sign "$TMP/missing.seed" "$TMP/sign.basm" >/dev/null 2>&1; then
    echo "FAIL: missing signing key accepted" >&2
    exit 1
fi
[ ! -e "$TMP/sign.proof" ] || {
    echo "FAIL: signing failure left an unsigned proof" >&2
    exit 1
}

perl -e 'print "%macro BIG 0\n"; print "db 0\n" x 14000; print "%endmacro\nsection .data\nBIG\n"' >"$TMP/big-macro.basm"
"$BASM" -f elf64 -o "$TMP/big-macro.o" "$TMP/big-macro.basm" >/dev/null
"$ELFTOOL" audit "$TMP/big-macro.o" >/dev/null

# INV-580: movsx/movzx width matrix + rdpkru opcode, byte-agreed with NASM
# (bin format keeps this independent of ELF metadata).
while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf 'bits 64\nsection .text\n%s\n' "$line" >"$TMP/movx.basm"
    if "$NASM" -f bin -o "$TMP/movx.n.bin" "$TMP/movx.basm" 2>/dev/null; then
        "$BASM" -f bin -o "$TMP/movx.b.bin" "$TMP/movx.basm" >/dev/null 2>&1 || {
            echo "FAIL: basm rejects NASM-accepted '$line'" >&2; exit 1; }
        cmp -s "$TMP/movx.n.bin" "$TMP/movx.b.bin" || {
            echo "FAIL: movsx/zx bytes differ for '$line'" >&2; exit 1; }
    else
        "$BASM" -f bin -o "$TMP/movx.b.bin" "$TMP/movx.basm" >/dev/null 2>&1 && {
            echo "FAIL: basm accepts NASM-rejected '$line'" >&2; exit 1; }
    fi
done <<'MOVX'
movsx rdi, al
movsx rdi, ax
movsx rdi, eax
movsx edi, al
movsx edi, ax
movsx di, al
movsx eax, al
movzx rdi, al
movzx rdi, ax
movzx edi, ax
movzx di, al
movzx rdi, eax
movsx di, ax
movsx edi, eax
movsx al, bl
movsx rax, rbx
movzx rax, rbx
movsx ax, bx
movsx r9w, ah
movsx rax, ah
movzx r9b, al
movsx rdi, byte [rbx]
movsx rdi, word [rbx]
movsx rdi, dword [rbx]
movzx rdi, byte [rbx]
movzx rdi, word [rbx]
movzx rdi, dword [rbx]
movsx rdi, dword [rbx+8]
rdpkru
wrpkru
MOVX

echo "PASS critical BearBasm regressions"
