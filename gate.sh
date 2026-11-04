#!/bin/sh
# Author: F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

# basm-core M0 acceptance gate.
# Asserts basm produces output byte-identical to NASM for start.basm, that the
# object links, and runs. Run from compiler/basm/ as ./gate.sh
#
# Portability: uses the sovereign `elftool` (built by make) instead of GNU
# binutils (objcopy/readelf), and `wc -c` instead of GNU stat.  Runs natively
# on macOS and Linux.  The link+run smoke test needs a Linux ELF loader, so it
# is executed on Linux and reported as SKIP elsewhere.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BASM=${BASM:-"$HERE/basm"}
ELFTOOL=${ELFTOOL:-"$HERE/elftool"}
case "$BASM" in /*) ;; *) BASM="$PWD/$BASM" ;; esac
case "$ELFTOOL" in /*) ;; *) ELFTOOL="$PWD/$ELFTOOL" ;; esac
STAGE0="$HERE/../stage0"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ -x "$BASM" ]    || { echo "FATAL: build basm first (make)"; exit 2; }
[ -x "$ELFTOOL" ] || { echo "FATAL: build elftool first (make elftool)"; exit 2; }
command -v nasm >/dev/null || { echo "FATAL: nasm not found (reference)"; exit 2; }

cd "$STAGE0"

# Per-file differential parity check: .text + symtab + relocs byte-identical.
check_file() {
    f=$1
    nasm -f elf64 -o "$TMP/n.o" "$f"
    "$BASM" -f elf64 -o "$TMP/b.o" "$f"
    "$ELFTOOL" sec "$TMP/n.o" .text > "$TMP/n.text" 2>/dev/null
    "$ELFTOOL" sec "$TMP/b.o" .text > "$TMP/b.text" 2>/dev/null
    if ! cmp -s "$TMP/n.text" "$TMP/b.text"; then
        echo "  $f  .text DIFFERS                            FAIL"
        cmp "$TMP/n.text" "$TMP/b.text" || true; return 1
    fi
    "$ELFTOOL" syms "$TMP/n.o" > "$TMP/n.sym"
    "$ELFTOOL" syms "$TMP/b.o" > "$TMP/b.sym"
    if ! diff -q "$TMP/n.sym" "$TMP/b.sym" >/dev/null; then
        echo "  $f  symtab DIFFERS                           FAIL"
        diff "$TMP/n.sym" "$TMP/b.sym" || true; return 1
    fi
    "$ELFTOOL" relocs "$TMP/n.o" > "$TMP/n.rel"
    "$ELFTOOL" relocs "$TMP/b.o" > "$TMP/b.rel"
    if ! diff -q "$TMP/n.rel" "$TMP/b.rel" >/dev/null; then
        echo "  $f  relocs DIFFER                            FAIL"
        diff "$TMP/n.rel" "$TMP/b.rel" || true; return 1
    fi
    sz=$(wc -c < "$TMP/b.text" | tr -d ' ')
    nr=$(grep -c . "$TMP/n.rel" 2>/dev/null || echo 0)
    echo "  $f  .text=${sz}B symtab+relocs(${nr}) == NASM    PASS"
}

check_opcode() {
    name=$1
    body=$2
    printf 'bits 64\nsection .text\nglobal _start\n_start:\n%s\n' "$body" > "$TMP/$name.basm"
    nasm -f elf64 -o "$TMP/$name.n.o" "$TMP/$name.basm"
    "$BASM" -f elf64 -o "$TMP/$name.b.o" "$TMP/$name.basm"
    "$ELFTOOL" sec "$TMP/$name.n.o" .text > "$TMP/$name.n.text" 2>/dev/null
    "$ELFTOOL" sec "$TMP/$name.b.o" .text > "$TMP/$name.b.text" 2>/dev/null
    if ! cmp -s "$TMP/$name.n.text" "$TMP/$name.b.text"; then
        echo "  $name  opcode DIFFERS                         FAIL"
        cmp "$TMP/$name.n.text" "$TMP/$name.b.text" || true
        return 1
    fi
    echo "  $name  opcode == NASM                          PASS"
}

echo "== basm-core differential parity vs NASM (per file) =="
PORTED="start.basm arena.basm"
for f in $PORTED; do check_file "$f" || exit 1; done

check_opcode "int-imm8" 'int 0x23
int 34
int3' || exit 1

check_opcode "rdfsbase" 'rdfsbase eax
rdfsbase rax
rdfsbase r11' || exit 1

check_opcode "kernel-x86_64-opcodes" 'wrfsbase rax
xchg rdi, rsi
rep insw
rep insb
rep outsw
rep outsb
out 0x20, al
fninit
clts
fnstsw ax
fxsave [rdi]
fxrstor [rdi]
frstor [rdi]
fnsave [rdi]
fnstcw [rdi]
xsave [rdi]
xrstor [rdi]
xgetbv
invpcid rdi, [rsp]
lldt di
sgdt [rdi]
sidt [rdi]
mfence
btr r8, 63' || exit 1

# Reference run-through (link + execute) needs a Linux ELF loader.
if [ "$(uname -s)" = "Linux" ]; then
    "$BASM" -f elf64 -o "$TMP/start.o" start.basm
    printf 'int main_c(int argc,char**argv){(void)argv;return argc+40;}\n' > "$TMP/tc.c"
    gcc -c -nostdlib -o "$TMP/tc.o" "$TMP/tc.c"
    ld -static -nostdlib -o "$TMP/prog" "$TMP/start.o" "$TMP/tc.o"
    set +e
    "$TMP/prog"; rc=$?
    set -e
    if [ "$rc" -eq 41 ]; then
        echo "  start.basm  link + run (exit=41)               PASS"
    else
        echo "  start.basm  link + run got exit=$rc, want 41    FAIL"
        exit 1
    fi
else
    echo "  start.basm  link + run                         SKIP (non-Linux host; parity gates above are authoritative)"
fi

echo "------------------------------------------------------"
echo "basm-core M1: ALL GATES GREEN (basm == nasm on: $PORTED)"
