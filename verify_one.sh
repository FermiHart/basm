#!/bin/sh
# Author: F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

# basm-core full differential parity check for one stage0 .basm file.
# Compares .text, .data, symtab, and relocations byte-for-byte against NASM,
# running both from the same dir (honest FILE-symbol match).
# Usage: sh verify_one.sh <file.basm>   (run from compiler/stage0)
set -u
f="$1"
BASM=../basm/basm
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
nasm -f elf64 -w-other -o "$T/n.o" "$f" 2>"$T/nerr" || { echo "$f: NASM failed: $(cat $T/nerr)"; exit 2; }
"$BASM" -f elf64 -o "$T/b.o" "$f" 2>"$T/berr" || { echo "$f: basm failed: $(cat $T/berr)"; exit 1; }

ok=1
# Functional parity gate: .text/.data/.rodata content + symtab (value/type/
# bind/ndx/name) + relocations identical. (Full ELF byte-identity additionally
# requires reproducing NASM's strtab string-insertion order, tracked separately;
# it does not affect linking or correctness.)
for sec in .text .data .rodata; do
    objcopy -O binary --only-section=$sec "$T/n.o" "$T/n$sec.bin" 2>/dev/null || : 
    objcopy -O binary --only-section=$sec "$T/b.o" "$T/b$sec.bin" 2>/dev/null || :
    [ -f "$T/n$sec.bin" ] || continue
    if ! cmp -s "$T/n$sec.bin" "$T/b$sec.bin"; then
        echo "$f: $sec DIFFERS (byte $(cmp $T/n$sec.bin $T/b$sec.bin 2>/dev/null | grep -oP 'byte \K[0-9]+'))"
        ok=0
    fi
done
readelf -sW "$T/n.o" | awk 'NR>3{print $2,$4,$5,$6,$7,$8}' > "$T/n.sym"
readelf -sW "$T/b.o" | awk 'NR>3{print $2,$4,$5,$6,$7,$8}' > "$T/b.sym"
diff -q "$T/n.sym" "$T/b.sym" >/dev/null || { echo "$f: SYMTAB differs"; diff "$T/n.sym" "$T/b.sym" | head; ok=0; }
readelf -rW "$T/n.o" 2>/dev/null | grep R_X86 | awk '{print $1,$3,$5,$6,$7}' > "$T/n.rel" || :
readelf -rW "$T/b.o" 2>/dev/null | grep R_X86 | awk '{print $1,$3,$5,$6,$7}' > "$T/b.rel" || :
diff -q "$T/n.rel" "$T/b.rel" >/dev/null || { echo "$f: RELOCS differ"; diff "$T/n.rel" "$T/b.rel" | head; ok=0; }

if [ "$ok" = 1 ]; then
    tsz=$(stat -c%s "$T/b.text.bin" 2>/dev/null || echo 0)
    nr=$(grep -c . "$T/n.rel" 2>/dev/null || echo 0)
    echo "$f: PARITY OK (.text=${tsz}B relocs=${nr} symtab==)"
else
    exit 1
fi
