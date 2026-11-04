#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  ddc-basm.sh — Diverse Double-Compiling gate for basm (Wheeler's DDC).
#
#  sP = basm sources (basm.c + modules/*.inc + sign.c + canonical ed25519).
#  cA = basm built by cc, cB = basm built by clang (independent lineage).
#  GATE: cA and cB assemble every admitted corpus file to byte-identical .o.
#  Correctness (non-vacuous): each candidate must (1) assemble the corpus
#  without error and (2) match NASM bytes on the parity subset.
#
#  Corpus = every repo .basm the reference ./basm assembles with -f elf64
#  (admission only; 32-bit regression fixtures and AppleDouble junk skip).
#  A file one candidate cannot assemble is an ALARM, never a skip.
#
#  Usage:  sh ddc-basm.sh           (run from toolchain/BearBasm)
#  Exit:   0 = DDC holds, 1 = differs, 2 = blocked (<2 diverse builds).
#  Author: F E R M I ∞ H A R T <contact@fermihart.com>
#  SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
#  SPDX-License-Identifier: BSD-3-Clause
#  Campaign: Thompson-10 W4 2026-09-19
# ─────────────────────────────────────────────────────────────────────────────
set -u
cd "$(dirname "$0")"
T="${W4_KEEPDIR:-/tmp/w4-basm-$$}"; rm -rf "$T"; mkdir -p "$T"
if [ -z "${W4_KEEPDIR:-}" ]; then trap 'rm -rf "$T"' EXIT; else trap - EXIT; fi

echo "[w4] building diverse basm binaries ..."
for spec in "cc:basm-cc" "clang:basm-clang"; do
    cc_alias="${spec%%:*}"; tag="${spec##*:}"
    if ! command -v "$cc_alias" >/dev/null 2>&1; then
        echo "[w4]   no $cc_alias — skipped"; continue
    fi
    if "$cc_alias" -std=c11 -O2 -w -D_DEFAULT_SOURCE -I. -I../.. \
        -o "$T/$tag" basm.c sign.c ../../crypto/ed25519.c \
        2>"$T/${tag}-build.log"; then
        echo "[w4]   $tag via $cc_alias: built"
    else
        echo "[w4]   $tag via $cc_alias: BUILD FAILED — skipped"
        tail -3 "$T/${tag}-build.log" | sed 's/^/        /'
    fi
done
CANDS=""
[ -x "$T/basm-cc" ] && CANDS="$CANDS basm-cc"
[ -x "$T/basm-clang" ] && CANDS="$CANDS basm-clang"
if [ "$(echo "$CANDS" | wc -w)" -lt 2 ]; then
    echo "[w4] BLOCKED: need >=2 diverse basm builds"; exit 2
fi
echo "[w4] candidates:$CANDS"

# ── corpus: every repo .basm the reference assembles (admission only) ──
REF=./basm
[ -x "$REF" ] || { echo "[w4] FAIL: reference ./basm missing"; exit 1; }
CORPUS="$T/corpus.txt"; : > "$CORPUS"
find .. ../.. ../../surfaces ../../ring0 ../../boot -name '*.basm' \
    -not -path '*/quarantine/*' 2>/dev/null | sort > "$T/all.txt"
n_admit=0; n_skip=0
while IFS= read -r f; do
    if "$REF" -f elf64 -o "$T/adm.o" "$f" >/dev/null 2>&1; then
        echo "$f" >> "$CORPUS"; n_admit=$((n_admit+1))
    else
        echo "  SKIP (ref cannot): $f"; n_skip=$((n_skip+1))
    fi
done < "$T/all.txt"
echo "[w4] corpus: $n_admit admitted, $n_skip skipped-by-reference"
cp "$CORPUS" "$T/corpus.final"

# ── correctness: NASM parity subset (independent anchor) ──
PARITY="$T/parity.txt"; : > "$PARITY"
for f in ../stage0/start.basm ../stage0/lex.basm ../stage0/codegen.basm; do
    [ -f "$f" ] || continue
    if nasm -f elf64 -w-other -o "$T/n.o" "$f" >/dev/null 2>&1; then
        echo "$f" >> "$PARITY"
    fi
done
npar=$(wc -l < "$PARITY")
echo "[w4] parity subset: $npar files"
for c in $CANDS; do
    ok=0; bad=0
    while IFS= read -r f; do
        nasm -f elf64 -w-other -o "$T/n.o" "$f" >/dev/null 2>&1
        if ! "$T/$c" -f elf64 -o "$T/c.o" "$f" >/dev/null 2>&1; then
            bad=$((bad+1)); continue
        fi
        same=1
        for sec in .text .data .rodata; do
            objcopy -O binary --only-section=$sec "$T/n.o" "$T/n.sec" 2>/dev/null || continue
            objcopy -O binary --only-section=$sec "$T/c.o" "$T/c.sec" 2>/dev/null || { same=0; break; }
            cmp -s "$T/n.sec" "$T/c.sec" || same=0
        done
        if [ "$same" = 1 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi
    done < "$PARITY"
    echo "[w4]   $c parity: $ok/$npar (bad=$bad)"
    if [ "$bad" -ne 0 ] || [ "$ok" -eq 0 ]; then
        echo "[w4] FAIL: $c is not a CORRECT basm"; exit 1
    fi
done

# ── DDC: candidates must agree byte-for-byte on the whole corpus ──
echo ""
printf "  %-40s | %-8s | %s\n" FILE "whole-.o" "verdict"
echo "  ----------------------------------------------------------------------"
FAIL=0; total=0
A=$(echo "$CANDS" | awk '{print $1}'); B=$(echo "$CANDS" | awk '{print $2}')
while IFS= read -r f; do
    total=$((total+1))
    if ! "$T/$A" -f elf64 -o "$T/a.o" "$f" >/dev/null 2>&1; then
        printf "  %-40s | %-8s | %s\n" "$f" "A-FAIL" "ALARM ($A cannot)"; FAIL=1; continue
    fi
    if ! "$T/$B" -f elf64 -o "$T/b.o" "$f" >/dev/null 2>&1; then
        printf "  %-40s | %-8s | %s\n" "$f" "B-FAIL" "ALARM ($B cannot)"; FAIL=1; continue
    fi
    if cmp -s "$T/a.o" "$T/b.o"; then
        printf "  %-40s | %-8s | %s\n" "$f" "IDENT" "PASS"
        cp "$T/a.o" "$T/w4a_$(basename $f .basm).o" 2>/dev/null
        cp "$T/b.o" "$T/w4b_$(basename $f .basm).o" 2>/dev/null
    else
        readelf -SW "$T/a.o" 2>/dev/null | awk '{print $2,$7}' >"$T/.sa"
        readelf -SW "$T/b.o" 2>/dev/null | awk '{print $2,$7}' >"$T/.sb"
        secs=$(diff "$T/.sa" "$T/.sb" 2>/dev/null | tr '\n' ' ')
        printf "  %-40s | %-8s | %s\n" "$f" "DIFF" "ALARM $secs"; FAIL=1
    fi
done < "$CORPUS"
cp "$T/$A" "$T/basm-diverse-a" 2>/dev/null; cp "$T/$B" "$T/basm-diverse-b" 2>/dev/null
echo ""
echo "[w4] files: $total"
if [ "$FAIL" = 0 ]; then
    echo "[w4] OK — $A == $B byte-identical on all $total corpus files."
    exit 0
else
    echo "[w4] ALARM — outputs differ; investigate before trust."
    exit 1
fi
