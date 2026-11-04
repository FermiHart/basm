#!/usr/bin/env bash
# tests/run_tests.sh — regression suite for NASM-subset features in basm.
# Usage: bash tests/run_tests.sh [path/to/basm]
set -euo pipefail

BASM="${1:-./basm}"
NASM="${NASM:-nasm}"
TESTDIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

has_nasm=0
if command -v "$NASM" >/dev/null 2>&1; then has_nasm=1; fi

# Sovereign semantic comparator: prefer elftool diff over objdump.
ELFTOOL="${ELFTOOL:-$TESTDIR/../elftool}"
has_elftool=0
if [ -x "$ELFTOOL" ]; then has_elftool=1; fi

fail=0
for src in "$TESTDIR"/*.basm "$TESTDIR"/regression/*.basm; do
    [ -e "$src" ] || continue
    name="$(basename "$src" .basm)"
    echo -n "TEST $name ... "
    if ! "$BASM" -f elf64 -o "$TMP/$name.basm.o" "$src" 2>"$TMP/$name.err"; then
        echo "FAIL (basm assemble)"
        cat "$TMP/$name.err"
        fail=1
        continue
    fi
    if [ "$has_nasm" -eq 1 ]; then
        if ! "$NASM" -f elf64 -o "$TMP/$name.nasm.o" "$src" 2>"$TMP/$name.nasm.err"; then
            echo "SKIP (nasm rejects subset extension)"
            continue
        fi
        if ! cmp -s "$TMP/$name.basm.o" "$TMP/$name.nasm.o"; then
            # ELF metadata may differ; compare semantics, not raw bytes.
            if [ "$has_elftool" -eq 1 ]; then
                # Sovereign path: canonical semantic diff (secs/syms/relocs).
                if ! "$ELFTOOL" diff "$TMP/$name.basm.o" "$TMP/$name.nasm.o" >"$TMP/$name.diff" 2>&1; then
                    echo "FAIL (semantic mismatch vs nasm)"
                    cat "$TMP/$name.diff"
                    fail=1
                    continue
                fi
            else
                # Fallback: .text disassembly parity via objdump.
                objdump -d "$TMP/$name.basm.o" | sed '1,/^Disassembly/d' >"$TMP/$name.basm.dis"
                objdump -d "$TMP/$name.nasm.o" | sed '1,/^Disassembly/d' >"$TMP/$name.nasm.dis"
                if ! diff -q "$TMP/$name.basm.dis" "$TMP/$name.nasm.dis" >/dev/null 2>&1; then
                    echo "FAIL (code mismatch vs nasm)"
                    diff "$TMP/$name.basm.dis" "$TMP/$name.nasm.dis" || true
                    fail=1
                    continue
                fi
            fi
        fi
    fi
    echo "PASS"
done

exit "$fail"
