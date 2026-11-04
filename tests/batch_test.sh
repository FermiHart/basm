#!/bin/sh
# INV-558: batch jobs are isolated and every output retains NASM parity.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
NASM=${NASM:-nasm}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-batch.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

for n in 1 2 3 4; do
    cat >"$TMP/job$n.basm" <<EOF
bits 64
section .text
global job$n
job$n:
    mov rax, rbx
    add rax, $n
    ret
EOF
    printf 'elf64\t%s/job%d.basm.o\t%s/job%d.basm\n' "$TMP" "$n" "$TMP" "$n" >>"$TMP/jobs.tsv"
done

"$BASM" --batch "$TMP/jobs.tsv" 2>"$TMP/batch.log"
grep -q 'batch complete jobs=4 concurrency=8' "$TMP/batch.log" || {
    printf 'FAIL batch: missing completion receipt\n' >&2
    exit 1
}
for n in 1 2 3 4; do
    "$NASM" -f elf64 -o "$TMP/job$n.nasm.o" "$TMP/job$n.basm"
    "$ELFTOOL" audit "$TMP/job$n.basm.o" >/dev/null
    "$ELFTOOL" diff "$TMP/job$n.basm.o" "$TMP/job$n.nasm.o" >/dev/null
done

printf 'elf64\t%s/should-not-exist.o\t%s/job1.basm\nmalformed\n' "$TMP" "$TMP" >"$TMP/malformed.tsv"
if "$BASM" --batch "$TMP/malformed.tsv" >/dev/null 2>&1; then
    printf 'FAIL batch: malformed manifest was accepted\n' >&2
    exit 1
fi
sleep 1
[ ! -e "$TMP/should-not-exist.o" ] || {
    printf 'FAIL batch: work started before complete manifest validation\n' >&2
    exit 1
}

printf 'PASS batch (4 isolated parallel jobs)\n'
