#!/bin/sh
# INV-392: the effective .text limit is the physical 4 MiB buffer, not 64 KiB.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
NASM=${NASM:-nasm}

for tool in "$BASM" "$ELFTOOL"; do
    [ -x "$tool" ] || { printf 'FAIL: missing executable: %s\n' "$tool" >&2; exit 1; }
done
command -v perl >/dev/null 2>&1 || { printf 'FAIL: perl not found\n' >&2; exit 1; }
command -v "$NASM" >/dev/null 2>&1 || { printf 'FAIL: nasm not found\n' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-text-capacity.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

perl -e '
    print "section .text\nglobal _start\n_start:\n";
    print "    nop\n" for 1 .. 70000;
    print "    ret\n";
' >"$TMP/capacity.basm"

set +e
perl -e '
    $pid = fork();
    exit 127 if !defined $pid;
    if ($pid == 0) {
        exec @ARGV;
        exit 127;
    }
    $SIG{ALRM} = sub {
        kill "TERM", $pid;
        waitpid $pid, 0;
        exit 124;
    };
    alarm 10;
    waitpid $pid, 0;
    alarm 0;
    exit(($? >> 8) || ($? & 127));
' "$BASM" -f elf64 -o "$TMP/basm.o" "$TMP/capacity.basm"
rc=$?
set -e

[ "$rc" -ne 124 ] || { printf 'FAIL: 70 KiB text assembly timed out\n' >&2; exit 1; }
[ "$rc" -eq 0 ] || { printf 'FAIL: basm rejected 70 KiB .text (rc=%d)\n' "$rc" >&2; exit 1; }
[ -s "$TMP/basm.o" ] || { printf 'FAIL: basm produced no object\n' >&2; exit 1; }

"$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/capacity.basm"
"$ELFTOOL" audit "$TMP/basm.o" >/dev/null
"$ELFTOOL" diff "$TMP/nasm.o" "$TMP/basm.o"

cat >"$TMP/overflow.basm" <<'EOF'
section .text
db 1
align 8388608
db 2
EOF
set +e
"$BASM" -f elf64 -o "$TMP/overflow.o" "$TMP/overflow.basm" \
    >"$TMP/overflow.stdout" 2>"$TMP/overflow.stderr"
overflow_rc=$?
set -e
[ "$overflow_rc" -ne 0 ] || { printf 'FAIL: align bypassed TEXT_MAX\n' >&2; exit 1; }
grep -q 'text overflow' "$TMP/overflow.stderr" || {
    printf 'FAIL: align overflow produced wrong diagnostic\n' >&2
    exit 1
}

printf 'PASS text capacity (70001 instructions, >64 KiB, align bounded)\n'
