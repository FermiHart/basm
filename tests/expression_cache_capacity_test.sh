#!/bin/sh
# INV-391: more unique constants than the cache capacity must still terminate.
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

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-expr-cache.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

perl -e '
    print "section .text\nglobal _start\n_start:\n";
    for ($i = 0; $i < 1200; $i++) {
        print "    add rax, $i\n";
    }
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

[ "$rc" -ne 124 ] || { printf 'FAIL: expression cache assembly timed out\n' >&2; exit 1; }
[ "$rc" -eq 0 ] || { printf 'FAIL: basm exited %d\n' "$rc" >&2; exit 1; }
[ -s "$TMP/basm.o" ] || { printf 'FAIL: basm produced no object\n' >&2; exit 1; }

"$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/capacity.basm"
"$ELFTOOL" audit "$TMP/basm.o" >/dev/null
"$ELFTOOL" diff "$TMP/nasm.o" "$TMP/basm.o"

cat >"$TMP/contextual.basm" <<'EOF'
org 0
section .data
db $
db $
EOF
"$BASM" -f bin -o "$TMP/contextual.basm.bin" "$TMP/contextual.basm"
"$NASM" -f bin -o "$TMP/contextual.nasm.bin" "$TMP/contextual.basm"
cmp "$TMP/contextual.nasm.bin" "$TMP/contextual.basm.bin"

printf 'PASS expression cache capacity (1200 constants + contextual offset)\n'
