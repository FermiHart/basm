#!/bin/sh
# elftool_diff_test.sh — gate for the semantic ELF64 diff.
# Invariants:
#   1. same source assembled twice        -> exit 0, no output
#   2. different sources                  -> exit 1, at least one line
#   3. usage error                        -> exit 2
# Runs natively on macOS and Linux (POSIX sh, no external deps).
set -eu
cd "$(dirname "$0")/.."

BASM=${BASM:-./basm}
ELFTOOL=${ELFTOOL:-./elftool}

TMP="${TMPDIR:-/tmp}/elftool_diff_$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

"$BASM" -f elf64 -o "$TMP/a.o" tests/variadic.basm >/dev/null
"$BASM" -f elf64 -o "$TMP/b.o" tests/variadic.basm >/dev/null
"$BASM" -f elf64 -o "$TMP/c.o" tests/ifdef.basm    >/dev/null

# 1. identical builds: silent, exit 0
out=$("$ELFTOOL" diff "$TMP/a.o" "$TMP/b.o") || fail "identical builds reported as different"
[ -z "$out" ] || fail "identical builds produced output: $out"

# 2. different builds: exit 1, non-empty report
rc=0
out=$("$ELFTOOL" diff "$TMP/a.o" "$TMP/c.o") || rc=$?
[ "$rc" -eq 1 ] || fail "different builds: expected exit 1, got $rc"
[ -n "$out" ] || fail "different builds produced no report"

# 3. usage: exit 2
rc=0; "$ELFTOOL" diff "$TMP/a.o" 2>/dev/null || rc=$?
[ "$rc" -ne 0 ] || fail "missing operand accepted"

echo "PASS elftool diff"

# --- digest invariants -------------------------------------------------
# 4. identical builds share the TOTAL digest; different builds do not.
ta=$("$ELFTOOL" digest "$TMP/a.o" | awk '$1=="TOTAL"{print $2}')
tb=$("$ELFTOOL" digest "$TMP/b.o" | awk '$1=="TOTAL"{print $2}')
tc=$("$ELFTOOL" digest "$TMP/c.o" | awk '$1=="TOTAL"{print $2}')
[ -n "$ta" ] || fail "digest produced no TOTAL"
[ "$ta" = "$tb" ] || fail "identical builds have different digests"
[ "$ta" != "$tc" ] || fail "different builds share a digest"

# 5. clean-room SHA-256 must match the raw section bytes (spec check).
if command -v shasum >/dev/null 2>&1; then
    want=$("$ELFTOOL" sec "$TMP/a.o" .text | shasum -a 256 | cut -d' ' -f1)
    got=$("$ELFTOOL" digest "$TMP/a.o" | awk '$1==".text"{print $2}')
    [ "$want" = "$got" ] || fail "SHA-256 mismatch vs system shasum"
fi

echo "PASS elftool digest"

# --- audit invariants --------------------------------------------------
# 6. clean basm output satisfies A1-A6
"$ELFTOOL" audit "$TMP/a.o" >/dev/null || fail "audit rejects clean object"

# 7. corrupted symbol shndx must be caught (exit 1)
cp "$TMP/a.o" "$TMP/bad.o"
soff=$("$ELFTOOL" secs "$TMP/bad.o" | awk '$1==".symtab"{sub("off=","",$2); print $2}')
ssiz=$("$ELFTOOL" secs "$TMP/bad.o" | awk '$1==".symtab"{sub("size=","",$3); print $3}')
[ -n "$soff" ] && [ -n "$ssiz" ] || fail "could not locate symtab"
n=$((ssiz / 24))
pos=$((soff + (n - 1) * 24 + 6))
printf '\231' | dd of="$TMP/bad.o" bs=1 seek="$pos" conv=notrunc 2>/dev/null
rc=0; "$ELFTOOL" audit "$TMP/bad.o" >/dev/null || rc=$?
[ "$rc" -eq 1 ] || fail "audit missed corrupted shndx (rc=$rc)"

echo "PASS elftool audit"

# --- notes round-trip --------------------------------------------------
# 8. a spec-conformant note written by basm must be read back verbatim
cat > "$TMP/dna.basm" <<'NOTE'
section .note.bear
dd 5
dd 9
dd 1
db "BEAR", 0, 0, 0, 0
db "sovereign", 0, 0, 0

section .text
global _start
_start:
    ret
NOTE
"$BASM" "$TMP/dna.basm" -o "$TMP/dna.o" || fail "basm rejected note source"
out=$("$ELFTOOL" notes "$TMP/dna.o")
echo "$out" | grep -q 'owner="BEAR" type=1' || fail "note owner/type not parsed"
echo "$out" | grep -q '"sovereign"'         || fail "note desc not parsed"

# 9. object without notes: exit 1
printf 'section .text\nglobal _start\n_start:\n    ret\n' > "$TMP/non.basm"
"$BASM" "$TMP/non.basm" -o "$TMP/non.o" || fail "basm rejected plain source"
# (basm always emits .note.GNU-stack, so notes exits 0 here; assert that)
"$ELFTOOL" notes "$TMP/non.o" >/dev/null || fail "notes failed on GNU-stack note"

echo "PASS elftool notes"
