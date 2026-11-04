#!/bin/sh
# INV-394: every fixed preprocessor/CLI capacity refuses before truncation/OOB.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}

[ -x "$BASM" ] || { printf 'FAIL: missing basm: %s\n' "$BASM" >&2; exit 1; }
command -v perl >/dev/null 2>&1 || { printf 'FAIL: perl not found\n' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-pp-limits.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

expect_fail() {
    label=$1
    pattern=$2
    shift 2
    set +e
    "$@" >"$TMP/$label.stdout" 2>"$TMP/$label.stderr"
    rc=$?
    set -e
    [ "$rc" -ne 0 ] || { printf 'FAIL: %s was accepted\n' "$label" >&2; exit 1; }
    grep -q "$pattern" "$TMP/$label.stderr" || {
        printf 'FAIL: %s produced wrong diagnostic\n' "$label" >&2
        exit 1
    }
}

# 1023 source bytes before newline fit the 1024-byte line buffer including NUL.
perl -e 'print ";", "x" x 1022, "\nsection .text\nret\n"' >"$TMP/line-ok.basm"
"$BASM" -f elf64 -o "$TMP/line-ok.o" "$TMP/line-ok.basm"

# 1024 source bytes before newline must refuse instead of truncating.
perl -e 'print ";", "x" x 1023, "\nsection .text\nret\n"' >"$TMP/line-too-long.basm"
expect_fail line-too-long 'source line exceeds 1023 bytes' \
    "$BASM" -f elf64 -o "$TMP/line-too-long.o" "$TMP/line-too-long.basm"

cat >"$TMP/define-four.basm" <<'EOF'
%define PICK4(a,b,c,d) d
section .data
db PICK4(1,2,3,4)
EOF
"$BASM" -f elf64 -o "$TMP/define-four.o" "$TMP/define-four.basm"

# INV-588: %undef removes the preprocessor definition before subsequent
# lines are expanded; it must not be swallowed by the assembly-time table.
cat >"$TMP/undef.basm" <<'EOF'
%define REMOVED 7
section .data
db REMOVED
%undef REMOVED
db REMOVED
EOF
expect_fail undef 'unknown symbol in expression' \
    "$BASM" -f elf64 -o "$TMP/undef.o" "$TMP/undef.basm"

cat >"$TMP/define-five.basm" <<'EOF'
%define PICK5(a,b,c,d,e) e
section .data
db PICK5(1,2,3,4,5)
EOF
expect_fail define-five '%define supports at most 4 parameters' \
    "$BASM" -f elf64 -o "$TMP/define-five.o" "$TMP/define-five.basm"

cat >"$TMP/include-paths.basm" <<'EOF'
section .text
ret
EOF

set --
i=0
while [ "$i" -lt 16 ]; do
    set -- "$@" "-I$TMP/inc-$i"
    i=$((i + 1))
done
"$BASM" "$@" -f elf64 -o "$TMP/include-16.o" "$TMP/include-paths.basm"

set -- "$@" "-I$TMP/inc-16"
expect_fail include-17 'too many include paths' \
    "$BASM" "$@" -f elf64 -o "$TMP/include-17.o" "$TMP/include-paths.basm"

cat >"$TMP/dead-include.basm" <<'EOF'
%if 0
%include "missing-dead-branch.inc"
%endif
section .text
ret
EOF
"$BASM" -f elf64 -o "$TMP/dead-include.o" "$TMP/dead-include.basm"

cat >"$TMP/include-inner.inc" <<'EOF'
%define INCLUDED_VALUE 7
EOF
cat >"$TMP/include-outer.inc" <<'EOF'
%if PARENT_VALUE
%include "include-inner.inc"
%endif
EOF
cat >"$TMP/active-nested-include.basm" <<'EOF'
%define PARENT_VALUE 7
%include "include-outer.inc"
section .data
db INCLUDED_VALUE
EOF
"$BASM" -f bin -o "$TMP/active-nested-include.bin" "$TMP/active-nested-include.basm"
printf '\007' >"$TMP/active-nested-include.expected"
cmp -s "$TMP/active-nested-include.expected" "$TMP/active-nested-include.bin" || {
    printf 'FAIL: nested include did not share preprocessor state\n' >&2
    exit 1
}

# INV-582: absurd repetition dies fast instead of hanging the build.
cat >"$TMP/rep-bomb.basm" <<'EOF'
%rep 2000000000
db 0
%endrep
section .text
ret
EOF
expect_fail rep-bomb 'excessive %rep count' \
    "$BASM" -f elf64 -o "$TMP/rep-bomb.o" "$TMP/rep-bomb.basm"

cat >"$TMP/rep-256.basm" <<'EOF'
%rep 256
db 0
%endrep
section .text
ret
EOF
"$BASM" -f elf64 -o "$TMP/rep-256.o" "$TMP/rep-256.basm"

cat >"$TMP/times-bomb.basm" <<'EOF'
section .text
times 2000000000 db 0
ret
EOF
expect_fail times-bomb 'times count too large' \
    "$BASM" -f elf64 -o "$TMP/times-bomb.o" "$TMP/times-bomb.basm"

cat >"$TMP/inc-cycle-a.inc" <<EOF
%include "inc-cycle-b.inc"
EOF
cat >"$TMP/inc-cycle-b.inc" <<EOF
%include "inc-cycle-a.inc"
EOF
cat >"$TMP/inc-cycle.basm" <<'EOF'
%include "inc-cycle-a.inc"
section .text
ret
EOF
(cd "$TMP" && expect_fail inc-cycle 'include depth exceeded' \
    "$BASM" -f elf64 -o "$TMP/inc-cycle.o" "$TMP/inc-cycle.basm")

printf 'PASS preprocessor limits (line, define/undef, include paths, conditional includes, repetition caps, include cycle)\n'
