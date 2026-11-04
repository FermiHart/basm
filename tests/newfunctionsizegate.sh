#!/usr/bin/env bash
# Host inspection/oracles only: BASM must be the actual product under test.
set -euo pipefail
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
READELF=${READELF:-readelf}
for tool in "$BASM" "$NASM" "$ELFTOOL" "$READELF" perl; do
    command -v "$tool" >/dev/null || { printf 'FAIL missing tool: %s\n' "$tool"; exit 1; }
done
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-function-size.XXXXXX")
if [ "${KEEP_TMP:-0}" = 1 ]; then
    trap 'printf "function size artifacts: %s\n" "$TMP"' EXIT
else
    trap 'rm -rf "$TMP"' EXIT
fi
fail=0
positive=0
negative=0

parity() {
    local name=$1
    "$NASM" -f elf64 -I"$TMP/" -o "$TMP/$name.n.o" "$TMP/$name.basm"
    if ! "$BASM" -f elf64 -I"$TMP/" -o "$TMP/$name.b.o" "$TMP/$name.basm"; then
        printf 'FAIL function size: rejected %s\n' "$name"
        fail=1
    elif ! "$ELFTOOL" diff "$TMP/$name.b.o" "$TMP/$name.n.o"; then
        printf 'FAIL function size: normalized ELF mismatch %s\n' "$name"
        fail=1
    else
        "$ELFTOOL" audit "$TMP/$name.b.o" >/dev/null
        positive=$((positive+1))
    fi
}

cat >"$TMP/forward.basm" <<'ASM'
section .text
global f:function (f_end-f)
f: ret
f_end:
ASM
parity forward

cat >"$TMP/functions.inc" <<'ASM'
section .text
global hw32:function (hw32_end-hw32)
global hw64:function ((hw64_end - hw64) + 0x1 - 1)
align 16
times 16 db 0x90
hw32:
xor eax, eax
ret
hw32_end:
align 16
times 16 db 0x90
hw64:
jmp hw64_done
times 130 db 0x90
hw64_done:
ret
hw64_end:
align 16
section .rodata
global function_table
function_table:
dd hw32_end-hw32, hw64_end-hw64
dq hw32, hw64
ASM
cat >"$TMP/ranges.basm" <<'ASM'
%include "functions.inc"
ASM
parity ranges
if [ -f "$TMP/ranges.b.o" ]; then
    "$READELF" -Ws "$TMP/ranges.b.o" | perl -ane '
        next unless @F == 8;
        if ($F[7] eq "hw32" || $F[7] eq "hw64") {
            my ($value,$size) = $F[7] eq "hw32" ? (16,3) : (48,136);
            die "FAIL prefix/function extent: $_" unless hex($F[1]) == $value &&
                $F[2] == $size && $F[3] eq "FUNC" && $F[4] eq "GLOBAL";
            $seen++;
        }
        END { die "FAIL missing function exports\n" unless $seen == 2; }
    ' || fail=1
fi

cat >"$TMP/legacy.basm" <<'ASM'
section .text
global plain
global unspecified:function
extern imported
plain: ret
unspecified: ret
call imported
ASM
parity legacy

cat >"$TMP/custom-local.basm" <<'ASM'
section .text.hot progbits alloc exec nowrite align=16
f: nop
global f:function (.end - f)
ret
.end:
global g:function (g_end - (g + 1) + 1)
g: ret
g_end:
section .data
db 0
ASM
parity custom-local

cat >"$TMP/literal.basm" <<'ASM'
section .text
global f:function 1
global zero:function 0
f: ret
zero:
ASM
parity literal

cat >"$TMP/bounds.basm" <<ASM
section .text
global f:function $(perl -e 'print "(" x 15, "1+(9223372036854775807-9223372036854775807)", ")" x 15')
global g:function $(perl -e 'print "+" x 254, "1"')
f: ret
g: ret
ASM
parity bounds

# NASM ..sym opts into symbol identity; ordinary dq must still section-fold.
for mode in default defined forward extern late-extern qualified; do
    case "$mode" in
        default|defined)
            cat >"$TMP/wrt-$mode.basm" <<'ASM'
section .text
global target:function (target_end-target)
times 16 db 0x90
target: ret
target_end:
section .data
ASM
            modifier=' wrt ..sym'
            [ "$mode" != default ] || modifier=''
            printf '__export_symbol_target: dq target%s\n' "$modifier" >>"$TMP/wrt-$mode.basm"
            ;;
        forward)
            printf 'section .data\ndq target wrt ..sym\nsection .text\nglobal target\ntarget: ret\n' >"$TMP/wrt-$mode.basm"
            ;;
        extern)
            printf 'extern target\nsection .data\ndq target wrt ..sym\n' >"$TMP/wrt-$mode.basm"
            ;;
        late-extern)
            printf 'section .data\ndq target wrt ..sym\nextern target\n' >"$TMP/wrt-$mode.basm"
            ;;
        qualified)
            printf 'section .text\nscope: nop\nglobal scope.target\n.target: ret\nsection .data\ndq .target wrt ..sym\n' >"$TMP/wrt-$mode.basm"
            ;;
    esac
    parity "wrt-$mode"
    # Assert the NAME/addend contract independently of the normalized diff.
    if [ -f "$TMP/wrt-$mode.b.o" ]; then
        "$READELF" -Wr "$TMP/wrt-$mode.b.o" | perl -ane '
            BEGIN { $mode = shift @ARGV; }
            next unless /R_X86_64_64/;
            my ($symbol,$addend) = $mode eq "default" ? (".text", "10") :
                ($mode eq "qualified" ? "scope.target" : "target", "0");
            die "FAIL wrt symbol/addend: $_" unless @F == 7 && $F[4] eq $symbol && $F[6] eq $addend;
            $seen++;
            END { die "FAIL wrt relocation count\n" unless $seen == 1; }
        ' -- "$mode" || fail=1
    fi
done

reject() {
    local name=$1 source=$2
    printf '%s\n' "$source" >"$TMP/reject.basm"
    # Failed validation must preserve an existing output, including flat output.
    for fmt in elf64 bin; do
        printf 'unchanged output\n' >"$TMP/reject.o"
        if "$BASM" -f "$fmt" -o "$TMP/reject.o" "$TMP/reject.basm" >"$TMP/reject.log" 2>&1; then
            printf 'FAIL function size: accepted %s (%s)\n' "$name" "$fmt"
            fail=1
        elif ! grep -Eq 'global|function size|wrt' "$TMP/reject.log"; then
            printf 'FAIL function size: wrong diagnostic %s (%s)\n' "$name" "$fmt"
            cat "$TMP/reject.log"
            fail=1
        elif [ "$(cat "$TMP/reject.o")" != 'unchanged output' ]; then
            printf 'FAIL function size: overwrote output for %s\n' "$name"
            fail=1
        else
            negative=$((negative+1))
        fi
    done
}

for expr in '()' '(f_end-)' '(f_end-f' 'f_end-f)' '(f_end-f) 1' \
    '(f_end-f), 1' '(f_end,f)' 'f_end f' '0x' '0xg' '(f_end-f)*1' '$-f' '$$' \
    '(f-f_end)' '2' '18446744073709551616' '9223372036854775807+1' \
    '-9223372036854775807-2' '18446744073709551617-18446744073709551616' \
    'missing-f' 'f_end-missing' 'f_end' '(missing-missing)+(f_end-f)'; do
    reject "$expr" "section .text
global f:function $expr
f: ret
f_end:"
done
for declaration in 'global' 'global :function (f_end-f)' 'global f:function ,' \
    'global f:function (f_end-f),' 'global f 1' 'global f,other' \
    'global f:unknown (f_end-f)'; do
    reject "$declaration" "section .text
$declaration
f: ret
f_end:"
done
reject undefined-function $'section .text\nglobal f:function 1\nret'
reject external $'section .text\nextern ext\nglobal f:function (ext-f)\nf: ret'
reject late-external $'section .text\nglobal f:function (ext-f)\nf: ret\nextern ext'
reject cross-section $'section .text\nglobal f:function (other-f)\nf: ret\nsection .data\nother:'
reject cancelled-cross-section $'section .text\nglobal f:function (other-other+1)\nf: ret\nsection .data\nother:'
reject non-code $'section .data\nglobal f:function (f_end-f)\nf: db 0\nf_end:'
reject custom-non-code $'section .custom progbits alloc\nglobal f:function 1\nf: db 0'
reject custom-nobits $'section .custom nobits alloc exec\nglobal f:function 1\nf: resb 1'
reject beyond-end $'section .text\nret\nglobal f:function 2\nf: ret'
reject different-code-section $'section .text\nglobal f:function (other-f)\nf: ret\nsection .other progbits alloc exec\nother:'
reject constant-alias $'section .text\nglobal f:function extent\nf: ret\nextent equ 1'
reject conflicting-size $'section .text\nglobal f:function 1\nglobal f:function 0\nf: ret'
reject conflicting-unspecified $'section .text\nglobal f:function 1\nglobal f:function\nf: ret'
reject long-expression "section .text
global f:function $(perl -e 'print "0+" x 128, "1"')
f: ret"
reject deep-expression "section .text
global f:function $(perl -e 'print "(" x 17, "1", ")" x 17')
f: ret"

for operand in 'target wrt' 'target wrt ..got' 'target wrt ..sym extra' \
    'target wrt ..sym, 0' 'target, wrt ..sym' 'target wrt, ..sym' \
    'target wrt ..sym,' 'target+1 wrt ..sym' '1 wrt ..sym' 'wrt ..sym'; do
    reject "wrt $operand" "section .text
global target
target: ret
section .data
dq $operand"
done
reject wrt-local $'section .text\ntarget: ret\nsection .data\ndq target wrt ..sym'
reject wrt-undefined $'section .data\ndq target wrt ..sym'
reject wrt-undefined-global $'global target\nsection .data\ndq target wrt ..sym'
reject wrt-wrong-width $'extern target\nsection .data\ndd target wrt ..sym'
long_name=$(perl -e 'print "x" x 255')
reject wrt-long-name "section .text
global $long_name
$long_name: ret
section .data
dq ${long_name}x wrt ..sym"

printf 'function size/wrt gate: %d parity cases, %d rejection checks, fail=%d\n' "$positive" "$negative" "$fail"
exit "$fail"
