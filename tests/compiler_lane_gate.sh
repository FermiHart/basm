#!/usr/bin/env bash
# INV-553: report raw Bear/GCC codegen and enforce the optimized Bear boundary
# against GCC using the same static Bear libc.
set -euo pipefail

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BEAR_BASM=${BEAR_BASM:-$ROOT/basm}
GCC_BASM=${GCC_BASM:-$ROOT/build/gcc-blibc/basm-gcc-blibc}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
ROUNDS=${BASM_COMPILER_ROUNDS:-15}

[[ $ROUNDS =~ ^[0-9]+$ ]] && (( ROUNDS >= 5 && ROUNDS <= 15 )) || {
    printf 'FAIL compiler lane: rounds must be between 5 and 15\n' >&2
    exit 2
}
for tool in "$BEAR_BASM" "$GCC_BASM" "$ELFTOOL"; do
    [[ -x $tool ]] || { printf 'FAIL compiler lane: missing %s\n' "$tool" >&2; exit 1; }
done

# INV-572: Bear backend bloat ratchet. Bear spills per statement/branch, so a
# branchy fast path compiles ~10x larger than under GCC and thrashes L1I.
# Fail if the hot fast-path functions ever re-bloat in the Bear object.
BEAR_OBJ=${BEAR_OBJ:-$ROOT/build/bear/basm.o}
if [[ -f $BEAR_OBJ ]] && nm --help 2>&1 | grep -q 'size-sort'; then
    fast_reg_size=$(nm -S --size-sort "$BEAR_OBJ" | awk '$NF=="fast_reg_find"{print "0x"$2}' | head -1)
    try_fast_size=$(nm -S --size-sort "$BEAR_OBJ" | awk '$NF=="try_fast_instruction"{print "0x"$2}' | head -1)
    # Absent symbol = backend inlined it: ratchet vacuously satisfied.
    if [[ -n $fast_reg_size ]]; then
        (( fast_reg_size <= 0x600 )) || {
            printf 'FAIL compiler lane: fast_reg_find Bear object bloat (%s > 0x600)\n' "$fast_reg_size" >&2; exit 1; }
    fi
    if [[ -n $try_fast_size ]]; then
        (( try_fast_size <= 0x2400 )) || {
            printf 'FAIL compiler lane: try_fast_instruction Bear object bloat (%s > 0x2400)\n' "$try_fast_size" >&2; exit 1; }
    fi
    printf 'compiler lane: Bear fast-path object sizes fast_reg=%s try_fast=%s (INV-572)\n' \
        "${fast_reg_size:-inlined}" "${try_fast_size:-inlined}"
else
    printf 'compiler lane: object-size ratchet skipped (no GNU nm / no Bear object)\n'
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-compiler-lane.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

{
    printf 'bits 64\nsection .text\nglobal _start\n_start:\n'
    for ((i=1;i<=2000;i++)); do
        printf 'mov rax,rbx\nadd rax,%d\nmov rcx,rdx\nxor rcx,%d\n' "$i" "$i"
    done
    printf 'ret\n'
} >"$TMP/codegen.basm"

run_one(){ "$1" -f elf64 -o "$2" "$TMP/codegen.basm"; }
run_one "$BEAR_BASM" "$TMP/bear.o"
run_one "$GCC_BASM" "$TMP/gcc.o"
"$ELFTOOL" audit "$TMP/bear.o" >/dev/null
"$ELFTOOL" diff "$TMP/bear.o" "$TMP/gcc.o" >/dev/null
if [[ ${BASM_COMPILER_PROFILE:-0} == 1 ]]; then
    "$BEAR_BASM" --profile -f elf64 -o "$TMP/bear.o" "$TMP/codegen.basm" 2>&1
    "$GCC_BASM" --profile -f elf64 -o "$TMP/gcc.o" "$TMP/codegen.basm" 2>&1
fi
dd if=/dev/zero of="$TMP/rel8.seed" bs=32 count=1 status=none
"$BEAR_BASM" --rel8-escrow "$TMP/rel8" --rel8-key "$TMP/rel8.seed" \
    -f elf64 -o "$TMP/bear-rel8.o" "$TMP/codegen.basm" >/dev/null 2>&1
"$BEAR_BASM" --rel8-escrow "$TMP/rel8" --rel8-key "$TMP/rel8.seed" \
    -f elf64 -o "$TMP/bear-rel8.o" "$TMP/codegen.basm" >/dev/null 2>&1
"$ELFTOOL" diff "$TMP/bear-rel8.o" "$TMP/gcc.o" >/dev/null
: >"$TMP/bear.times"; : >"$TMP/gcc.times"; : >"$TMP/bear-rel8.times"

time_one(){
    perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e '
        open STDERR, ">", "/dev/null" or exit 127;
        $start=clock_gettime(CLOCK_MONOTONIC); system @ARGV; $status=$?;
        printf "%.9f\n",clock_gettime(CLOCK_MONOTONIC)-$start;
        exit(($status >> 8) || ($status & 127));
    ' "$@"
}
for ((round=1;round<=ROUNDS;round++)); do
    if (( round & 1 )); then
        time_one "$BEAR_BASM" -f elf64 -o "$TMP/bear.o" "$TMP/codegen.basm" >>"$TMP/bear.times"
        time_one "$GCC_BASM" -f elf64 -o "$TMP/gcc.o" "$TMP/codegen.basm" >>"$TMP/gcc.times"
        time_one "$BEAR_BASM" --rel8-escrow "$TMP/rel8" --rel8-key "$TMP/rel8.seed" -f elf64 -o "$TMP/bear-rel8.o" "$TMP/codegen.basm" >>"$TMP/bear-rel8.times"
    else
        time_one "$BEAR_BASM" --rel8-escrow "$TMP/rel8" --rel8-key "$TMP/rel8.seed" -f elf64 -o "$TMP/bear-rel8.o" "$TMP/codegen.basm" >>"$TMP/bear-rel8.times"
        time_one "$GCC_BASM" -f elf64 -o "$TMP/gcc.o" "$TMP/codegen.basm" >>"$TMP/gcc.times"
        time_one "$BEAR_BASM" -f elf64 -o "$TMP/bear.o" "$TMP/codegen.basm" >>"$TMP/bear.times"
    fi
done

perl -e '
    sub med { my @v=sort{$a<=>$b}@_; my $n=@v; return $n%2?$v[int($n/2)]:($v[$n/2-1]+$v[$n/2])/2 }
    sub vals { open my $f,"<",$_[0] or die $!; return map {0+$_} <$f> }
    $bear=med(vals($ARGV[0])); $gcc=med(vals($ARGV[1])); $rel8=med(vals($ARGV[2]));
    printf "Bear+blibc raw median: %.3f ms\nGCC+blibc raw median: %.3f ms\nBear/GCC raw ratio: %.3fx\nBear+Rel8 median: %.3f ms\nRel8 speed vs GCC: %.3fx\n",
        $bear*1000,$gcc*1000,$bear/$gcc,$rel8*1000,$gcc/$rel8;
    if($rel8>$gcc){ print STDERR "FAIL: optimized Bear path is slower than GCC with the same blibc (INV-553)\n"; exit 1 }
    print "PASS compiler lane: optimized Bear path beats uncached GCC on the same runtime\n";
' "$TMP/bear.times" "$TMP/gcc.times" "$TMP/bear-rel8.times"
