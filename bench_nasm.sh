#!/bin/bash
# Author: F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

# INV-393: compare quarantined, modular, and NASM on one validated source.
set -euo pipefail

LC_ALL=C
export LC_ALL

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULAR="$HERE/basm"
ELFTOOL="$HERE/elftool"
NASM="${NASM:-nasm}"
BLOCKS="${1:-500}"
ROUNDS="${2:-10}"
INSTRUCTIONS=$((BLOCKS * 4 + 1))

[[ "$BLOCKS" =~ ^[1-9][0-9]*$ ]] || { printf 'error: blocks must be positive\n' >&2; exit 2; }
[[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || { printf 'error: rounds must be positive\n' >&2; exit 2; }
(( BLOCKS <= 500 )) || {
    printf 'error: legacy comparison is limited to 500 blocks (INV-391)\n' >&2
    exit 2
}
[[ -x "$MODULAR" ]] || { printf 'error: build basm first\n' >&2; exit 1; }
[[ -x "$ELFTOOL" ]] || { printf 'error: build elftool first\n' >&2; exit 1; }
command -v "$NASM" >/dev/null 2>&1 || { printf 'error: nasm not found\n' >&2; exit 1; }
command -v perl >/dev/null 2>&1 || { printf 'error: perl not found\n' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-bench.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

CC_FLAGS=(-O2 -Wall -Wextra -Werror -I"$HERE" -I"$HERE/../..")
if [[ "$(uname -m)" == x86_64 ]]; then
    CC_FLAGS+=(-msha -msse4.1 -mssse3)
fi
if [[ "$(uname -s)" == Darwin ]]; then
    CC_FLAGS+=(-DBASM_NO_PROC_SELF_EXE)
fi
if [[ "$(uname -s)" == Linux ]]; then
    for flag in -Wno-misleading-indentation -Wno-stringop-truncation -Wno-format-truncation; do
        if cc "$flag" -Werror -x c -c /dev/null -o /dev/null >/dev/null 2>&1; then
            CC_FLAGS+=("$flag")
        fi
    done
fi

cc "${CC_FLAGS[@]}" -o "$TMP/basm-legacy" \
    "$HERE/quarantine/basm_monolith_legacy.c" \
    "$HERE/sign.c" "$HERE/../../crypto/ed25519.c"

perl -e '
    $n = $ARGV[0];
    print "section .text\nglobal _start\n_start:\n";
    for ($i = 1; $i <= $n; $i++) {
        print "    mov rax, rbx\n";
        print "    add rax, $i\n";
        print "    mov rcx, rdx\n";
        print "    xor rcx, $i\n";
    }
    print "    ret\n";
' "$BLOCKS" >"$TMP/bench.basm"

run_tool() {
    case "$1" in
        legacy)  "$TMP/basm-legacy" -f elf64 -o "$TMP/legacy.o" "$TMP/bench.basm" >/dev/null ;;
        modular) "$MODULAR" -f elf64 -o "$TMP/modular.o" "$TMP/bench.basm" >/dev/null ;;
        nasm)    "$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/bench.basm" >/dev/null ;;
    esac
}

for tool in legacy modular nasm; do
    run_tool "$tool"
    run_tool "$tool"
    run_tool "$tool"
    : >"$TMP/$tool.times"
done

for ((round = 1; round <= ROUNDS; round++)); do
    for tool in legacy modular nasm; do
        case "$tool" in
            legacy) command=("$TMP/basm-legacy" -f elf64 -o "$TMP/legacy.o" "$TMP/bench.basm") ;;
            modular) command=("$MODULAR" -f elf64 -o "$TMP/modular.o" "$TMP/bench.basm") ;;
            nasm) command=("$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/bench.basm") ;;
        esac
        perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e '
            $start = clock_gettime(CLOCK_MONOTONIC);
            system @ARGV;
            $status = $?;
            $elapsed = clock_gettime(CLOCK_MONOTONIC) - $start;
            printf "%.9f\n", $elapsed;
            exit 127 if $status == -1;
            exit(($status >> 8) || ($status & 127));
        ' "${command[@]}" >>"$TMP/$tool.times"
    done
done

cmp "$TMP/legacy.o" "$TMP/modular.o"
"$ELFTOOL" audit "$TMP/legacy.o" >/dev/null
"$ELFTOOL" audit "$TMP/modular.o" >/dev/null
"$ELFTOOL" audit "$TMP/nasm.o" >/dev/null
"$ELFTOOL" diff "$TMP/modular.o" "$TMP/nasm.o"

printf '=== BearBasm benchmark: %d instructions, %d rounds ===\n' "$INSTRUCTIONS" "$ROUNDS"
perl -e '
    $instructions = shift @ARGV;
    for $path (@ARGV) {
        open $fh, "<", $path or die $!;
        @values = sort { $a <=> $b } map { 0 + $_ } <$fh>;
        $count = @values;
        $sum = 0; $sum += $_ for @values;
        $mean = $sum / $count;
        $median = $count % 2
            ? $values[int($count / 2)]
            : ($values[$count / 2 - 1] + $values[$count / 2]) / 2;
        $variance = 0; $variance += ($_ - $mean) ** 2 for @values;
        $sd = sqrt($variance / $count);
        ($name = $path) =~ s!.*/!!; $name =~ s/\.times$//;
        printf "%-7s mean=%8.3fms median=%8.3fms sd=%7.3fms throughput=%9.0f instr/s\n",
            $name, $mean * 1000, $median * 1000, $sd * 1000,
            $instructions / $mean;
        $means{$name} = $mean;
    }
    printf "modular/legacy time ratio: %.3fx\n", $means{modular} / $means{legacy};
    printf "modular speed vs NASM: %.3fx\n", $means{nasm} / $means{modular};
' "$INSTRUCTIONS" "$TMP/legacy.times" "$TMP/modular.times" "$TMP/nasm.times"

printf 'objects: legacy=%s modular=%s nasm=%s bytes\n' \
    "$(wc -c <"$TMP/legacy.o" | tr -d ' ')" \
    "$(wc -c <"$TMP/modular.o" | tr -d ' ')" \
    "$(wc -c <"$TMP/nasm.o" | tr -d ' ')"
printf 'PASS benchmark outputs validated\n'
