#!/usr/bin/env bash
# INV-543: BearBasm must not regress behind NASM on its bulk-incbin workload.
set -euo pipefail

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
ROUNDS=${BASM_PERF_ROUNDS:-16}

for tool in "$BASM" "$ELFTOOL"; do
    [ -x "$tool" ] || { printf 'FAIL: missing executable: %s\n' "$tool" >&2; exit 1; }
done
command -v "$NASM" >/dev/null 2>&1 || { printf 'FAIL: nasm not found\n' >&2; exit 1; }
command -v dd >/dev/null 2>&1 || { printf 'FAIL: dd not found\n' >&2; exit 1; }
command -v perl >/dev/null 2>&1 || { printf 'FAIL: perl not found\n' >&2; exit 1; }
[[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || { printf 'FAIL: BASM_PERF_ROUNDS must be positive\n' >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-performance.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

dd if=/dev/zero of="$TMP/payload.bin" bs=1048576 count=16 status=none
printf 'bits 64\nsection .rodata\nglobal payload_start\npayload_start:\nincbin "%s"\n' \
    "$TMP/payload.bin" >"$TMP/perf.basm"

run_basm() { "$BASM" -f elf64 -o "$TMP/basm.o" "$TMP/perf.basm"; }
run_nasm() { "$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/perf.basm"; }

for _ in 1 2 3 4; do run_basm; run_nasm; done
"$ELFTOOL" audit "$TMP/basm.o" >/dev/null
"$ELFTOOL" audit "$TMP/nasm.o" >/dev/null
"$ELFTOOL" diff "$TMP/basm.o" "$TMP/nasm.o" >/dev/null
: >"$TMP/basm.times"
: >"$TMP/nasm.times"

time_one() {
    perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e '
        $start = clock_gettime(CLOCK_MONOTONIC);
        system @ARGV;
        $status = $?;
        $elapsed = clock_gettime(CLOCK_MONOTONIC) - $start;
        printf "%.9f\n", $elapsed;
        exit 127 if $status == -1;
        exit(($status >> 8) || ($status & 127));
    ' "$@"
}

for ((round = 1; round <= ROUNDS; round++)); do
    if (( round & 1 )); then
        time_one "$BASM" -f elf64 -o "$TMP/basm.o" "$TMP/perf.basm" >>"$TMP/basm.times"
        time_one "$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/perf.basm" >>"$TMP/nasm.times"
    else
        time_one "$NASM" -f elf64 -o "$TMP/nasm.o" "$TMP/perf.basm" >>"$TMP/nasm.times"
        time_one "$BASM" -f elf64 -o "$TMP/basm.o" "$TMP/perf.basm" >>"$TMP/basm.times"
    fi
done

perl -e '
    sub median {
        my @v = sort { $a <=> $b } @_;
        my $n = scalar @v;
        return $n % 2 ? $v[int($n / 2)] : ($v[$n / 2 - 1] + $v[$n / 2]) / 2;
    }
    sub read_values {
        my ($path) = @_;
        open my $fh, "<", $path or die $!;
        return map { 0 + $_ } <$fh>;
    }
    sub relative_mad {
        my ($med, @v) = @_;
        return 1e9 if $med <= 0;
        return median(map { abs($_ - $med) } @v) / $med;
    }
    my @basm_values = read_values($ARGV[0]);
    my @nasm_values = read_values($ARGV[1]);
    die "wrong sample count\n" if @basm_values != '"$ROUNDS"' || @nasm_values != '"$ROUNDS"';
    my $basm = median(@basm_values);
    my $nasm = median(@nasm_values);
    # INV-566 pattern: paired per-round ratios decide, not the ratio of
    # medians (outlier asymmetry between lanes must not move the number).
    my @paired = map { $nasm_values[$_] / $basm_values[$_] } 0 .. $#basm_values;
    my $speed = median(@paired);
    my $stable = relative_mad($basm, @basm_values) <= 0.25
              && relative_mad($nasm, @nasm_values) <= 0.25
              && relative_mad($speed, @paired) <= 0.25;
    printf "BearBasm median: %.3f ms\nNASM median: %.3f ms\n", $basm * 1000, $nasm * 1000;
    printf "BearBasm speed vs NASM: %.3fx (paired median, %d rounds)\n", $speed, scalar @paired;
    printf "stability: BearBasm MAD=%.3f NASM MAD=%.3f paired MAD=%.3f %s\n",
        relative_mad($basm, @basm_values), relative_mad($nasm, @nasm_values),
        relative_mad($speed, @paired), ($stable ? "STABLE" : "UNSTABLE");
    if (!$stable) {
        printf STDERR "FAIL: performance run inconclusive (UNSTABLE evidence, INV-543)\n";
        exit 1;
    }
    if ($speed < 1.0) {
        printf STDERR "FAIL: BearBasm is slower than NASM (INV-543)\n";
        exit 1;
    }
    printf "PASS performance: BearBasm is not slower than NASM (INV-543)\n";
' "$TMP/basm.times" "$TMP/nasm.times"
