#!/usr/bin/env bash
# INV-544: generated workload classes must retain semantic parity with NASM
# before a stable paired timing result may enforce the performance boundary.
set -euo pipefail

LC_ALL=C
export LC_ALL

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
NASM=${NASM:-nasm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
ROUNDS=${BASM_PERF_MATRIX_ROUNDS:-15}

fail() {
    printf 'FAIL performance matrix: %s\n' "$1" >&2
    exit 1
}

require_tool() {
    local tool=$1
    local label=$2
    if [[ $tool == */* ]]; then
        [[ -x $tool ]] || fail "$label is not executable: $tool"
    else
        command -v -- "$tool" >/dev/null 2>&1 || fail "$label not found: $tool"
    fi
}

require_tool "$BASM" BASM
require_tool "$NASM" NASM
require_tool "$ELFTOOL" ELFTOOL
require_tool perl perl
require_tool cmp cmp
[[ $ROUNDS =~ ^[0-9]+$ ]] && (( ROUNDS >= 5 && ROUNDS <= 15 )) || \
    fail 'BASM_PERF_MATRIX_ROUNDS must be between 5 and 15'

TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-performance-matrix.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/includes"

cat >"$TMP/tiny.basm" <<'EOF'
bits 64
section .text
global _start
_start:
    mov rax, rbx
    add rax, 7
    xor rcx, rcx
    ret
EOF

{
    printf 'bits 64\nsection .text\nglobal _start\n_start:\n'
    for ((i = 1; i <= 320; i++)); do
        printf '    mov rax, rbx\n    add rax, %d\n' "$i"
        printf '    mov rcx, rdx\n    xor rcx, %d\n' "$i"
    done
    printf '    ret\n'
} >"$TMP/instruction-heavy.basm"

cat >"$TMP/macro-heavy.basm" <<'EOF'
bits 64
%macro MATRIX_MIX 2
    mov rax, %1
    add rax, %2
    xor rcx, rax
    sub rdx, %2
%endmacro
section .text
global _start
_start:
EOF
for ((i = 1; i <= 256; i++)); do
    printf '    MATRIX_MIX rbx, %d\n' "$i" >>"$TMP/macro-heavy.basm"
done
printf '    ret\n' >>"$TMP/macro-heavy.basm"

{
    printf 'bits 64\nsection .text\nglobal _start\n_start:\n'
    for ((part = 0; part < 12; part++)); do
        printf '%%include "matrix-%02d.inc"\n' "$part"
    done
    printf '    ret\n'
} >"$TMP/include-heavy.basm"
for ((part = 0; part < 12; part++)); do
    include_file=$(printf '%s/includes/matrix-%02d.inc' "$TMP" "$part")
    for ((i = 1; i <= 32; i++)); do
        value=$((part * 32 + i))
        printf '    add rax, %d\n    xor rbx, %d\n' "$value" "$value"
    done >"$include_file"
done

{
    printf 'bits 64\nextern matrix_external\nsection .text\nglobal _start\n_start:\n'
    for ((i = 0; i < 384; i++)); do
        printf '    call matrix_external\n'
    done
    printf '    ret\n'
} >"$TMP/relocation-heavy.basm"

{
    printf 'bits 64\nsection .text\nglobal _start\n_start:\n'
    for ((i = 0; i < 320; i++)); do
        printf '    cmp rax, %d\n    jne .take_%d\n    nop\n' "$i" "$i"
        printf '.take_%d:\n    test rbx, rbx\n    jz .done_%d\n    inc rbx\n.done_%d:\n' \
            "$i" "$i" "$i"
    done
    printf '    ret\n'
} >"$TMP/branch-heavy.basm"

{
    printf 'bits 64\n'
    for ((section = 0; section < 8; section++)); do
        printf 'section .matrix%d alloc noexec nowrite progbits align=16\n' "$section"
        printf 'global matrix_section_%d\nmatrix_section_%d:\n' "$section" "$section"
        for ((i = 0; i < 32; i++)); do
            printf '    dq 0x%08x\n' "$((section * 256 + i))"
        done
    done
    printf 'section .text\nglobal matrix_custom_entry\nmatrix_custom_entry:\n    ret\n'
} >"$TMP/custom-section.basm"

{
    printf 'bits 64\norg 0x1000\nsection .text\nflat_start:\n'
    for ((i = 0; i < 128; i++)); do
        printf '    add rax, %d\n    jne flat_next_%d\n    nop\nflat_next_%d:\n' \
            "$i" "$i" "$i"
    done
    printf '    ret\n'
} >"$TMP/flat-bin.basm"

perl -e '$b = join "", map { chr($_) } 0 .. 255; print $b for 1 .. 4096' \
    >"$TMP/payload.bin"
printf 'bits 64\nsection .rodata\nglobal matrix_payload\nmatrix_payload:\nincbin "%s"\n' \
    "$TMP/payload.bin" >"$TMP/incbin.basm"

assemble() {
    local tool=$1
    local format=$2
    local output=$3
    local source=$4
    local include_dir=$5
    local -a command=("$tool" -f "$format" -o "$output")
    [[ -z $include_dir ]] || command+=("-I${include_dir%/}/")
    command+=("$source")
    "${command[@]}"
}

time_assemble() {
    local tool=$1
    local format=$2
    local output=$3
    local source=$4
    local include_dir=$5
    local -a command=("$tool" -f "$format" -o "$output")
    [[ -z $include_dir ]] || command+=("-I${include_dir%/}/")
    command+=("$source")
    perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e '
        $start = clock_gettime(CLOCK_MONOTONIC);
        $pid = fork();
        exit 127 if !defined $pid;
        if ($pid == 0) {
            open STDOUT, ">", "/dev/null" or exit 127;
            open STDERR, ">", "/dev/null" or exit 127;
            exec @ARGV;
            exit 127;
        }
        waitpid $pid, 0;
        $status = $?;
        $elapsed = clock_gettime(CLOCK_MONOTONIC) - $start;
        printf "%.9f\n", $elapsed;
        exit 127 if $status == -1;
        exit(128 + ($status & 127)) if $status & 127;
        exit($status >> 8);
    ' "${command[@]}"
}

report_case() {
    perl -e '
        sub median {
            my @v = sort { $a <=> $b } @_;
            my $n = scalar @v;
            return $n % 2 ? $v[int($n / 2)]
                          : ($v[$n / 2 - 1] + $v[$n / 2]) / 2;
        }
        sub read_values {
            open my $fh, "<", $_[0] or die "$ARGV[0]: $!";
            return map { 0 + $_ } <$fh>;
        }
        sub relative_mad {
            my ($med, @v) = @_;
            return 1e9 if $med <= 0;
            return median(map { abs($_ - $med) } @v) / $med;
        }
        my ($label, $bpath, $npath, $rounds) = @ARGV;
        my @b = read_values($bpath);
        my @n = read_values($npath);
        die "wrong sample count for $label\n" if @b != $rounds || @n != $rounds;
        my $bm = median(@b);
        my $nm = median(@n);
        my @paired = map { $n[$_] / $b[$_] } 0 .. $#b;
        my $pm = median(@paired);
        my $stable = relative_mad($bm, @b) <= 0.25
                  && relative_mad($nm, @n) <= 0.25
                  && relative_mad($pm, @paired) <= 0.25;
        my $ratio = $pm; # INV-566: enforce the paired statistic we stabilized.
        my $status = !$stable ? "UNSTABLE" : $ratio >= 1.0 ? "PASS" : "FAIL";
        printf "%-20s %12.3f %12.3f %9.3fx  %-8s\n",
            $label, $bm * 1000, $nm * 1000, $ratio, $status;
        exit 2 if !$stable;
        exit 1 if $ratio < 1.0;
        exit 0;
    ' "$1" "$2" "$3" "$ROUNDS"
}

validated=0
stable=0
unstable=0
failures=0
case_number=0

printf 'BearBasm performance matrix (INV-544): %d paired rounds; speed = paired NASM/BearBasm median\n' "$ROUNDS"
printf '%-20s %12s %12s %10s  %-8s\n' CASE BASM-med-ms NASM-med-ms SPEED STATUS

run_case() {
    local label=$1
    local format=$2
    local source=$3
    local include_dir=${4:-}
    local basm_out="$TMP/$label.basm.out"
    local nasm_out="$TMP/$label.nasm.out"
    local basm_times="$TMP/$label.basm.times"
    local nasm_times="$TMP/$label.nasm.times"

    assemble "$BASM" "$format" "$basm_out" "$source" "$include_dir" || \
        fail "$label: BASM rejected its bounded fixture"
    assemble "$NASM" "$format" "$nasm_out" "$source" "$include_dir" || \
        fail "$label: NASM rejected the comparable fixture"
    [[ -s $basm_out && -s $nasm_out ]] || fail "$label: assembler produced an empty output"

    if [[ $format == elf64 ]]; then
        "$ELFTOOL" audit "$basm_out" >/dev/null || fail "$label: BASM ELF audit failed"
        "$ELFTOOL" audit "$nasm_out" >/dev/null || fail "$label: NASM ELF audit failed"
        "$ELFTOOL" diff "$basm_out" "$nasm_out" || fail "$label: semantic diff failed"
    else
        cmp -s "$basm_out" "$nasm_out" || fail "$label: flat binary differs from NASM"
    fi
    validated=$((validated + 1))

    assemble "$BASM" "$format" "$basm_out" "$source" "$include_dir"
    assemble "$NASM" "$format" "$nasm_out" "$source" "$include_dir"
    : >"$basm_times"
    : >"$nasm_times"
    case_number=$((case_number + 1))
    for ((round = 1; round <= ROUNDS; round++)); do
        if (( (round + case_number) & 1 )); then
            time_assemble "$BASM" "$format" "$basm_out" "$source" "$include_dir" \
                >>"$basm_times" || fail "$label: timed BASM invocation failed"
            time_assemble "$NASM" "$format" "$nasm_out" "$source" "$include_dir" \
                >>"$nasm_times" || fail "$label: timed NASM invocation failed"
        else
            time_assemble "$NASM" "$format" "$nasm_out" "$source" "$include_dir" \
                >>"$nasm_times" || fail "$label: timed NASM invocation failed"
            time_assemble "$BASM" "$format" "$basm_out" "$source" "$include_dir" \
                >>"$basm_times" || fail "$label: timed BASM invocation failed"
        fi
    done

    if report_case "$label" "$basm_times" "$nasm_times"; then
        stable=$((stable + 1))
    else
        local rc=$?
        case $rc in
            1) stable=$((stable + 1)); failures=$((failures + 1)) ;;
            2) unstable=$((unstable + 1)) ;;
            *) fail "$label: timing report failed (rc=$rc)" ;;
        esac
    fi
}

run_case tiny elf64 "$TMP/tiny.basm"
run_case instruction-heavy elf64 "$TMP/instruction-heavy.basm"
run_case macro-heavy elf64 "$TMP/macro-heavy.basm"
run_case include-heavy elf64 "$TMP/include-heavy.basm" "$TMP/includes"
run_case relocation-heavy elf64 "$TMP/relocation-heavy.basm"
run_case branch-heavy elf64 "$TMP/branch-heavy.basm"
run_case custom-section elf64 "$TMP/custom-section.basm"
run_case flat-bin bin "$TMP/flat-bin.basm"
run_case incbin elf64 "$TMP/incbin.basm"

printf 'SUMMARY cases=9 validated=%d stable=%d unstable=%d skipped=0 failures=%d\n' \
    "$validated" "$stable" "$unstable" "$failures"
(( validated == 9 )) || fail "matrix incomplete: validated $validated of 9 cases"
(( unstable == 0 )) || fail "$unstable case(s) remained timing-inconclusive"
(( failures == 0 )) || fail "$failures stable case(s) were slower than NASM"
printf 'PASS performance matrix: all cases validated, stable, and no slower than NASM\n'
