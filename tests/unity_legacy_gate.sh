#!/bin/sh
# Prove immutable legacy provenance, registered modular source, equivalent
# legacy-corpus behavior, and byte-identical output from every modular build.
set -eu

LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
EXPECTED_LEGACY_HASH=06107c5f98be182b415f90104d71536b902a3c370246964e0b498c5b0b9865bf
EXPECTED_MODULAR_HASH=c2df97f6a4a183434acc4d09f58d91382af7d64a25a0b0b3d64488e999362d22

failures=0
corpus=0
format_runs=0
cli_runs=0

summary() {
    printf 'unity legacy gate: corpus=%d format-runs=%d cli-negative=%d failures=%d\n' \
        "$corpus" "$format_runs" "$cli_runs" "$failures"
}

fatal() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
    summary >&2
    exit 1
}

record_failure() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

same_file() {
    if ! cmp -s "$2" "$3"; then
        record_failure "$1"
    fi
}

for tool in bash cc cat cmp cp make mkdir mktemp uname; do
    command -v "$tool" >/dev/null 2>&1 || fatal "required tool not found: $tool"
done

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        fatal "neither sha256sum nor shasum is available"
    fi
}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/bearbasm-unity.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
trap 'exit 2' HUP INT TERM

LEGACY_STAGE=$TMP/legacy
MODULAR_STAGE=$TMP/modular
ELFTOOL_STAGE=$TMP/elftool
RESULTS=$TMP/results
mkdir -p "$LEGACY_STAGE" "$MODULAR_STAGE" "$ELFTOOL_STAGE" "$RESULTS" || \
    fatal "cannot create temporary staging directories"

LEGACY_SOURCE=$ROOT/quarantine/basm_monolith_legacy.c
MODULE_01=$ROOT/modules/01_foundation.inc
MODULE_02=$ROOT/modules/02_encoding.inc
MODULE_03=$ROOT/modules/03_parser.inc
MODULE_04=$ROOT/modules/04_writer.inc
MODULE_05=$ROOT/modules/05_preprocessor.inc
MODULE_06=$ROOT/modules/06_attestation.inc
MODULE_07=$ROOT/modules/07_main.inc

legacy_hash=$(hash_file "$LEGACY_SOURCE") || fatal "cannot hash quarantined monolith"
legacy_hash=${legacy_hash%% *}
[ "$legacy_hash" = "$EXPECTED_LEGACY_HASH" ] || \
    fatal "legacy hash mismatch: expected $EXPECTED_LEGACY_HASH, got $legacy_hash"

if ! cat \
    "$MODULE_01" \
    "$MODULE_02" \
    "$MODULE_03" \
    "$MODULE_04" \
    "$MODULE_05" \
    "$MODULE_06" \
    "$MODULE_07" >"$MODULAR_STAGE/basm.c"; then
    fatal "cannot concatenate the seven unity modules"
fi
cp "$LEGACY_SOURCE" "$LEGACY_STAGE/basm.c" || fatal "cannot stage legacy basm.c"

cat "$MODULAR_STAGE/basm.c" "$ROOT/isa/intent_forms.h" "$ROOT/intent/trace.inc" \
    "$ROOT/intent/cfg.inc" >"$TMP/modular-closure" || fatal "cannot stage modular closure"
modular_hash=$(hash_file "$TMP/modular-closure") || fatal "cannot hash modular unity source closure"
modular_hash=${modular_hash%% *}
[ "$modular_hash" = "$EXPECTED_MODULAR_HASH" ] || \
    fatal "modular hash mismatch: expected $EXPECTED_MODULAR_HASH, got $modular_hash"

stage_support() {
    for support_stage in "$LEGACY_STAGE" "$MODULAR_STAGE" "$ELFTOOL_STAGE"; do
        mkdir -p "$support_stage/crypto" || return 1
        cp "$ROOT/sign.c" "$ROOT/sign.h" "$ROOT/sha256_ni.h" \
            "$support_stage/" || return 1
        cp "$ROOT/../../crypto/ed25519.c" "$ROOT/../../crypto/ed25519.h" \
            "$support_stage/crypto/" || return 1
    done
    cp "$ROOT/elftool.c" "$ELFTOOL_STAGE/elftool.c" || return 1
    mkdir -p "$MODULAR_STAGE/isa" "$MODULAR_STAGE/intent" || return 1
    cp "$ROOT/isa/intent_forms.h" "$MODULAR_STAGE/isa/" || return 1
    cp "$ROOT/intent/trace.inc" "$MODULAR_STAGE/intent/" || return 1
    cp "$ROOT/intent/cfg.inc" "$MODULAR_STAGE/intent/" || return 1
}
stage_support || fatal "cannot stage identical build dependencies"

BUILD_FLAGS='-O2 -Wall -Wextra -Werror -I.'
if [ "$(uname -m)" = x86_64 ]; then
    BUILD_FLAGS="$BUILD_FLAGS -msha -msse4.1 -mssse3"
fi
if [ "$(uname -s)" = Darwin ]; then
    BUILD_FLAGS="$BUILD_FLAGS -DBASM_NO_PROC_SELF_EXE"
fi
if [ "$(uname -s)" = Linux ]; then
    for warning_flag in \
        -Wno-misleading-indentation \
        -Wno-stringop-truncation \
        -Wno-format-truncation; do
        if cc "$warning_flag" -Werror -x c -c /dev/null -o /dev/null >/dev/null 2>&1; then
            BUILD_FLAGS="$BUILD_FLAGS $warning_flag"
        fi
    done
fi

build_basm() {
    (CDPATH= cd "$1" && cc $BUILD_FLAGS -o basm basm.c sign.c crypto/ed25519.c)
}

build_elftool() {
    (CDPATH= cd "$1" && cc $BUILD_FLAGS -o elftool elftool.c sign.c crypto/ed25519.c)
}

build_basm "$LEGACY_STAGE" || fatal "legacy host-cc build failed"
build_basm "$MODULAR_STAGE" || fatal "modular host-cc build failed"
# INV-390: the standalone build is a supported door and must stay buildable.
BASM_OUT="$TMP/build-script-basm" bash "$ROOT/build.sh" >"$TMP/build-script.out" || \
    fatal "standalone build.sh failed"
file "$TMP/build-script-basm" | grep -q 'statically linked' || \
    fatal "standalone build.sh did not produce a static Bear build"
make -C "$ROOT" BIN="$TMP/make-basm" "$TMP/make-basm" >"$TMP/make-build.out" || \
    fatal "Makefile basm build failed"
cmp -s "$TMP/build-script-basm" "$TMP/make-basm" || \
    fatal "sovereign build doors produced different binaries"
build_elftool "$ELFTOOL_STAGE" || fatal "temporary elftool build failed"

LEGACY_BASM=$LEGACY_STAGE/basm
MODULAR_BASM=$MODULAR_STAGE/basm
ELFTOOL=$ELFTOOL_STAGE/elftool

audit_elf_pair() {
    audit_label=$1
    audit_legacy=$2
    audit_modular=$3
    audit_dir=$4

    legacy_audit_rc=0
    "$ELFTOOL" audit "$audit_legacy" >"$audit_dir/legacy.audit.out" \
        2>"$audit_dir/legacy.audit.err" || legacy_audit_rc=$?
    modular_audit_rc=0
    "$ELFTOOL" audit "$audit_modular" >"$audit_dir/modular.audit.out" \
        2>"$audit_dir/modular.audit.err" || modular_audit_rc=$?

    [ "$legacy_audit_rc" -eq 0 ] || \
        record_failure "$audit_label: elftool audit rejected legacy ELF (rc=$legacy_audit_rc)"
    [ "$modular_audit_rc" -eq 0 ] || \
        record_failure "$audit_label: elftool audit rejected modular ELF (rc=$modular_audit_rc)"
    same_file "$audit_label: elftool audit stdout differs" \
        "$audit_dir/legacy.audit.out" "$audit_dir/modular.audit.out"
    same_file "$audit_label: elftool audit stderr differs" \
        "$audit_dir/legacy.audit.err" "$audit_dir/modular.audit.err"

    elf_diff_rc=0
    "$ELFTOOL" diff "$audit_legacy" "$audit_modular" >"$audit_dir/elftool.diff.out" \
        2>"$audit_dir/elftool.diff.err" || elf_diff_rc=$?
    [ "$elf_diff_rc" -eq 0 ] || \
        record_failure "$audit_label: elftool diff reported a semantic divergence (rc=$elf_diff_rc)"
    [ ! -s "$audit_dir/elftool.diff.out" ] || \
        record_failure "$audit_label: elftool diff produced output for equivalent ELFs"
    [ ! -s "$audit_dir/elftool.diff.err" ] || \
        record_failure "$audit_label: elftool diff produced stderr for equivalent ELFs"
}

run_format_case() {
    case_fmt=$1
    case_src=$2
    case_dir=$3
    case_label=$case_src' ['$case_fmt']'
    mkdir -p "$case_dir" || fatal "cannot create result directory for $case_label"

    legacy_rc=0
    "$LEGACY_BASM" -f "$case_fmt" -o "$case_dir/legacy.out" "$case_src" \
        >"$case_dir/legacy.stdout" 2>"$case_dir/legacy.stderr" || legacy_rc=$?
    modular_rc=0
    "$MODULAR_BASM" -f "$case_fmt" -o "$case_dir/modular.out" "$case_src" \
        >"$case_dir/modular.stdout" 2>"$case_dir/modular.stderr" || modular_rc=$?

    [ "$legacy_rc" -eq "$modular_rc" ] || \
        record_failure "$case_label: exit status differs (legacy=$legacy_rc modular=$modular_rc)"
    same_file "$case_label: stdout differs" "$case_dir/legacy.stdout" "$case_dir/modular.stdout"
    same_file "$case_label: stderr differs" "$case_dir/legacy.stderr" "$case_dir/modular.stderr"

    if [ "$legacy_rc" -eq 0 ] && [ "$modular_rc" -eq 0 ]; then
        if [ ! -f "$case_dir/legacy.out" ] || [ ! -f "$case_dir/modular.out" ]; then
            record_failure "$case_label: successful assembly did not create both outputs"
        else
            same_file "$case_label: successful output bytes differ" \
                "$case_dir/legacy.out" "$case_dir/modular.out"
            if [ "$case_fmt" = elf64 ]; then
                audit_elf_pair "$case_label" "$case_dir/legacy.out" \
                    "$case_dir/modular.out" "$case_dir"
            fi
        fi
    fi
    format_runs=$((format_runs + 1))
}

for src in "$ROOT"/tests/*.basm "$ROOT"/tests/regression/*.basm; do
    [ -f "$src" ] || continue
    corpus=$((corpus + 1))
    run_format_case elf64 "$src" "$RESULTS/$corpus-elf64"
    run_format_case bin "$src" "$RESULTS/$corpus-bin"
done
[ "$corpus" -gt 0 ] || fatal "zero .basm files found in the required corpus"

run_negative_case() {
    negative_label=$1
    shift
    cli_runs=$((cli_runs + 1))
    negative_dir=$RESULTS/cli-$cli_runs
    mkdir -p "$negative_dir" || fatal "cannot create CLI result directory"

    legacy_cli_rc=0
    "$LEGACY_BASM" "$@" >"$negative_dir/legacy.stdout" \
        2>"$negative_dir/legacy.stderr" || legacy_cli_rc=$?
    modular_cli_rc=0
    "$MODULAR_BASM" "$@" >"$negative_dir/modular.stdout" \
        2>"$negative_dir/modular.stderr" || modular_cli_rc=$?

    [ "$legacy_cli_rc" -ne 0 ] || record_failure "$negative_label: legacy accepted invalid CLI"
    [ "$modular_cli_rc" -ne 0 ] || record_failure "$negative_label: modular accepted invalid CLI"
    [ "$legacy_cli_rc" -eq "$modular_cli_rc" ] || \
        record_failure "$negative_label: CLI exit status differs (legacy=$legacy_cli_rc modular=$modular_cli_rc)"
    same_file "$negative_label: CLI stdout differs" \
        "$negative_dir/legacy.stdout" "$negative_dir/modular.stdout"
    same_file "$negative_label: CLI stderr differs" \
        "$negative_dir/legacy.stderr" "$negative_dir/modular.stderr"
}

run_negative_case 'CLI/no arguments'
run_negative_case 'CLI/missing -f argument' -f
run_negative_case 'CLI/missing -o argument' -o
run_negative_case 'CLI/unsupported format' -f coff "$ROOT/tests/variadic.basm"
run_negative_case 'CLI/nonexistent input' "$TMP/does-not-exist.basm"
run_negative_case 'CLI/missing attestation argument' --verify-attestation

summary
if [ "$failures" -ne 0 ]; then
    exit 1
fi
printf 'PASS: modules=7 legacy-hash=%s modular-hash=%s legacy-corpus-compatible\n' \
    "$legacy_hash" "$modular_hash"
