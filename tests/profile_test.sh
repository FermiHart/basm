#!/bin/sh
# INV-546: opt-in phase telemetry must stay parseable and preserve output bytes.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-profile.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/profile.basm" <<'EOF'
bits 64
section .text
global _start
_start:
    mov eax, 60
    xor edi, edi
    syscall
EOF

"$BASM" -f elf64 -o "$TMP/plain.o" "$TMP/profile.basm"
"$BASM" --profile -f elf64 -o "$TMP/profiled.o" "$TMP/profile.basm" 2>"$TMP/profile.log"
cmp -s "$TMP/plain.o" "$TMP/profiled.o" || {
    printf 'FAIL profile: telemetry changed output bytes\n' >&2
    exit 1
}
line=$(cat "$TMP/profile.log")
case "$line" in
    BASM_PROFILE\ source_ns=[0-9]*\ preprocess_ns=[0-9]*\ layout_ns=[0-9]*\ emit_ns=[0-9]*\ write_ns=[0-9]*\ layout_passes=[0-9]*\ final_pass=[01]\ source_bytes=[0-9]*\ output_bytes=[0-9]*\ cache_hit=[01]\ total_ns=[0-9]*\ cache_ns=[0-9]*\ attestation_ns=[0-9]*\ explain_ns=[0-9]*\ cleanup_ns=[0-9]*\ expanded_bytes=[0-9]*\ scan_bytes=[0-9]*\ file_bytes=[0-9]*\ hash_tool_calls=[0-9]*\ hash_tool_reuses=[0-9]*\ hash_dependency_calls=[0-9]*\ hash_dependency_reuses=[0-9]*) ;;
    *) printf 'FAIL profile: malformed telemetry: %s\n' "$line" >&2; exit 1 ;;
esac

printf 'PASS phase profile (parseable + byte-identical)\n'
