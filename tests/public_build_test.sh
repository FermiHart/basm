#!/bin/sh
# INV-589: failed public compilation cannot bless a stale object.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
BASM_SOV_DIR=${BASM_SOV_DIR:-$ROOT/build/bear}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-public-build.XXXXXX")
trap 'if [ "${KEEP_TMP:-0}" = 1 ]; then printf "public build evidence: %s\n" "$TMP"; else rm -rf "$TMP"; fi' EXIT
mkdir "$TMP/build"
printf 'stale public object\n' >"$TMP/build/basm-public.o"
touch -t 200001010000 "$TMP/build/basm-public.o"
cat >"$TMP/fail-bear" <<'EOF'
#!/bin/sh
printf 'deliberate public compile failure\n' >&2
exit 1
EOF
chmod +x "$TMP/fail-bear"
if make -C "$ROOT" SOV_DIR="$TMP/build" BEAR="$TMP/fail-bear" \
    "$TMP/build/basm-public.o" >"$TMP/make.log" 2>&1; then
    printf 'FAIL public build: compiler failure accepted stale object\n' >&2
    exit 1
fi
grep -q 'deliberate public compile failure' "$TMP/make.log"
# INV-597: a newer same-stem C file must not trigger an implicit tool rebuild.
printf '#error prebuilt tool must never compile here\n' >"$TMP/fail-bear.c"
touch -t 200001010000 "$TMP/fail-bear"
cp "$TMP/fail-bear" "$TMP/tool-before"
make -C "$ROOT" BEAR="$TMP/fail-bear" "$TMP/fail-bear" >"$TMP/tool-rule.log" 2>&1
cmp "$TMP/fail-bear" "$TMP/tool-before"
cp "$TMP/fail-bear" "$TMP/basm"
if ! PATH="$TMP:$PATH" make -C "$ROOT" -o "$BASM" BIN="$BASM" SOV_DIR="$BASM_SOV_DIR" test-bear-provenance >"$TMP/provenance.log" 2>&1; then
    printf 'FAIL provenance: current artifact was not verified independently of PATH\n' >&2
    exit 1
fi
printf 'PASS public build rejects stale object after compiler failure\n'
