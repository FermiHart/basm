#!/bin/sh
# elftool_attest_test.sh — gate for sovereign attestation-chain verification.
# Invariants (ADR-000 §13 — attestation em três camadas):
#   1. valid unsigned proof              -> PASS (with NOTE), exit 0
#   2. --strict rejects unsigned proofs  -> exit 1
#   3. signed proof + --strict + --tool  -> PASS, SIGNER + ANCHOR lines
#   4. tampered output file              -> FAIL, exit 1
#   5. swapped source_path               -> FAIL signature before following paths
#   6. source bytes changed, proof intact -> FAIL source hash, signature still valid
#   7. broken chain custody              -> FAIL (tool != previous output)
# Runs natively on macOS and Linux (POSIX sh, no external deps).
set -eu
cd "$(dirname "$0")/.."

BASM=${BASM:-./basm}
ELFTOOL=${ELFTOOL:-./elftool}

TMP="${TMPDIR:-/tmp}/elftool_attest_$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

SRC=tests/test_istruc.basm

# 1. valid unsigned proof: PASS
"$BASM" -f elf64 --emit-attestation "$TMP/u.proof" -o "$TMP/u.o" "$SRC" >/dev/null
"$ELFTOOL" attest "$TMP/u.proof" >/dev/null || fail "valid unsigned proof rejected"

# 2. --strict rejects unsigned
rc=0; "$ELFTOOL" attest --strict "$TMP/u.proof" >/dev/null || rc=$?
[ "$rc" -eq 1 ] || fail "--strict accepted unsigned proof (rc=$rc)"

# 3. signed proof, strict, anchored to the basm binary
head -c 32 /dev/urandom > "$TMP/key.seed" 2>/dev/null || \
    dd if=/dev/urandom of="$TMP/key.seed" bs=32 count=1 2>/dev/null
"$BASM" -f elf64 --emit-attestation "$TMP/s.proof" --sign "$TMP/key.seed" \
    -o "$TMP/s.o" "$SRC" >/dev/null
out=$("$ELFTOOL" attest --strict --tool "$BASM" "$TMP/s.proof") || \
    fail "signed strict verification failed"
echo "$out" | grep -q "ATTEST SIGNER" || fail "missing SIGNER line"
echo "$out" | grep -q "ATTEST ANCHOR" || fail "missing ANCHOR line"

# 4. tampered output: detected
printf '\000' >> "$TMP/s.o"
rc=0; "$ELFTOOL" attest "$TMP/s.proof" >/dev/null || rc=$?
[ "$rc" -eq 1 ] || fail "tampered output not detected (rc=$rc)"

# 5. Swapped source_path: reject the signature before following claimed paths.
sed 's/at POINT.x,  dq 42/at POINT.x,  dq 43/' "$SRC" > "$TMP/evil.basm"
"$BASM" -f elf64 --emit-attestation "$TMP/e.proof" --sign "$TMP/key.seed" \
    -o "$TMP/e.o" "$TMP/evil.basm" >/dev/null
sed "s|^source_path:.*|source_path: $SRC|" "$TMP/e.proof" > "$TMP/e2.proof"
out=$("$ELFTOOL" attest "$TMP/e2.proof") && fail "swapped source accepted"
echo "$out" | grep -q "signature invalid"    || fail "no signature FAIL"
if echo "$out" | grep -q "source hash mismatch"; then
    fail "followed source path before rejecting the invalid signature"
fi

# 6. Intact signed proof, changed source bytes: independent hash check must fail.
printf '\n; source changed after attestation\n' >> "$TMP/evil.basm"
out=$("$ELFTOOL" attest "$TMP/e.proof") && fail "changed source accepted"
echo "$out" | grep -q "source hash mismatch" || fail "no source-hash FAIL"
if echo "$out" | grep -q "signature invalid"; then
    fail "unchanged proof lost its valid signature"
fi

# 7. chain custody: same proof twice -> tool != previous output
rc=0; "$ELFTOOL" attest "$TMP/u.proof" "$TMP/u.proof" >/dev/null || rc=$?
[ "$rc" -eq 1 ] || fail "broken chain not detected (rc=$rc)"

echo "PASS elftool attest — cadeia de attestation verificada"
