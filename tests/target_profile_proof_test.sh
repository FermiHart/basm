#!/bin/sh
# INV-589: profile/policy evidence is hash binding, not proof of semantics.
# Uses existing binaries only; the caller builds the integrated product first.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
ELFTOOL=${ELFTOOL:-$ROOT/elftool}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-profile-proof.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL target-profile proof: %s\n' "$*" >&2; exit 1; }
accept() {
    "$BASM" --verify-attestation "$1" || fail "basm rejected $1"
    "$ELFTOOL" attest --tool "$BASM" "$1" >/dev/null || fail "elftool rejected $1"
}
reject() {
    rc=0
    "$BASM" --verify-attestation "$1" >"$TMP/reject.log" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || fail "basm did not refuse $1 (rc=$rc)"
    rc=0
    "$ELFTOOL" attest --tool "$BASM" "$1" >"$TMP/reject.log" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || fail "elftool did not refuse $1 (rc=$rc)"
}
refuse_metadata() {
    rm -f "$TMP/refused.proof"
    rc=0
    "$@" >"$TMP/refused.log" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || fail "invalid metadata returned rc=$rc"
    [ ! -e "$TMP/refused.proof" ] || fail "invalid metadata left a proof"
}

unset BASM_DDC_COMPILER_HASH BASM_DDC_COMPILER_PATH
export SOURCE_DATE_EPOCH=0
"$BASM" --capabilities >"$TMP/capabilities" || fail "--capabilities unavailable"
printf '%s\n' 'bits 64' 'section .text' 'global entry' 'entry:' '    ret' >"$TMP/in.basm"
# Public test key only, never a production signing key.
printf '%s\n' '0000000000000000000000000000000000000000000000000000000000000000' >"$TMP/key"

# INV-591: trailer-like text inside a value is data, in both signing directions.
metadata_bad=0
ddc_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
for name in plain signature_name 'signature:literal' 'signature_alg:literal'; do
    cp "$TMP/in.basm" "$TMP/$name.basm"
    for mode in unsigned signed; do
        set --
        if [ "$mode" = signed ]; then set -- --sign "$TMP/key"; fi
        if ! (
            BASM_DDC_COMPILER_HASH="$ddc_hash" BASM_DDC_COMPILER_PATH="$TMP/compiler-$name" \
                "$BASM" --target-profile public -f elf64 -o "$TMP/$name-$mode.o" \
                --emit-attestation "$TMP/$name-$mode.proof" "$@" "$TMP/$name.basm" || fail "metadata emission failed"
            grep -Fqx "ddc_compiler_sha256: $ddc_hash" "$TMP/$name-$mode.proof" || fail "DDC hash lost"
            grep -Fqx "ddc_compiler_path: $TMP/compiler-$name" "$TMP/$name-$mode.proof" || fail "DDC path lost"
            accept "$TMP/$name-$mode.proof"
            if [ "$mode" = signed ]; then
                "$BASM" --verify-attestation-strict "$TMP/$name-$mode.proof" || fail "signed path round-trip"
                "$ELFTOOL" attest --strict --tool "$BASM" "$TMP/$name-$mode.proof" >/dev/null || fail "signed path strict verification"
            fi
        ); then
            printf 'FAIL metadata round-trip: %s %s\n' "$name" "$mode" >&2
            metadata_bad=1
        fi
    done
done

# INV-589: the producer must refuse unrepresentable metadata, not emit evidence
# that its own verifier rejects. A newline injecting a valid optional field is
# also refused, even though the resulting field set could pass a schema check.
newline=$(printf '\nX')
tab=$(printf '\tX')
long_value=$(printf '%01024d' 0)
for value in '' invalid "${ddc_hash}0" "${ddc_hash}${newline}"; do
    if ! (BASM_DDC_COMPILER_HASH="$value" refuse_metadata "$BASM" --target-profile public \
        -f elf64 -o "$TMP/refused.o" --emit-attestation "$TMP/refused.proof" "$TMP/in.basm"); then
        printf 'FAIL invalid DDC hash was not refused cleanly\n' >&2
        metadata_bad=1
    fi
done
injected_path=$(printf 'compiler\nddc_compiler_sha256: %s' "$ddc_hash")
for value in '' "$long_value" "compiler${newline}" "compiler${tab}" "$injected_path"; do
    if ! (BASM_DDC_COMPILER_PATH="$value" refuse_metadata "$BASM" --target-profile public \
        -f elf64 -o "$TMP/refused.o" --emit-attestation "$TMP/refused.proof" --sign "$TMP/key" "$TMP/in.basm"); then
        printf 'FAIL invalid DDC path was not refused cleanly\n' >&2
        metadata_bad=1
    fi
done
for suffix in "$newline" "$tab"; do
    cp "$TMP/in.basm" "$TMP/input-$suffix.basm"
    if ! (refuse_metadata "$BASM" --target-profile public -f elf64 -o "$TMP/refused.o" \
        --emit-attestation "$TMP/refused.proof" "$TMP/input-$suffix.basm"); then
        printf 'FAIL invalid source path was not refused cleanly\n' >&2
        metadata_bad=1
    fi
    if ! (refuse_metadata "$BASM" --target-profile public -f elf64 -o "$TMP/output-$suffix.o" \
        --emit-attestation "$TMP/refused.proof" "$TMP/in.basm"); then
        printf 'FAIL invalid output path was not refused cleanly\n' >&2
        metadata_bad=1
    fi
done
[ "$metadata_bad" -eq 0 ] || fail "metadata regression checks"

"$BASM" -f elf64 -o "$TMP/compat.o" --emit-attestation "$TMP/v2" "$TMP/in.basm"
grep -qx 'basm attestation v2' "$TMP/v2" || fail "compatibility changed wire version"
! grep -Eq '^(policy|target_profile|bootstrap):' "$TMP/v2" || fail "v3 fields leaked into v2"
accept "$TMP/v2"

for profile in public beyond; do
    "$BASM" --target-profile "$profile" -f elf64 -o "$TMP/$profile.o" \
        --emit-attestation "$TMP/$profile" "$TMP/in.basm"
    grep -qx 'basm attestation v3' "$TMP/$profile" || fail "$profile did not emit v3"
    grep -qx "target_profile: $profile" "$TMP/$profile" || fail "wrong profile"
    grep -qx 'policy: basm-profile-v1' "$TMP/$profile" || fail "wrong policy"
    grep -qx 'bootstrap: none' "$TMP/$profile" || fail "unexpected bootstrap"
    accept "$TMP/$profile"
done

# Production embeds the pinned mixed-mode AP trampoline in an ELF object.
AP="$ROOT/../../ring0/arch/amd64/ap_trampoline.basm"
"$BASM" --target-profile beyond --bootstrap ap-trampoline-v1 -f elf64 \
    -o "$TMP/ap.o" --emit-attestation "$TMP/ap.proof" "$AP"
grep -qx 'basm attestation v3' "$TMP/ap.proof" || fail "AP did not emit v3"
grep -qx 'output_format: elf64' "$TMP/ap.proof" || fail "AP proof is not ELF"
grep -qx 'target_profile: beyond' "$TMP/ap.proof" || fail "wrong AP profile"
grep -qx 'bootstrap: ap-trampoline-v1' "$TMP/ap.proof" || fail "missing AP bootstrap identity"
grep -qx 'source_sha256: f0f6ba9d486c1ee1620ccbd6bfaff9f95584a90cb60a3df35fc98aed473cf02e' \
    "$TMP/ap.proof" || fail "AP raw source pin changed"
accept "$TMP/ap.proof"

for profile in compatibility public; do
    set --
    if [ "$profile" != compatibility ]; then set -- --target-profile "$profile"; fi
    "$BASM" "$@" -f elf64 -o "$TMP/signed.o" \
        --emit-attestation "$TMP/signed" --sign "$TMP/key" "$TMP/in.basm"
    accept "$TMP/signed"
    "$BASM" --verify-attestation-strict "$TMP/signed" || fail "basm $profile signed strict round-trip"
    "$ELFTOOL" attest --strict --tool "$BASM" "$TMP/signed" >/dev/null || fail "elftool $profile signed strict round-trip"
done
if "$BASM" --verify-attestation-strict "$TMP/public" >/dev/null 2>&1; then
    fail "basm strict accepted unsigned v3"
fi
if "$ELFTOOL" attest --strict "$TMP/public" >/dev/null 2>&1; then
    fail "elftool strict accepted unsigned v3"
fi

for proof in public signed; do
    sed 's/^target_profile: public$/target_profile: beyond/' "$TMP/$proof" >"$TMP/tamper"
    reject "$TMP/tamper"
    sed 's/^policy: basm-profile-v1$/policy: basm-profile-v2/' "$TMP/$proof" >"$TMP/tamper"
    reject "$TMP/tamper"
    sed 's/^bootstrap: none$/bootstrap: ap-trampoline-v1/' "$TMP/$proof" >"$TMP/tamper"
    reject "$TMP/tamper"
    sed 's/^output_format: elf64$/output_format: bin/' "$TMP/$proof" >"$TMP/tamper"
    reject "$TMP/tamper"
    sed '1s/v3/v2/' "$TMP/$proof" >"$TMP/downgrade"
    reject "$TMP/downgrade"
done

# A valid v2 root plus v3 fields must also fail, not merely a mismatched root.
for field in 'policy: basm-profile-v1' 'target_profile: public' 'bootstrap: none'; do
    { cat "$TMP/v2"; printf '%s\n' "$field"; } >"$TMP/downgrade"
    reject "$TMP/downgrade"
done

for field in tool tool_sha256 source_path source_sha256 output_path output_sha256 \
             output_format merkle_node_id build_epoch policy target_profile bootstrap signature; do
    sed "/^$field:/d" "$TMP/public" >"$TMP/missing"
    reject "$TMP/missing"
    sed "/^$field:/p" "$TMP/public" >"$TMP/duplicate"
    reject "$TMP/duplicate"
done
for field in signature_alg signature_pub signature signature_pqc_alg signature_pqc_pub signature_pqc; do
    sed "/^$field:/p" "$TMP/signed" >"$TMP/duplicate"
    reject "$TMP/duplicate"
done
for field in signature_alg signature_pub; do
    sed "/^$field:/d" "$TMP/signed" >"$TMP/missing"
    reject "$TMP/missing"
done
for value in '' ' basm-profile-v1' 'basm-profile-v1 ' 'basm-profile-v1-extra'; do
    sed "s/^policy:.*/policy: $value/" "$TMP/public" >"$TMP/malformed"
    reject "$TMP/malformed"
done
for value in compatibility unknown ' public' 'public '; do
    sed "s/^target_profile:.*/target_profile: $value/" "$TMP/public" >"$TMP/malformed"
    reject "$TMP/malformed"
done
for value in unknown 'none ' 'ap-trampoline-v1-extra'; do
    sed "s/^bootstrap:.*/bootstrap: $value/" "$TMP/public" >"$TMP/malformed"
    reject "$TMP/malformed"
done
sed 's/^policy: /policy:/' "$TMP/public" >"$TMP/malformed"
reject "$TMP/malformed"
sed 's/^policy:/policy_extra:/' "$TMP/public" >"$TMP/malformed"
reject "$TMP/malformed"
sed 's/^source_sha256:.*/&0/' "$TMP/public" >"$TMP/malformed"
reject "$TMP/malformed"
{ cat "$TMP/public"; printf '\000policy: basm-profile-v1\n'; } >"$TMP/malformed"
reject "$TMP/malformed"
# Policy after the signing boundary is not signed evidence, even with a valid signature.
{ sed '/^policy:/d' "$TMP/signed"; printf 'policy: basm-profile-v1\n'; } >"$TMP/malformed"
reject "$TMP/malformed"

# Warm compatibility escrow cannot answer a public request for the same input.
for profile in compatibility public beyond public; do
    set --
    if [ "$profile" != compatibility ]; then set -- --target-profile "$profile"; fi
    "$BASM" "$@" --rel8-escrow "$TMP/cache" --rel8-key "$TMP/key" \
        -f elf64 -o "$TMP/cached.o" --emit-attestation "$TMP/cached" "$TMP/in.basm" \
        2>"$TMP/cache-$profile.log"
    accept "$TMP/cached"
    if [ "$profile" = public ] && [ -e "$TMP/public-seen" ]; then
        grep -q 'rel8 escrow hit' "$TMP/cache-public.log" || fail "public warm cache missed"
    else
        ! grep -q 'rel8 escrow hit' "$TMP/cache-$profile.log" || fail "$profile reused another profile's cache"
    fi
    if [ "$profile" = public ]; then : >"$TMP/public-seen"; fi
done
printf '%s\n' 'bits 16' 'nop' >"$TMP/legacy.basm"
"$BASM" --rel8-escrow "$TMP/legacy-cache" --rel8-key "$TMP/key" \
    -f bin -o "$TMP/legacy.bin" "$TMP/legacy.basm"
if "$BASM" --target-profile public --rel8-escrow "$TMP/legacy-cache" --rel8-key "$TMP/key" \
    -f bin -o "$TMP/rejected.bin" "$TMP/legacy.basm" >"$TMP/legacy.log" 2>&1; then
    fail "compatibility cache bypassed public validation"
fi
[ ! -e "$TMP/rejected.bin" ] || fail "public rejection published output"

printf 'PASS target-profile evidence (v2/v3, signatures, strict fields, tampering, cache separation)\n'
