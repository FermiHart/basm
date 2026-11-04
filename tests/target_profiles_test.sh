#!/bin/sh
# INV-589: modern profile policy survives preprocessing, caching and batch.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
PUBLIC=${PUBLIC:-$ROOT/basm-public}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/basm-target-profiles.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL profiles: %s\n' "$*" >&2; exit 1; }
reject() {
    if "$@" >"$TMP/reject.out" 2>"$TMP/reject.err"; then fail "accepted: $*"; fi
    [ ! -e "$TMP/rejected.o" ] || fail 'rejected source published output'
}

"$BASM" --target-profile public --capabilities >"$TMP/public.json"
perl -MJSON::PP -0777 -e '
    my $v=decode_json(<>);
    die "profile manifest\n" unless $v->{target_profile} eq "public" &&
        $v->{policy} eq "basm-profile-v1" && $v->{modes} eq "64" &&
        $v->{semantic_verification} eq "unimplemented";
' "$TMP/public.json"
"$BASM" --target-profile public --list-instructions >"$TMP/instructions.json"
"$BASM" --target-profile public --list-forms >"$TMP/forms.json"
perl -MJSON::PP -0777 -e '
    my $v=decode_json(<>); my %m=map { $_->{mnemonic}=>$_ } @{$v->{instructions}};
    die "inventory drift\n" unless $v->{count}==203 && scalar(keys %m)==203 &&
        $m{mov}{modeled_forms}==4 && $m{cpuid}{modeled_forms}==1 &&
        $m{adc}{modeled_forms}==2 && $m{ror}{modeled_forms}==1 && $m{rol}{modeled_forms}==1 &&
        $m{subsd}{modeled_forms}==1 &&
        $m{lea}{modeled_forms}==0 && !$m{pushad} && !$m{popad};
' "$TMP/instructions.json"
perl -MJSON::PP -0777 -e '
    my $v=decode_json(<>); my %f=map { $_->{id}=>1 } @{$v->{forms}};
    die "forms drift\n" unless @{$v->{forms}}==109 && scalar(keys %f)==109;
' "$TMP/forms.json"
cat >"$TMP/modern.basm" <<'EOF'
bits 64
section .text
global entry
entry:
    mov eax, ebx
    mov r8w, r9w
    push byte 1
    pop rax
    push rbx
    pop rbx
    ret
EOF
"$BASM" -f elf64 -o "$TMP/default.o" "$TMP/modern.basm"
for profile in public beyond; do
    "$BASM" --target-profile "$profile" --profile -f elf64 \
        -o "$TMP/$profile.o" "$TMP/modern.basm" 2>"$TMP/$profile.log"
    cmp "$TMP/default.o" "$TMP/$profile.o"
    grep -q '^BASM_PROFILE ' "$TMP/$profile.log" || fail 'telemetry was repurposed'
    for directive in 'bits 16' 'bits 32' '[BITS 32]' '[BITS 640]' \
        'BITS' 'bits 64 extra' '[bits 64' 'bItS 32' 'bits,32' ',bits 16'; do
        printf '%s\nret\n' "$directive" >"$TMP/bad.basm"
        reject "$BASM" --target-profile "$profile" -f elf64 \
            -o "$TMP/rejected.o" "$TMP/bad.basm"
    done
    for insn in 'pushad' 'popad' 'popa' 'o64 popad' 'rep popad' 'push eax' 'pop eax' \
        'push dword [rax]' 'pop word [rax]' 'jmp dword 8:0' \
        'push byte 1 + 127' 'push byte 1 2' 'push byte 1junk'; do
        printf 'bits 64\n%s\n' "$insn" >"$TMP/bad.basm"
        reject "$BASM" --target-profile "$profile" -f elf64 \
            -o "$TMP/rejected.o" "$TMP/bad.basm"
    done
    cat >"$TMP/macro.basm" <<'EOF'
%macro MODE 0
[BITS 32]
%endmacro
MODE
ret
EOF
    reject "$BASM" --target-profile "$profile" -f elf64 \
        -o "$TMP/rejected.o" "$TMP/macro.basm"
    printf 'bits 32\n' >"$TMP/mode.inc"
    printf '%%include "mode.inc"\nret\n' >"$TMP/include.basm"
    reject "$BASM" --target-profile "$profile" -f elf64 \
        -o "$TMP/rejected.o" "$TMP/include.basm"
done
printf 'bits 64\npush byte 1 + 2\nret\n' >"$TMP/push-expression.basm"
printf '\152\003\303' >"$TMP/push-expression.expected"
"$BASM" --target-profile public -f bin -o "$TMP/push-expression.bin" "$TMP/push-expression.basm"
cmp "$TMP/push-expression.expected" "$TMP/push-expression.bin"
printf 'bits 64\nnop\nsection .data align=1\ndb 7\n' >"$TMP/implicit-text.basm"
printf '\220\007' >"$TMP/implicit-text.expected"
for profile in public beyond; do
    "$BASM" --target-profile "$profile" -f bin -o "$TMP/implicit-text.bin" "$TMP/implicit-text.basm"
    cmp "$TMP/implicit-text.expected" "$TMP/implicit-text.bin"
done
"$BASM" -f bin -o "$TMP/implicit-text.bin" "$TMP/implicit-text.basm"
cmp "$TMP/implicit-text.expected" "$TMP/implicit-text.bin"
reject "$BASM" --target-profile Nostalgia --capabilities
reject "$BASM" --target-profile public --target-profile beyond --capabilities
reject "$BASM" --target-profile

# The existing no-selector invocation remains available during caller migration.
printf 'bits 32\nret\n' >"$TMP/compat.basm"
"$BASM" -f elf64 -o "$TMP/compat.o" "$TMP/compat.basm"
printf 'elf64\t%s\t%s\n' "$TMP/rejected.o" "$TMP/compat.basm" >"$TMP/jobs.tsv"
reject "$BASM" --target-profile public --batch "$TMP/jobs.tsv"
printf 'elf64\t%s\t%s\n' "$TMP/job.o" "$TMP/modern.basm" >"$TMP/jobs.tsv"
"$BASM" --target-profile public --batch "$TMP/jobs.tsv"
cmp "$TMP/default.o" "$TMP/job.o"

AP="$ROOT/../../ring0/arch/amd64/ap_trampoline.basm"
"$BASM" -f elf64 -o "$TMP/ap-default.o" "$AP"
"$BASM" --target-profile beyond --bootstrap ap-trampoline-v1 \
    -f elf64 -o "$TMP/ap.o" "$AP"
cmp "$TMP/ap-default.o" "$TMP/ap.o"
reject "$BASM" --target-profile beyond -f elf64 -o "$TMP/rejected.o" "$AP"
reject "$BASM" --target-profile public --bootstrap ap-trampoline-v1 \
    -f elf64 -o "$TMP/rejected.o" "$AP"
reject "$BASM" --target-profile beyond --bootstrap ap-trampoline-v1 \
    -DX=1 -f elf64 -o "$TMP/rejected.o" "$AP"
cp "$AP" "$TMP/ap-modified.basm"
printf '\nnop\n' >>"$TMP/ap-modified.basm"
reject "$BASM" --target-profile beyond --bootstrap ap-trampoline-v1 \
    -f elf64 -o "$TMP/rejected.o" "$TMP/ap-modified.basm"

[ -x "$PUBLIC" ] || fail "missing public build: $PUBLIC"
"$PUBLIC" --capabilities >"$TMP/public-only.json"
grep -q '"build":"public-only"' "$TMP/public-only.json" || fail 'public build policy'
"$PUBLIC" -f elf64 -o "$TMP/public-only.o" "$TMP/modern.basm"
cmp "$TMP/default.o" "$TMP/public-only.o"
reject "$PUBLIC" --target-profile beyond --capabilities
reject "$PUBLIC" -f elf64 -o "$TMP/rejected.o" "$TMP/compat.basm"
nm "$PUBLIC" >"$TMP/public-symbols"
if grep -Eq ' [bBdD] g_bits$' "$TMP/public-symbols"; then fail 'public retains mutable encoding mode'; fi
strings "$PUBLIC" >"$TMP/public-strings"
if grep -Ex 'pusha|pushad|popa|popad' "$TMP/public-strings"; then fail 'public registers legacy-only mnemonics'; fi
printf 'PASS target profiles (modes, bootstrap identity, operands, batch, public build)\n'
