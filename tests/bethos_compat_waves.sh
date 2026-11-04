#!/usr/bin/env bash
set -euo pipefail

BASM="${BASM:-./basm}"
NASM="${NASM:-nasm}"
ELFTOOL="${ELFTOOL:-./elftool}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ ! -x "$BASM" ]; then
    echo "missing basm: $BASM" >&2
    exit 1
fi
if ! command -v "$NASM" >/dev/null 2>&1; then
    echo "missing nasm oracle" >&2
    exit 1
fi
if [ ! -x "$ELFTOOL" ]; then
    echo "missing elftool: $ELFTOOL" >&2
    exit 1
fi

compare() {
    local name="$1"
    shift
    local src="$TMP/$name.asm"
    if [ ! -f "$src" ]; then
        src="$TMP/${name%_*}.asm"
    fi
    "$BASM" -f elf64 "$@" -o "$TMP/$name.basm.o" "$src"
    "$NASM" -f elf64 "$@" -o "$TMP/$name.nasm.o" "$src"
    "$ELFTOOL" diff "$TMP/$name.basm.o" "$TMP/$name.nasm.o" >/dev/null
    "$ELFTOOL" audit "$TMP/$name.basm.o" >/dev/null
    echo "PASS $name"
}

cat >"$TMP/wave01_cli.asm" <<'ASM'
bits 64
section .text
global wave01
wave01:
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave01_cli -Wall -w-reloc-rel-dword -w-reloc-abs-qword
if "$BASM" --not-a-basm-option -f elf64 -o "$TMP/bad.o" "$TMP/wave01_cli.asm" >/dev/null 2>&1; then
    echo "FAIL wave01_cli unknown option accepted" >&2
    exit 1
fi

cat >"$TMP/wave02_define.asm" <<'ASM'
bits 64
section .text
global wave02
wave02:
%if BETHOS_PROOF_IMAGE
    mov eax, 1
%else
    mov eax, 0
%endif
%ifdef BETHOS_PROOF_IMAGE
    add eax, 2
%endif
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave02_define_zero -DBETHOS_PROOF_IMAGE=0
compare wave02_define_one -DBETHOS_PROOF_IMAGE=1

mkdir -p "$TMP/inc"
cat >"$TMP/inc/bethos_abi.inc" <<'ASM'
%define BETHOS_MODEL_SERVICE_VERSION 7
ASM
cat >"$TMP/wave03_include.asm" <<'ASM'
bits 64
%include "bethos_abi.inc"
section .text
global wave03
wave03:
    mov eax, BETHOS_MODEL_SERVICE_VERSION
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave03_include -I"$TMP/inc/"

cat >"$TMP/wave04_sections.asm" <<'ASM'
bits 64
section .text.entry
global wave04_entry
wave04_entry:
    ret
section .rodata.payload
align 16
payload: dq wave04_entry
section .bss.boot nobits
alignb 16
boot_pages: resq 8
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave04_sections

cat >"$TMP/wave05_relocs.asm" <<'ASM'
bits 64
extern external_target
section .rodata.payload
global wave05_payload
wave05_payload:
    call external_target
    jne wave05_fail
    times 125 db 0x90
wave05_fail:
    jmp .again
.again:
    lea rax, [rel payload_data]
    ret
payload_data: dq wave05_payload
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave05_relocs

cat >"$TMP/wave06_addressing.asm" <<'ASM'
bits 64
default rel
section .text
global wave06
wave06:
    mov rax, [cell]
    mov rbx, [abs cell]
    ret
section .data
cell: dq 0x1234
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave06_addressing

cat >"$TMP/wave07_modes.asm" <<'ASM'
bits 16
section .text
global wave07
wave07:
    jmp 0x18:0x1234
protected:
bits 32
    jmp dword 0x08:0x12345678
long_mode:
bits 64
    je short done
    jne near done
done:
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave07_modes

cat >"$TMP/wave08_times.asm" <<'ASM'
bits 64
section .rodata
global wave08_data
wave08_data: times 4 dq 0x1111111111111111
tail: times 16 db 0x22
section .bss nobits
scratch: times 8 resb 4
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave08_times

cat >"$TMP/wave09_state.asm" <<'ASM'
bits 64
section .text
global wave09
wave09:
    lfence
    or rax, 0x1 | 0x2
    mov rdx, 0x8000000000000000 | 0x1
    mov rax, -1
    mov rbx, 0xffffffffffffffda
    stmxcsr [rsp - 4]
    ldmxcsr [rel mxcsr_value]
    fldcw [rel fcw_value]
    fnstcw [rsp - 8]
    ret
section .rodata
mxcsr_value: dd 0x1f80
fcw_value: dw 0x037f
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave09_state

cat >"$TMP/wave10_simd.asm" <<'ASM'
bits 64
section .text
global wave10
wave10:
    movdqu xmm0, [rel xbytes]
    vmovdqa ymm0, [rel ybytes]
    vmovdqu [rel ybytes], ymm8
    vpxor ymm1, ymm0, [rel ybytes]
    vpor ymm0, ymm0, ymm2
    vpcmpeqd ymm0, ymm0, ymm0
    vptest ymm1, ymm1
    vxorps ymm3, ymm3, ymm3
    vaddps ymm4, ymm3, [rel ybytes]
    vmulps ymm9, ymm8, ymm4
    vbroadcastss ymm5, [rel scalar]
    vbroadcastss ymm10, xmm9
    vxorps xmm6, xmm6, xmm6
    vaddps xmm7, xmm6, [rel xbytes]
    vmulps xmm11, xmm10, xmm7
    vbroadcastss xmm12, [rel scalar]
    ret
section .rodata
align 16
xbytes: times 16 db 0
scalar: dd 0
align 32
ybytes: times 32 db 0
section .note.GNU-stack noalloc noexec nowrite progbits
ASM
compare wave10_simd

echo "PASS bethos_compat_waves"
