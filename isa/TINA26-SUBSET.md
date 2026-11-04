# Tina Batch 26 Backend Subset

INV-740 and INV-741 are proposed, not registered by this backend change. The
coordinator owns Makefile/registry wiring and the ten Tina port integrations.
No algorithm port, independent C algorithm harness, compiler flag change, AVX
replacement, or inline data masquerading as SIMD instructions belongs here.

## Original Inventory

Paths below are relative to TinaLinux `kernel/`. Source was read directly,
before the RED test and implementation, not inferred from an edited port.

| Source | Original operand forms | BASM destination-first spelling |
| --- | --- | --- |
| `arch/x86/entry/vdso/vgetrandom-chacha.S:44` | MOVAPS RIP-relative constant to XMM | `movaps xmm5,[rel CONSTANTS]` |
| Same, lines 46-47 and 146-155 | MOVUPS m128 to XMM, XMM to m128 | `movups xmm6,[rsi]`, `movups [rdi+16],xmm2` |
| Same, lines 49,52,166 | MOVQ m64 to XMM, r64 to XMM, XMM to m64 | `movq xmm8,[rdx]`, `movq xmm9,rax`, `movq [rdx],xmm8` |
| Same, lines 56-59 and quarter-round copies | MOVDQA XMM to XMM | `movdqa xmm1,xmm5` |
| Same, quarter rounds and line 158 | PADDD, PADDQ, PXOR, POR XMM to XMM | `paddd xmm1,xmm2`, `paddq xmm8,xmm9`, `pxor xmm4,xmm1`, `por xmm4,xmm0` |
| Same, quarter rounds | PSLLD/PSRLD imm8,XMM | `pslld xmm0,16`, `psrld xmm4,16`; original counts 7,8,12,16,20,24,25 |
| Same, lines 96-100 and 135-139 | PSHUFD imm8,XMM,XMM | `pshufd xmm2,xmm2,0x39`; original controls 0x39,0x4e,0x93 |
| `arch/x86/crypto/nh-sse2-x86_64.S:37-48,77-79,121-122` | MOVDQU m128/XMM both directions, MOVDQA and PADDD XMM/XMM | `movdqu xmm9,[rsi+16]`, `movdqu [rcx],xmm8` |
| Same, lines 51-66 | PSHUFD imm8/XMM/XMM, PMULUDQ and PADDQ XMM/XMM | `pshufd xmm12,xmm4,0x10`, `pmuludq xmm4,xmm12`, `paddq xmm0,xmm4`; controls 0x10,0x32 |
| Same, lines 115-120 | PUNPCKLQDQ/PUNPCKHQDQ, PADDQ XMM/XMM | `punpcklqdq xmm8,xmm1`, `punpckhqdq xmm0,xmm1` |

NH uses every XMM register, including XMM15. The schema admits 26 explicitly
reviewed forms, not every operand form of these 15 mnemonics. Move RR/RM/MR
forms share one encoder; MOVQ also supports the inverse XMM-to-r64 transfer.
Packed arithmetic is RR only. No memory shuffle/count forms or MMX are added.
All forms are unprefixed BITS 64 with unsized memory operands and imm8 literals
0..255. `SUPPORTED-SUBSET.md` is the normative syntax and addressing boundary.

## ELF Requirements

- `arch/x86/entry/vdso/vdso-note.S:11-13` invokes ELFNOTE_START/END. The actual
  `include/linux/elfnote.h:42-54` requests `@note`, SHF_ALLOC and four-byte
  alignment/padding. Use `section .note.Linux alloc noexec nowrite note align=4`
  and `alignb 4`; do not use ordinary `align` to pad note names/descriptors.
- `arch/x86/entry/vsyscall/vsyscall_emu_64.S:17,39` explicitly declares OBJECT
  size 4096. Use `global __vsyscall_page:data 4096`. Its original 0xcc page
  fill is the port's responsibility, not an excuse to change `alignb` globally.
- `arch/x86/boot/compressed/kernel_info.S:7-22` declares a global label, no
  function/object type or `.size`. `global kernel_info:hidden` emits GLOBAL
  HIDDEN NOTYPE with size zero when the selected build context requires hidden.
  The compressed Makefile lines 28,45,52 establish the PIE/hidden-header flags;
  `include/linux/hidden.h:19` is a C visibility pragma, NOT an assembler `.hidden`
  directive. This backend does not infer hidden from that pragma or a section
  name, and does not claim the unqualified standalone original is hidden.
  The coordinator must preserve/check the exact selected original symbol ABI.
- `arch/x86/purgatory/entry64.S` and `setup-x86_64.S` use SYM_CODE_END (sized
  GLOBAL NOTYPE) and SYM_DATA_END(_LABEL) (OBJECT, including local GDT/stack).
  `include/linux/linkage.h:166-169,307-339` supplies the actual type/size.
  Use `global name:notype SIZE`, `global name:data SIZE`, or
  `static name:data SIZE` as appropriate, not a FUNC workaround.
- Purgatory LGDT RIP-relative, segment MOV from EAX, RETFQ, RIP-relative
  indirect memory JMP, and CR MOV use existing encoders. Tests compare bytes
  only, never execute those privileged or transfer sequences. IBT annotation
  sections continue to use the existing `dd NAME-$` PC32 field grammar.

All explicit extents use the existing full-width bounded evaluator: labels in
the symbol's own section, absolute expression, no overflow, nonnegative result
within the remaining section. Hidden is a standalone qualifier for a defined
GLOBAL NOTYPE, not an unchecked qualifier list. Unknown NOTE options, commas,
GROUP/COMDAT, W+X, writable/executable NOTE, duplicate attributes and conflicting
redeclared type/flags/alignment fail before publication. Selecting an existing
section by name alone is allowed. Fixed `.note.GNU-stack` remains PROGBITS.

## Evidence Boundary

`tina26_backend_test.py --red` records missing forms and silent PROGBITS against
the pinned cca94 full BASM before implementation. Positive tests cover every
XMM0..15 RR pair, MOVQ GPR pairs, displacement edges, base/index/scale products,
RIP targets and PC32 boundary addends. NASM and GAS are independent encoding/ELF
oracles only. Ignored long-mode ES/CS/SS/DS overrides use NASM byte parity:
GAS may elide a default segment, so its bytes are not silently normalized.

`tina26_semantics_test.py` executes only reviewed host-safe SysV instruction
leaves after whole-wrapper NASM parity and RW-to-RX transition. Caller-owned
buffers and caller-saved registers are used; packed lane arithmetic, moves,
shuffles, out-of-range shift zeroing and RFLAGS preservation have integer
references. This is not either port's independent ChaCha/NH algorithm harness.

`tina26_sharing_test.py` proves exact retained bytes/refusal diagnostics for the
VEX, SETcc, PUSH/POP and segment classifier sharing used to fit the full-product
budget. The prior size behavior/sharing gates remain in force. Legacy AVX is
retained, not substituted for SSE2. Runtime, signing and Ed25519 objects remain
in both fresh static builds; text budget is still 750000.

Declared `reads/writes/flags` are metadata, not verified semantics. Memory and
effective-address reads are explicit; all these SSE instructions preserve
RFLAGS. Unmodeled neighbors stay unmodeled, CFG stays partial, and
`semantic_verification` stays `unimplemented`. No host test authorizes kernel
execution, boot qualification, canonical binary promotion, or global gate claims.
