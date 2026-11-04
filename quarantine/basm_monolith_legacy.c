/*
 * basm-core -- the Bear assembler.
 *
 * Author:  F E R M I HART <contact@fermihart.com>
 * SPDX-License-Identifier: Unlicense
 *
 * Assembles the NASM-syntax subset that the compiler/stage0 .basm files emit, targeting
 * ELF64 relocatable objects on Linux x86-64. Goal: remove NASM from the stage0
 * dependency graph (sovereignty over the assembly step). Verified by a
 * differential gate (basm output byte-identical to NASM 2.16). See
 * Docs/specs/basm-asm.md for the product roadmap.
 *
 * Sections: .text .data .bss .note.GNU-stack
 * Defaults: RIP-relative addressing, shortest-encoding (matches NASM).
 *
 * Build:  make (host gcc, hardened).  Usage:  basm -f elf64 -o out.o in.basm
 */

/* dprintf, fseeko, etc. are POSIX.1-2008 — expose them on debian/glibc. */
#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#ifdef BASM_NO_PROC_SELF_EXE
#include <mach-o/dyld.h>
#endif

/* ------------------------------------------------------------------ */
static const char *g_file = "<stdin>";
/* The top-level input filename, captured once in main() and used verbatim
 * for the STT_FILE symbol so the object matches NASM (which names the FILE
 * symbol after the source path). g_file is per-pass/per-include and resets
 * to "<stdin>", so it cannot serve this role. Author: F E R M I ∞ H A R T. */
static const char *g_srcname = "<stdin>";

/* incbin / include search paths from -I. g_srcdir is the directory of the
 * top-level input file (NASM looks there first). Author: F E R M I ∞ H A R T. */
#define INCPATH_MAX 16
static const char *g_incpaths[INCPATH_MAX]; static int g_nincpaths = 0;
static char g_srcdir[512] = "";
static FILE *incbin_open(const char *fn) {
    char path[1024];
    FILE *bf = fopen(fn, "rb");           /* as given (absolute or CWD-relative) */
    if (bf) return bf;
    if (g_srcdir[0]) {                    /* relative to the source file's dir */
        snprintf(path, sizeof(path), "%s/%s", g_srcdir, fn);
        bf = fopen(path, "rb"); if (bf) return bf;
    }
    for (int i=0;i<g_nincpaths;i++) {     /* -I search paths */
        snprintf(path, sizeof(path), "%s/%s", g_incpaths[i], fn);
        bf = fopen(path, "rb"); if (bf) return bf;
    }
    return NULL;
}
static int g_line = 0;
static int g_pass; /* 1 or 2 */
static int g_fwd_unresolved; /* set to 1 in pass 1 if a forward ref is seen */
static int g_bits = 64; /* 16, 32, or 64 (default: 64-bit long mode) */
static uint64_t g_org = 0; /* origin address for flat binaries (org directive) */
static const char *g_fmt = "elf64"; /* output format: "elf64" or "bin" */

static void die(const char *msg) {
    dprintf(2, "%s:%d: error: %s\n", g_file, g_line, msg);
    exit(1);
}
static void die2(const char *msg, const char *detail) {
    dprintf(2, "%s:%d: error: %s '%s'\n", g_file, g_line, msg, detail);
    exit(1);
}

/*=============================================================================
 * Wave A, B, C, D: Security Hardening (Constants and helpers)
 *===========================================================================*/
#define MAX_OPERAND_LEN 512
#define MAX_SYMBOL_LEN  63
#define MAX_CODE_SIZE (64 * 1024)  /* 64KB code buffer limit */
/* `*` = SIB scale ([base+index*4]); `:` = segment override ([gs:0x10]). */
#define VALID_OPERAND_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[].\\-+_/0 *:"
#define VALID_SYMBOL_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."

static int g_emit_safe = 1;

static int validate_operand_len(const char *op) {
    if (op == NULL) return 0;
    if (strnlen(op, MAX_OPERAND_LEN + 1) > MAX_OPERAND_LEN) return 0;
    return 1;
}

static int validate_address_contents(const char *addr) {
    if (addr == NULL) return 0;
    size_t len = strnlen(addr, MAX_OPERAND_LEN);
    if (len > MAX_OPERAND_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!strchr(VALID_OPERAND_CHARS, addr[i])) return 0;
    }
    return 1;
}

/* ADR-033 hardening helper — implemented but not yet wired (see note below). */
__attribute__((unused))
static int is_valid_symbol(const char *name, size_t len) {
    if (len == 0 || len > MAX_SYMBOL_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!strchr(VALID_SYMBOL_CHARS, name[i])) return 0;
    }
    return 1;
}

/* ADR-033 hardening helper — implemented but not yet wired into the parser.
 * Kept under attribute((unused)) so -Werror stays strict for everything else;
 * wiring is tracked as a pending hardening task. */
__attribute__((unused))
static int validate_register_name(const char *reg) {
    if (reg == NULL || strlen(reg) > 8) return 0;
    const char *valid_prefixes[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
                                    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                                    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
                                    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
                                    "spl", "bpl", "sil", "dil", NULL};
    for (int i = 0; valid_prefixes[i]; i++) {
        if (strcmp(reg, valid_prefixes[i]) == 0) return 1;
    }
    return 0;
}

/* ADR-033 hardening helper — implemented but not yet wired (see note above). */
__attribute__((unused))
static int sanitize_symbol_name(char *out, const char *in, size_t in_len) {
    if (in == NULL || out == NULL) return 0;
    if (in_len == 0 || in_len > MAX_SYMBOL_LEN) return 0;
    for (size_t i = 0; i < in_len && in[i] != '\0'; i++) {
        if (isalnum((unsigned char)in[i]) || in[i] == '_' || in[i] == '.') {
            out[i] = in[i];
        } else {
            out[i] = '_';
        }
    }
    out[in_len] = '\0';
    return 1;
}

#define NAME_MAX 256   /* raised 64->256: symbols + UTF-8/box-drawing db strings
                          (Beyond is beautiful from the boot; ASCII-only is 1991) */
#define MAXTOK 32

/* Symbol capture for absolute-reloc emission. When parse_expr evaluates an
 * expression containing a cross-section LABEL (not a %define const), these
 * record it so callers (parse_mem / data_define) emit an R_X86_64_32/64
 * reloc against the section + addend instead of baking a wrong value.
 * g_expr_symcount>1 means a non-linear label expr (unsupported → bake).
 * Author: F E R M I ∞ H A R T. */
static int  g_expr_symcount;
static int  g_expr_sym_section;
static long g_expr_sym_offset;
static char g_expr_sym_name[NAME_MAX];
static int  g_expr_sym_global;

#define MACRO_MAX 256
#define INCLUDE_DEPTH 16

/* ── Open-addressing hash-table accelerators for symbol/macro/const lookup.
 *    The dense arrays still own insertion order (needed for defseq / output
 *    symbol table); the hash tables store (hash, len, index) triples so the
 *    hot lookups become O(1) amortised instead of O(n), and comparisons avoid
 *    strcmp by checking length first and then memcmp.
 *    Author: F E R M I ∞ H A R T. */
typedef struct { uint32_t hash; uint8_t len; int idx; } HTEntry;

static uint32_t str_hash(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    return h ? h : 1; /* 0 marks an empty slot */
}

static void ht_insert(HTEntry *tab, int cap, uint32_t h, uint8_t len, int idx) {
    int mask = cap - 1;
    int i = (int)(h & (uint32_t)mask);
    while (tab[i].hash) i = (i + 1) & mask;
    tab[i].hash = h;
    tab[i].len  = len;
    tab[i].idx  = idx;
}

/* Compare a known-length C string `a` against a string literal `lit`.
 * Avoids strlen(lit) at runtime because sizeof(lit) is a compile-time constant. */
#define STR_EQ_LIT(a, alen, lit) \
    ((alen) == (sizeof(lit) - 1) && memcmp((a), (lit), (sizeof(lit) - 1)) == 0)

/* Simple macro table for %define */
typedef struct { char name[NAME_MAX]; char value[256]; int active; } Macro;
static Macro g_macros[MACRO_MAX];
static int g_nmacros = 0;

#define MACRO_HT_CAP 512
static HTEntry g_macro_ht[MACRO_HT_CAP];

static Macro *macro_find(const char *name) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    uint32_t h = str_hash(name, nl);
    int mask = MACRO_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_macro_ht[i].hash) {
        int idx = g_macro_ht[i].idx;
        if (g_macro_ht[i].hash == h && g_macro_ht[i].len == nl &&
            memcmp(g_macros[idx].name, name, nl) == 0 && g_macros[idx].active)
            return &g_macros[idx];
        i = (i + 1) & mask;
    }
    return NULL;
}
static void macro_add(const char *name, const char *value) {
    Macro *m = macro_find(name);
    if (m) {
        size_t vl = strlen(value);
        if (vl >= sizeof(m->value)) vl = sizeof(m->value) - 1;
        memcpy(m->value, value, vl);
        m->value[vl] = 0;
        return;
    }
    if (g_nmacros >= MACRO_MAX) { printf("Error: too many macros\n"); exit(1); }
    int idx = g_nmacros++;
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    memcpy(g_macros[idx].name, name, nl);
    g_macros[idx].name[nl] = 0;
    size_t vl = strlen(value);
    if (vl >= sizeof(g_macros[idx].value)) vl = sizeof(g_macros[idx].value) - 1;
    memcpy(g_macros[idx].value, value, vl);
    g_macros[idx].value[vl] = 0;
    g_macros[idx].active = 1;
    ht_insert(g_macro_ht, MACRO_HT_CAP, str_hash(g_macros[idx].name, nl), (uint8_t)nl, idx);
}

/* Include stack for %include */
static struct { char *buf; char *p; char fname[NAME_MAX]; } g_inc_stack[INCLUDE_DEPTH];
static int g_inc_depth = 0;

/* Conditional assembly state */
static int g_if_stack[64]; static int g_if_depth=0; static int g_if_active=1;

static char g_last_global[NAME_MAX]; /* most recent non-local label, for ".x" qualification */

/* Append src to dst[sz], guaranteeing NUL termination and never overflowing.
 * Returns the resulting strlen(dst), clamped to sz-1. */
static size_t strbuf_append(char *dst, size_t sz, const char *src) {
    size_t len = strlen(dst);
    if (len >= sz) { dst[sz-1] = 0; return sz-1; }
    size_t room = sz - len - 1;
    size_t sl = strlen(src);
    if (sl > room) sl = room;
    memcpy(dst + len, src, sl);
    dst[len + sl] = 0;
    return len + sl;
}

/* ------------------------------------------------------------------ */
/* Section model                                                      */
/* ------------------------------------------------------------------ */
enum { SEC_NONE=-1, SEC_TEXT=0, SEC_DATA=1, SEC_BSS=2, SEC_NOTE=3, SEC_RODATA=4,
       SEC_CUSTOM0=5 };
#define SEC_MAX 24         /* 5 fixed + up to CUSTOM_MAX(16) custom named sections.
                            * MUST be >= SEC_CUSTOM0(5)+CUSTOM_MAX, else arrays
                            * indexed by `sec` overflow for custom sections >2
                            * (garbage .rela.<name> headers). F E R M I HART. */

#define TEXT_MAX (1 << 22)
#define DATA_MAX (1 << 25)  /* 32 MiB: initramfs.cpio is incbin'd into kernel
                             * .rodata and the full C-jash userland pushed it
                             * past the old 4 MiB. Static BSS on the HOST
                             * assembler only — no target-side cost.
                             * F E R M I ∞ H A R T 2026-07-03 */
#define BASM_LONG_MAX ((long)(((unsigned long)-1) >> 1))
static uint8_t g_text[TEXT_MAX];  static int g_textlen = 0;
static uint8_t g_data[DATA_MAX];  static int g_datalen = 0;
static uint8_t g_rodata[DATA_MAX];static int g_rodatalen = 0;
static long    g_bsslen = 0;      /* .bss is size-only */
static int     g_cur = SEC_TEXT;

/* Custom named sections (e.g. .multiboot, .ap_trampoline). Each gets its own
 * byte buffer, name, ELF sh_flags and sh_type. Author: F E R M I ∞ H A R T. */
#define CUSTOM_MAX 16   /* was 3 — crtend/crtbegin use .ctors/.dtors/.eh_frame/.jcr/... */
static char    g_custom_name[CUSTOM_MAX][NAME_MAX];
static uint8_t g_custom_buf[CUSTOM_MAX][DATA_MAX];
static int     g_custom_len[CUSTOM_MAX];
static uint64_t g_custom_flags[CUSTOM_MAX];  /* ELF sh_flags */
static uint32_t g_custom_type[CUSTOM_MAX];   /* ELF sh_type (1=PROGBITS,8=NOBITS) */
static int     g_ncustom = 0;
static int     custom_idx(int sec){ return sec - SEC_CUSTOM0; }  /* sec>=SEC_CUSTOM0 */

/* section appearance order (NASM assigns indices by first `section` directive) */
static int g_secorder[8]; static int g_nsecorder = 0;
static int g_secalign[SEC_MAX] = {1,1,1,1,1,1,1,1}; /* max align directive seen per section */
static void secorder_touch(int sec) {
    for (int i=0;i<g_nsecorder;i++) if (g_secorder[i]==sec) return;
    if (g_nsecorder >= SEC_MAX) die("too many sections");
    g_secorder[g_nsecorder++] = sec;
}

/* emit into current section */
static void emit(uint8_t b) {
    /* Wave C: additional bounds check for code buffer */
    if (g_cur == SEC_TEXT && g_emit_safe && g_textlen >= MAX_CODE_SIZE - 16) {
        die("emit: code buffer overflow (>64KB)");
    }
    if (g_cur == SEC_TEXT) {
        if (g_textlen >= TEXT_MAX) die("text overflow");
        g_text[g_textlen++] = b;
    } else if (g_cur == SEC_DATA) {
        if (g_datalen >= DATA_MAX) die("data overflow");
        g_data[g_datalen++] = b;
    } else if (g_cur == SEC_RODATA) {
        if (g_rodatalen >= DATA_MAX) die("rodata overflow");
        g_rodata[g_rodatalen++] = b;
    } else if (g_cur >= SEC_CUSTOM0) {
        int ci = custom_idx(g_cur);
        if (g_custom_len[ci] >= DATA_MAX) die("custom section overflow");
        g_custom_buf[ci][g_custom_len[ci]++] = b;
    } else die("cannot emit bytes into this section");
}
static void emit16(uint32_t v){ emit(v&0xff); emit((v>>8)&0xff); }
static void emit32(uint32_t v){ emit16(v&0xffff); emit16((v>>16)&0xffff); }
static void emit64(uint64_t v){ emit32(v&0xffffffff); emit32((v>>32)&0xffffffff); }

static int cur_off(void) {
    int off;
    if (g_cur >= SEC_CUSTOM0) off = g_custom_len[custom_idx(g_cur)];
    else off = (g_cur==SEC_TEXT)?g_textlen : (g_cur==SEC_DATA)?g_datalen :
               (g_cur==SEC_RODATA)?g_rodatalen : (g_cur==SEC_BSS)?(int)g_bsslen : 0;
    /* s->offset stores relative offset; g_org applied at emission time */
    return off;
}

/* ------------------------------------------------------------------ */
/* Symbols                                                            */
/* ------------------------------------------------------------------ */
#define SYM_MAX 2048
#define CONST_MAX 512
/* The output symbol table holds, worst case: null + FILE + up to 8 section
 * symbols + every emit_sym .equ const (≤CONST_MAX) + every defined/global
 * label (≤SYM_MAX). Size syms[] to cover all contributors so a large TU
 * (e.g. stage0 parse.basm: ~485 labels + ~107 consts) cannot smash the stack. */
#define SYMTAB_CAP (SYM_MAX + CONST_MAX + 8)

typedef struct {
    char name[NAME_MAX];
    int  defined;   /* 1 if a label, 0 if extern/undefined */
    int  global;    /* exported */
    int  is_func;   /* :function attribute */
    int  weak;      /* `weak` directive → STB_WEAK binding (crtbegin's optional ctor hooks) */
    int  is_local;  /* leading '.' local label (LOCAL bind) */
    int  section;   /* SEC_TEXT/DATA/BSS if defined */
    int  offset;    /* offset within its section */
    int  defseq;    /* source-definition order (-1 until defined); NASM emits
                     * local symbols in this order, interleaved with consts. */
} Sym;
static Sym g_syms[SYM_MAX];
static int g_nsyms = 0;
/* Monotonic definition counter shared by labels and equ-constants so the
 * output symbol table can reproduce NASM's source-definition ordering. */
static int g_defseq = 0;

#define SYM_HT_CAP 4096
static HTEntry g_sym_ht[SYM_HT_CAP];

static Sym *sym_find(const char *name) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    uint32_t h = str_hash(name, nl);
    int mask = SYM_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_sym_ht[i].hash) {
        int idx = g_sym_ht[i].idx;
        if (g_sym_ht[i].hash == h && g_sym_ht[i].len == nl &&
            memcmp(g_syms[idx].name, name, nl) == 0)
            return &g_syms[idx];
        i = (i + 1) & mask;
    }
    return NULL;
}
static Sym *sym_intern(const char *name) {
    Sym *s = sym_find(name);
    if (s) return s;
    if (g_nsyms >= SYM_MAX) die("too many symbols");
    int idx = g_nsyms++;
    s = &g_syms[idx];
    memset(s, 0, sizeof(*s));
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    memcpy(s->name, name, nl);
    s->name[nl] = 0;
    s->is_local = (name[0] == '.');
    s->section = SEC_NONE;
    s->defseq = -1;
    ht_insert(g_sym_ht, SYM_HT_CAP, str_hash(s->name, nl), (uint8_t)nl, idx);
    return s;
}

/* assembler constants (NAME equ value). NASM emits each as a LOCAL NOTYPE ABS
 * symbol, in definition order, right after the section symbols. */
typedef struct { char name[NAME_MAX]; long value; int emit_sym; int defseq; } Const;
static Const g_consts[CONST_MAX]; static int g_nconsts = 0;

#define CONST_HT_CAP 1024
static HTEntry g_const_ht[CONST_HT_CAP];

static int const_lookup(const char *name, long *out) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    uint32_t h = str_hash(name, nl);
    int mask = CONST_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_const_ht[i].hash) {
        int idx = g_const_ht[i].idx;
        if (g_const_ht[i].hash == h && g_const_ht[i].len == nl &&
            memcmp(g_consts[idx].name, name, nl) == 0) {
            *out = g_consts[idx].value;
            return 1;
        }
        i = (i + 1) & mask;
    }
    return 0;
}
static void const_set(const char *name, long v) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) die2("equ constant name too long", name);
    uint32_t h = str_hash(name, nl);
    int mask = CONST_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_const_ht[i].hash) {
        int idx = g_const_ht[i].idx;
        if (g_const_ht[i].hash == h && g_const_ht[i].len == nl &&
            memcmp(g_consts[idx].name, name, nl) == 0) {
            g_consts[idx].value = v;
            return;
        }
        i = (i + 1) & mask;
    }
    if (g_nconsts >= CONST_MAX) die("too many equ constants");
    int idx = g_nconsts++;
    memcpy(g_consts[idx].name, name, nl + 1);
    g_consts[idx].value = v;
    g_consts[idx].emit_sym = 1;
    g_consts[idx].defseq = g_defseq++;
    ht_insert(g_const_ht, CONST_HT_CAP, h, (uint8_t)nl, idx);
}

/* ------------------------------------------------------------------ */
/* Relocations                                                        */
/* ------------------------------------------------------------------ */
#define RELOC_MAX 4096
typedef struct {
    int   offset;       /* offset where the field sits */
    int   section;      /* which section the field is IN (text/data/rodata) */
    int   reltype;      /* 2 = R_X86_64_PC32, 1 = R_X86_64_64 */
    int   sym_kind;     /* 0 = named symbol, 1 = section symbol */
    char  sym[NAME_MAX];
    int   target_sec;   /* section-symbol case: which section */
    long  addend;
} Reloc;
static Reloc g_relocs[RELOC_MAX];
static int g_nrelocs = 0;

static void add_reloc_named(int offset, const char *sym, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = SEC_TEXT; r->reltype = 2;
    r->sym_kind = 0; r->target_sec = SEC_NONE; r->addend = addend;
    size_t n = strlen(sym); if (n >= NAME_MAX) n = NAME_MAX-1;
    memcpy(r->sym, sym, n); r->sym[n] = 0;
}
static void add_reloc_section(int offset, int section, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = SEC_TEXT; r->reltype = 2;
    r->sym_kind = 1; r->target_sec = section; r->addend = addend; r->sym[0] = 0;
}
/* 64-bit absolute reloc against a named symbol, in the current data section. */
static void add_reloc_abs64(int offset, int in_section, const char *sym) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = in_section; r->reltype = 1;
    r->sym_kind = 0; r->target_sec = SEC_NONE; r->addend = 0;
    size_t n = strlen(sym); if (n >= NAME_MAX) n = NAME_MAX-1;
    memcpy(r->sym, sym, n); r->sym[n] = 0;
}

/* 64-bit absolute reloc against a SECTION symbol + addend (NASM folds a
 * defined local symbol's offset into the addend, like the PC32 path). */
static void add_reloc_abs64_section(int offset, int in_section, int target_sec, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = in_section; r->reltype = 1;
    r->sym_kind = 1; r->target_sec = target_sec; r->addend = addend; r->sym[0]=0;
}

/* 32-bit absolute reloc (R_X86_64_32, type 10) against a SECTION symbol +
 * addend, in the given section. Used for absolute memory-operand
 * displacements [label+disp] and dd label+disp where the label lives in
 * another section — the linker resolves the final address, the constant
 * arithmetic rides in the addend (NASM behaviour). Author: F E R M I ∞ H A R T. */
static void add_reloc_abs32_section(int offset, int in_section, int target_sec, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = in_section; r->reltype = 10;
    r->sym_kind = 1; r->target_sec = target_sec; r->addend = addend; r->sym[0]=0;
}
static void add_reloc_abs32_named(int offset, int in_section, const char *sym, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = in_section; r->reltype = 10;
    r->sym_kind = 0; r->target_sec = SEC_NONE; r->addend = addend;
    size_t n = strlen(sym); if (n >= NAME_MAX) n = NAME_MAX-1;
    memcpy(r->sym, sym, n); r->sym[n] = 0;
}

/* ------------------------------------------------------------------ */
/* Registers                                                          */
/* ------------------------------------------------------------------ */
typedef struct { const char *name; int num; int size; int rex_req; } Reg; /* size:1,4,8; rex_req: needs REX even if empty (spl/bpl/sil/dil) */
static const Reg g_regs[] = {
    {"rax",0,8,0},{"rcx",1,8,0},{"rdx",2,8,0},{"rbx",3,8,0},
    {"rsp",4,8,0},{"rbp",5,8,0},{"rsi",6,8,0},{"rdi",7,8,0},
    {"r8",8,8,0},{"r9",9,8,0},{"r10",10,8,0},{"r11",11,8,0},
    {"r12",12,8,0},{"r13",13,8,0},{"r14",14,8,0},{"r15",15,8,0},
    {"eax",0,4,0},{"ecx",1,4,0},{"edx",2,4,0},{"ebx",3,4,0},
    {"esp",4,4,0},{"ebp",5,4,0},{"esi",6,4,0},{"edi",7,4,0},
    {"r8d",8,4,0},{"r9d",9,4,0},{"r10d",10,4,0},{"r11d",11,4,0},
    {"r12d",12,4,0},{"r13d",13,4,0},{"r14d",14,4,0},{"r15d",15,4,0},
    {"al",0,1,0},{"cl",1,1,0},{"dl",2,1,0},{"bl",3,1,0},
    {"ah",4,1,0},{"ch",5,1,0},{"dh",6,1,0},{"bh",7,1,0},
    {"spl",4,1,1},{"bpl",5,1,1},{"sil",6,1,1},{"dil",7,1,1},
    {"r8b",8,1,0},{"r9b",9,1,0},{"r10b",10,1,0},{"r11b",11,1,0},
    {"r12b",12,1,0},{"r13b",13,1,0},{"r14b",14,1,0},{"r15b",15,1,0},
    {"ax",0,2,0},{"cx",1,2,0},{"dx",2,2,0},{"bx",3,2,0},
    {"sp",4,2,0},{"bp",5,2,0},{"si",6,2,0},{"di",7,2,0},
    {"r8w",8,2,0},{"r9w",9,2,0},{"r10w",10,2,0},{"r11w",11,2,0},
    {"r12w",12,2,0},{"r13w",13,2,0},{"r14w",14,2,0},{"r15w",15,2,0},
    {NULL,0,0,0}
};
/* Perfect hash table for register lookup. Found offline: h=24, multiplier=37,
 * modulo 256 maps all 68 register names to distinct slots. Author: F E R M I ∞ H A R T. */
#define REG_HT_CAP 256
static int g_reg_idx[REG_HT_CAP];
static int g_reg_ht_ready = 0;

static uint32_t reg_hash(const char *s) {
    if (!s) return 0;
    const unsigned char *us = (const unsigned char *)s;
    uint32_t h = 24;
    /* Hash until the terminating NUL.  The previous version took an explicit
     * length and the analyzer could not prove every caller passed an
     * initialised buffer of that length.  Reading to the NUL lets the analyzer
     * see the bound is derived from the string itself. */
    for (size_t i = 0; us[i]; i++) h = h * 37 + us[i];
    return h;
}

static void reg_ht_init(void) {
    for (int i = 0; i < REG_HT_CAP; i++) g_reg_idx[i] = -1;
    for (int i = 0; g_regs[i].name; i++) {
        int slot = (int)(reg_hash(g_regs[i].name) & (REG_HT_CAP - 1));
        g_reg_idx[slot] = i;
    }
    g_reg_ht_ready = 1;
}

static const Reg *reg_find(const char *s) {
    if (!g_reg_ht_ready) reg_ht_init();
    int slot = (int)(reg_hash(s) & (REG_HT_CAP - 1));
    int idx = g_reg_idx[slot];
    if (idx >= 0 && g_regs[idx].name && strcmp(g_regs[idx].name, s) == 0)
        return &g_regs[idx];
    return NULL;
}

/* Segment-register index for mov Sreg forms, or -1. es=0 cs=1 ss=2 ds=3 fs=4 gs=5. */
static int seg_reg(const char *s) {
    if (!strcmp(s,"es")) return 0;
    if (!strcmp(s,"cs")) return 1;
    if (!strcmp(s,"ss")) return 2;
    if (!strcmp(s,"ds")) return 3;
    if (!strcmp(s,"fs")) return 4;
    if (!strcmp(s,"gs")) return 5;
    return -1;
}

/* Control-register index for mov CR forms, or -1. cr0=0 cr2=2 cr3=3 cr4=4. */
static int cr_reg(const char *s) {
    if (!strcmp(s,"cr0")) return 0;
    if (!strcmp(s,"cr2")) return 2;
    if (!strcmp(s,"cr3")) return 3;
    if (!strcmp(s,"cr4")) return 4;
    return -1;
}

/* ------------------------------------------------------------------ */
static void qualify(const char *target, char *out); /* fwd decl */
/* Expression / integer parse                                         */
/* ------------------------------------------------------------------ */
/* Parse a numeric expression: term ((+|-|*) term)*, term = int|const|char.
 * Used for immediates and data values (e.g. "IR_SIZE * IR_MAX", "-1"). */
static long parse_sum(const char **pp);  /* fwd: parens use full precedence */
static long parse_or(const char **pp);   /* fwd: full bitwise/shift precedence */
static long parse_term(const char **pp) {
    const char *p = *pp;
    while (*p == ' ') p++;
    long v;
    if (*p == '-') { p++; *pp = p; return -parse_term(pp); }
    if (*p == '(') {
        p++; *pp = p; long r;
        r = parse_or(pp); p = *pp; while(*p==' ')p++;
        if (*p==')') p++;
        *pp=p; return r;
    }
    if (*p == '\'') { /* char literal 'x' */
        p++; v = (unsigned char)*p++; if (*p=='\'') p++; *pp=p; return v;
    }
    if (*p == '`') { /* backtick char/escape literal `\n` `\'` `\\` */
        p++;
        if (*p == '\\') {
            p++; char c=*p++;
            switch(c){case 'n':v='\n';break;case 't':v='\t';break;case 'r':v='\r';break;
                      case '0':v=0;break;case '\\':v='\\';break;case '\'':v='\'';break;
                      case '"':v='"';break;default:v=(unsigned char)c;}
        } else v=(unsigned char)*p++;
        if (*p=='`') p++;
        *pp=p; return v;
    }
    if (isdigit((unsigned char)*p)) {
        char *end;
        unsigned long uv;
        if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) uv = strtoull(p,&end,16);
        else uv = strtoull(p,&end,10);
        *pp = end; return (long)uv;
    }
    /* `$` = current position, `$$` = section start (NASM-compatible) */
    if (*p == '$') {
        p++;
        if (*p == '$') { p++; *pp = p; return 0; } /* $$ = section start offset */
        *pp = p; return cur_off(); /* $ = current offset in section */
    }
    /* identifier: a constant */
    char name[NAME_MAX]; int i=0;
    while ((isalnum((unsigned char)*p)||*p=='_') && i<NAME_MAX-1) name[i++]=*p++;
    name[i]=0;
    if (i==0) die("bad expression term");
    if (!const_lookup(name, &v)) {
        /* Try symbol lookup (labels), not just %define constants */
        char qname[NAME_MAX]; qualify(name, qname);
        Sym *s = sym_find(qname);
        if (s && s->defined && s->section != SEC_NONE) {
            v = s->offset; /* defined label: use its relative offset */
            /* For flat binaries, add org to get absolute address */
            if (!strcmp(g_fmt, "bin")) v += (long)g_org;
            /* Capture for reloc emission: a real label (in a section) was
             * referenced. The caller decides whether to emit a reloc.
             * Author: F E R M I ∞ H A R T. */
            g_expr_symcount++;
            g_expr_sym_section = s->section;
            g_expr_sym_offset  = (long)s->offset;
            g_expr_sym_global  = s->global;
            strncpy(g_expr_sym_name, qname, NAME_MAX-1); g_expr_sym_name[NAME_MAX-1]=0;
        } else if (s && s->global && !s->defined) {
            /* EXTERN symbol (declared `extern`, defined in another TU, e.g.
             * the linker-script symbols __bss_start/__bss_end used as a 32-bit
             * immediate in `mov edi, __bss_start`). Capture it for a NAMED
             * R_X86_64_32 reloc instead of dying — the caller (mov-imm / data)
             * emits the reloc and the linker fills the address.
             * Author: F E R M I ∞ H A R T. */
            v = 0;
            g_expr_symcount++;
            g_expr_sym_section = SEC_NONE;
            g_expr_sym_offset  = 0;
            g_expr_sym_global  = 1;
            strncpy(g_expr_sym_name, qname, NAME_MAX-1); g_expr_sym_name[NAME_MAX-1]=0;
        } else if (g_pass == 1) {
            g_fwd_unresolved = 1; v = 0; /* forward ref: resolve in pass 2 */
            g_expr_symcount++;           /* a label (not yet defined) */
            g_expr_sym_section = SEC_NONE;
            strncpy(g_expr_sym_name, qname, NAME_MAX-1); g_expr_sym_name[NAME_MAX-1]=0;
        } else {
            die2("unknown symbol in expression", name);
        }
    }
    *pp = p; return v;
}
/* Parse a numeric expression with correct precedence: +/- (low) over * (high).
 * term handles literals/consts/parens; product chains *; expr chains +/-. */
static long parse_product(const char **pp) {
    long acc = parse_term(pp);
    const char *p = *pp;
    while (1) {
        while (*p==' ') p++;
        if (*p=='*') { p++; *pp=p; acc *= parse_term(pp); p=*pp; }
        else break;
    }
    *pp = p;
    return acc;
}
static long parse_sum(const char **pp) {
    long acc = parse_product(pp);
    const char *p = *pp;
    while (*p) {
        while (*p==' ') p++;
        if (*p=='+') { p++; *pp=p; acc += parse_product(pp); p=*pp; }
        else if (*p=='-') { p++; *pp=p; acc -= parse_product(pp); p=*pp; }
        else break;
    }
    *pp = p;
    return acc;
}
/* Bitwise/shift layer (NASM precedence, low→high): | ^ & << >> over +/-.
 * Author: F E R M I ∞ H A R T. */
static long parse_shift(const char **pp) {
    long acc = parse_sum(pp);
    const char *p = *pp;
    while (*p) {
        while (*p==' ') p++;
        if (p[0]=='<'&&p[1]=='<') { p+=2; *pp=p; long sh=parse_sum(pp); if(sh<0||sh>=(long)(sizeof(long)*8)) die("shift out of range"); acc <<= sh; p=*pp; }
        else if (p[0]=='>'&&p[1]=='>') { p+=2; *pp=p; long sh=parse_sum(pp); if(sh<0||sh>=(long)(sizeof(long)*8)) die("shift out of range"); acc >>= sh; p=*pp; }
        else break;
    }
    *pp=p; return acc;
}
static long parse_and(const char **pp) {
    long acc = parse_shift(pp);
    const char *p = *pp;
    while (*p) { while(*p==' ')p++;
        if (p[0]=='&'&&p[1]!='&') { p++; *pp=p; acc &= parse_shift(pp); p=*pp; }
        else break; }
    *pp=p; return acc;
}
static long parse_xor(const char **pp) {
    long acc = parse_and(pp);
    const char *p = *pp;
    while (*p) { while(*p==' ')p++;
        if (*p=='^') { p++; *pp=p; acc ^= parse_and(pp); p=*pp; }
        else break; }
    *pp=p; return acc;
}
static long parse_or(const char **pp) {
    long acc = parse_xor(pp);
    const char *p = *pp;
    while (*p) { while(*p==' ')p++;
        if (p[0]=='|'&&p[1]!='|') { p++; *pp=p; acc |= parse_xor(pp); p=*pp; }
        else break; }
    *pp=p; return acc;
}
/* Simple expression cache: pure-constant expressions are evaluated many times
 * (especially in data directives and repeated operands). Keyed by FNV-1a hash
 * plus a short string comparison. Reset each assemble_pass because symbol
 * values change between passes. Author: F E R M I ∞ H A R T. */
#define EXPR_CACHE_CAP 1024
typedef struct { uint32_t hash; long value; } ExprCacheEntry;
static ExprCacheEntry g_expr_cache[EXPR_CACHE_CAP];
static int g_expr_cache_valid = 0;

static void expr_cache_reset(void) {
    for (int i = 0; i < EXPR_CACHE_CAP; i++) g_expr_cache[i].hash = 0;
    g_expr_cache_valid = 1;
}

static uint32_t expr_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h ? h : 1;
}

static long parse_expr(const char *s) {
    uint32_t h = 0;
    if (g_expr_cache_valid) {
        h = expr_hash(s);
        int mask = EXPR_CACHE_CAP - 1;
        int i = (int)(h & (uint32_t)mask);
        /* Probe only a few slots; avoidstrcmp on the hot path by checking hash first. */
        for (int probe = 0; probe < 4 && g_expr_cache[i].hash; probe++) {
            if (g_expr_cache[i].hash == h) return g_expr_cache[i].value;
            i = (i + 1) & mask;
        }
    }
    const char *p = s;
    long v = parse_or(&p);
    if (g_expr_cache_valid && g_expr_symcount == 0) {
        if (h == 0) h = expr_hash(s);
        int mask = EXPR_CACHE_CAP - 1;
        int i = (int)(h & (uint32_t)mask);
        while (g_expr_cache[i].hash) i = (i + 1) & mask;
        g_expr_cache[i].hash = h;
        g_expr_cache[i].value = v;
    }
    return v;
}

/* Evaluate an expression, capturing whether it references exactly one
 * cross-section label (linear: label ± constants). Returns the baked value.
 * Out-params: *has_sym=1 if a single label was seen (caller should emit a
 * reloc with addend = value - label_offset); sec/off/name/glob describe
 * the label. >1 label refs → *has_sym=0 (fall back to baking the value).
 * Author: F E R M I ∞ H A R T. */
/* Pre-scan for `name equ value` definitions so that simple constants
 * (e.g. `banner_len equ $ - banner`) are available during pass-1 .text
 * processing. This prevents `mov r64,imm` forward-ref code from emitting
 * 10-byte movabs in the sizing pass but 5-byte `mov r32,imm32` in the
 * final pass, which desyncs the layout and corrupts branch displacements.
 * Values depending on `$` or forward labels will be wrong here, but they
 * are overwritten when the actual `equ` directive is processed during
 * normal assembly. Author: F E R M I ∞ H A R T. */
static void prescan_equ(const char *src) {
    int save_pass = g_pass;
    g_pass = 1;
    const char *p = src;
    while (*p) {
        if (*p == '\n' || *p == '\r') { p++; continue; }
        const char *line = p;
        while (*p && *p != '\n' && *p != '\r') p++;
        size_t llen = (size_t)(p - line);
        if (llen > 4095) { continue; }
        char buf[4096]; memcpy(buf, line, llen); buf[llen] = 0;
        const char *s = buf;
        while (*s == ' ' || *s == '\t') s++;
        if (!*s || *s == ';') continue;
        const char *eq = strstr(s, " equ ");
        if (!eq) eq = strstr(s, "\tequ ");
        if (!eq) eq = strstr(s, " equ\t");
        if (!eq) continue;
        const char *name_end = eq;
        while (name_end > s && (name_end[-1] == ' ' || name_end[-1] == '\t'))
            name_end--;
        if (name_end <= s) continue;
        size_t nml = (size_t)(name_end - s);
        if (nml >= NAME_MAX) nml = NAME_MAX - 1;
        char name[NAME_MAX]; memcpy(name, s, nml); name[nml] = 0;
        const char *val = eq + 5;
        while (*val == ' ' || *val == '\t') val++;
        if (!*val) continue;
        g_fwd_unresolved = 0;
        long v = parse_expr(val);
        /* Always register the constant, even if forward refs make v wrong.
         * It will be overwritten when the actual `equ` directive is processed
         * during normal assembly. */
        const_set(name, v);
    }
    g_pass = save_pass;
}

static long parse_expr_reloc(const char *s, int *has_sym, int *sec,
                             long *off, char *name, int *glob) {
    g_expr_symcount = 0; g_expr_sym_section = SEC_NONE;
    g_expr_sym_offset = 0; g_expr_sym_name[0] = 0; g_expr_sym_global = 0;
    long v = parse_expr(s);
    if (g_expr_symcount == 1) {
        *has_sym = 1; *sec = g_expr_sym_section; *off = g_expr_sym_offset;
        *glob = g_expr_sym_global;
        strncpy(name, g_expr_sym_name, NAME_MAX-1); name[NAME_MAX-1]=0;
    } else {
        *has_sym = 0;
    }
    return v;
}

/* ------------------------------------------------------------------ */
/* Encoding primitives                                                */
/* ------------------------------------------------------------------ */
static void emit_rex(int w, int r, int x, int b, int force) {
    if (g_bits != 64) return; /* REX prefixes are invalid in 16/32-bit mode (decoded as INC/DEC r32) */
    int rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
    if (w || r || x || b || force) emit(rex);
}
static void emit_modrm(int mod, int reg, int rm) {
    emit((mod << 6) | ((reg & 7) << 3) | (rm & 7));
}
static int fits_imm8(long v){ return v >= -128 && v <= 127; }
static int fits_u8(long v){ return v >= 0 && v <= 255; }

/* Operand-size (0x66) and address-size (0x67) prefix decisions are
 * MODE-DEPENDENT. The "default" operand/address size is 16 in BITS 16,
 * else 32. A prefix is emitted only when the desired size differs from the
 * mode default. This makes the SAME `xor ax,ax` emit `31 c0` in BITS 16 but
 * `66 31 c0` in BITS 32/64. Author: F E R M I ∞ H A R T. */
static int opsize_default(void){ return (g_bits==16)?16:32; }
/* emit the 0x66 operand-size prefix iff `opsize` (16 or 32) != mode default */
static void emit_opsize(int opsize){ if (opsize != opsize_default()) emit(0x66); }
/* ------------------------------------------------------------------ */
/* Tokenizer                                                          */
/* ------------------------------------------------------------------ */
static char *g_tok[MAXTOK];
static int g_ntok = 0;

static void tokenize(char *line) {
    g_ntok = 0;
    char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == 0 || *p == ';' || *p == '\n' || *p == '\r') break;
        char *start = p;
        if (*p == '[') { while (*p && *p != ']') p++; if (*p==']') p++; }
        else if (*p == '"' || *p=='\'' || *p=='`') {
            char q=*p; p++; while (*p && *p!=q) p++; if (*p) p++;
        } else {
            while (*p && *p!=' ' && *p!='\t' && *p!=',' &&
                   *p!=';' && *p!='\n' && *p!='\r') p++;
        }
        if (g_ntok >= MAXTOK) die("too many tokens on line");
        /* Terminate token in place and advance p past the delimiter */
        char delim = *p;
        *p = 0;
        /* Macro expansion: if token is a macro, point to its persistent value */
        Macro *m = macro_find(start);
        g_tok[g_ntok] = m ? m->value : start;
        g_ntok++;
        if (delim == 0) break;
        p++;
    }
}

/* ------------------------------------------------------------------ */
/* Structure support (struc/istruc) - F E R M I ∞ H A R T            */
/* ------------------------------------------------------------------ */
#define MAX_STRUCTS 128
#define MAX_FIELDS 64
#define MAX_ISTRUC_DEPTH 8

typedef struct {
    char name[NAME_MAX];
    int offset;
    int size;
} StructField;

typedef struct {
    char name[NAME_MAX];
    StructField fields[MAX_FIELDS];
    int nfields;
    int total_size;
} StructDef;

static StructDef g_structs[MAX_STRUCTS];
static int g_nstructs = 0;

/* State machine for struc parsing */
static int g_in_struc = 0;
static int g_struc_offset = 0;
static char g_current_struc[NAME_MAX];

/* Stack for nested istruc blocks */
typedef struct {
    int struct_idx;
    int base_offset;
} IStrucFrame;

static IStrucFrame g_istruc_stack[MAX_ISTRUC_DEPTH];
static int g_istruc_depth = 0;

static int find_struct(const char *name) {
    for (int i = 0; i < g_nstructs; i++) {
        if (!strcmp(g_structs[i].name, name)) return i;
    }
    return -1;
}

static int find_field(int struct_idx, const char *field_name) {
    StructDef *s = &g_structs[struct_idx];
    for (int i = 0; i < s->nfields; i++) {
        if (!strcmp(s->fields[i].name, field_name)) return i;
    }
    return -1;
}

static void handle_struc_start(void) {
    if (g_ntok < 2) die("struc requires a name");
    if (g_nstructs >= MAX_STRUCTS) die("too many structures");
    if (g_in_struc) die("nested struc not allowed");
    
    strncpy(g_current_struc, g_tok[1], NAME_MAX-1);
    g_current_struc[NAME_MAX-1] = 0;
    
    if (find_struct(g_current_struc) >= 0) die2("duplicate structure", g_current_struc);
    
    g_in_struc = 1;
    g_struc_offset = 0;
}

static void handle_struc_field(void) {
    if (!g_in_struc) die("field outside struc");
    if (g_ntok < 3) die("field requires: name resb/resw/resd/resq size");
    
    int struct_idx = g_nstructs;
    if (struct_idx >= MAX_STRUCTS) die("too many structures");
    
    StructDef *s = &g_structs[struct_idx];
    if (s->nfields == 0) {
        strncpy(s->name, g_current_struc, NAME_MAX-1);
        s->name[NAME_MAX-1] = 0;
    }
    
    char field_name[NAME_MAX];
    strncpy(field_name, g_tok[0], NAME_MAX-1);
    field_name[NAME_MAX-1] = 0;
    
    int field_size = 0;
    int count = 1;
    
    if (!strcmp(g_tok[1], "resb")) field_size = 1;
    else if (!strcmp(g_tok[1], "resw")) field_size = 2;
    else if (!strcmp(g_tok[1], "resd")) field_size = 4;
    else if (!strcmp(g_tok[1], "resq")) field_size = 8;
    else die2("unknown field type", g_tok[1]);
    
    if (g_ntok >= 3) {
        count = (int)parse_expr(g_tok[2]);
    }
    
    /* Align field to its size */
    int align = field_size;
    g_struc_offset = (g_struc_offset + align - 1) & ~(align - 1);
    
    if (s->nfields >= MAX_FIELDS) die("too many fields in structure");
    
    StructField *f = &s->fields[s->nfields];
    strncpy(f->name, field_name, NAME_MAX-1);
    f->name[NAME_MAX-1] = 0;
    f->offset = g_struc_offset;
    f->size = field_size * count;
    
    /* Define STRUCT.field constant */
    char const_name[NAME_MAX * 2 + 2];
    snprintf(const_name, sizeof(const_name), "%s.%s", g_current_struc, field_name);
    const_set(const_name, g_struc_offset);
    
    s->nfields++;
    g_struc_offset += field_size * count;
}

static void handle_endstruc(void) {
    if (!g_in_struc) die("endstruc without struc");
    
    StructDef *s = &g_structs[g_nstructs];
    s->total_size = g_struc_offset;
    
    /* Define STRUCT_size constant */
    char size_name[NAME_MAX + 6];
    snprintf(size_name, sizeof(size_name), "%s_size", g_current_struc);
    const_set(size_name, g_struc_offset);
    
    g_nstructs++;
    g_in_struc = 0;
}

static void handle_istruc(void) {
    if (g_ntok < 2) die("istruc requires a structure name");
    if (g_istruc_depth >= MAX_ISTRUC_DEPTH) die("istruc nesting too deep");
    
    char name[NAME_MAX];
    strncpy(name, g_tok[1], NAME_MAX-1);
    name[NAME_MAX-1] = 0;
    
    int struct_idx = find_struct(name);
    if (struct_idx < 0) die2("unknown structure", name);
    
    IStrucFrame *frame = &g_istruc_stack[g_istruc_depth];
    frame->struct_idx = struct_idx;
    frame->base_offset = cur_off();
    
    g_istruc_depth++;
}

static void data_define(int unit, int ntok); /* fwd: defined in the data section */

static void handle_at(void) {
    if (g_istruc_depth == 0) die("at without istruc");
    if (g_ntok < 4) die("at requires: at field, db/dw/dd/dq value");
    
    IStrucFrame *frame = &g_istruc_stack[g_istruc_depth - 1];
    StructDef *s = &g_structs[frame->struct_idx];
    
    char field_name[NAME_MAX];
    strncpy(field_name, g_tok[1], NAME_MAX-1);
    field_name[NAME_MAX-1] = 0;
    
    int field_idx = find_field(frame->struct_idx, field_name);
    int at_offset = 0;
    if (field_idx >= 0) {
        at_offset = s->fields[field_idx].offset;
    } else {
        /* NASM semantics: STRUCT.field is a preprocessor define that
         * expands to the numeric offset before assembly, so accept a
         * plain numeric offset here too. */
        char *endp = NULL;
        long v = strtol(field_name, &endp, 0);
        if (endp && endp != field_name && *endp == 0 &&
            v >= 0 && v <= s->total_size) {
            at_offset = (int)v;
        } else {
            die2("unknown field", field_name);
        }
    }

    /* Skip comma token */
    int value_tok = 2;
    if (!strcmp(g_tok[value_tok], ",")) value_tok++;
    
    if (value_tok >= g_ntok - 1) die("at requires a value");

    const char *type = g_tok[value_tok];

    /* Pad to field offset */
    int target_offset = frame->base_offset + at_offset;
    int current_offset = cur_off();

    if (current_offset < target_offset) {
        int pad = target_offset - current_offset;
        for (int i = 0; i < pad; i++) emit(0);
    }

    /* Delegate value emission to data_define so `at` supports strings,
     * multiple comma-separated values and symbol relocations exactly
     * like a plain db/dw/dd/dq line. Shift the value tokens down so
     * they start at index 1, as data_define expects. This line's
     * tokens are not reused afterwards, so mutating g_tok is safe.
     * Author: F E R M I ∞ H A R T. */
    int unit = 0;
    if (!strcmp(type, "db")) unit = 1;
    else if (!strcmp(type, "dw")) unit = 2;
    else if (!strcmp(type, "dd")) unit = 4;
    else if (!strcmp(type, "dq")) unit = 8;
    else die2("unknown data type", type);

    int nvals = g_ntok - (value_tok + 1);
    for (int i = 0; i < nvals; i++) g_tok[1 + i] = g_tok[value_tok + 1 + i];
    g_ntok = 1 + nvals;
    data_define(unit, g_ntok);
}

static void handle_iend(void) {
    if (g_istruc_depth == 0) die("iend without istruc");
    
    IStrucFrame *frame = &g_istruc_stack[g_istruc_depth - 1];
    StructDef *s = &g_structs[frame->struct_idx];
    
    /* Pad to structure size */
    int target_offset = frame->base_offset + s->total_size;
    int current_offset = cur_off();
    
    if (current_offset < target_offset) {
        int pad = target_offset - current_offset;
        for (int i = 0; i < pad; i++) emit(0);
    }
    
    g_istruc_depth--;
}

/* ------------------------------------------------------------------ */
/* Memory operands                                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    int  rip;        /* 1 = RIP-relative symbol reference */
    char sym[NAME_MAX];
    int  base, has_index, index, scale, has_disp;
    long disp;
    int  seg;        /* segment-override prefix byte (0 = none): gs=0x65 fs=0x64 */
    int  addr32;     /* 1 = 32-bit address size ([eax+ecx*4]) → 0x67 prefix */
    int  no_base;    /* 1 = pure displacement, no base reg (e.g. [gs:0x10]) */
    int  disp_has_sym;   /* 1 = disp32 needs an absolute reloc against a label */
    int  disp_sym_sec;   /* section of that label */
    int  disp_sym_glob;  /* label is global → named reloc */
    long disp_sym_off;   /* label's section-relative offset (for named addend) */
    char disp_sym_name[NAME_MAX];
} Mem;


static void parse_mem(const char *tok, Mem *out) {
    if (!validate_operand_len(tok)) die2("parse_mem: operand exceeds max length", tok);
    if (!validate_address_contents(tok)) die2("parse_mem: invalid operand chars", tok);
    
    Mem m; memset(&m,0,sizeof(m)); m.base=-1; m.scale=1;
    char buf[NAME_MAX];
    strncpy(buf, tok, NAME_MAX-1); buf[NAME_MAX-1]=0;
    if (buf[0] != '[') die2("expected memory operand", tok);
    char *p = buf+1; char *end = strchr(p, ']');
    if (!end) die2("unterminated memory operand", tok);
    *end = 0;
    while (*p==' ') p++;
    /* Segment override: [gs:disp], [fs:disp], etc. The "seg:" prefix
     * selects an override prefix byte and (for the common per-CPU form
     * [gs:0x10]) leaves a pure-displacement operand with no base reg.
     * Author: F E R M I ∞ H A R T. */
    {
        char *colon = strchr(p, ':');
        if (colon && (colon - p) <= 2) {
            char segname[3] = {0,0,0};
            int n = (int)(colon - p);
            for (int i=0;i<n && i<2;i++) segname[i] = p[i];
            int sg = -1;
            if (!strcmp(segname,"gs")) sg = 0x65;
            else if (!strcmp(segname,"fs")) sg = 0x64;
            else if (!strcmp(segname,"es")) sg = 0x26;
            else if (!strcmp(segname,"cs")) sg = 0x2e;
            else if (!strcmp(segname,"ss")) sg = 0x36;
            else if (!strcmp(segname,"ds")) sg = 0x3e;
            if (sg >= 0) { m.seg = sg; p = colon + 1; while(*p==' ')p++; }
        }
    }
    /* RIP-relative form: [rel SYM] or [rel SYM+disp] */
    if (strncmp(p, "rel ", 4) == 0) {
        p += 4; while(*p==' ')p++;
        char sym[NAME_MAX]; int i=0;
        while ((isalnum((unsigned char)*p)||*p=='_'||*p=='.') && i<NAME_MAX-1) sym[i++]=*p++;
        sym[i]=0;
        m.rip = 1;
        qualify(sym, m.sym);
        while(*p==' ')p++;
        if (*p=='+'||*p=='-') { int neg=(*p=='-'); p++; long d=parse_expr(p); m.disp = neg?-d:d; m.has_disp=1; }
        *out = m; return;
    }
    /* base+index*scale+disp */
    int sign=1, seen_base=0;
    while (*p) {
        while(*p==' ')p++;
        if (*p==0) break;
        char comp[NAME_MAX]; int ci=0;
        while (*p && *p!='+' && *p!='-' && ci<NAME_MAX-1) comp[ci++]=*p++;
        comp[ci]=0; while(ci>0&&comp[ci-1]==' ')comp[--ci]=0;
        if (ci>0) {
            char *star = strchr(comp,'*'); int scale=1;
            if (star){ *star=0; scale=(int)parse_expr(star+1); }
            int cl=(int)strlen(comp); while(cl>0&&comp[cl-1]==' ')comp[--cl]=0;
            const Reg *r = reg_find(comp);
            if (r) {
                /* Address-size: 64-bit regs are the default; 32-bit regs
                 * select the 0x67 address-size override (same ModRM/SIB
                 * numbering). Mixing sizes in one operand is illegal.
                 * Author: F E R M I ∞ H A R T. */
                int is32 = (r->size == 4);
                if (r->size != 4 && r->size != 8)
                    die2("address register must be 32- or 64-bit", tok);
                if ((seen_base || m.has_index) && m.addr32 != is32)
                    die2("mixed address register sizes", tok);
                if (is32) m.addr32 = 1;
                if (!seen_base && scale==1){ m.base=r->num; seen_base=1; }
                else { m.has_index=1; m.index=r->num; m.scale=scale; }
            } else {
                /* Non-register disp component. If it had a `*`, it is a pure
                 * constant product (e.g. `511 * 8` = the PML4[511] index byte
                 * offset) — apply the scale to the constant. Author: F E R M I ∞ H A R T. */
                int hs=0, sc=SEC_NONE, gl=0; long of=0; char nm[NAME_MAX];
                long dv = parse_expr_reloc(comp, &hs, &sc, &of, nm, &gl) * scale;
                m.disp += sign*dv; m.has_disp=1;
                if (hs && sc!=SEC_NONE) {
                    if (m.disp_has_sym) { m.disp_has_sym=2; }  /* >1 label → bake */
                    else { m.disp_has_sym=1; m.disp_sym_sec=sc; m.disp_sym_glob=gl; m.disp_sym_off=of;
                           strncpy(m.disp_sym_name,nm,NAME_MAX-1); m.disp_sym_name[NAME_MAX-1]=0; }
                }
            }
        }
        if (*p=='+'){sign=1;p++;} else if(*p=='-'){sign=-1;p++;}
    }
    if (m.base<0) {
        /* No base register. Legal for:
         *  - a segment-override pure-displacement operand ([gs:0x10]), or
         *  - a pure absolute-address constant ([TRAMP_BASE+0x20]) used by
         *    fixed-address trampoline code.
         * Both encode as disp32 with no base. Author: F E R M I ∞ H A R T. */
        if (m.seg || m.has_index || m.has_disp) { m.no_base = 1; m.has_disp = 1; *out = m; return; }
        die2("memory operand needs base register", tok);
    }
    *out = m; return;
}

static void mem_rex_bits(Mem *m, int *rex_x, int *rex_b) {
    if (m->rip) { *rex_x=0; *rex_b=0; return; }
    *rex_x = (m->has_index && m->index>=8)?1:0;
    *rex_b = (m->base>=8)?1:0;
}
/* Single choke-point for memory operands: emits the legacy prefixes owned by
 * the effective address (segment override, then 0x67 address-size when the EA
 * uses 32-bit registers) and computes the REX.X/REX.B bits. Every memory
 * encoder MUST call this instead of mem_rex_bits, so the prefix invariant is
 * structural and cannot be forgotten by a new encoder. Prefix order matches
 * nasm byte-for-byte (seg, 0x67, then any 0x66 the caller emits, then REX).
 * Author: F E R M I ∞ H A R T. */
static void mem_begin(Mem *m, int *rex_x, int *rex_b) {
    if (m->seg)    emit(m->seg);
    if (m->addr32) emit(0x67);
    mem_rex_bits(m, rex_x, rex_b);
}
static int scale_bits(int s){ switch(s){case 1:return 0;case 2:return 1;case 4:return 2;case 8:return 3;} die("bad scale"); return 0; }

/* Emit ModRM(+SIB+disp) for a memory operand. trailing_imm = #imm bytes that
 * follow the displacement (needed for RIP reloc addend). */
static void encode_mem(int regfield, Mem *m, int trailing_imm) {
    if (m->rip) {
        emit_modrm(0, regfield, 5);              /* RIP-relative */
        int disp_off = cur_off();
        Sym *s = sym_find(m->sym);
        long extra = m->has_disp ? m->disp : 0;
        if (s && s->defined && s->section!=SEC_NONE) {
            /* reloc against section symbol; addend folds the symbol's offset */
            add_reloc_section(disp_off, s->section,
                              (long)s->offset + extra - 4 - trailing_imm);
        } else {
            /* extern / undefined: reloc against named symbol */
            add_reloc_named(disp_off, m->sym, extra - 4 - trailing_imm);
        }
        emit32(0);
        return;
    }
    if (m->no_base) {
        /* No base register, pure absolute displacement. In 16-bit mode this is
         * encoded as mod=00, rm=110 + disp16 (no SIB) — used by ap_trampoline.S
         * `mov byte [TRAMP_BASE+...]`. In 32/64-bit it's mod=00, rm=100 (SIB),
         * base=101 + optional index + scale → disp32. A label disp emits an
         * R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
        if (g_bits==16 && !m->has_index) {
            emit_modrm(0, regfield, 6);   /* rm=110 → disp16 direct */
            if (m->disp_has_sym==1) {
                int disp_off = cur_off();
                long disp = m->disp;
                /* disp already has g_org from parse_expr for symbols */
                if (!strcmp(g_fmt, "bin")) {
                    emit16((uint32_t)disp);
                } else {
                    if (m->disp_sym_glob) add_reloc_abs32_named(disp_off, g_cur, m->disp_sym_name, disp - m->disp_sym_off);
                    else                  add_reloc_abs32_section(disp_off, g_cur, m->disp_sym_sec, disp);
                    emit16(0);
                }
            } else emit16((uint32_t)m->disp);
            return;
        }
        /* No base register, absolute disp32. In 32-bit mode (no index) the
         * shortest form is mod=00, rm=101 + disp32 (NO SIB) — matches nasm and
         * avoids a 1-byte-per-instruction bloat in the BITS 32 trampoline.
         * In 64-bit mode rm=101 means RIP-relative, so an absolute there (or
         * any indexed form) must use the SIB form mod=00 rm=100, base=101.
         * Author: F E R M I ∞ H A R T. */
        if (g_bits==32 && !m->has_index) {
            emit_modrm(0, regfield, 5);   /* rm=101 → disp32 absolute (32-bit) */
            if (m->disp_has_sym==1) {
                int disp_off = cur_off();
                long disp = m->disp;
                /* disp already has g_org from parse_expr for symbols */
                if (!strcmp(g_fmt, "bin")) {
                    emit32((uint32_t)disp);
                } else {
                    if (m->disp_sym_glob) add_reloc_abs32_named(disp_off, g_cur, m->disp_sym_name, disp - m->disp_sym_off);
                    else                  add_reloc_abs32_section(disp_off, g_cur, m->disp_sym_sec, disp);
                    emit32(0);
                }
            } else emit32((uint32_t)m->disp);
            return;
        }
        /* No base register. Absolute disp32, optionally with an index register
         * (e.g. [P(pd_table) + ecx*8] — the 2MB page-map loop). Encoded as
         * mod=00, rm=100 (SIB); SIB base=101 (disp32) + index (or none=100) +
         * scale. If the disp references a label, emit an R_X86_64_32 reloc
         * (addend = baked disp). Author: F E R M I ∞ H A R T. */
        emit_modrm(0, regfield, 4);
        int nidx = m->has_index ? (m->index & 7) : 4;   /* 100 = no index */
        emit((scale_bits(m->scale)<<6)|(nidx<<3)|5);    /* base=101 → disp32 */
        if (m->disp_has_sym==1) {
            int disp_off = cur_off();
            if (m->disp_sym_glob) add_reloc_abs32_named(disp_off, g_cur, m->disp_sym_name, m->disp - m->disp_sym_off);
            else                  add_reloc_abs32_section(disp_off, g_cur, m->disp_sym_sec, m->disp);
            emit32(0);
        } else {
            emit32((uint32_t)m->disp);
        }
        return;
    }
    int base_low = m->base & 7;
    int need_sib = m->has_index || (base_low==4);
    int mod;
    int disp_zero = (!m->has_disp || m->disp==0);
    if (disp_zero) mod = (base_low==5)?1:0;
    else if (fits_imm8(m->disp)) mod=1; else mod=2;
    if (need_sib) {
        emit_modrm(mod, regfield, 4);
        int idx = m->has_index?(m->index&7):4;
        emit((scale_bits(m->scale)<<6)|(idx<<3)|base_low);
    } else emit_modrm(mod, regfield, base_low);
    if (mod==1) emit((uint8_t)(m->disp&0xff));
    else if (mod==2) emit32((uint32_t)m->disp);
}

/* ------------------------------------------------------------------ */
/* Operand classification                                             */
/* ------------------------------------------------------------------ */
static int is_mem(const char *t){ return t[0]=='['; }

/* ------------------------------------------------------------------ */
/* Instruction encoders                                               */
/* ------------------------------------------------------------------ */

/* MOV in all forms used by stage0. */
static void enc_mov(const char *dst, const char *src) {
    const Reg *rd = reg_find(dst), *rs = reg_find(src);
    /* reg, [mem] */
    if (rd && is_mem(src)) {
        Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
               /* BUG-06: Use short form A1 for mov eax, [disp32] in 32-bit mode */
        if (rd->size==4 && rd->num==0 && m.no_base && !m.has_index && g_bits==32) {
            emit(0xa1);
            emit32((uint32_t)m.disp);
            return;
        }
        if (rd->size==1)      { emit_rex(0,rr,rx,rb,rd->rex_req); emit(0x8a); }
        else if (rd->size==2) { emit(0x66); emit_rex(0,rr,rx,rb,0); emit(0x8b); }
        else                  { emit_rex(rd->size==8,rr,rx,rb,0); emit(0x8b); }
        encode_mem(rd->num, &m, 0); return;
    }
    /* [mem], reg */
    if (is_mem(dst) && rs) {
        Mem m; parse_mem(dst, &m); int rr=(rs->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
               /* BUG-04: Use short form A2 for mov [disp32], al in 32-bit mode */
        if (rs->size==1 && rs->num==0 && m.no_base && !m.has_index && g_bits==32) {
            emit(0xa2);
            emit32((uint32_t)m.disp);
            return;
        }
        if (rs->size==1)      { emit_rex(0,rr,rx,rb,rs->rex_req); emit(0x88); }
        else if (rs->size==2) { emit(0x66); emit_rex(0,rr,rx,rb,0); emit(0x89); }
        else                  { emit_rex(rs->size==8,rr,rx,rb,0); emit(0x89); }
        encode_mem(rs->num, &m, 0); return;
    }
    /* reg, reg */
    if (rd && rs) {
        int rr=(rs->num>=8), rb=(rd->num>=8);
        emit_rex(rd->size==8,rr,0,rb,(rd->rex_req||rs->rex_req));
        emit(rd->size==1?0x88:0x89);
        emit_modrm(3, rs->num, rd->num); return;
    }
    /* reg, imm */
    if (rd && !rs && !is_mem(src)) {
        /* Capture a label ref in the immediate so a 32-bit register load
         * (e.g. `mov eax, P(pml4_table)` for the cr3 value) emits an
         * R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
        int ihs=0,isec=SEC_NONE,igl=0; long ioff=0; char inm[NAME_MAX];
        long imm = parse_expr_reloc(src, &ihs, &isec, &ioff, inm, &igl);
        if (rd->size==8) {
            /* r64 immediate referencing a label (e.g. `mov rsp, P(stack_top)`):
             * emit movabs (REX.W B8+rd io) with a 64-bit absolute reloc so the
             * linker resolves the address. Author: F E R M I ∞ H A R T. */
            if (ihs && isec!=SEC_NONE) {
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xb8+(rd->num&7));
                int io=cur_off();
                if (igl) { add_reloc_abs64(io, g_cur, inm);
                           /* abs64 named carries no addend; fold offset by
                            * using section reloc when there is one */ }
                else     add_reloc_abs64_section(io, g_cur, isec, imm);
                emit64(0); return;
            }
            /* FORWARD symbol ref (a label seen, but not yet defined in this
             * SIZING pass — isec is still SEC_NONE). It WILL become a movabs
             * (10 bytes) in the final pass once the label resolves. The sizing
             * pass MUST reserve those same 10 bytes here, or every label after
             * this instruction shifts by 5 between pass 1 and pass 2 — which
             * desynced forward Jcc displacements (`jz .no_avx` assembled as
             * `74 fe`, an infinite self-loop) and hung the kernel at the TSS
             * setup. Detect "a symbol was referenced" via g_expr_symcount and
             * emit the full movabs width. Author: F E R M I ∞ H A R T. */
            if (g_expr_symcount >= 1) {
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xb8+(rd->num&7));
                emit64(0); return;
            }
            if (imm>=0 && imm<=0xffffffffL) { /* fold to 32-bit (zero-extends) */
                if (rd->num>=8) emit(0x41);
                emit(0xb8+(rd->num&7)); emit32((uint32_t)imm); return;
            }
            if (imm>=-2147483648L && imm<0) { /* mov r/m64,imm32 sign-extended: C7 /0 */
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xc7); emit_modrm(3,0,rd->num); emit32((uint32_t)imm); return;
            }
            /* movabs: REX.W B8+rd io */
            emit_rex(1,0,0,(rd->num>=8),0);
            emit(0xb8+(rd->num&7)); emit64((uint64_t)imm); return;
        }
        if (rd->size==4) { if(rd->num>=8)emit(0x41); emit(0xb8+(rd->num&7));
            if (ihs && isec!=SEC_NONE) {
                /* BUG-02: In bin format, resolve label directly (no reloc) */
                if (!strcmp(g_fmt, "bin")) {
                    emit32((uint32_t)imm);
                } else {
                    int io=cur_off();
                    if (igl) add_reloc_abs32_named(io, g_cur, inm, imm - ioff);
                    else     add_reloc_abs32_section(io, g_cur, isec, imm);
                    emit32(0);
                }
            } else if (ihs && igl) {
                /* EXTERN symbol as a 32-bit immediate (e.g. mov edi,__bss_start):
                 * named R_X86_64_32 reloc, the linker supplies the address.
                 * Author: F E R M I ∞ H A R T. */
                int io=cur_off();
                add_reloc_abs32_named(io, g_cur, inm, imm - ioff);
                emit32(0);
            } else emit32((uint32_t)imm);
            return; }
        if (rd->size==2) { emit(0x66); if(rd->num>=8)emit(0x41); emit(0xb8+(rd->num&7)); emit16((uint32_t)imm); return; }
        /* 8-bit: B0+rd ib (with forced REX for spl/bpl/sil/dil) */
        if (rd->num>=8) emit(0x41); else if (rd->rex_req) emit(0x40);
        emit(0xb0+(rd->num&7)); emit((uint8_t)imm); return;
    }
    die("unsupported mov form");
}

/* mov <size> [mem], imm  (size keyword present) */
static void enc_mov_mem_imm(const char *szkw, const char *memtok, const char *immtok) {
    Mem m; parse_mem(memtok, &m);
    /* Capture a label ref in the immediate (e.g. `mov dword [..], P(pdpt)+3`)
     * so the stored 32-bit value gets an R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
    int ihs=0, isec=SEC_NONE, iglob=0; long ioff=0; char inm[NAME_MAX];
    long imm = parse_expr_reloc(immtok, &ihs, &isec, &ioff, inm, &iglob);
    int rx, rb; mem_begin(&m,&rx,&rb);
    if (strcmp(szkw,"byte")==0) {
        emit_rex(0,0,rx,rb,0); emit(0xc6); encode_mem(0, &m,1); emit((uint8_t)imm);
    } else if (strcmp(szkw,"word")==0) {
        emit(0x66); emit_rex(0,0,rx,rb,0); emit(0xc7); encode_mem(0, &m,2); emit16((uint32_t)imm);
    } else if (strcmp(szkw,"dword")==0) {
        emit_rex(0,0,rx,rb,0); emit(0xc7); encode_mem(0, &m,4);
        if (ihs && isec!=SEC_NONE) {
            /* BUG-12: In bin format, resolve label directly (no reloc) */
            if (!strcmp(g_fmt, "bin")) {
                emit32((uint32_t)imm);
            } else {
                int io=cur_off();
                /* Reloc addend must EXCLUDE the label's own offset (the linker adds
                 * the symbol's final address): addend = baked_value - label_offset.
                 * Author: F E R M I ∞ H A R T. */
                if (iglob) add_reloc_abs32_named(io, g_cur, inm, imm - ioff);
                else       add_reloc_abs32_section(io, g_cur, isec, imm);
                emit32(0);
            }
        } else emit32((uint32_t)imm);
    } else if (strcmp(szkw,"qword")==0) {
        emit_rex(1,0,rx,rb,0); emit(0xc7); encode_mem(0, &m,4);
        /* `mov qword [mem], symbol` (e.g. `mov qword [rax+4], stack_top` for
         * TSS RSP0): the imm32 (sign-extended to 64) is a symbol address, so
         * it needs the SAME R_X86_64_32 reloc the dword case emits — otherwise
         * the raw .bss offset gets baked and RSP0 points at a bogus low
         * address (TSS corruption, #GP/#PF on the first ring transition).
         * Author: F E R M I ∞ H A R T. */
        if (ihs && isec!=SEC_NONE) {
            /* BUG-12: In bin format, resolve label directly (no reloc) */
            if (!strcmp(g_fmt, "bin")) {
                emit32((uint32_t)imm);
            } else {
                int io=cur_off();
                if (iglob) add_reloc_abs32_named(io, g_cur, inm, imm - ioff);
                else       add_reloc_abs32_section(io, g_cur, isec, imm);
                emit32(0);
            }
        } else if (ihs && iglob) {
            int io=cur_off();
            add_reloc_abs32_named(io, g_cur, inm, imm - ioff);
            emit32(0);
        } else emit32((uint32_t)imm);
    } else die2("unknown size keyword", szkw);
}

static void enc_lea(const char *dst, const char *src) {
    const Reg *rd = reg_find(dst);
    if (!rd || !is_mem(src)) die("unsupported lea form");
    Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
    emit_rex(rd->size==8,rr,rx,rb,0); emit(0x8d); encode_mem(rd->num, &m,0);
}

/* movsxd r64, r/m32  (4c 63 /r) */
static void enc_movsxd(const char *dst, const char *src) {
    const Reg *rd=reg_find(dst), *rs=reg_find(src);
    if (!rd) die("movsxd dst not reg");
    if (rs) { emit_rex(1,(rd->num>=8),0,(rs->num>=8),0); emit(0x63); emit_modrm(3,rd->num,rs->num); return; }
    if (is_mem(src)) { Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(1,(rd->num>=8),rx,rb,0); emit(0x63); encode_mem(rd->num, &m,0); return; }
    die("movsxd src");
}

/* movzx/movsx byte/word -> reg (0F B6/B7/BE/BF) */
static void enc_movx(int sign_ext, int srcsize, const char *dst, const char *src) {
    const Reg *rd=reg_find(dst); if(!rd) die("movzx/movsx dst");
    int op = sign_ext ? (srcsize==1?0xbe:0xbf) : (srcsize==1?0xb6:0xb7);
    if (is_mem(src)) { Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(rd->size==8,(rd->num>=8),rx,rb,0); emit(0x0f); emit(op); encode_mem(rd->num, &m,0); return; }
    const Reg *rs=reg_find(src); if(!rs) die("movzx/movsx src");
    emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),0); emit(0x0f); emit(op); emit_modrm(3,rd->num,rs->num);
}

/* ALU reg,imm using /digit group1 (add=0 or=1 and=4 sub=5 xor=6 cmp=7). */
static void enc_alu_ri(int ext, const Reg *rd, long imm) {
    int rb=(rd->num>=8);
    if (rd->size==1) { /* 8-bit: 80 /digit ib (AL short form 04+8*ext) */
        if (rd->num==0) { static const int acc8[8]={0x04,0x0c,0x14,0x1c,0x24,0x2c,0x34,0x3c};
            emit(acc8[ext]); emit((uint8_t)imm); return; }
        emit_rex(0,0,0,rb,rd->rex_req); emit(0x80); emit_modrm(3,ext,rd->num); emit((uint8_t)imm); return;
    }
    /* operand-size prefix: 0x66 when reg width != mode default (e.g.
     * `or eax,1` in BITS 16 needs 66). Author: F E R M I ∞ H A R T. */
    if (rd->size==2) emit_opsize(16); else if (rd->size==4) emit_opsize(32);
    if (fits_imm8(imm)) { emit_rex(rd->size==8,0,0,rb,0); emit(0x83); emit_modrm(3,ext,rd->num); emit((uint8_t)imm); return; }
    /* accumulator short form for imm32: 05/0d/25/2d/35/3d depends on op */
    if (rd->num==0 && (rd->size==8||rd->size==4)) {
        static const int acc[8]={0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d};
        emit_rex(rd->size==8,0,0,0,0); emit(acc[ext]); emit32((uint32_t)imm); return;
    }
    emit_rex(rd->size==8,0,0,rb,0); emit(0x81); emit_modrm(3,ext,rd->num);
    if (rd->size==2) emit16((uint32_t)imm); else emit32((uint32_t)imm);
}
/* ALU reg,reg using the "01+8*ext" opcode family (op /r, r/m,reg). */
static void enc_alu_rr(int opbase, const Reg *rd, const Reg *rs) {
    if (rd->size==1) { /* 8-bit form: opbase-1 (e.g. xor 30 vs 31) */
        emit_rex(0,(rs->num>=8),0,(rd->num>=8),(rd->rex_req||rs->rex_req));
        emit(opbase-1); emit_modrm(3, rs->num, rd->num); return;
    }
    if (rd->size==2) emit_opsize(16); /* 16-bit operand: 0x66 only if not the mode default */
    else if (rd->size==4) emit_opsize(32); /* 32-bit operand: 0x66 in BITS 16 */
    emit_rex(rd->size==8,(rs->num>=8),0,(rd->num>=8),0);
    emit(opbase); emit_modrm(3, rs->num, rd->num);
}

/* generic 2-operand ALU dispatch */
static void enc_alu(const char *mn, const char *dst, const char *src) {
    /* opcode bases: add 01, or 09, and 21, sub 29, xor 31, cmp 39 ; ext digits */
    int ext, rrbase, rmbase;
    if      (!strcmp(mn,"add")){ext=0;rrbase=0x01;rmbase=0x03;}
    else if (!strcmp(mn,"or")) {ext=1;rrbase=0x09;rmbase=0x0b;}
    else if (!strcmp(mn,"and")){ext=4;rrbase=0x21;rmbase=0x23;}
    else if (!strcmp(mn,"sub")){ext=5;rrbase=0x29;rmbase=0x2b;}
    else if (!strcmp(mn,"xor")){ext=6;rrbase=0x31;rmbase=0x33;}
    else if (!strcmp(mn,"cmp")){ext=7;rrbase=0x39;rmbase=0x3b;}
    else { die2("alu?",mn); return; }
    const Reg *rd=reg_find(dst), *rs=reg_find(src);
    /* reg, [mem]  -> rmbase /r */
    if (rd && is_mem(src)) {
        Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(rd->size==8,rr,rx,rb,0); emit(rmbase); encode_mem(rd->num, &m,0); return;
    }
    /* [mem], reg -> rrbase /r */
    if (is_mem(dst) && rs) {
        Mem m; parse_mem(dst, &m); int rr=(rs->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(rs->size==8,rr,rx,rb,0); emit(rrbase); encode_mem(rs->num, &m,0); return;
    }
    if (rd && rs) { enc_alu_rr(rrbase, rd, rs); return; }
    if (rd && !rs && !is_mem(src)) { enc_alu_ri(ext, rd, parse_expr(src)); return; }
    die2("unsupported alu form", mn);
}

/* alu <size> [mem], imm  (e.g. cmp byte [r14],'-') */
static void enc_alu_mem_imm(int ext, const char *szkw, const char *memtok, const char *immtok) {
    Mem m; parse_mem(memtok, &m); long imm=parse_expr(immtok);
    int rx,rb; mem_begin(&m,&rx,&rb);
    if (!strcmp(szkw,"byte")) { emit_rex(0,0,rx,rb,0); emit(0x80); encode_mem(ext, &m,1); emit((uint8_t)imm); }
    else if (!strcmp(szkw,"word")) { emit(0x66); emit_rex(0,0,rx,rb,0);
        if(fits_imm8(imm)){emit(0x83);encode_mem(ext, &m,1);emit((uint8_t)imm);} else {emit(0x81);encode_mem(ext, &m,2);emit16((uint32_t)imm);} }
    else if (!strcmp(szkw,"dword")) { emit_rex(0,0,rx,rb,0);
        if(fits_imm8(imm)){emit(0x83);encode_mem(ext, &m,1);emit((uint8_t)imm);} else {emit(0x81);encode_mem(ext, &m,4);emit32((uint32_t)imm);} }
    else if (!strcmp(szkw,"qword")) { emit_rex(1,0,rx,rb,0);
        if(fits_imm8(imm)){emit(0x83);encode_mem(ext, &m,1);emit((uint8_t)imm);} else {emit(0x81);encode_mem(ext, &m,4);emit32((uint32_t)imm);} }
    else die2("alu mem size", szkw);
}

/* shift reg, imm8 (C1 /4 shl, /5 shr, /7 sar) or reg,1 (D1) */
static void enc_shift(int ext, const char *dst, const char *src) {
    const Reg *rd=reg_find(dst); if(!rd) die("shift dst");
    /* Variable-count shift: shl rax, cl → D3 /4 (uses CL register) */
    const Reg *rc=reg_find(src);
    if (rc && rc->num == 1 && rc->size == 1) { /* cl register */
        if (rd->size==1) { emit_rex(0,0,0,(rd->num>=8),rd->rex_req); emit(0xd2); emit_modrm(3,ext,rd->num); return; }
        if (rd->size==2) emit(0x66);
        emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(0xd3); emit_modrm(3,ext,rd->num); return;
    }
    long n = parse_expr(src); int rb=(rd->num>=8);
    if (rd->size==1) {
        /* 8-bit: D0 /ext (by 1), C0 /ext ib (by imm) */
        if (n==1) { emit_rex(0,0,0,rb,rd->rex_req); emit(0xd0); emit_modrm(3,ext,rd->num); return; }
        emit_rex(0,0,0,rb,rd->rex_req); emit(0xc0); emit_modrm(3,ext,rd->num); emit((uint8_t)n); return;
    }
    if (rd->size==2) emit(0x66); /* 16-bit operand prefix */
    if (n==1) { emit_rex(rd->size==8,0,0,rb,0); emit(0xd1); emit_modrm(3,ext,rd->num); return; }
    emit_rex(rd->size==8,0,0,rb,0); emit(0xc1); emit_modrm(3,ext,rd->num); emit((uint8_t)n);
}

/* inc/dec : reg (FF /0, /1) or  <size> [mem] */
static void enc_incdec(int ext, int ntok) {
    if (ntok==2) { /* inc reg */
        const Reg *rd=reg_find(g_tok[1]); if(!rd) die("inc/dec reg");
        /* BUG-01: In BITS 16/32, use short form (0x40+rd for inc, 0x48+rd for dec) */
        if (g_bits != 64 && rd->size != 1 && rd->num < 8) {
            emit((ext == 0 ? 0x40 : 0x48) + rd->num);
            return;
        }
        emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(rd->size==1?0xfe:0xff); emit_modrm(3,ext,rd->num); return;
    }
    /* inc <size> [mem] : 3 tokens (mnemonic, size, [mem]) */
    const char *szkw=g_tok[1]; Mem m; parse_mem(g_tok[2], &m); int rx,rb; mem_begin(&m,&rx,&rb);
    if (!strcmp(szkw,"byte")) { emit_rex(0,0,rx,rb,0); emit(0xfe); }
    else if (!strcmp(szkw,"word")) { emit(0x66); emit_rex(0,0,rx,rb,0); emit(0xff); }
    else if (!strcmp(szkw,"dword")) { emit_rex(0,0,rx,rb,0); emit(0xff); }
    else if (!strcmp(szkw,"qword")) { emit_rex(1,0,rx,rb,0); emit(0xff); }
    else die2("inc/dec size", szkw);
    encode_mem(ext, &m, 0);
}

/* neg/mul/imul1/div : F7 /3 neg, /4 mul, /5 imul, /6 div, /7 idiv */
static void enc_unary_grp3(int ext, const char *r) {
    const Reg *rd=reg_find(r); if(!rd) die("grp3 needs reg");
    emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(0xf7); emit_modrm(3,ext,rd->num);
}
/* imul r, r/m  (two-operand 0F AF /r) — also handles imul r, [mem] */
static void enc_imul2(const char *dst, const char *src) {
    const Reg *rd=reg_find(dst); if(!rd) die("imul2 dst");
    const Reg *rs=reg_find(src);
    if (rs) {
        /* reg, reg */
        emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),0); emit(0x0f); emit(0xaf);
        emit_modrm(3,rd->num,rs->num);
        return;
    }
    /* reg, [mem] — 0F AF /r with r/m = mem */
    if (is_mem(src)) {
        Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(rd->size==8,(rd->num>=8),rx,rb,0); emit(0x0f); emit(0xaf);
        encode_mem(rd->num, &m, 0);
        return;
    }
    die("imul2 needs reg or [mem] source");
}

static void enc_push(const char *r){ const Reg *rg=reg_find(r); if(!rg||(rg->size!=8&&rg->size!=4))die("push r64/r32"); if(rg->num>=8)emit(0x41); emit(0x50+(rg->num&7)); }
static void enc_pop (const char *r){ const Reg *rg=reg_find(r); if(!rg||(rg->size!=8&&rg->size!=4))die("pop r64/r32");  if(rg->num>=8)emit(0x41); emit(0x58+(rg->num&7)); }

/* call: if target is a symbol defined in .text, resolve to rel32 directly
 * (no reloc, like NASM); otherwise emit a PC32 reloc against the named symbol. */
static void enc_call(const char *t) {
    /* Register-indirect call: `call r12` → FF /2 (REX.B if r8-r15).
     * The operand is a 64-bit GPR, not a branch target. Author: F E R M I ∞ H A R T. */
    const Reg *rg = reg_find(t);
    if (rg && rg->size==8) {
        if (rg->num>=8) emit(0x41);          /* REX.B for r8-r15 */
        emit(0xff); emit_modrm(3, 2, rg->num);  /* /2 = call r/m64 */
        return;
    }
    char q[NAME_MAX]; qualify(t,q); Sym *s=sym_find(q);
    emit(0xe8);
    if (s && s->defined && s->section==SEC_TEXT) {
        long rel = (long)s->offset - (long)(g_textlen+4);
        emit32((uint32_t)rel);
    } else {
        add_reloc_named(g_textlen, q, -4);
        emit32(0);
    }
}

/* SETcc r8: 0F 9X+cond /0 (ModRM.reg=0, rm=reg). The codegen emits
 * `setX al` etc. so the operand is an 8-bit register. Author: F E R M I ∞ H A R T. */

static void qualify(const char *target, char *out) {
    if (target[0]=='.' && g_last_global[0]) {
        size_t gl=strlen(g_last_global), tl=strlen(target);
        if (gl+tl>=NAME_MAX) die("qualified label too long");
        memcpy(out,g_last_global,gl); memcpy(out+gl,target,tl+1);
    } else { strncpy(out,target,NAME_MAX-1); out[NAME_MAX-1]=0; }
}

/* Branch-size relaxation, NASM-style. The decision of rel8 vs rel32 must be
 * made from a SINGLE consistent layout: mixing this-pass branch positions with
 * last-pass target offsets falsely inflates forward displacements and promotes
 * branches that actually fit (observed: disp=3 wrongly sized rel32). So the emit
 * functions during sizing only RECORD each branch's position, target offset and
 * known-ness into parallel arrays; the driver then decides promotions AFTER the
 * pass completes, when every label offset belongs to the same layout. Monotonic:
 * a branch promoted to rel32 never shrinks, so iteration always converges. */
static int  g_branch_long[8192]; /* 1 if this branch ordinal needs rel32 */
static long g_branch_pos[8192];  /* byte offset of the branch (recorded in sizing) */
static char g_branch_tgt[8192][NAME_MAX]; /* qualified target name (re-resolved post-pass) */
static int g_branch_ord = 0;
static int g_sizing = 0;        /* 1 during sizing iterations */

static long branch_target_off(const char *target, int *known) {
    char q[NAME_MAX]; qualify(target,q); Sym *s=sym_find(q);
    if (s && s->defined && s->section==SEC_TEXT) { *known=1; return s->offset; }
    *known=0; return 0;
}

/* Resolve a branch target to its (interned) Sym* by its already-qualified
 * name, or NULL if not yet defined. */
static void *branch_sym_byname(const char *qname) {
    return (void*)sym_find(qname);
}

/* jmp: rel8 (EB) or rel32 (E9). Fixpoint sizing: each sizing pass recomputes
 * every branch's size from the current layout; the driver repeats passes until
 * the layout stops changing (NASM-style shrinking to the minimal encoding). To
 * guarantee termination we also keep a monotonic "sticky long" set: a branch
 * that was long in the PREVIOUS converged attempt stays long, preventing 2-cycles. */
static void enc_jmp(const char *target) {
    /* Far direct jump `jmp [dword] sel:offset` — EA <off> <sel16>.
     * boot.S uses `jmp 0x08:long_mode_entry` (32-bit offset) to reload CS;
     * ap_trampoline.S (BITS 16) uses `jmp dword 0x08:(...)` where `dword`
     * forces a 32-bit offset, which in 16-bit mode needs a 0x66 prefix.
     * The offset may be a label expression needing an R_X86_64_32 reloc.
     * Author: F E R M I ∞ H A R T. */
    {
        /* strip an optional leading size keyword (word/dword) */
        int far_opsize = 32;   /* far-jump offset width: 16 or 32 */
        const char *t = target;
        while (*t==' ') t++;
        if (!strncmp(t,"dword",5) && (t[5]==':'||t[5]==' '||t[5]=='0')) { far_opsize=32; t+=5; while(*t==' ')t++; }
        else if (!strncmp(t,"word",4) && (t[4]==':'||t[4]==' '||t[4]=='0')) { far_opsize=16; t+=4; while(*t==' ')t++; }
        const char *colon = strchr(t, ':');
        /* only treat as far jump if the part before ':' is a pure number
         * (a selector) — avoids clobbering rip-relative / local-label refs */
        if (colon) {
            char selstr[NAME_MAX]; int sl=(int)(colon-t);
            if (sl>0 && sl<NAME_MAX) {
                memcpy(selstr,t,sl); selstr[sl]=0;
                long sel = parse_expr(selstr);
                const char *offexpr = colon+1;
                int hs=0,sc=SEC_NONE,gl=0; long of=0; char nm[NAME_MAX];
                long off = parse_expr_reloc(offexpr,&hs,&sc,&of,nm,&gl);
                emit_opsize(far_opsize);   /* 0x66 if offset width != mode default */
                emit(0xea);
                if (far_opsize==32) {
                    if (hs && sc!=SEC_NONE) {
                        int io=cur_off();
                        /* off already has g_org from parse_expr for symbols */
                        if (!strcmp(g_fmt, "bin")) {
                            emit32((uint32_t)off);
                        } else {
                            if (gl) add_reloc_abs32_named(io,g_cur,nm,off-of);
                            else    add_reloc_abs32_section(io,g_cur,sc,off);
                            emit32(0);
                        }
                    } else emit32((uint32_t)off);
                } else {
                    /* off already has g_org from parse_expr for symbols */
                    emit16((uint32_t)off);
                }
                emit16((uint32_t)sel);
                return;
            }
        }
    }
    /* Register-indirect jump: `jmp r12` → FF /4 (REX.B if r8-r15).
     * Fixed-size (no branch relaxation), so handle before the ordinal
     * machinery. Author: F E R M I ∞ H A R T. */
    const Reg *rg = reg_find(target);
    if (rg && rg->size==8) {
        if (rg->num>=8) emit(0x41);          /* REX.B for r8-r15 */
        emit(0xff); emit_modrm(3, 4, rg->num);  /* /4 = jmp r/m64 */
        return;
    }
    /* Memory-indirect jump: `jmp [rdx+192]` (AT&T `jmp *PC(%rdx)`) → FF /4.
     * Without this it falls through to the relative path and collapses to
     * `eb 00`. ucontext's `jmp *PC(%rdx)` needs it. Author: F E R M I HART. */
    if (is_mem(target)) {
        Mem m; parse_mem(target, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(0,0,rx,rb,0);              /* jmp m64: default 64-bit, no REX.W */
        emit(0xff); encode_mem(4, &m, 0);   /* /4 = jmp r/m64 */
        return;
    }
    if (g_branch_ord >= 8192) die("too many branches");
    int ord = g_branch_ord++;
    int known; long toff = branch_target_off(target,&known);
    if (g_sizing) {  /* record only; the driver decides sizes after the pass */
        g_branch_pos[ord]=g_textlen; qualify(target,g_branch_tgt[ord]);
    }
    /* A jmp whose target is an EXTERN symbol (declared `extern`, defined in
     * another object — e.g. `jmp switch_to_user`) is resolved at LINK time and
     * MUST use the 5-byte near form E9 + R_X86_64_PC32 reloc.  rel8 (EB) has no
     * room for a relocation, so without this the branch collapsed to `eb 00`
     * (jump to the very next instruction) — a silent fall-through into whatever
     * code follows.  Mirror enc_call's extern path: force the long encoding and
     * emit a PC32 reloc against the named symbol.  Author fix: F E R M I HART. */
    char xq[NAME_MAX]; qualify(target,xq); Sym *xs=sym_find(xq);
    int is_extern = (xs && xs->global && !xs->defined);
    int is_long = g_branch_long[ord] || is_extern;
    if (!is_long) { emit(0xeb); emit((uint8_t)(known?toff-(long)(g_textlen+1):0)); }
    else if (is_extern) { emit(0xe9); add_reloc_named(g_textlen, xq, -4); emit32(0); }
    else { emit(0xe9); if(!g_sizing&&!known)die2("jmp target undefined",target);
           emit32((uint32_t)(known?toff-(long)(g_textlen+4):0)); }
}

/* conditional jump: rel8 (70+cc) or rel32 (0F 80+cc). */
static void enc_jcc(int cc, const char *target) {
    if (g_branch_ord >= 8192) die("too many branches");
    int ord = g_branch_ord++;
    int known; long toff = branch_target_off(target,&known);
    if (g_sizing) {  /* record only; the driver decides sizes after the pass */
        g_branch_pos[ord]=g_textlen; qualify(target,g_branch_tgt[ord]);
    }
    int is_long = g_branch_long[ord];
    if (!is_long) { emit(0x70+cc); emit((uint8_t)(known?toff-(long)(g_textlen+1):0)); }
    else { emit(0x0f); emit(0x80+cc); if(!g_sizing&&!known)die2("jcc target undefined",target);
           emit32((uint32_t)(known?toff-(long)(g_textlen+4):0)); }
}

/* After a sizing pass, decide promotions from the just-recorded consistent
 * layout. Target offset is re-read from the Sym NOW (every label holds this
 * pass's offset), so forward and backward branches use the SAME layout. A
 * branch needs rel32 iff, as rel8, its displacement (target - end-of-2-byte-
 * insn) doesn't fit a signed byte. Monotonic: once long, stays long, so the
 * iteration always converges. Returns 1 if any branch was promoted. */
static int branch_decide(int nbr) {
    int changed=0;
    for (int ord=0; ord<nbr; ord++) {
        if (g_branch_long[ord]) continue;          /* already long, sticky */
        Sym *s = (Sym*)branch_sym_byname(g_branch_tgt[ord]);
        if (!s || !s->defined || s->section!=SEC_TEXT) continue; /* external/abs */
        long disp = s->offset - (g_branch_pos[ord] + 2);
        if (!fits_imm8(disp)) { g_branch_long[ord]=1; changed=1; }
    }
    return changed;
}

/* ------------------------------------------------------------------ */
/* Instruction dispatch                                               */
/* ------------------------------------------------------------------ */
static int is_size_kw(const char *t){ return !strcmp(t,"byte")||!strcmp(t,"word")||!strcmp(t,"dword")||!strcmp(t,"qword"); }

/* Join tokens [from..g_ntok) into one expression string (operands like
 * "'a' - 10" get split by the tokenizer on spaces; rejoin them here). */
static void join_from(int from, char *out, int outsz) {
    out[0]=0; int len=0;
    for (int i=from;i<g_ntok;i++){ int tl=(int)strlen(g_tok[i]);
        if (len+tl+1>=outsz) die("operand expression too long");
        memcpy(out+len,g_tok[i],tl); len+=tl; out[len]=0; }
}

static void enc_alu_dispatch(int ext, const char *op) {
    if (g_ntok==4 && is_size_kw(g_tok[1])) enc_alu_mem_imm(ext,g_tok[1],g_tok[2],g_tok[3]);
    else enc_alu(op,g_tok[1],g_tok[2]);
}

/* O(1) instruction dispatch: mnemonics are hashed once into an enum, then
 * a single integer switch routes to the encoder. Author: F E R M I ∞ H A R T. */
typedef enum {
    INSN_add, INSN_and, INSN_btr, INSN_call, INSN_cdq, INSN_cdqe, INSN_clac,
    INSN_clc, INSN_cld, INSN_cli, INSN_clts, INSN_cmp, INSN_cpuid, INSN_cqo,
    INSN_cwde, INSN_dec, INSN_div, INSN_fninit, INSN_fnsave, INSN_fnstcw,
    INSN_fnstsw, INSN_frstor, INSN_fwait, INSN_fxrstor, INSN_fxsave, INSN_hlt,
    INSN_idiv, INSN_imul, INSN_in, INSN_inc, INSN_insb, INSN_insd, INSN_insw,
    INSN_int, INSN_int3, INSN_invlpg, INSN_invpcid, INSN_iret, INSN_iretd, INSN_iretq, INSN_ja,
    INSN_jae, INSN_jb, INSN_jbe, INSN_jc, INSN_je, INSN_jg, INSN_jge, INSN_jl,
    INSN_jle, INSN_jmp, INSN_jnc, INSN_jne, INSN_jns, INSN_jnz, INSN_js,
    INSN_jz, INSN_lea, INSN_leave, INSN_lgdt, INSN_lidt, INSN_lldt, INSN_lock,
    INSN_lodsb, INSN_lodsd, INSN_ltr, INSN_mfence, INSN_monitor, INSN_mov,
    INSN_movsb, INSN_movsd, INSN_movsq, INSN_movsx, INSN_movsxd, INSN_movzx,
    INSN_mul, INSN_mwait, INSN_neg, INSN_nop, INSN_o64, INSN_or, INSN_out,
    INSN_outsb, INSN_outsd, INSN_outsw, INSN_pause, INSN_pop, INSN_popa,
    INSN_popad, INSN_popf, INSN_popfq, INSN_push, INSN_pusha, INSN_pushad,
    INSN_pushf, INSN_pushfq, INSN_rdfsbase, INSN_rdmsr, INSN_rdpkru,
    INSN_rdrand, INSN_rdseed, INSN_rdtsc, INSN_rdtscp, INSN_rep, INSN_repe,
    INSN_repne, INSN_repnz, INSN_repz, INSN_ret, INSN_retf, INSN_retfq,
    INSN_sar, INSN_scasb, INSN_sgdt, INSN_shl, INSN_shr, INSN_sidt, INSN_stac,
    INSN_stc, INSN_std, INSN_sti, INSN_stosb, INSN_stosd, INSN_stosq,
    INSN_stosw, INSN_sub, INSN_swapgs, INSN_syscall, INSN_sysret, INSN_sysretq,
    INSN_sete, INSN_setne, INSN_setl, INSN_setg, INSN_setle, INSN_setge,
    INSN_setb, INSN_setae, INSN_setbe, INSN_seta, INSN_seto, INSN_setno,
    INSN_sets, INSN_setns, INSN_setp, INSN_setnp,
    INSN_test, INSN_ud2, INSN_wbinvd, INSN_wrfsbase, INSN_wrmsr, INSN_wrpkru,
    INSN_xchg, INSN_xgetbv, INSN_xor, INSN_xrstor, INSN_xsave, INSN_xsetbv,
    INSN_COUNT, INSN_UNKNOWN = INSN_COUNT
} InsnKind;

#define INSN_HT_CAP 256
typedef struct { uint32_t hash; uint8_t len; InsnKind kind; const char *name; } InsnHTEntry;
static InsnHTEntry g_insn_ht[INSN_HT_CAP];
static int g_insn_ht_ready = 0;

static void insn_ht_insert(const char *name, InsnKind kind) {
    size_t nl = strlen(name);
    uint32_t h = str_hash(name, nl);
    int mask = INSN_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_insn_ht[i].hash) i = (i + 1) & mask;
    g_insn_ht[i].hash = h;
    g_insn_ht[i].len = (uint8_t)nl;
    g_insn_ht[i].kind = kind;
    g_insn_ht[i].name = name;
}

static void insn_ht_init(void) {
    if (g_insn_ht_ready) return;
#define I(name) insn_ht_insert(#name, INSN_##name)
    I(add); I(and); I(btr); I(call); I(cdq); I(cdqe); I(clac); I(clc); I(cld);
    I(cli); I(clts); I(cmp); I(cpuid); I(cqo); I(cwde); I(dec); I(div);
    I(fninit); I(fnsave); I(fnstcw); I(fnstsw); I(frstor); I(fwait);
    I(fxrstor); I(fxsave); I(hlt); I(idiv); I(imul); I(in); I(inc); I(insb);
    I(insd); I(insw); I(int); I(int3); I(invlpg); I(invpcid); I(iret); I(iretd); I(iretq); I(ja);
    I(jae); I(jb); I(jbe); I(jc); I(je); I(jg); I(jge); I(jl); I(jle); I(jmp);
    I(jnc); I(jne); I(jns); I(jnz); I(js); I(jz); I(lea); I(leave); I(lgdt);
    I(lidt); I(lldt); I(lock); I(lodsb); I(lodsd); I(ltr); I(mfence);
    I(monitor); I(mov); I(movsb); I(movsd); I(movsq); I(movsx); I(movsxd);
    I(movzx); I(mul); I(mwait); I(neg); I(nop); I(o64); I(or); I(out); I(outsb);
    I(outsd); I(outsw); I(pause); I(pop); I(popa); I(popad); I(popf); I(popfq);
    I(push); I(pusha); I(pushad); I(pushf); I(pushfq); I(rdfsbase); I(rdmsr);
    I(rdpkru); I(rdrand); I(rdseed); I(rdtsc); I(rdtscp); I(rep); I(repe);
    I(repne); I(repnz); I(repz); I(ret); I(retf); I(retfq); I(sar); I(scasb);
    I(sgdt); I(shl); I(shr); I(sidt); I(stac); I(stc); I(std); I(sti);
    I(stosb); I(stosd); I(stosq); I(stosw); I(sub); I(swapgs); I(syscall);
    I(sysret); I(sysretq); I(sete); I(setne); I(setl); I(setg); I(setle); I(setge);
    I(setb); I(setae); I(setbe); I(seta); I(seto); I(setno); I(sets); I(setns);
    I(setp); I(setnp); I(test); I(ud2); I(wbinvd); I(wrfsbase); I(wrmsr);
    I(wrpkru); I(xchg); I(xgetbv); I(xor); I(xrstor); I(xsave); I(xsetbv);
#undef I
    g_insn_ht_ready = 1;
}

/* SETcc r8: 0F 9X+cond /0 (ModRM.reg=0, rm=reg). The codegen emits
 * `setX al` etc. so the operand is an 8-bit register. Author: F E R M I ∞ H A R T. */
static void enc_setcc(InsnKind insn, const char *reg) {
    const Reg *rd = reg_find(reg);
    if (!rd || rd->size != 1) die("setcc needs an 8-bit register");
    /* Map INSN to the condition nibble (the 0F 9X opcode byte).
     * SETcc encoding: 0F 90+cc /0, where cc is the condition code.
     * seto=0, setno=1, setb=2(setc=2), setae=3(setnc=3),
     * sete=4(setz=4), setne=5(setnz=5), setbe=6(setna=6), seta=7(setnbe=7),
     * setl=0xC, setge=0xD, setle=0xE, setg=0xF,
     * sets=8, setns=9, setp=0xA(setpo=0xA), setnp=0xB. */
    uint8_t cc;
    switch (insn) {
        case INSN_seto:  cc = 0; break;
        case INSN_setno: cc = 1; break;
        case INSN_setb:  cc = 2; break;
        case INSN_setae: cc = 3; break;
        case INSN_sete:  cc = 4; break;
        case INSN_setne: cc = 5; break;
        case INSN_setbe: cc = 6; break;
        case INSN_seta:  cc = 7; break;
        case INSN_sets:  cc = 8; break;
        case INSN_setns: cc = 9; break;
        case INSN_setp:  cc = 0xA; break;
        case INSN_setnp: cc = 0xB; break;
        case INSN_setl:  cc = 0xC; break;
        case INSN_setge: cc = 0xD; break;
        case INSN_setle: cc = 0xE; break;
        case INSN_setg:  cc = 0xF; break;
        default:         cc = 0; break;
    }
    emit(0x0f); emit(0x90 + (cc & 0xF));
    /* REX: W=0, R=0 (the /0 extension), X=0, B=(rd>=8), force for spl/bpl/sil/dil */
    emit_rex(0, 0, 0, rd->num >= 8, rd->rex_req);
    emit_modrm(3, 0, rd->num & 7);          /* /0, register-direct */
}
static InsnKind insn_kind(const char *op) {
    if (!g_insn_ht_ready) insn_ht_init();
    size_t nl = strlen(op);
    uint32_t h = str_hash(op, nl);
    int mask = INSN_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (g_insn_ht[i].hash) {
        if (g_insn_ht[i].hash == h && g_insn_ht[i].len == nl &&
            memcmp(op, g_insn_ht[i].name, nl) == 0)
            return g_insn_ht[i].kind;
        i = (i + 1) & mask;
    }
    return INSN_UNKNOWN;
}

static void do_instruction(void) {
    const char *op = g_tok[0];
    const size_t oplen = strlen(op);
#define OP_IS(lit) (oplen == (sizeof(lit) - 1) && memcmp(op, (lit), sizeof(lit) - 1) == 0)
    /* o64/o32/a32 operand/address-size override prefixes. `o64 sysret`
     * forces REX.W → sysretq (48 0F 07). Emit the prefix, drop the
     * prefix token, and fall through to encode the real instruction.
     * For o64 specifically we special-case the known REX.W forms.
     * Author: F E R M I ∞ H A R T. */
    if (OP_IS("o64")) {
        if (g_ntok>=2 && !strcmp(g_tok[1],"sysret")) { emit(0x48); emit(0x0f); emit(0x07); return; }
        if (g_ntok>=2 && !strcmp(g_tok[1],"iret"))   { emit(0x48); emit(0xcf); return; }
        /* generic: emit REX.W then re-dispatch the tail */
        emit(0x48);
        for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
        g_ntok--; op = g_tok[0];
    }
    /* Rejoin a multi-token second operand that is an arithmetic expression
     * (e.g. "'a' - 10"): only when the 3rd token onward are operator/number
     * pieces, NOT a "byte [mem]" memory form. */
    if (g_ntok>3 && g_tok[1][0]!='[' && !is_size_kw(g_tok[2])) {
        int arith=0;
        for (int i=3;i<g_ntok;i++){ char c=g_tok[i][0];
            if (c=='+'||c=='-'||c=='*'||isdigit((unsigned char)c)||c=='\'') arith=1; }
        if (arith && !is_size_kw(g_tok[1])) {
            char ex[256]; join_from(2,ex,sizeof(ex));
            size_t exlen=strlen(ex);
            /* g_tok[2] is char[NAME_MAX]; a joined operand longer than that would
             * be silently truncated by strncpy -> a silent miscompile. Fail loud
             * instead. (No current stage0 *.basm input triggers this.) */
            if (exlen >= (size_t)NAME_MAX) die("operand expression too long for token buffer");
            memcpy(g_tok[2],ex,exlen+1); g_ntok=3;
        }
    }
    /* Rejoin a multi-token immediate in "mov <size> [mem], expr" form */
    if (g_ntok>4 && is_size_kw(g_tok[1]) && g_tok[2][0]=='[') {
        int arith=0;
        for (int i=4;i<g_ntok;i++){ char c=g_tok[i][0];
            if (c=='+'||c=='-'||c=='*'||isdigit((unsigned char)c)||c=='\'') arith=1; }
        if (arith) {
            char ex[256]; join_from(3,ex,sizeof(ex));
            size_t exlen=strlen(ex);
            if (exlen >= (size_t)NAME_MAX) die("operand expression too long for token buffer");
            memcpy(g_tok[3],ex,exlen+1); g_ntok=4;
        }
    }
    switch (insn_kind(op)) {
    case INSN_add:
    {
        enc_alu_dispatch(0, op);
    }
    break;
    case INSN_and:
    {
        enc_alu_dispatch(4, op);
    }
    break;
    case INSN_btr:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=4&&r->size!=8))die("btr needs r32/r64, imm8");
        long imm=parse_expr(g_tok[2]); if(!fits_u8(imm))die("btr imm out of range");
        emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xba); emit_modrm(3,6,r->num); emit((uint8_t)imm);
    }
    break;
    case INSN_cwde:
    {
        emit(0x98);
    }
    break;
    case INSN_cmp:
    {
        enc_alu_dispatch(7, op);
    }
    break;
    case INSN_cli:
    {
        emit(0xfa);
    }
    break;
    case INSN_cld:
    {
        emit(0xfc);
    }
    break;
    case INSN_clc:
    {
        emit(0xf8);
    }
    break;
    case INSN_cdq:
    {
        emit(0x99);
    }
    break;
    case INSN_call:
    {
        enc_call(g_tok[1]);
    }
    break;
    case INSN_cqo:
    {
        emit(0x48); emit(0x99);
    }
    break;
    case INSN_cdqe:
    {
        emit(0x48); emit(0x98);
    }
    break;
    case INSN_cpuid:
    {
        emit(0x0f); emit(0xa2);
    }
    break;
    case INSN_clac:
    {
        emit(0x0f); emit(0x01); emit(0xca);
    }
    break;
    case INSN_clts:
    {
        emit(0x0f); emit(0x06);
    }
    break;
    case INSN_dec:
    {
        enc_incdec(1,g_ntok);
    }
    break;
    case INSN_div:
    {
        enc_unary_grp3(6,g_tok[1]);
    }
    break;
    case INSN_fninit:
    {
        emit(0xdb); emit(0xe3);
    }
    break;
    case INSN_fwait:
    {
        emit(0x9b);
    }
    break;
    case INSN_fnstsw:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=2||r->num!=0)die("fnstsw supports ax"); emit(0xdf); emit(0xe0);
    }
    break;
    case INSN_fnstcw:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0xd9); encode_mem(7,&m,0);
    }
    break;
    case INSN_frstor:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0xdd); encode_mem(4,&m,0);
    }
    break;
    case INSN_fnsave:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0xdd); encode_mem(6,&m,0);
    }
    break;
    case INSN_fxsave:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0xae); encode_mem(0,&m,0);
    }
    break;
    case INSN_fxrstor:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0xae); encode_mem(1,&m,0);
    }
    break;
    case INSN_int3:
    {
        emit(0xcc);
    }
    break;
    case INSN_insd:
    {
        emit(0x6d);
    }
    break;
    case INSN_insb:
    {
        emit(0x6c);
    }
    break;
    case INSN_inc:
    {
        enc_incdec(0,g_ntok);
    }
    break;
    case INSN_idiv:
    {
        enc_unary_grp3(7,g_tok[1]);
    }
    break;
    case INSN_imul:
    {
        if (g_ntok==3) {
            if (reg_find(g_tok[2])) enc_imul2(g_tok[1],g_tok[2]);
            else if (is_mem(g_tok[2])) enc_imul2(g_tok[1],g_tok[2]);
            else { /* imul reg, imm */
                const Reg*rd=reg_find(g_tok[1]); if(!rd)die("imul reg,imm");
                long imm=parse_expr(g_tok[2]);
                emit_rex(rd->size==8,(rd->num>=8),0,(rd->num>=8),0);
                if (fits_imm8(imm)){ emit(0x6b); emit_modrm(3,rd->num,rd->num); emit((uint8_t)imm); }
                else { emit(0x69); emit_modrm(3,rd->num,rd->num); emit32((uint32_t)imm); }
            }
        } else if (g_ntok==2) enc_unary_grp3(5,g_tok[1]);
    }
    break;
    case INSN_int:
    {
        if (g_ntok != 2) die("int needs imm8 vector");
        long imm = parse_expr(g_tok[1]);
        if (!fits_u8(imm)) die("int vector out of range");
        emit(0xcd); emit((uint8_t)imm);
    }
    break;
    case INSN_iret:
    case INSN_iretd:
    {
        emit(0xcf);
    }
    break;
    case INSN_iretq:
    {
        emit(0x48); emit(0xcf);
    }
    break;
    case INSN_in:
    {
        const Reg*rd=reg_find(g_tok[1]); const Reg*rp=reg_find(g_tok[2]);
        if(!rd||!rp||rp->num!=2) die("in: use 'in al|ax|eax, dx'");
        if(rd->size==1) emit(0xec);
        else if(rd->size==2){ emit_opsize(16); emit(0xed); }
        else if(rd->size==4){ emit_opsize(32); emit(0xed); }
        else die("in: bad dest size");
    }
    break;
    case INSN_insw:
    {
        emit(0x66); emit(0x6d);
    }
    break;
    case INSN_invlpg:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0x01); encode_mem(7,&m,0);
    }
    break;
    case INSN_invpcid:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=8)die("invpcid needs r64, m128");
        Mem m; parse_mem(g_tok[2],&m); int rx,rb; mem_begin(&m,&rx,&rb);
        /* INVPCID: 66 0F 38 82 /r — r64 implicito em modo 64-bit, sem REX.W (== NASM) */
        emit(0x66); emit_rex(0,(r->num>=8),rx,rb,0); emit(0x0f); emit(0x38); emit(0x82); encode_mem(r->num,&m,0);
    }
    break;
    case INSN_hlt:
    {
        emit(0xf4);
    }
    break;
    case INSN_jz:
    {
        enc_jcc(0x4,g_tok[1]);
    }
    break;
    case INSN_js:
    {
        enc_jcc(0x8,g_tok[1]);
    }
    break;
    case INSN_jnz:
    {
        enc_jcc(0x5,g_tok[1]);
    }
    break;
    case INSN_jns:
    {
        enc_jcc(0x9,g_tok[1]);
    }
    break;
    case INSN_jne:
    {
        enc_jcc(0x5,g_tok[1]);
    }
    break;
    case INSN_jnc:
    {
        enc_jcc(0x3,g_tok[1]);
    }
    break;
    case INSN_jle:
    {
        enc_jcc(0xe,g_tok[1]);
    }
    break;
    case INSN_jl:
    {
        enc_jcc(0xc,g_tok[1]);
    }
    break;
    case INSN_jge:
    {
        enc_jcc(0xd,g_tok[1]);
    }
    break;
    case INSN_jg:
    {
        enc_jcc(0xf,g_tok[1]);
    }
    break;
    case INSN_je:
    {
        enc_jcc(0x4,g_tok[1]);
    }
    break;
    case INSN_jc:
    {
        enc_jcc(0x2,g_tok[1]);
    }
    break;
    case INSN_jbe:
    {
        enc_jcc(0x6,g_tok[1]);
    }
    break;
    case INSN_jb:
    {
        enc_jcc(0x2,g_tok[1]);
    }
    break;
    case INSN_jae:
    {
        enc_jcc(0x3,g_tok[1]);
    }
    break;
    case INSN_ja:
    {
        enc_jcc(0x7,g_tok[1]);
    }
    break;
    case INSN_jmp:
    {
        /* Far jump operands like `dword 0x08:(long_mode_entry - VMA + LMA)`
        * get split across tokens (size keyword + selector:offset with spaces
        * inside the parens). Rejoin if any token carries a ':' or the first
        * is a size keyword. A space after a leading size keyword is kept so
        * enc_jmp can strip it. Author: F E R M I ∞ H A R T. */
        int has_colon=0; for(int k=1;k<g_ntok;k++) if(strchr(g_tok[k],':')){has_colon=1;break;}
        if (g_ntok>2 && (has_colon || is_size_kw(g_tok[1]))) {
        char j[256]; size_t jl=0; j[0]=0;
        for (int k=1;k<g_ntok;k++){ size_t tl=strlen(g_tok[k]);
        if (jl+tl<sizeof(j)-1){ memcpy(j+jl,g_tok[k],tl); jl+=tl; j[jl]=0; }
        if (k==1 && is_size_kw(g_tok[k]) && jl<sizeof(j)-1){ j[jl++]=' '; j[jl]=0; } }
        enc_jmp(j);
        } else enc_jmp(g_tok[1]);
    }
    break;
    case INSN_lodsd:
    {
        emit(0xad);
    }
    break;
    case INSN_lodsb:
    {
        emit(0xac);
    }
    break;
    case INSN_leave:
    {
        emit(0xc9);
    }
    break;
    case INSN_lea:
    {
        enc_lea(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_lgdt:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0x01); encode_mem(2,&m,0);
    }
    break;
    case INSN_lidt:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0x01); encode_mem(3,&m,0);
    }
    break;
    case INSN_ltr:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r)die("ltr needs r/m16");
        if(r->num>=8)emit_rex(0,0,0,1,0); emit(0x0f); emit(0x00); emit_modrm(3,3,r->num);
    }
    break;
    case INSN_lock:
    {
        emit(0xf0);
        for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
        g_ntok--; do_instruction();
    }
    break;
    case INSN_lldt:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=2)die("lldt needs r/m16"); if(r->num>=8)emit_rex(0,0,0,1,0); emit(0x0f); emit(0x00); emit_modrm(3,2,r->num);
    }
    break;
    case INSN_mul:
    {
        enc_unary_grp3(4,g_tok[1]);
    }
    break;
    case INSN_movsxd:
    {
        enc_movsxd(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_movsd:
    {
        emit(0xa5);
    }
    break;
    case INSN_movsb:
    {
        emit(0xa4);
    }
    break;
    case INSN_mov:
    {
        /* mov Sreg, r/m16 (8E /r) and mov r/m16, Sreg (8C /r). Segment regs
        * (es=0,cs=1,ss=2,ds=3,fs=4,gs=5) are needed for GDT segment reloads.
        * NASM emits no operand-size prefix for these. Ref: Intel SDM Vol 2. */
        /* mov r32/r64, crN (0F 20 /r) and mov crN, r32/r64 (0F 22 /r).
        * In 32-bit (trampoline) code the GPR is r32 and no REX is emitted;
        * in long mode it's r64. The 0F 20/22 opcode bytes are identical —
        * operand size follows the current BITS mode. Accept r32 or r64.
        * Author: F E R M I ∞ H A R T. */
        int cd = cr_reg(g_tok[1]);
        int cs2 = cr_reg(g_tok[2]);
        if (cd >= 0) { const Reg*rs=reg_find(g_tok[2]); if(!rs||(rs->size!=8&&rs->size!=4))die("mov crN needs r32/r64");
        if(rs->num>=8||cd>=8)emit(0x40|((cd>=8)<<2)|((rs->num>=8)<<0)); emit(0x0f); emit(0x22); emit_modrm(3,cd&7,rs->num&7); }
        else if (cs2 >= 0) { const Reg*rd=reg_find(g_tok[1]); if(!rd||(rd->size!=8&&rd->size!=4))die("mov from crN needs r32/r64");
        if(rd->num>=8||cs2>=8)emit(0x40|((cs2>=8)<<2)|((rd->num>=8)<<0)); emit(0x0f); emit(0x20); emit_modrm(3,cs2&7,rd->num&7); }
        else {
        int sd = seg_reg(g_tok[1]);
        int ss2 = seg_reg(g_tok[2]);
        if (sd >= 0) { const Reg*rs=reg_find(g_tok[2]); if(!rs)die("mov sreg needs r16/r32");
        if(rs->num>=8)emit(0x41); emit(0x8e); emit_modrm(3,sd,rs->num&7); }
        else if (ss2 >= 0) { const Reg*rd=reg_find(g_tok[1]); if(!rd)die("mov from sreg needs r16/r32");
        if(rd->size==2)emit(0x66); if(rd->num>=8)emit(0x41); emit(0x8c); emit_modrm(3,ss2,rd->num&7); }
        else if (g_ntok==4 && is_size_kw(g_tok[1])) {
        /* If source is a register (not immediate), dispatch to enc_mov.
        * enc_mov_mem_imm only handles <size> [mem], imm — not <size> [mem], reg */
        if (reg_find(g_tok[3])) enc_mov(g_tok[2], g_tok[3]);
        else enc_mov_mem_imm(g_tok[1],g_tok[2],g_tok[3]);
        }
        else enc_mov(g_tok[1],g_tok[2]);
        }
    }
    break;
    case INSN_movzx:
    {
        if(is_size_kw(g_tok[2]))enc_movx(0,!strcmp(g_tok[2],"byte")?1:2,g_tok[1],g_tok[3]); else { /* infer from src reg */ const Reg*rs=reg_find(g_tok[2]); enc_movx(0, rs&&rs->size==1?1:2, g_tok[1],g_tok[2]); }
    }
    break;
    case INSN_movsx:
    {
        if(is_size_kw(g_tok[2]))enc_movx(1,!strcmp(g_tok[2],"byte")?1:2,g_tok[1],g_tok[3]); else { const Reg*rs=reg_find(g_tok[2]); enc_movx(1, rs&&rs->size==1?1:2, g_tok[1],g_tok[2]); }
    }
    break;
    case INSN_movsq:
    {
        emit(0x48); emit(0xa5);
    }
    break;
    case INSN_monitor:
    {
        emit(0x0f); emit(0x01); emit(0xc8);
    }
    break;
    case INSN_mwait:
    {
        emit(0x0f); emit(0x01); emit(0xc9);
    }
    break;
    case INSN_mfence:
    {
        emit(0x0f); emit(0xae); emit(0xf0);
    }
    break;
    case INSN_neg:
    {
        enc_unary_grp3(3,g_tok[1]);
    }
    break;
    case INSN_nop:
    {
        emit(0x90);
    }
    break;
    case INSN_outsd:
    {
        emit(0x6f);
    }
    break;
    case INSN_outsb:
    {
        emit(0x6e);
    }
    break;
    case INSN_or:
    {
        enc_alu_dispatch(1, op);
    }
    break;
    case INSN_out:
    {
        const Reg*rp=reg_find(g_tok[1]); const Reg*rs=reg_find(g_tok[2]);
        if(!rp) { long port=parse_expr(g_tok[1]); rs=reg_find(g_tok[2]);
        if(!fits_u8(port)||!rs||rs->num!=0) die("out imm8: use 'out imm8, al|ax|eax'");
        if(rs->size==1){ emit(0xe6); emit((uint8_t)port); }
        else if(rs->size==2){ emit_opsize(16); emit(0xe7); emit((uint8_t)port); }
        else if(rs->size==4){ emit_opsize(32); emit(0xe7); emit((uint8_t)port); }
        else die("out imm8: bad src size"); return; }
        if(rp->num!=2||!rs) die("out: use 'out dx, al|ax|eax'");
        if(rs->size==1) emit(0xee);
        else if(rs->size==2){ emit_opsize(16); emit(0xef); }
        else if(rs->size==4){ emit_opsize(32); emit(0xef); }
        else die("out: bad src size");
    }
    break;
    case INSN_outsw:
    {
        emit(0x66); emit(0x6f);
    }
    break;
    case INSN_popad:
    {
        emit(0x61);
    }
    break;
    case INSN_popa:
    {
        emit(0x61);
    }
    break;
    case INSN_push:
    {
        /* push r64 | push imm (optionally with a size keyword, e.g.
        * `push qword 0x08`). NASM: imm8 sign-extended -> 6A ib, else
        * imm32 sign-extended -> 68 id. Default operand size is 64 in
        * long mode, so no operand-size prefix is emitted. */
        if (reg_find(g_tok[1])) enc_push(g_tok[1]);
        else if (is_mem(g_tok[1]) || (is_size_kw(g_tok[1]) && g_ntok>2 && is_mem(g_tok[2]))) {
        /* push m64: FF /6. Handles `push qword [gs:0x10]` and
        * `push [mem]`. Segment override precedes the opcode.
        * Author: F E R M I ∞ H A R T. */
        const char *mt = is_mem(g_tok[1]) ? g_tok[1] : g_tok[2];
        Mem m; parse_mem(mt, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(0,0,rx,rb,0);   /* default op size 64 in long mode; no REX.W */
        emit(0xff); encode_mem(6, &m, 0);
        }
        else {
        const char *imt = is_size_kw(g_tok[1]) ? g_tok[2] : g_tok[1];
        g_expr_symcount = 0;  /* Reset before parsing */
        long imm = parse_expr(imt);
        /* BUG-03: If immediate is a label, always use imm32 form to avoid
         * size mismatch between pass 1 (label=0, fits imm8) and pass 2
         * (label=large value, needs imm32). */
        if (g_expr_symcount > 0) {
            emit(0x68); emit32((uint32_t)imm);
        } else if (fits_imm8(imm)) { 
            emit(0x6a); emit((uint8_t)imm); 
        } else { 
            emit(0x68); emit32((uint32_t)imm); 
        }
        }
    }
    break;
    case INSN_pop:
    {
        /* pop m64: 8F /0. Mirrors push m64 (FF /6). ucontext's `pop PC(%rdx)`
        * pops the return address straight into the saved context. F E R M I HART. */
        if (!reg_find(g_tok[1]) &&
        (is_mem(g_tok[1]) || (is_size_kw(g_tok[1]) && g_ntok>2 && is_mem(g_tok[2])))) {
        const char *mt = is_mem(g_tok[1]) ? g_tok[1] : g_tok[2];
        Mem m; parse_mem(mt, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(0,0,rx,rb,0);           /* default op size 64; no REX.W */
        emit(0x8f); encode_mem(0, &m, 0);  /* /0 = pop r/m64 */
        } else enc_pop(g_tok[1]);
    }
    break;
    case INSN_pushf:
    {
        /* BUG-05: In 32/64-bit mode, pushf is 1 byte (0x9c).
         * In 16-bit mode, pushfd needs prefix (0x66 0x9c). */
        if (g_bits == 16) emit(0x66);
        emit(0x9c);
    }
    break;
    case INSN_pushfq:
    {
        emit(0x9c);
    }
    break;
    case INSN_popf:
    {
        /* BUG-05: In 32/64-bit mode, popf is 1 byte (0x9d).
         * In 16-bit mode, popfd needs prefix (0x66 0x9d). */
        if (g_bits == 16) emit(0x66);
        emit(0x9d);
    }
    break;
    case INSN_popfq:
    {
        emit(0x9d);
    }
    break;
    case INSN_pushad:
    {
        emit(0x60);
    }
    break;
    case INSN_pause:
    {
        emit(0xf3); emit(0x90);
    }
    break;
    case INSN_ret:
    {
        emit(0xc3);
    }
    break;
    case INSN_retfq:
    {
        emit(0x48); emit(0xcb);
    }
    break;
    case INSN_rep:
    {
        int rp = (g_cur==SEC_TEXT) ? g_textlen : -1;
        emit(0xf3);
        for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
        g_ntok--; do_instruction();
        /* NASM emits operand-size prefix (66) BEFORE rep (f3): swap to match */
        if (rp >= 0 && g_textlen > rp+1 && g_text[rp+1] == 0x66) {
            g_text[rp] = 0x66; g_text[rp+1] = 0xf3;
        }
    }
    break;
    case INSN_repne:
    {
        int rp = (g_cur==SEC_TEXT) ? g_textlen : -1;
        emit(0xf2);
        for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
        g_ntok--; do_instruction();
        if (rp >= 0 && g_textlen > rp+1 && g_text[rp+1] == 0x66) {
            g_text[rp] = 0x66; g_text[rp+1] = 0xf2;
        }
    }
    break;
    case INSN_rdmsr:
    {
        emit(0x0f); emit(0x32);
    }
    break;
    case INSN_rdtsc:
    {
        emit(0x0f); emit(0x31);
    }
    break;
    case INSN_rdtscp:
    {
        emit(0x0f); emit(0x01); emit(0xf9);
    }
    break;
    case INSN_rdrand:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=2&&r->size!=4&&r->size!=8))die("rdrand needs r16/r32/r64");
        emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0xf3); emit(0x0f); emit(0xc7); emit_modrm(3,6,r->num);
    }
    break;
    case INSN_rdseed:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=2&&r->size!=4&&r->size!=8))die("rdseed needs r16/r32/r64");
        emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0xf3); emit(0x0f); emit(0xc7); emit_modrm(3,7,r->num);
    }
    break;
    case INSN_rdpkru:
    {
        emit(0x0f); emit(0x01); emit(0xe7);
    }
    break;
    case INSN_rdfsbase:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=4&&r->size!=8))die("rdfsbase needs r32/r64");
        emit(0xf3); emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xae); emit_modrm(3,0,r->num);
    }
    break;
    case INSN_retf:
    {
        emit(0xcb);
    }
    break;
    case INSN_sub:
    {
        enc_alu_dispatch(5, op);
    }
    break;
    case INSN_stosd:
    {
        emit(0xab);
    }
    break;
    case INSN_stosb:
    {
        emit(0xaa);
    }
    break;
    case INSN_sti:
    {
        emit(0xfb);
    }
    break;
    case INSN_std:
    {
        emit(0xfd);
    }
    break;
    case INSN_stc:
    {
        emit(0xf9);
    }
    break;
    case INSN_shr:
    {
        enc_shift(5,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_shl:
    {
        enc_shift(4,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_scasb:
    {
        emit(0xae);
    }
    break;
    case INSN_sar:
    {
        enc_shift(7,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_sete: case INSN_setne: case INSN_setl: case INSN_setg:
    case INSN_setle: case INSN_setge: case INSN_setb: case INSN_setae:
    case INSN_setbe: case INSN_seta: case INSN_seto: case INSN_setno:
    case INSN_sets: case INSN_setns: case INSN_setp: case INSN_setnp:
    {
        /* SETcc r8 — all share the same encoding via enc_setcc */
        enc_setcc(insn_kind(g_tok[0]), g_tok[1]);
    }
    break;
    case INSN_syscall:
    {
        emit(0x0f); emit(0x05);
    }
    break;
    case INSN_stosw:
    {
        emit(0x66); emit(0xab);
    }
    break;
    case INSN_stosq:
    {
        emit(0x48); emit(0xab);
    }
    break;
    case INSN_sysret:
    {
        emit(0x0f); emit(0x07);
    }
    break;
    case INSN_sysretq:
    {
        emit(0x0f); emit(0x07);
    }
    break;
    case INSN_swapgs:
    {
        emit(0x0f); emit(0x01); emit(0xf8);
    }
    break;
    case INSN_stac:
    {
        emit(0x0f); emit(0x01); emit(0xcb);
    }
    break;
    case INSN_sgdt:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0x01); encode_mem(0,&m,0);
    }
    break;
    case INSN_sidt:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0x01); encode_mem(1,&m,0);
    }
    break;
    case INSN_test:
    {
        const Reg*rd=reg_find(g_tok[1]),*rs=reg_find(g_tok[2]);
        if(rd && rs){
        if(rd->size==1){ emit_rex(0,(rs->num>=8),0,(rd->num>=8),(rd->rex_req||rs->rex_req)); emit(0x84); emit_modrm(3,rs->num,rd->num); }
        else { if(rd->size==2)emit(0x66); emit_rex(rd->size==8,(rs->num>=8),0,(rd->num>=8),0); emit(0x85); emit_modrm(3,rs->num,rd->num); }
        } else if(rd && !rs && !is_mem(g_tok[2])){
        /* test reg,imm — F6 /0 ib (8-bit) or F7 /0 id; accumulator
        * short form A8 ib / A9 id (matches NASM byte-for-byte).
        * test has NO imm8-sign-extended (0x83) form. ∞HART */
        long imm=parse_expr(g_tok[2]); int rb=(rd->num>=8);
        if(rd->size==1){
        if(rd->num==0 && !rd->rex_req){ emit(0xa8); emit((uint8_t)imm); }
        else { emit_rex(0,0,0,rb,rd->rex_req); emit(0xf6); emit_modrm(3,0,rd->num); emit((uint8_t)imm); }
        } else {
        if(rd->size==2)emit(0x66);
        if(rd->num==0){ emit_rex(rd->size==8,0,0,0,0); emit(0xa9); emit32((uint32_t)imm); }
        else { emit_rex(rd->size==8,0,0,rb,0); emit(0xf7); emit_modrm(3,0,rd->num); emit32((uint32_t)imm); }
        }
        } else die("test reg,reg");
    }
    break;
    case INSN_ud2:
    {
        emit(0x0f); emit(0x0b);
    }
    break;
    case INSN_wrmsr:
    {
        emit(0x0f); emit(0x30);
    }
    break;
    case INSN_wrpkru:
    {
        emit(0x0f); emit(0x01); emit(0xef);
    }
    break;
    case INSN_wrfsbase:
    {
        const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=4&&r->size!=8))die("wrfsbase needs r32/r64");
        emit(0xf3); emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xae); emit_modrm(3,2,r->num);
    }
    break;
    case INSN_wbinvd:
    {
        emit(0x0f); emit(0x09);
    }
    break;
    case INSN_xor:
    {
        enc_alu_dispatch(6, op);
    }
    break;
    case INSN_xchg:
    {
        const Reg*rd=reg_find(g_tok[1]); const Reg*rs=reg_find(g_tok[2]);
        if(!rd||!rs||rd->size!=rs->size||(rd->size!=4&&rd->size!=8))die("xchg supports r32/r64, r32/r64");
        /* NASM canonical direction for the ambiguous 87 /r encoding:
         * first operand in the reg field, second in r/m (parity gate). */
        emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),0); emit(0x87); emit_modrm(3,rd->num,rs->num);
    }
    break;
    case INSN_xgetbv:
    {
        emit(0x0f); emit(0x01); emit(0xd0);
    }
    break;
    case INSN_xsetbv:
    {
        emit(0x0f); emit(0x01); emit(0xd1);
    }
    break;
    case INSN_xsave:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0xae); encode_mem(4,&m,0);
    }
    break;
    case INSN_xrstor:
    {
        Mem m; parse_mem(g_tok[1],&m); int rx,rb; mem_begin(&m,&rx,&rb); emit_rex(0,0,rx,rb,0); emit(0x0f); emit(0xae); encode_mem(5,&m,0);
    }
    break;
    default: die2("unknown instruction", op);
    }
#undef OP_IS
}


/* ------------------------------------------------------------------ */
/* Data directives                                                    */
/* ------------------------------------------------------------------ */
/* emit a data item list for db/dw/dd/dq. Strings allowed for db. */
static void data_define(int unit, int ntok) {
    long cv_tmp;
    for (int i=1;i<ntok;i++) {
        char *t=g_tok[i];
        if (t[0]=='"'||t[0]=='`'||t[0]=='\'') {
            char q=t[0]; char *p=t+1;
            while (*p && *p!=q) {
                if (q=='`' && *p=='\\') { p++; char c=*p++;
                    switch(c){case 'n':emit('\n');break;case 't':emit('\t');break;
                              case '0':emit(0);break;case '\\':emit('\\');break;
                              case 'r':emit('\r');break;default:emit((uint8_t)c);}
                } else { for(int k=0;k<unit;k++) emit(k==0?(uint8_t)*p:0); p++; }
            }
        } else if (unit==8 && (isalpha((unsigned char)t[0])||t[0]=='_'||t[0]=='.')
                   && (cv_tmp=0, !const_lookup(t,&cv_tmp))
                   && !(i+1<ntok && (g_tok[i+1][0]=='+'||g_tok[i+1][0]=='-'||g_tok[i+1][0]=='*'))) {
            /* dq <symbol>: a lone (non-const) symbol with no trailing operator
             * needs an 8-byte absolute reloc (R_X86_64_64). Constants and
             * symbol+offset expressions fall through to the expression path.
             * Author: F E R M I ∞ H A R T. */
            { char q[NAME_MAX]; qualify(t,q);
                   Sym *s=sym_find(q);
                   if (s && s->defined && !s->global && s->section!=SEC_NONE)
                       /* defined local symbol: NASM relocs against the section
                        * symbol with the symbol's offset folded into the addend. */
                       add_reloc_abs64_section(cur_off(),g_cur,s->section,(long)s->offset);
                   else
                       add_reloc_abs64(cur_off(),g_cur,q);
                   emit64(0); }
        } else {
            /* An arithmetic expression may have been split across tokens by
             * the tokenizer (it drops spaces AND commas), e.g.
             * `dd -(MBOOT2_MAGIC + 0 + 24)`. Rejoin following tokens while
             * parentheses are unbalanced or the expression ends on a binary
             * operator. Author: F E R M I ∞ H A R T. */
            char ex[256]; size_t el=0; ex[0]=0;
            int depth=0;
            int j=i;
            for (;;) {
                const char *tk=g_tok[j];
                size_t tl=strlen(tk);
                if (el+tl+1>=sizeof(ex)) die("data expression too long");
                memcpy(ex+el,tk,tl); el+=tl; ex[el]=0;
                for (const char *c=tk;*c;c++){ if(*c=='(')depth++; else if(*c==')')depth--; }
                char last = el? ex[el-1] : 0;
                int trailing_op = (last=='+'||last=='-'||last=='*'||last=='/'||
                                   last=='<'||last=='>'||last=='|'||last=='&'||last=='^');
                int next_is_op = (j+1<ntok) && (g_tok[j+1][0]=='+'||g_tok[j+1][0]=='-'||
                                                g_tok[j+1][0]=='*'||g_tok[j+1][0]=='/'||
                                                g_tok[j+1][0]=='<'||g_tok[j+1][0]=='>'||
                                                g_tok[j+1][0]=='|'||g_tok[j+1][0]=='&'||
                                                g_tok[j+1][0]=='^');
                if ((depth>0 || trailing_op || next_is_op) && j+1<ntok) { j++; continue; }
                break;
            }
            i=j;
            /* Evaluate with symbol capture: if the expression references one
             * cross-section label (e.g. `gdt_start - VMA + LMA` or
             * `isr0 + 8`), emit an absolute reloc (R_X86_64_32 for dd,
             * R_X86_64_64 for dq) against that section/symbol with the baked
             * value as addend, so the linker resolves the final address.
             * Author: F E R M I ∞ H A R T. */
            int has_sym=0, ssec=SEC_NONE, sglob=0; long soff=0; char sname[NAME_MAX];
            long v = parse_expr_reloc(ex, &has_sym, &ssec, &soff, sname, &sglob);
            /* For flat binaries, emit absolute values directly (no relocs) */
            if (!strcmp(g_fmt, "bin")) {
                for (int k=0;k<unit;k++) emit((uint8_t)((uint64_t)v>>(k*8)));
            } else if (has_sym && (unit==4 || unit==8) && ssec!=SEC_NONE) {
                if (unit==8) {
                    if (sglob) add_reloc_abs64(cur_off(), g_cur, sname);
                    else       add_reloc_abs64_section(cur_off(), g_cur, ssec, v);
                } else {
                    if (sglob) add_reloc_abs32_named(cur_off(), g_cur, sname, v - soff);
                    else       add_reloc_abs32_section(cur_off(), g_cur, ssec, v);
                }
                for (int k=0;k<unit;k++) emit(0);
            } else {
                for (int k=0;k<unit;k++) emit((uint8_t)((uint64_t)v>>(k*8)));
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Directive / label handling                                         */
/* ------------------------------------------------------------------ */
static int handle_directive_or_label(char *line) {
    (void)line; /* tokens are already produced by process_source's tokenize(buf) */
    if (g_ntok==0) return 1;
    const char *t0 = g_tok[0];

    /* NASM directives are case-insensitive. The .S files use bare
     * `BITS 16/32/64` (uppercase, no brackets). This MUST update g_bits at
     * assembly time (not just in the preprocessor) so operand/address-size
     * prefixes and REX validity follow the current mode — ap_trampoline.S
     * switches BITS 16 → 32 → 64 mid-file. Author: F E R M I ∞ H A R T. */
    if (!strcmp(t0,"bits") || !strcmp(t0,"BITS") || !strcmp(t0,"Bits")) {
        if (g_ntok>1) {
            if (!strcmp(g_tok[1],"16")) g_bits=16;
            else if (!strcmp(g_tok[1],"32")) g_bits=32;
            else if (!strcmp(g_tok[1],"64")) g_bits=64;
        }
        return 1;
    }
    if (!strcmp(t0,"org") || !strcmp(t0,"ORG") || !strcmp(t0,"Org")) {
        if (g_ntok>1) g_org = (uint64_t)parse_expr(g_tok[1]);
        return 1;
    }
    if (!strcmp(t0,"default") || !strcmp(t0,"DEFAULT")) return 1;
    if (!strcmp(t0,"global")) {
        char name[NAME_MAX]; strncpy(name,g_tok[1],NAME_MAX-1); name[NAME_MAX-1]=0;
        int isf=0; char *c=strchr(name,':'); if(c){ if(!strcmp(c+1,"function"))isf=1; *c=0; }
        Sym *s=sym_intern(name); s->global=1; s->is_func=isf; return 1;
    }
    if (!strcmp(t0,"extern")) { Sym *s=sym_intern(g_tok[1]); s->global=1; s->defined=0; return 1; }
    /* `weak <sym>` → exported with STB_WEAK binding. Like global, but a weak
     * symbol may stay undefined (resolves to 0) without erroring. Used by the
     * NetBSD csu crtbegin for its optional __cxa_finalize / frame-info hooks.
     * Author: F E R M I HART. */
    if (!strcmp(t0,"weak")) {
        char name[NAME_MAX]; strncpy(name,g_tok[1],NAME_MAX-1); name[NAME_MAX-1]=0;
        char *c=strchr(name,':'); if(c) *c=0;
        Sym *s=sym_intern(name); s->global=1; s->weak=1; return 1;
    }
    
    /* Structure directives (struc/istruc/at/endstruc/iend) */
    if (!strcmp(t0,"struc")) { handle_struc_start(); return 1; }
    if (!strcmp(t0,"endstruc")) { handle_endstruc(); return 1; }
    if (!strcmp(t0,"istruc")) { handle_istruc(); return 1; }
    if (!strcmp(t0,"at")) { handle_at(); return 1; }
    if (!strcmp(t0,"iend")) { handle_iend(); return 1; }
    
    /* If we're inside a struc, treat this line as a field definition */
    if (g_in_struc) {
        handle_struc_field();
        return 1;
    }
    if (!strcmp(t0,"section") || !strcmp(t0,"segment")) {
        if (strstr(g_tok[1],".text")) g_cur=SEC_TEXT;
        else if (strstr(g_tok[1],".rodata")) g_cur=SEC_RODATA;
        else if (strstr(g_tok[1],".data")) g_cur=SEC_DATA;
        else if (strstr(g_tok[1],".bss")) g_cur=SEC_BSS;
        else if (strstr(g_tok[1],".note.GNU-stack")) g_cur=SEC_NOTE;
        else {
            /* Custom named section (e.g. .multiboot, .ap_trampoline). Intern
             * it, parse NASM attributes (alloc/exec/write/nobits/progbits/
             * align=N), and select it as current. Author: F E R M I ∞ H A R T. */
            int found=-1;
            for (int i=0;i<g_ncustom;i++) if(!strcmp(g_custom_name[i],g_tok[1])){found=i;break;}
            if (found<0) {
                if (g_ncustom>=CUSTOM_MAX) die2("too many custom sections", g_tok[1]);
                found=g_ncustom++;
                strncpy(g_custom_name[found],g_tok[1],NAME_MAX-1);
                g_custom_name[found][NAME_MAX-1]=0;
                /* defaults: PROGBITS, SHF_ALLOC|SHF_EXECINSTR (code-like) */
                g_custom_type[found]=1; g_custom_flags[found]=0x2|0x4;
                /* parse attribute tokens */
                int has_attr=0;
                for (int i=2;i<g_ntok;i++){
                    const char *a=g_tok[i];
                    if(!strcmp(a,"alloc")){ if(!has_attr){g_custom_flags[found]=0;has_attr=1;} g_custom_flags[found]|=0x2; }
                    else if(!strcmp(a,"noalloc")){ if(!has_attr){g_custom_flags[found]=0;has_attr=1;} g_custom_flags[found]&=~0x2ULL; }
                    else if(!strcmp(a,"exec")){ if(!has_attr){g_custom_flags[found]=0;has_attr=1;} g_custom_flags[found]|=0x4; }
                    else if(!strcmp(a,"noexec")){ if(!has_attr){g_custom_flags[found]=0;has_attr=1;} g_custom_flags[found]&=~0x4ULL; }
                    else if(!strcmp(a,"write")){ if(!has_attr){g_custom_flags[found]=0;has_attr=1;} g_custom_flags[found]|=0x1; }
                    else if(!strcmp(a,"progbits")){ g_custom_type[found]=1; }
                    else if(!strcmp(a,"nobits")){ g_custom_type[found]=8; }
                    else if(!strncmp(a,"align=",6)){ g_secalign[SEC_CUSTOM0+found]=(int)parse_expr(a+6); }
                }
            }
            g_cur=SEC_CUSTOM0+found;
        }
        secorder_touch(g_cur);
        return 1;
    }
    
    /* NASM-style preprocessor directives */
    if (!strcmp(t0,"%define") && g_ntok>=3) {
        char val[512]; val[0]=0;
        for (int i=2;i<g_ntok;i++){ strbuf_append(val,sizeof(val),g_tok[i]); if(i<g_ntok-1)strbuf_append(val,sizeof(val)," "); }
        macro_add(g_tok[1], val); return 1;
    }
    if (!strcmp(t0,"%undef")) { Macro *m=macro_find(g_tok[1]); if(m)m->active=0; return 1; }
    
    /* %if / %elif / %else / %endif - simple conditional assembly */
    if (!strcmp(t0,"%if")) {
        if (g_if_depth >= 64) die("%if nesting too deep");
        long val = (g_ntok>=2) ? parse_expr(g_tok[1]) : 0;
        int new_active = (val != 0) && g_if_active;
        g_if_stack[g_if_depth] = g_if_active ? (val ? 1 : 2) : 3;
        g_if_depth++; g_if_active = new_active;
        return 1;
    }
    if (!strcmp(t0,"%elif")) {
        if (g_if_depth==0) die("%%elif without %%if");
        if (g_if_stack[g_if_depth-1]==1) g_if_active=0;
        else if (g_if_stack[g_if_depth-1]==3) { }
        else { long val = (g_ntok>=2) ? parse_expr(g_tok[1]) : 0; g_if_stack[g_if_depth-1] = val?1:2; g_if_active = val?1:0; }
        return 1;
    }
    if (!strcmp(t0,"%else")) {
        if (g_if_depth==0) die("%%else without %%if");
        if (g_if_stack[g_if_depth-1]==1) g_if_active=0;
        else if (g_if_stack[g_if_depth-1]==2) g_if_active=1;
        return 1;
    }
    if (!strcmp(t0,"%endif")) {
        if (g_if_depth==0) die("%%endif without %%if");
        g_if_depth--; g_if_active = (g_if_depth==0) ? 1 : (g_if_stack[g_if_depth-1]!=3);
        return 1;
    }
    if (!strcmp(t0,"%include") && g_ntok>=2) {
        char fname[NAME_MAX]; memset(fname,0,sizeof(fname)); strncpy(fname,g_tok[1],NAME_MAX-1); fname[NAME_MAX-1]=0;
        size_t fl=strlen(fname); if(fl>2&&fname[0]=='"'&&fname[fl-1]=='"'){fname[fl-1]=0;memmove(fname,fname+1,fl-2);fname[fl-2]=0;}
        if(g_inc_depth>=INCLUDE_DEPTH) { printf("Error: include depth\n"); exit(1); }
        FILE *f=fopen(fname,"rb"); if(!f) die2("cannot open include file",fname);
        if(fseek(f,0,SEEK_END)!=0) { fclose(f); die2("cannot seek include file",fname); }
        long sz=ftell(f); fseek(f,0,SEEK_SET);
        if(sz<0) { fclose(f); die2("cannot size include file",fname); }
        char *buf=malloc((size_t)sz+1); if(!buf) { fclose(f); die("oom include"); }
        if(fread(buf,1,(size_t)sz,f)!=(size_t)sz) { fclose(f); free(buf); die2("cannot read include file",fname); }
        buf[sz]=0; fclose(f);
        g_inc_stack[g_inc_depth].buf=buf; g_inc_stack[g_inc_depth].p=buf;
        strncpy(g_inc_stack[g_inc_depth].fname,fname,NAME_MAX-1);
        g_inc_stack[g_inc_depth].fname[NAME_MAX-1]=0;
        g_inc_depth++;
        return 1;
    }
    if (!strcmp(t0,"align") || !strcmp(t0,"alignb")) {
        int a=(int)parse_expr(g_tok[1]);
        if (a <= 0 || (a & (a - 1)) != 0) die2("align needs positive power of two", g_tok[1]);
        if (a > g_secalign[g_cur]) g_secalign[g_cur] = a;
        /* `align` (vs `alignb`) fills with NOP (0x90) in progbits sections —
         * NASM does this for .text AND .rodata/.data; `alignb` fills with 0x00.
         * .bss has no contents. Match NASM byte-for-byte. */
        int fill = !strcmp(t0,"alignb") ? 0x00 : 0x90;
        if (g_cur==SEC_DATA) while(g_datalen % a) g_data[g_datalen++]=fill;
        else if (g_cur==SEC_RODATA) while(g_rodatalen % a) g_rodata[g_rodatalen++]=fill;
        else if (g_cur==SEC_BSS) while(g_bsslen % a) g_bsslen++;
        else while(g_textlen % a) g_text[g_textlen++]=fill;
        return 1;
    }
    /* NAME equ expr */
    if (g_ntok>=3 && !strcmp(g_tok[1],"equ")) {
        /* reconstruct expr from remaining tokens (may contain spaces) */
        char ex[256]; ex[0]=0;
        for (int i=2;i<g_ntok;i++){ strbuf_append(ex,sizeof(ex),g_tok[i]); }
        const_set(t0, parse_expr(ex)); return 1;
    }
    /* data def directives: db/dw/dd/dq/resb */
    if (!strcmp(t0,"db")) { data_define(1,g_ntok); return 1; }
    if (!strcmp(t0,"dw")) { data_define(2,g_ntok); return 1; }
    if (!strcmp(t0,"dd")) { data_define(4,g_ntok); return 1; }
    if (!strcmp(t0,"dq")) { data_define(8,g_ntok); return 1; }
    if (!strcmp(t0,"resb") || !strcmp(t0,"resw") || !strcmp(t0,"resd") || !strcmp(t0,"resq")) {
        char ex[256]; join_from(1, ex, sizeof(ex));
        long n = parse_expr(ex);
        if (n < 0) die2("res* count must be non-negative", ex);
        int unit = !strcmp(t0,"resb") ? 1 : !strcmp(t0,"resw") ? 2 : !strcmp(t0,"resd") ? 4 : 8;
        if (n > BASM_LONG_MAX / unit) die2("res* count too large", ex);
        g_bsslen += n * unit;
        return 1;
    }
    /* incbin "file" [,skip[,count]] — embed a binary file verbatim into the
     * current section (used by initramfs_blob.S to ride the cpio archive in
     * .rodata). The filename token retains its quotes from the tokenizer.
     * Resolved relative to the including .asm's directory, then CWD, then -I
     * paths. Author: F E R M I ∞ H A R T. */
    if (!strcmp(t0,"incbin")) {
        char fn[512]; const char *q=g_tok[1]; int qi=0;
        if (*q=='"'||*q=='\''||*q=='`') q++;
        while (*q && *q!='"' && *q!='\'' && *q!='`' && qi<(int)sizeof(fn)-1) fn[qi++]=*q++;
        fn[qi]=0;
        long skip = (g_ntok>2)? parse_expr(g_tok[2]) : 0;
        long want = (g_ntok>3)? parse_expr(g_tok[3]) : -1;
        FILE *bf = incbin_open(fn);
        if (!bf) die2("incbin: cannot open", fn);
        if (skip>0) fseek(bf, skip, SEEK_SET);
        int c; long n=0;
        while ((c=fgetc(bf))!=EOF) { if (want>=0 && n>=want) break; emit((uint8_t)c); n++; }
        fclose(bf);
        return 1;
    }
    /* times <n> db <val> : repeat a byte n times (boot sector padding) */
    if (!strcmp(t0,"times")) {
        g_fwd_unresolved = 0;
        long count = parse_expr(g_tok[1]);
        if (g_fwd_unresolved) die("times: forward reference in count (NASM compatibility)");
        int byte_idx = -1;
        for (int i=2;i<g_ntok;i++) {
            if (!strcmp(g_tok[i],"db") || !strcmp(g_tok[i],"resb")) { byte_idx = i+1; break; }
        }
        if (byte_idx < 0 || byte_idx >= g_ntok) die("times needs 'db <byte>'");
        g_fwd_unresolved = 0;
        long val = parse_expr(g_tok[byte_idx]);
        if (g_fwd_unresolved) die("times: forward reference in value (NASM compatibility)");
        for (long k=0;k<count;k++) emit((uint8_t)val);
        return 1;
    }

    /* label "name:" possibly followed by a directive/instruction */
    size_t l=strlen(t0);
    if (l>1 && t0[l-1]==':') {
        char name[NAME_MAX]; memcpy(name,t0,l-1); name[l-1]=0;
        char qual[NAME_MAX];
        if (name[0]=='.' && g_last_global[0]) {
            size_t gl=strlen(g_last_global), nl=strlen(name);
            if(gl+nl>=NAME_MAX)die("label too long");
            memcpy(qual,g_last_global,gl); memcpy(qual+gl,name,nl+1);
        } else { strncpy(qual,name,NAME_MAX-1); qual[NAME_MAX-1]=0;
                 if(name[0]!='.'){ strncpy(g_last_global,name,NAME_MAX-1); g_last_global[NAME_MAX-1]=0; } }
        Sym *s=sym_intern(qual); s->defined=1; s->is_local=(name[0]=='.');
        s->section=g_cur; s->offset=cur_off();
        if (s->defseq<0) s->defseq=g_defseq++;  /* source-definition order for symtab */
        if (g_ntok>1) {
            /* rest of line is a directive or instruction: shift tokens left */
            for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
            g_ntok--;
            /* re-dispatch: could be data or instruction */
            const char *n0=g_tok[0];
            if(!strcmp(n0,"db")){data_define(1,g_ntok);return 1;}
            if(!strcmp(n0,"dw")){data_define(2,g_ntok);return 1;}
            if(!strcmp(n0,"dd")){data_define(4,g_ntok);return 1;}
            if(!strcmp(n0,"dq")){data_define(8,g_ntok);return 1;}
            if(!strcmp(n0,"resb") || !strcmp(n0,"resw") || !strcmp(n0,"resd") || !strcmp(n0,"resq")){
                char ex[256]; join_from(1, ex, sizeof(ex));
                long n = parse_expr(ex);
                if (n < 0) die2("res* count must be non-negative", ex);
                int unit = !strcmp(n0,"resb") ? 1 : !strcmp(n0,"resw") ? 2 : !strcmp(n0,"resd") ? 4 : 8;
                if (n > BASM_LONG_MAX / unit) die2("res* count too large", ex);
                g_bsslen += n * unit;
                return 1;
            }
            return 0; /* instruction */
        }
        return 1;
    }
    /* Implicit labels in data sections: "my_var dq 100" without colon */
    if ((g_cur==SEC_DATA || g_cur==SEC_RODATA || g_cur==SEC_BSS) &&
        (isalpha((unsigned char)t0[0]) || t0[0]=='_')) {
        /* Create implicit label */
        char name[NAME_MAX]; strncpy(name,t0,NAME_MAX-1); name[NAME_MAX-1]=0;
        char qual[NAME_MAX];
        if (name[0]=='.' && g_last_global[0]) {
            size_t gl=strlen(g_last_global), nl=strlen(name);
            if(gl+nl>=NAME_MAX)die("label too long");
            memcpy(qual,g_last_global,gl); memcpy(qual+gl,name,nl+1);
        } else { strncpy(qual,name,NAME_MAX-1); qual[NAME_MAX-1]=0;
                 if(name[0]!='.'){ strncpy(g_last_global,name,NAME_MAX-1); g_last_global[NAME_MAX-1]=0; } }
        Sym *s=sym_intern(qual); s->defined=1; s->is_local=(name[0]=='.');
        s->section=g_cur; s->offset=(g_cur==SEC_BSS)?g_bsslen:(g_cur==SEC_RODATA?g_rodatalen:g_datalen);
        if (s->defseq<0) s->defseq=g_defseq++;
        
        /* Now process the rest of the line as directive */
        if (g_ntok>1) {
            for (int i=1;i<g_ntok;i++) memmove(&g_tok[i-1],&g_tok[i],sizeof(char*));
            g_ntok--;
            const char *n0=g_tok[0];
            if(!strcmp(n0,"db")){data_define(1,g_ntok);return 1;}
            if(!strcmp(n0,"dw")){data_define(2,g_ntok);return 1;}
            if(!strcmp(n0,"dd")){data_define(4,g_ntok);return 1;}
            if(!strcmp(n0,"dq")){data_define(8,g_ntok);return 1;}
            if(!strcmp(n0,"resb") || !strcmp(n0,"resw") || !strcmp(n0,"resd") || !strcmp(n0,"resq")){
                char ex[256]; join_from(1, ex, sizeof(ex));
                long n = parse_expr(ex);
                if (n < 0) die2("res* count must be non-negative", ex);
                int unit = !strcmp(n0,"resb") ? 1 : !strcmp(n0,"resw") ? 2 : !strcmp(n0,"resd") ? 4 : 8;
                if (n > BASM_LONG_MAX / unit) die2("res* count too large", ex);
                g_bsslen += n * unit;
                return 1;
            }
            return 0; /* instruction (unlikely in data section) */
        }
        return 1;
    }

    return 0;
}

/* Process a single source buffer (used for main file and includes) */
static void process_source(char *src) {
    char *p = src;
    /* Per-source buffer for tokenization.  Allocated once per source to avoid
     * the StackAddressEscape warning that a fixed stack buffer would trigger
     * when g_tok points into it; lifetime is exactly this function call. */
    char *buf = (char*)malloc(1024);
    if (!buf) die("oom source buffer");
    while (*p) {
        g_line++;
        char *eol = strchr(p, '\n');
        int len = eol ? (int)(eol-p) : (int)strlen(p);
        if (len >= 1024) len = 1023;
        memcpy(buf, p, len); buf[len] = 0;
        tokenize(buf);
        
        /* Handle %include directive */
        if (g_ntok > 0 && !strcmp(g_tok[0], "%include")) {
            handle_directive_or_label(buf);
            /* process included file */
            while (g_inc_depth > 0) {
                int idx = g_inc_depth - 1;
                g_file = g_inc_stack[idx].fname;
                process_source(g_inc_stack[idx].buf);
                free(g_inc_stack[idx].buf);
                g_inc_depth--;
                g_file = "<stdin>";
            }
            p = eol ? eol+1 : p + strlen(p);
            continue;
        }
        
        /* Check conditional assembly state */
        int is_cond_directive = (g_ntok>0 && (
            !strcmp(g_tok[0],"%if") || !strcmp(g_tok[0],"%elif") ||
            !strcmp(g_tok[0],"%else") || !strcmp(g_tok[0],"%endif")));
        
        if (!g_if_active && !is_cond_directive) {
            /* Skip this line */
        } else {
            if (!handle_directive_or_label(buf)) { if(g_ntok>0) do_instruction(); }
        }
        if (!eol) break;
        p = eol + 1;
    }
    /* Tokens are ephemeral and point into the per-line stack buffer.  Clear
     * the global pointers before returning so static analyzers (and future
     * readers) know they are intentionally invalidated. */
    for (int i = 0; i < g_ntok; i++) g_tok[i] = NULL;
    g_ntok = 0;
    free(buf);
}

static void assemble_pass(char *src) {
    g_textlen=0; g_datalen=0; g_rodatalen=0; g_bsslen=0; g_cur=SEC_TEXT; g_last_global[0]=0;
    g_bits=64;  /* default mode each pass; bare BITS directives override */
    g_secalign[SEC_TEXT]=16; g_secalign[SEC_DATA]=4; g_secalign[SEC_BSS]=4;
    g_secalign[SEC_RODATA]=4; g_secalign[SEC_NOTE]=1;
    /* Reset custom sections each pass; the `section` directive re-declares
     * them by name as the source is re-scanned. Author: F E R M I ∞ H A R T. */
    for (int i=0;i<CUSTOM_MAX;i++){ g_custom_len[i]=0; g_secalign[SEC_CUSTOM0+i]=1; }
    g_ncustom=0;
    g_nsecorder=0;
    g_branch_ord=0; g_nrelocs=0; g_fwd_unresolved=0;
    g_inc_depth = 0;
    g_line = 0;
    g_file = "<stdin>";
    expr_cache_reset();
    process_source(src);
    /* Cleanup any pending includes */
    while (g_inc_depth > 0) { free(g_inc_stack[--g_inc_depth].buf); }
}
/* ------------------------------------------------------------------ */
/* ELF64 writer                                                       */
/* ------------------------------------------------------------------ */
static void w8(FILE*f,uint8_t v){fputc(v,f);}
static void w16(FILE*f,uint16_t v){fputc(v&0xff,f);fputc((v>>8)&0xff,f);}
static void w32(FILE*f,uint32_t v){for(int i=0;i<4;i++)fputc((v>>(i*8))&0xff,f);}
static void w64(FILE*f,uint64_t v){for(int i=0;i<8;i++)fputc((v>>(i*8))&0xff,f);}

typedef struct { char buf[65536]; int len; } Strtab;
static int strtab_add(Strtab*st,const char*s){
    if(st->len==0){st->buf[0]=0;st->len=1;}
    int off=st->len; int n=(int)strlen(s)+1;
    if(st->len+n>(int)sizeof(st->buf)){dprintf(2,"strtab overflow\n");exit(1);}
    memcpy(st->buf+st->len,s,n); st->len+=n; return off;
}

typedef struct { uint32_t name; uint8_t info; uint8_t other; uint16_t shndx; uint64_t value; uint64_t size; } E64Sym;
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STT_NOTYPE 0
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4

/* section indices in the output are assigned dynamically (NASM order). */
static int g_sh_index[SEC_MAX]; /* SEC_* -> output section header index, or 0 */

/* Uniform section accessors so the ELF writer treats fixed + custom sections
 * identically. Author: F E R M I ∞ H A R T. */
static int sec_len(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_len[custom_idx(sec)];
    return (sec==SEC_TEXT)?g_textlen : (sec==SEC_DATA)?g_datalen :
           (sec==SEC_RODATA)?g_rodatalen : (sec==SEC_BSS)?(int)g_bsslen : 0;
}
static const uint8_t *sec_buf(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_buf[custom_idx(sec)];
    return (sec==SEC_TEXT)?g_text : (sec==SEC_DATA)?g_data :
           (sec==SEC_RODATA)?g_rodata : NULL;
}
static int sec_has_content(int sec){ /* progbits-like (occupies file space) */
    if (sec>=SEC_CUSTOM0) return g_custom_type[custom_idx(sec)]!=8;
    return sec==SEC_TEXT||sec==SEC_DATA||sec==SEC_RODATA;
}
static const char *secname(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_name[custom_idx(sec)];
    return sec==SEC_TEXT?".text": sec==SEC_DATA?".data":
           sec==SEC_RODATA?".rodata": sec==SEC_BSS?".bss":".note.GNU-stack";
}

static void write_bin(const char *path) {
    /* Raw binary: dump .text + .data + .rodata in appearance order.
     * No ELF headers, no relocations, no symbol table. */
    FILE *f = fopen(path, "wb"); if(!f){perror("fopen");exit(1);}
    for (int i=0;i<g_nsecorder;i++){
        int sec = g_secorder[i];
        if (sec_has_content(sec)) fwrite(sec_buf(sec),1,sec_len(sec),f);
    }
    fclose(f);
}

static void write_elf(const char *path) {
    secorder_touch(SEC_TEXT);
    secorder_touch(SEC_NOTE);

    /* Which content sections have relocations (in appearance order) -> each
     * gets a .rela.<sec> section. NASM section order:
     *   NULL, <content in appearance order>, .shstrtab, .symtab, .strtab,
     *   .rela.<sec> for each content sec with relocs (appearance order). */
    int has_rela[SEC_MAX]={0}; 
    for (int i=0;i<g_nrelocs;i++) has_rela[g_relocs[i].section]=1;

    for (int i=0;i<SEC_MAX;i++) g_sh_index[i]=0;
    int shidx = 1;
    for (int i=0;i<g_nsecorder;i++) g_sh_index[g_secorder[i]] = shidx++;
    int idx_shstr  = shidx++;
    int idx_symtab = shidx++;
    int idx_strtab = shidx++;
    int rela_shidx[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        if (has_rela[sec]) rela_shidx[sec]=shidx++; }
    int nsec = shidx;
    int shstrndx = idx_shstr;

    /* ---- symbol table ---- */
    /* Hard capacity guard: the local syms[] array is SYMTAB_CAP entries. A TU
     * whose (sections + emit_sym consts + defined/global labels) exceeds that
     * would smash the stack. Fail cleanly instead. */
    if (g_nsecorder + g_nconsts + g_nsyms + 8 > SYMTAB_CAP)
        die("symbol table capacity exceeded (raise SYM_MAX/CONST_MAX)");
    Strtab strtab; strtab.len=0;
    E64Sym syms[SYMTAB_CAP]; int nsym=0;
    /* Zero the whole syms array so unset fields (notably .other) don't
     * leak stack garbage into the symbol table. Without this, bear-built
     * basm leaked non-zero st_other bytes for some symbols (8 bytes
     * differ in /tmp/sov_parse.asm.o vs host); gcc-built basm got 0 by
     * happenstance. Author: F E R M I ∞ H A R T. */
    memset(syms, 0, sizeof(syms));
    int sec_sym_index[SEC_MAX]; for(int i=0;i<SEC_MAX;i++) sec_sym_index[i]=-1;

    nsym++;
    syms[nsym].name=strtab_add(&strtab,g_srcname);
    syms[nsym].info=(STB_LOCAL<<4)|STT_FILE; syms[nsym].shndx=0xfff1; nsym++;

    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        syms[nsym].info=(STB_LOCAL<<4)|STT_SECTION; syms[nsym].shndx=g_sh_index[sec];
        sec_sym_index[sec]=nsym; nsym++; }

    /* Local symbols: emit consts (ABS) and defined non-global labels INTERLEAVED
     * in source-definition order (defseq), matching NASM byte-for-byte. Build a
     * merged index list, then sort by defseq. */
    int sym_index_of[SYM_MAX]; for(int i=0;i<g_nsyms;i++)sym_index_of[i]=-1;
    /* gather: kind 0 = const[idx], kind 1 = label g_syms[idx] */
    struct { int kind; int idx; int seq; } loc[SYMTAB_CAP]; int nloc=0;
    for (int i=0;i<g_nconsts;i++){ if(!g_consts[i].emit_sym) continue;
        loc[nloc].kind=0; loc[nloc].idx=i; loc[nloc].seq=g_consts[i].defseq; nloc++; }
    for (int i=0;i<g_nsyms;i++){ Sym*s=&g_syms[i];
        if (s->defined && !s->global){ loc[nloc].kind=1; loc[nloc].idx=i; loc[nloc].seq=s->defseq; nloc++; } }
    /* stable insertion sort by defseq (nloc is small; keeps equal-seq order) */
    for (int a=1;a<nloc;a++){ int ja=a; while(ja>0 && loc[ja-1].seq>loc[ja].seq){
        int tk=loc[ja].kind,ti=loc[ja].idx,ts=loc[ja].seq;
        loc[ja]=loc[ja-1]; loc[ja-1].kind=tk; loc[ja-1].idx=ti; loc[ja-1].seq=ts; ja--; } }
    for (int n=0;n<nloc;n++){
        if (loc[n].kind==0){ int i=loc[n].idx;
            syms[nsym].name=strtab_add(&strtab,g_consts[i].name);
            syms[nsym].info=(STB_LOCAL<<4)|STT_NOTYPE; syms[nsym].shndx=0xfff1;
            syms[nsym].value=(uint64_t)g_consts[i].value; nsym++;
        } else { int i=loc[n].idx; Sym*s=&g_syms[i];
            syms[nsym].name=strtab_add(&strtab,s->name);
            syms[nsym].info=(STB_LOCAL<<4)|STT_NOTYPE; syms[nsym].shndx=g_sh_index[s->section];
            syms[nsym].value=s->offset; sym_index_of[i]=nsym; nsym++;
        }
    }

    int first_global=nsym;
    for (int i=0;i<g_nsyms;i++){ Sym*s=&g_syms[i]; if(!s->global)continue;
        syms[nsym].name=strtab_add(&strtab,s->name);
        int bind = s->weak ? 2 /*STB_WEAK*/ : STB_GLOBAL;
        if (s->defined){ syms[nsym].info=(bind<<4)|(s->is_func?STT_FUNC:STT_NOTYPE);
            syms[nsym].shndx=g_sh_index[s->section]; syms[nsym].value=s->offset; }
        else { syms[nsym].info=(bind<<4)|STT_NOTYPE; syms[nsym].shndx=0; }
        sym_index_of[i]=nsym; nsym++;
    }

    /* ---- section header string table (NASM order: content, shstrtab,
     * symtab, strtab, rela.*) ---- */
    Strtab shstr; shstr.len=0; strtab_add(&shstr,"");
    int sh_name[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        sh_name[sec]=strtab_add(&shstr,secname(sec)); }
    int shn_shstr =strtab_add(&shstr,".shstrtab");
    int shn_symtab=strtab_add(&shstr,".symtab");
    int shn_strtab=strtab_add(&shstr,".strtab");
    int rela_name[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        char nm[96]; snprintf(nm,sizeof(nm),".rela%s",secname(sec));
        rela_name[sec]=strtab_add(&shstr,nm); }

    /* count relocs per section */
    int rela_count[SEC_MAX]={0};
    for (int i=0;i<g_nrelocs;i++) rela_count[g_relocs[i].section]++;

    /* ---- file layout: NASM places the section header table immediately after
     * the ELF header (offset 64), then section contents, then shstrtab,
     * symtab, strtab, rela.* ---- */
    uint64_t shoff = 64;
    uint64_t off = 64 + (uint64_t)nsec*64;
    uint64_t sec_off[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        while(off%16)off++;            /* NASM aligns every section's file offset to 16 */
        sec_off[sec]=off;
        if (sec_has_content(sec)) off+=sec_len(sec);
        /* bss/note: no file content */
    }
    while(off%16)off++;
    uint64_t shstr_off=off; off+=shstr.len;
    while(off%16)off++;
    uint64_t symtab_off=off; off+=(uint64_t)nsym*24;
    while(off%16)off++;
    uint64_t strtab_off=off; off+=strtab.len;
    uint64_t rela_off[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        while(off%16)off++;
        rela_off[sec]=off; off+=(uint64_t)rela_count[sec]*24; }

    FILE*f=fopen(path,"wb"); if(!f){perror("fopen");exit(1);}
    w8(f,0x7f);w8(f,'E');w8(f,'L');w8(f,'F');w8(f,2);w8(f,1);w8(f,1);w8(f,0);
    for(int i=0;i<8;i++)w8(f,0);
    w16(f,1); w16(f,0x3e); w32(f,1); w64(f,0); w64(f,0); w64(f,shoff);
    w32(f,0); w16(f,64); w16(f,0); w16(f,0); w16(f,64); w16(f,nsec); w16(f,shstrndx);

    /* ---- section headers (immediately after ELF header) ---- */
    for(int i=0;i<64;i++)w8(f,0); /* null */
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        if (sec==SEC_TEXT){ w32(f,sh_name[sec]);w32(f,1);w64(f,0x6);w64(f,0);w64(f,sec_off[sec]);w64(f,g_textlen);w32(f,0);w32(f,0);w64(f,g_secalign[sec]);w64(f,0); }
        else if (sec==SEC_DATA){ w32(f,sh_name[sec]);w32(f,1);w64(f,0x3);w64(f,0);w64(f,sec_off[sec]);w64(f,g_datalen);w32(f,0);w32(f,0);w64(f,g_secalign[sec]);w64(f,0); }
        else if (sec==SEC_RODATA){ w32(f,sh_name[sec]);w32(f,1);w64(f,0x2);w64(f,0);w64(f,sec_off[sec]);w64(f,g_rodatalen);w32(f,0);w32(f,0);w64(f,g_secalign[sec]);w64(f,0); }
        else if (sec==SEC_BSS){ w32(f,sh_name[sec]);w32(f,8);w64(f,0x3);w64(f,0);w64(f,sec_off[sec]);w64(f,(uint64_t)g_bsslen);w32(f,0);w32(f,0);w64(f,g_secalign[sec]);w64(f,0); }
        else if (sec>=SEC_CUSTOM0){ int ci=custom_idx(sec);
            w32(f,sh_name[sec]);w32(f,g_custom_type[ci]);w64(f,g_custom_flags[ci]);w64(f,0);w64(f,sec_off[sec]);
            w64(f,(uint64_t)g_custom_len[ci]);w32(f,0);w32(f,0);w64(f,g_secalign[sec]);w64(f,0); }
        else { w32(f,sh_name[sec]);w32(f,1);w64(f,0);w64(f,0);w64(f,sec_off[sec]);w64(f,0);w32(f,0);w32(f,0);w64(f,1);w64(f,0); }
    }
    w32(f,shn_shstr);w32(f,3);w64(f,0);w64(f,0);w64(f,shstr_off);w64(f,shstr.len);w32(f,0);w32(f,0);w64(f,1);w64(f,0);
    w32(f,shn_symtab);w32(f,2);w64(f,0);w64(f,0);w64(f,symtab_off);w64(f,(uint64_t)nsym*24);w32(f,idx_strtab);w32(f,first_global);w64(f,8);w64(f,24);
    w32(f,shn_strtab);w32(f,3);w64(f,0);w64(f,0);w64(f,strtab_off);w64(f,strtab.len);w32(f,0);w32(f,0);w64(f,1);w64(f,0);
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        w32(f,rela_name[sec]);w32(f,4);w64(f,0);w64(f,0);w64(f,rela_off[sec]);
        w64(f,(uint64_t)rela_count[sec]*24);w32(f,idx_symtab);w32(f,g_sh_index[sec]);w64(f,8);w64(f,24);
    }

    /* ---- section contents in appearance order ---- */
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        while(ftell(f)<(long)sec_off[sec]) w8(f,0);
        if (sec_has_content(sec)) fwrite(sec_buf(sec),1,sec_len(sec),f);
    }
    while(ftell(f)<(long)shstr_off) w8(f,0);
    fwrite(shstr.buf,1,shstr.len,f);
    while(ftell(f)<(long)symtab_off) w8(f,0);
    for(int i=0;i<nsym;i++){ w32(f,syms[i].name);w8(f,syms[i].info);w8(f,syms[i].other);
        w16(f,syms[i].shndx);w64(f,syms[i].value);w64(f,syms[i].size); }
    while(ftell(f)<(long)strtab_off) w8(f,0);
    fwrite(strtab.buf,1,strtab.len,f);
    for (int si=0;si<g_nsecorder;si++){ int sec=g_secorder[si]; if(!has_rela[sec])continue;
        while(ftell(f)<(long)rela_off[sec]) w8(f,0);
        for (int i=0;i<g_nrelocs;i++){ Reloc*r=&g_relocs[i]; if(r->section!=sec)continue;
            int ix=-1;
            if (r->sym_kind==1) ix=sec_sym_index[r->target_sec];
            else { Sym*s=sym_find(r->sym); if(s) ix=sym_index_of[(int)(s - g_syms)]; }
            if(ix<0) die2("reloc against unknown symbol", r->sym_kind?"<section>":r->sym);
            w64(f,(uint64_t)r->offset); w64(f,((uint64_t)ix<<32)|r->reltype); w64(f,(uint64_t)r->addend);
        }
    }

    fclose(f);
    (void)idx_symtab; (void)rela_shidx;
}

/* ------------------------------------------------------------------ */
/* Linear memory arena for preprocessor scratch allocations            */
/* ------------------------------------------------------------------ */
#define ARENA_BLK 65536
typedef struct Arena { char *base; size_t used, cap; struct Arena *next; } Arena;
static Arena *g_pp_arena = NULL;

static void *arena_alloc(size_t n) {
    n = (n + 7) & ~(size_t)7; /* 8-byte alignment */
    if (!g_pp_arena || g_pp_arena->used + n > g_pp_arena->cap) {
        Arena *blk = (Arena*)malloc(sizeof(Arena));
        if (!blk) die("oom arena block");
        blk->base = (char*)malloc(ARENA_BLK);
        if (!blk->base) die("oom arena base");
        blk->used = 0; blk->cap = ARENA_BLK; blk->next = g_pp_arena;
        g_pp_arena = blk;
    }
    void *p = g_pp_arena->base + g_pp_arena->used;
    g_pp_arena->used += n;
    return p;
}

static void arena_reset(void) {
    Arena *blk = g_pp_arena;
    while (blk) { Arena *next = blk->next; free(blk->base); free(blk); blk = next; }
    g_pp_arena = NULL;
}

/* ------------------------------------------------------------------ */
/* NASM-subset preprocessor                                           */
/* ------------------------------------------------------------------ */
/* Runs once over the source before assembly, emitting an expanded source
 * the existing parser consumes verbatim. Supports exactly the minimal NASM
 * preprocessor constructs the SigilOS kernel asm uses (and nothing more):
 *
 *   %define NAME value            whole-word text substitution
 *   %macro NAME n ... %endmacro   positional (%1..%9) multi-line macros,
 *                                 with %N pasted even INSIDE identifiers
 *                                 (NASM token paste, e.g. isr_%1 -> isr_0)
 *   %if 0 / %if <nonzero> ... [%else] ... %endif   constant conditional
 *   [BITS 64]                     no-op (basm is 64-bit only); [BITS 16/32]
 *                                 are a clear error (separate later task).
 *
 * Precedent: this is the documented behaviour of NASM's own preprocessor
 * (NASM manual ch.4 "The NASM Preprocessor"). It uses fixed-size tables and
 * bounded buffers (no realloc), matching basm's existing allocation style so
 * the sovereign bear+blibc build keeps working. */
#define PP_MAXDEF 256
#define PP_MAXMAC 64
/* PPDef: object-like (%define X val) OR function-like (%define P(a,b) body).
 * nparam<0 means object-like; >=0 means function-like with that many params.
 * Author: F E R M I ∞ H A R T. */
typedef struct { char name[NAME_MAX]; char value[256];
                 int nparam; char params[4][NAME_MAX]; } PPDef;
/* argc = minimum required args; max_argc = declared ceiling (-1 = variadic/inf);
 * variadic = 1 allows extra arguments beyond argc. */
typedef struct { char name[NAME_MAX]; int argc; int variadic; char *body; } PPMac;
static PPDef pp_defs[PP_MAXDEF]; static int pp_ndef=0;
static PPMac pp_macs[PP_MAXMAC]; static int pp_nmac=0;

#define PPDEF_HT_CAP  512
#define PPMAC_HT_CAP  128
static HTEntry pp_def_ht[PPDEF_HT_CAP];
static HTEntry pp_mac_ht[PPMAC_HT_CAP];

static char  *pp_out; static size_t pp_len, pp_cap;
static void pp_emit_ch(char c){
    if (pp_len >= pp_cap) {
        size_t new_cap = pp_cap ? pp_cap * 2 : 4096;
        if (new_cap < pp_len + 1) new_cap = pp_len + 1;
        char *p = (char*)realloc(pp_out, new_cap);
        if (!p) die("oom in preprocessor");
        pp_out = p; pp_cap = new_cap;
    }
    pp_out[pp_len++] = c;
}
static void pp_emit_str(const char *s){ while(*s) pp_emit_ch(*s++); }

static int pp_is_ident(int c){ return isalnum(c)||c=='_'; }

/* whole-word substitution of every %define name found in `in` -> `out`.
 * Object-like defines substitute their value; function-like defines
 * P(a,b) capture parenthesized args and substitute the body with each
 * param replaced. Author: F E R M I ∞ H A R T. */
static void pp_subst_defines(const char *in, char *out, int outsz){
    int oi=0; const char *p=in;
    while(*p){
        if (pp_is_ident((unsigned char)*p) &&
            !(p>in && pp_is_ident((unsigned char)p[-1]))){
            const char *s=p;
            while(pp_is_ident((unsigned char)*p) || *p=='.') p++;
            int len=(int)(p-s); int matched=0;
            /* Hash lookup of the identifier in the %define table. */
            char idbuf[NAME_MAX];
            if (len >= NAME_MAX) len = NAME_MAX - 1;
            memcpy(idbuf, s, len); idbuf[len] = 0;
            uint32_t h = str_hash(idbuf, (size_t)len);
            int mask = PPDEF_HT_CAP - 1;
            int hi = (int)(h & (uint32_t)mask);
            int didx = -1;
            while (pp_def_ht[hi].hash) {
                int idx = pp_def_ht[hi].idx;
                if (pp_def_ht[hi].hash == h && pp_def_ht[hi].len == (uint8_t)len &&
                    memcmp(pp_defs[idx].name, idbuf, (size_t)len) == 0) {
                    didx = idx; break;
                }
                hi = (hi + 1) & mask;
            }
            if (didx >= 0) {
                if (pp_defs[didx].nparam>=0) {
                    /* function-like: require '(' next, capture comma args */
                    const char *q=p; while(*q==' '||*q=='	')q++;
                    if(*q=='(') {
                        q++;
                        char args[4][256]; int na=0; int depth=1;
                        while(*q && depth>0){
                            while(*q==' '||*q=='	')q++;
                            int ai=0;
                            while(*q && depth>0){
                                if(*q=='(')depth++;
                                else if(*q==')'){ depth--; if(depth==0){q++;break;} }
                                else if(*q==',' && depth==1){ q++; break; }
                                if(na<4&&ai<255) args[na][ai++]=*q;
                                q++;
                            }
                            if(na<4){ while(ai>0&&(args[na][ai-1]==' '))ai--; args[na][ai]=0; na++; }
                        }
                        /* substitute body: replace each param ident with its arg */
                        const char *b=pp_defs[didx].value;
                        while(*b){
                            if(pp_is_ident((unsigned char)*b) &&
                               !(b>pp_defs[didx].value && pp_is_ident((unsigned char)b[-1]))){
                                const char *bs=b; while(pp_is_ident((unsigned char)*b))b++;
                                int bl=(int)(b-bs); int pm=-1;
                                for(int k=0;k<pp_defs[didx].nparam;k++)
                                    if((int)strlen(pp_defs[didx].params[k])==bl && !strncmp(pp_defs[didx].params[k],bs,bl)){pm=k;break;}
                                if(pm>=0 && pm<na){ const char*a=args[pm]; while(*a){if(oi<outsz-1)out[oi++]=*a;a++;} }
                                else { for(const char*c=bs;c<b;c++){if(oi<outsz-1)out[oi++]=*c;} }
                            } else { if(oi<outsz-1)out[oi++]=*b; b++; }
                        }
                        p=q; matched=1;
                    }
                } else {
                    const char *v=pp_defs[didx].value;
                    while(*v){ if(oi<outsz-1)out[oi++]=*v; v++; }
                    matched=1;
                }
            }
            if(!matched) for(const char *q=s;q<p;q++){ if(oi<outsz-1)out[oi++]=*q; }
        } else { if(oi<outsz-1)out[oi++]=*p; p++; }
    }
    out[oi]=0;
}

static void pp_process_line(const char *line, int depth);
static const char *pp_trim(const char *q);  /* fwd */

/* Lookup a %define by name. Returns index or -1. */
static int pp_def_find(const char *name) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    uint32_t h = str_hash(name, nl);
    int mask = PPDEF_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (pp_def_ht[i].hash) {
        int idx = pp_def_ht[i].idx;
        if (pp_def_ht[i].hash == h && pp_def_ht[i].len == nl &&
            memcmp(pp_defs[idx].name, name, nl) == 0)
            return idx;
        i = (i + 1) & mask;
    }
    return -1;
}

/* expand macro `mac` with the given args, recursively processing each body
 * line (so %define and nested macros still apply inside the expansion). */
static void pp_expand_macro(PPMac *mac, char args[][256], int nargs, int depth){
    if (depth>256) die("macro expansion too deep");
    if (!mac->variadic && nargs != mac->argc)
        die2("macro expects fixed number of arguments", mac->name);
    if (mac->variadic && nargs < mac->argc)
        die2("macro expects more arguments", mac->name);

    /* Work on a mutable copy so %rotate can reorder arguments per line. */
    char margs[16][256]; int mnargs = nargs < 16 ? nargs : 16;
    for(int i=0;i<mnargs;i++){ strncpy(margs[i], args[i], 255); margs[i][255]=0; }

    const char *b=mac->body;
    while(*b){
        const char *eol=strchr(b,'\n');
        int len = eol?(int)(eol-b):(int)strlen(b);
        char tmp[2048]; int ti=0;
        int i=0;
        while(i<len){
            char c=b[i];
            if(c=='%' && i+1<len){
                if(b[i+1]=='0'){
                    char buf[32]; snprintf(buf,sizeof(buf),"%d",mnargs);
                    const char *a=buf;
                    while(*a && ti<(int)sizeof(tmp)-1) tmp[ti++]=*a++;
                    i+=2; continue;
                }
                if(b[i+1]>='1' && b[i+1]<='9'){
                    int idx=b[i+1]-'1';
                    const char *a=(idx<mnargs)?margs[idx]:"";
                    while(*a && ti<(int)sizeof(tmp)-1) tmp[ti++]=*a++;
                    i+=2; continue;
                }
                /* %rotate N  — circularly shift macro arguments */
                if(i+7<len && b[i+1]=='r' && b[i+2]=='o' && b[i+3]=='t' && b[i+4]=='a' && b[i+5]=='t' && b[i+6]=='e' &&
                   (b[i+7]==' '||b[i+7]=='\t'||b[i+7]=='+'||b[i+7]=='-'||isdigit((unsigned char)b[i+7]))){
                    int j=i+7;
                    while(j<len && (b[j]==' '||b[j]=='\t')) j++;
                    int sign=1;
                    if(j<len && b[j]=='-'){ sign=-1; j++; }
                    else if(j<len && b[j]=='+') j++;
                    int n=0;
                    while(j<len && isdigit((unsigned char)b[j])){ n=n*10+(b[j]-'0'); j++; }
                    n *= sign;
                    if(mnargs>0){
                        n = ((n % mnargs) + mnargs) % mnargs;
                        char rot[16][256];
                        for(int k=0;k<mnargs;k++) strncpy(rot[k], margs[k], 255), rot[k][255]=0;
                        for(int k=0;k<mnargs;k++) strncpy(margs[k], rot[(k+n)%mnargs], 255), margs[k][255]=0;
                    }
                    i=j; continue;
                }
            }
            if(ti<(int)sizeof(tmp)-1) tmp[ti++]=c;
            i++;
        }
        tmp[ti]=0;
        pp_process_line(tmp, depth+1);
        if(!eol) break;
        b=eol+1;
    }
}

/* Apply %define substitution to one line, then either expand a macro
 * invocation or emit the line verbatim. */
static void pp_process_line(const char *line, int depth){
    /* Handle %assign on the RAW line first — before define substitution would
     * clobber the target name (e.g. `%assign vec vec+1` must not have the
     * leading `vec` replaced by its current value). The RHS is substituted
     * explicitly below. Author: F E R M I ∞ H A R T. */
    {
        const char *t=line; while(*t==' '||*t=='\t')t++;
        size_t tlen = strlen(t);
        if(tlen >= 7 && !strncmp(t,"%assign",7) && (tlen == 7 || t[7]==' '||t[7]=='\t')){
            const char *c=pp_trim(t+7);
            char nm[NAME_MAX]; int ni=0;
            while(*c && pp_is_ident((unsigned char)*c) && ni<NAME_MAX-1) nm[ni++]=*c++;
            nm[ni]=0;
            if(ni==0) die("%assign needs a name");
            const char *v=pp_trim(c);
            char raw[256]; int ri=0; while(*v&&*v!=';'&&ri<255)raw[ri++]=*v++; raw[ri]=0;
            char sub[512]; pp_subst_defines(raw, sub, sizeof(sub));
            long val = parse_expr(sub);
            char vbuf[32]; snprintf(vbuf,sizeof(vbuf),"%ld",val);
            int found = pp_def_find(nm);
            if(found<0){ if(pp_ndef>=PP_MAXDEF)die("too many %assign"); found=pp_ndef++;
                         strncpy(pp_defs[found].name,nm,NAME_MAX-1); pp_defs[found].name[NAME_MAX-1]=0;
                         ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[found].name, strlen(nm)), (uint8_t)strlen(nm), found); }
            strncpy(pp_defs[found].value,vbuf,255); pp_defs[found].value[255]=0;
            pp_defs[found].nparam=-1;
            return;
        }
    }
    char exp0[4096];
    pp_subst_defines(line, exp0, sizeof(exp0));

    /* NASM token paste `%+`: collapse `A %+ B` -> `AB` (used by isr_stubs.S
     * `dq isr %+ vec` to build isr0..isr255). Done after define substitution
     * so the operands are already expanded. Author: F E R M I ∞ H A R T. */
    char exp[4096];
    {
        int oi=0; const char *p=exp0;
        while(*p){
            if(p[0]=='%'&&p[1]=='+'){
                while(oi>0 && (exp[oi-1]==' '||exp[oi-1]=='\t')) oi--;
                p+=2;
                while(*p==' '||*p=='\t')p++;
                continue;
            }
            if(oi<(int)sizeof(exp)-1) exp[oi++]=*p;
            p++;
        }
        exp[oi]=0;
    }

    const char *p=exp; while(*p==' '||*p=='\t')p++;
    if (*p && *p!=';'){
        const char *s=p;
        while(*p && *p!=' '&&*p!='\t'&&*p!=','&&*p!=';'&&*p!='\n'&&*p!='\r')p++;
        int nlen=(int)(p-s);
        if (nlen>0 && nlen<NAME_MAX){
            char name[NAME_MAX]; memcpy(name,s,nlen); name[nlen]=0;
            PPMac *mac=NULL;
            uint32_t mh = str_hash(name, (size_t)nlen);
            int mmask = PPMAC_HT_CAP - 1;
            int mhi = (int)(mh & (uint32_t)mmask);
            while (pp_mac_ht[mhi].hash) {
                int idx = pp_mac_ht[mhi].idx;
                if (pp_mac_ht[mhi].hash == mh && pp_mac_ht[mhi].len == (uint8_t)nlen &&
                    memcmp(pp_macs[idx].name, name, (size_t)nlen) == 0) {
                    mac = &pp_macs[idx]; break;
                }
                mhi = (mhi + 1) & mmask;
            }
            if(mac){
                char args[16][256]; int nargs=0;
                const char *a=p;
                int ai=0; int had_comma=0;
                while(*a && *a!=';' && *a!='\n' && *a!='\r'){
                    if(*a==','){
                        if(nargs<16){ args[nargs][ai]=0; nargs++; }
                        ai=0; had_comma=1; a++; continue;
                    }
                    if((*a==' '||*a=='\t') && ai==0){ a++; continue; } /* leading spaces */
                    if(nargs<16 && ai<255) args[nargs][ai++]=*a;
                    had_comma=0;
                    a++;
                }
                if(ai>0 || had_comma){
                    if(nargs<16){ args[nargs][ai]=0; nargs++; }
                }
                pp_expand_macro(mac, args, nargs, depth);
                return;
            }
        }
    }
    pp_emit_str(exp);
    pp_emit_ch('\n');
}

/* trimmed start of a line buffer */
static const char *pp_trim(const char *q){ while(*q==' '||*q=='\t')q++; return q; }

/* Conditional-assembly frame.  active==1 means the current branch is being
 * emitted; matched==1 means some earlier branch in this %if was true, so
 * later %elif/%else must stay off. */
typedef struct { int active; int matched; } PPFrame;

/* True if `name` is a currently-defined preprocessor symbol (%define or
 * %assign). */
static int pp_is_defined(const char *name){
    return pp_def_find(name) >= 0;
}

/* Parse one identifier from *pp into out; returns 1 if an identifier was
 * parsed.  Advances *pp past trailing spaces. */
static int pp_parse_ident(const char **pp, char *out, size_t outs){
    const char *p = pp_trim(*pp);
    size_t n = 0;
    while (*p && (pp_is_ident((unsigned char)*p) || *p=='.') && n+1 < outs){
        out[n++] = *p++;
    }
    if (n == 0) return 0;
    out[n] = 0;
    *pp = pp_trim(p);
    return 1;
}

/* Parse a comma-separated token for %ifidn (NASM compares single tokens).
 * Strips surrounding whitespace and returns 0 if nothing before comma/EOL. */
static int pp_parse_idn_arg(const char **pp, char *out, size_t outs){
    const char *p = pp_trim(*pp);
    size_t n = 0;
    while (*p && *p!=',' && *p!=';' && *p!='\n' && *p!='\r' && *p!='\t' && n+1 < outs){
        out[n++] = *p++;
    }
    while (n > 0 && (out[n-1]==' ' || out[n-1]=='\t')) n--;
    if (n == 0) return 0;
    out[n] = 0;
    *pp = p;
    if (*p == ',') { (*pp)++; *pp = pp_trim(*pp); }
    return 1;
}

/* Evaluate a preprocessor conditional expression (after the directive name).
 * The leading '%' has already been stripped, so the body for "%ifdef FOO"
 * arrives as "def FOO".  Supports:
 *   <number>                truthy if nonzero
 *   <name>                  truthy if defined
 *   def name                true if name defined
 *   ndef name               true if name not defined
 *   idn a, b                true if token a == token b
 *   nidn a, b               true if token a != token b
 */
static int pp_eval_cond(const char *expr){
    const char *p = pp_trim(expr);
    if (!*p || *p == ';') return 0;

    /* def / ndef */
    if (!strncmp(p, "def", 3) && (p[3]==' '||p[3]=='\t'||p[3]==0)){
        char nm[NAME_MAX];
        const char *q = pp_trim(p+3);
        if (!pp_parse_ident(&q, nm, sizeof(nm))) die("%ifdef needs identifier");
        return pp_is_defined(nm);
    }
    if (!strncmp(p, "ndef", 4) && (p[4]==' '||p[4]=='\t'||p[4]==0)){
        char nm[NAME_MAX];
        const char *q = pp_trim(p+4);
        if (!pp_parse_ident(&q, nm, sizeof(nm))) die("%ifndef needs identifier");
        return !pp_is_defined(nm);
    }
    /* idn / nidn */
    if (!strncmp(p, "idn", 3) && (p[3]==' '||p[3]=='\t'||p[3]==0)){
        char a[NAME_MAX], b[NAME_MAX];
        const char *q = pp_trim(p+3);
        if (!pp_parse_idn_arg(&q, a, sizeof(a)) || !pp_parse_idn_arg(&q, b, sizeof(b)))
            die("%ifidn needs two comma-separated tokens");
        return strcmp(a, b) == 0;
    }
    if (!strncmp(p, "nidn", 4) && (p[4]==' '||p[4]=='\t'||p[4]==0)){
        char a[NAME_MAX], b[NAME_MAX];
        const char *q = pp_trim(p+4);
        if (!pp_parse_idn_arg(&q, a, sizeof(a)) || !pp_parse_idn_arg(&q, b, sizeof(b)))
            die("%ifnidn needs two comma-separated tokens");
        return strcmp(a, b) != 0;
    }

    /* Numeric / bare identifier (legacy %if behaviour) */
    long cv = strtol(p, NULL, 0);
    if (p[0]=='0' && (p[1]==0 || p[1]==' ' || p[1]=='\t' || p[1]==';')) return 0;
    if (cv != 0) return 1;
    if (isdigit((unsigned char)p[0])) return 0;
    /* bare identifier: true if defined */
    char nm[NAME_MAX];
    const char *q = p;
    if (pp_parse_ident(&q, nm, sizeof(nm))) return pp_is_defined(nm);
    return 1; /* non-empty unknown expression -> true, matching NASM leniency */
}

/* Main preprocessor pass. Returns a freshly-allocated expanded source. */
static char *preprocess(char *src, long sz){
    pp_cap = (size_t)sz + 4096; /* start small; pp_emit_ch grows exponentially */
    pp_out = malloc(pp_cap); if(!pp_out) die("oom in preprocessor");
    pp_len = 0;

    PPFrame frame[64]; int fsp=0; int nfalse=0; /* nfalse = number of inactive frames */
    char *p=src; g_line=0;
    while(*p){
        g_line++;
        char *eol=strchr(p,'\n');
        char *next = eol?eol+1:NULL;
        char buf[1024];
        int len = eol?(int)(eol-p):(int)strlen(p);
        if(len>=(int)sizeof(buf))len=sizeof(buf)-1;
        memcpy(buf,p,len); buf[len]=0;
        const char *q=pp_trim(buf);

        /* ---- conditional assembly: track %if/%elif/%else/%endif even while skipping */
        int is_if_directive = 0, is_elif = 0;
        if (!strncmp(q, "%if", 3)) {
            const char *r = q + 3;
            if (*r==' '||*r=='\t'||*r==0) { is_if_directive = 1; is_elif = 0; }
            else if (!strncmp(r, "def", 3) && (r[3]==' '||r[3]=='\t'||r[3]==0)) { is_if_directive = 1; is_elif = 0; }
            else if (!strncmp(r, "ndef", 4) && (r[4]==' '||r[4]=='\t'||r[4]==0)) { is_if_directive = 1; is_elif = 0; }
            else if (!strncmp(r, "idn", 3) && (r[3]==' '||r[3]=='\t'||r[3]==0)) { is_if_directive = 1; is_elif = 0; }
            else if (!strncmp(r, "nidn", 4) && (r[4]==' '||r[4]=='\t'||r[4]==0)) { is_if_directive = 1; is_elif = 0; }
        }
        if (!is_if_directive && !strncmp(q, "%elif", 5)) {
            const char *r = q + 5;
            if (*r==' '||*r=='\t'||*r==0) { is_if_directive = 1; is_elif = 1; }
            else if (!strncmp(r, "def", 3) && (r[3]==' '||r[3]=='\t'||r[3]==0)) { is_if_directive = 1; is_elif = 1; }
            else if (!strncmp(r, "ndef", 4) && (r[4]==' '||r[4]=='\t'||r[4]==0)) { is_if_directive = 1; is_elif = 1; }
            else if (!strncmp(r, "idn", 3) && (r[3]==' '||r[3]=='\t'||r[3]==0)) { is_if_directive = 1; is_elif = 1; }
            else if (!strncmp(r, "nidn", 4) && (r[4]==' '||r[4]=='\t'||r[4]==0)) { is_if_directive = 1; is_elif = 1; }
        }
        if(is_if_directive){
            const char *body = pp_trim(q + (is_elif ? 5 : 3));
            int cond = pp_eval_cond(body);
            /* Parent frames must all be active for this branch to fire. */
            int parent_active = (nfalse == 0);
            if(!is_elif){
                if(fsp>=64) die("%if nesting too deep");
                frame[fsp].active = parent_active && cond;
                frame[fsp].matched = frame[fsp].active;
                fsp++;
                if(!frame[fsp-1].active) nfalse++;
            } else {
                if(fsp<=0) die("%elif without %if");
                PPFrame *fr = &frame[fsp-1];
                /* Ancestors active?  The current frame itself may be inactive,
                 * in which case nfalse counts it; allow that one. */
                int ancestors_active = (nfalse == 0) || (nfalse == 1 && !fr->active);
                if(fr->matched || !ancestors_active){
                    if(fr->active){ fr->active = 0; nfalse++; }
                } else {
                    fr->active = ancestors_active && cond;
                    if(fr->active){ fr->matched = 1; if(nfalse>0) nfalse--; }
                }
            }
            if(!next)break; p=next; continue;
        }
        if(!strncmp(q,"%else",5) && (q[5]==' '||q[5]=='\t'||q[5]==0)){
            if(fsp<=0) die("%else without %if");
            PPFrame *fr = &frame[fsp-1];
            int parent_active = (nfalse == 0 || (fr->active && nfalse == 1));
            if(fr->matched){
                if(fr->active){ fr->active = 0; nfalse++; }
            } else {
                if(parent_active){
                    if(!fr->active){ fr->active = 1; if(nfalse>0) nfalse--; }
                }
            }
            fr->matched = 1;
            if(!next)break; p=next; continue;
        }
        if(!strncmp(q,"%endif",6) && (q[6]==' '||q[6]=='\t'||q[6]==0)){
            if(fsp<=0) die("%endif without %if");
            PPFrame *fr = &frame[--fsp];
            if(!fr->active) nfalse--;
            if(!next)break; p=next; continue;
        }
        if(nfalse>0){ if(!next)break; p=next; continue; } /* inside a dead block */

        /* ---- %define ---- */
        if(!strncmp(q,"%define",7) && (q[7]==' '||q[7]=='\t')){
            const char *c=pp_trim(q+7);
            char nm[NAME_MAX]; int ni=0;
            while(*c && (pp_is_ident((unsigned char)*c)) && ni<NAME_MAX-1) nm[ni++]=*c++;
            nm[ni]=0;
            if(ni==0) die("%define needs a name");
            if(pp_ndef>=PP_MAXDEF) die("too many %define");
            int nparam=-1; char params[4][NAME_MAX];
            /* function-like define: name immediately followed by '(' */
            if(*c=='('){
                c++; nparam=0;
                while(*c && *c!=')'){
                    while(*c==' '||*c=='\t'||*c==',')c++;
                    int pi=0;
                    while(*c && pp_is_ident((unsigned char)*c) && pi<NAME_MAX-1) params[nparam][pi++]=*c++;
                    params[nparam][pi]=0;
                    if(pi>0 && nparam<4) nparam++;
                    while(*c==' '||*c=='\t')c++;
                }
                if(*c==')')c++;
            }
            const char *v=pp_trim(c);
            char val[256]; int vi=0;
            while(*v && *v!=';' && vi<255) val[vi++]=*v++;
            while(vi>0 && (val[vi-1]==' '||val[vi-1]=='\t')) vi--;
            val[vi]=0;
            strncpy(pp_defs[pp_ndef].name,nm,NAME_MAX-1); pp_defs[pp_ndef].name[NAME_MAX-1]=0;
            strncpy(pp_defs[pp_ndef].value,val,255); pp_defs[pp_ndef].value[255]=0;
            pp_defs[pp_ndef].nparam=nparam;
            for(int k=0;k<nparam&&k<4;k++){ strncpy(pp_defs[pp_ndef].params[k],params[k],NAME_MAX-1); pp_defs[pp_ndef].params[k][NAME_MAX-1]=0; }
            ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[pp_ndef].name, strlen(nm)), (uint8_t)strlen(nm), pp_ndef);
            pp_ndef++;
            if(!next)break; p=next; continue;
        }

        /* ---- %assign NAME expr : reassignable numeric (NASM). Evaluated now;
         * stored as a decimal-string object-like define. Used by isr_stubs.S
         * to generate vectored stubs. Author: F E R M I ∞ H A R T. ---- */
        if(!strncmp(q,"%assign",7) && (q[7]==' '||q[7]=='\t')){
            const char *c=pp_trim(q+7);
            char nm[NAME_MAX]; int ni=0;
            while(*c && pp_is_ident((unsigned char)*c) && ni<NAME_MAX-1) nm[ni++]=*c++;
            nm[ni]=0;
            if(ni==0) die("%assign needs a name");
            const char *v=pp_trim(c);
            /* substitute existing defines into the expr, then evaluate */
            char raw[256]; int ri=0; while(*v&&*v!=';'&&ri<255)raw[ri++]=*v++; raw[ri]=0;
            char sub[512]; pp_subst_defines(raw, sub, sizeof(sub));
            long val = parse_expr(sub);
            char vbuf[32]; snprintf(vbuf,sizeof(vbuf),"%ld",val);
            /* reassign if exists, else add */
            int found = pp_def_find(nm);
            if(found<0){ if(pp_ndef>=PP_MAXDEF)die("too many %assign"); found=pp_ndef++;
                         strncpy(pp_defs[found].name,nm,NAME_MAX-1); pp_defs[found].name[NAME_MAX-1]=0;
                         ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[found].name, strlen(nm)), (uint8_t)strlen(nm), found); }
            strncpy(pp_defs[found].value,vbuf,255); pp_defs[found].value[255]=0;
            pp_defs[found].nparam=-1;
            if(!next)break; p=next; continue;
        }

        /* ---- %macro NAME argc ... %endmacro ---- */
        if(!strncmp(q,"%macro",6) && (q[6]==' '||q[6]=='\t'||q[6]==0)){
            const char *c=pp_trim(q+6);
            char nm[NAME_MAX]; int ni=0;
            while(*c && *c!=' '&&*c!='\t' && ni<NAME_MAX-1) nm[ni++]=*c++;
            nm[ni]=0; c=pp_trim(c);
            int argc=0; int variadic=0;
            if(*c=='*'){ argc=0; variadic=1; c++; }
            else if((*c=='+'||*c=='-'||*c=='*'||isdigit((unsigned char)*c)) &&
                    (strchr(c,'*') || strchr(c,'+'))){
                /* forms: n-*, n+  */
                argc=(int)strtol(c,NULL,10);
                while(*c && *c!='*' && *c!='+') c++;
                if(*c=='*' || *c=='+') variadic=1;
            }
            else { argc=(int)strtol(c,NULL,10); }
            if(ni==0) die("%macro needs a name");
            if(pp_nmac>=PP_MAXMAC) die("too many %macro");
            /* body spans from next line up to (not including) the %endmacro line */
            char *bp = next; char *scan = next; char *body_end=NULL; char *after=NULL;
            while(scan && *scan){
                char *se=strchr(scan,'\n'); char *snext=se?se+1:NULL;
                char lb[1024]; int ll=se?(int)(se-scan):(int)strlen(scan);
                if(ll>=(int)sizeof(lb))ll=sizeof(lb)-1;
                memcpy(lb,scan,ll); lb[ll]=0;
                const char *et=pp_trim(lb);
                if(!strncmp(et,"%endmacro",9) && (et[9]==' '||et[9]=='\t'||et[9]==0)){ body_end=scan; after=snext; break; }
                if(!snext){ body_end=scan+strlen(scan); after=NULL; break; }
                scan=snext;
            }
            if(!body_end) die("%macro without %endmacro");
            int blen=(int)(body_end-bp);
            char *body=(char*)arena_alloc((size_t)blen+1);
            memcpy(body,bp,blen); body[blen]=0;
            strncpy(pp_macs[pp_nmac].name,nm,NAME_MAX-1); pp_macs[pp_nmac].name[NAME_MAX-1]=0;
            pp_macs[pp_nmac].argc=argc; pp_macs[pp_nmac].variadic=variadic; pp_macs[pp_nmac].body=body;
            ht_insert(pp_mac_ht, PPMAC_HT_CAP, str_hash(pp_macs[pp_nmac].name, strlen(nm)), (uint8_t)strlen(nm), pp_nmac);
            pp_nmac++;
            if(!after) break; p=after; continue;
        }

        /* ---- struc NAME ... endstruc ---- */
        if(!strncmp(q,"struc",5) && (q[5]==' '||q[5]=='\t'||q[5]==0)){
            const char *c=pp_trim(q+5);
            char nm[NAME_MAX]; int ni=0;
            while(*c && *c!=' '&&*c!='\t' && ni<NAME_MAX-1) nm[ni++]=*c++;
            nm[ni]=0;
            if(ni==0) die("struc needs a name");
            /* body spans from next line up to (not including) endstruc */
            char *bp = next; char *scan = next; char *body_end=NULL; char *after=NULL;
            while(scan && *scan){
                char *se=strchr(scan,'\n'); char *snext=se?se+1:NULL;
                char lb[1024]; int ll=se?(int)(se-scan):(int)strlen(scan);
                if(ll>=(int)sizeof(lb))ll=sizeof(lb)-1;
                memcpy(lb,scan,ll); lb[ll]=0;
                const char *t=pp_trim(lb);
                if(!strncmp(t,"endstruc",8) && (t[8]==' '||t[8]=='\t'||t[8]==0)){ body_end=scan; after=snext; break; }
                if(!snext){ body_end=scan+strlen(scan); after=NULL; break; }
                scan=snext;
            }
            if(!body_end) die("struc without endstruc");
            int blen=(int)(body_end-bp);
            char *body=(char*)arena_alloc((size_t)blen+1);
            memcpy(body,bp,blen); body[blen]=0;
            /* Register the struct in the assembler-level table too, so
             * istruc/at/iend (which run at assembly time) can find it.
             * Offsets are sequential (NASM semantics), matching the
             * %define constants emitted below. Preprocess runs exactly
             * once, so this never double-registers across passes.
             * Author: F E R M I ∞ H A R T. */
            int reg_idx = -1;
            if (find_struct(nm) < 0 && g_nstructs < MAX_STRUCTS) {
                reg_idx = g_nstructs;
                strncpy(g_structs[reg_idx].name, nm, NAME_MAX-1);
                g_structs[reg_idx].name[NAME_MAX-1] = 0;
                g_structs[reg_idx].nfields = 0;
            }
            /* Emit structure constants as %define offsets */
            int offset = 0;
            char *l = body;
            while(*l){
                char *eol = strchr(l,'\n');
                int ll = eol?(int)(eol-l):(int)strlen(l);
                char tmp[2048]; int ti=0;
                for(int j=0;j<ll;j++) if(ti<(int)sizeof(tmp)-1) tmp[ti++]=l[j];
                tmp[ti]=0;
                /* Parse: field resb/resd/resq/resw SIZE */
                const char *t = pp_trim(tmp);
                /* Skip leading dot for local labels */
                if(*t=='.') t++;
                char fname[NAME_MAX]; int fn=0;
                while(*t && pp_is_ident((unsigned char)*t) && fn<NAME_MAX-1) fname[fn++]=*t++;
                fname[fn]=0; t=pp_trim(t);
                int size=0;
                if(!strncmp(t,"resb",4)){ 
                    t+=4; t=pp_trim(t);
                    size=(int)strtol(t,NULL,10); if(size==0) size=1;
                    while(*t && pp_is_ident((unsigned char)*t)) t++;
                    t=pp_trim(t);
                }
                else if(!strncmp(t,"resw",4)){
                    t+=4; t=pp_trim(t);
                    size=(int)strtol(t,NULL,10)*2; if(size==0) size=2;
                    while(*t && pp_is_ident((unsigned char)*t)) t++;
                    t=pp_trim(t);
                }
                else if(!strncmp(t,"resd",4)){
                    t+=4; t=pp_trim(t);
                    size=(int)strtol(t,NULL,10)*4; if(size==0) size=4;
                    while(*t && pp_is_ident((unsigned char)*t)) t++;
                    t=pp_trim(t);
                }
                else if(!strncmp(t,"resq",4)){
                    t+=4; t=pp_trim(t);
                    size=(int)strtol(t,NULL,10)*8; if(size==0) size=8;
                    while(*t && pp_is_ident((unsigned char)*t)) t++;
                    t=pp_trim(t);
                }
                /* Skip initializer if present */
                while(*t && *t!=';' && *t!='\n') t++;
                if(fn>0 && size>0){
                    /* Define STRUCT.field = offset */
                    char defname[NAME_MAX+64];
                    snprintf(defname, sizeof(defname), "%s.%s", nm, fname);
                    char defval[64];
                    snprintf(defval, sizeof(defval), "%d", offset);
                    if(pp_ndef<PP_MAXDEF){
                        size_t namelen = strlen(defname);
                        strncpy(pp_defs[pp_ndef].name, defname, NAME_MAX-1);
                        pp_defs[pp_ndef].name[NAME_MAX-1]=0;
                        strncpy(pp_defs[pp_ndef].value, defval, 255);
                        pp_defs[pp_ndef].value[255]=0;
                        pp_defs[pp_ndef].nparam = -1;
                        uint32_t h = str_hash(defname, namelen);
                        ht_insert(pp_def_ht, PPDEF_HT_CAP, h, (uint8_t)namelen, pp_ndef);
                        pp_ndef++;
                    }
                    if (reg_idx >= 0 && g_structs[reg_idx].nfields < MAX_FIELDS) {
                        StructField *sf = &g_structs[reg_idx].fields[g_structs[reg_idx].nfields++];
                        strncpy(sf->name, fname, NAME_MAX-1);
                        sf->name[NAME_MAX-1] = 0;
                        sf->offset = offset;
                        sf->size = size;
                    }
                    offset += size;
                }
                if(!eol) break;
                l=eol+1;
            }
            /* Define STRUCT_size = total offset */
            if(pp_ndef<PP_MAXDEF){
                char defname[NAME_MAX+64];
                snprintf(defname, sizeof(defname), "%s_size", nm);
                char defval[64];
                snprintf(defval, sizeof(defval), "%d", offset);
                size_t namelen = strlen(defname);
                strncpy(pp_defs[pp_ndef].name, defname, NAME_MAX-1);
                pp_defs[pp_ndef].name[NAME_MAX-1]=0;
                strncpy(pp_defs[pp_ndef].value, defval, 255);
                pp_defs[pp_ndef].value[255]=0;
                pp_defs[pp_ndef].nparam = -1;
                uint32_t h = str_hash(defname, namelen);
                ht_insert(pp_def_ht, PPDEF_HT_CAP, h, (uint8_t)namelen, pp_ndef);
                pp_ndef++;
            }
            /* Commit the assembler-level struct registration. */
            if (reg_idx >= 0) {
                g_structs[reg_idx].total_size = offset;
                g_nstructs++;
            }
            if(!after) break; p=after; continue;
        }

        /* ---- %rep N ... %endrep ---- */
        if(!strncmp(q,"%rep",4) && (q[4]==' '||q[4]=='\t')){
            const char *c=pp_trim(q+4);
            int count=(int)strtol(c,NULL,10);
            /* body spans from next line up to (not including) the %endrep line */
            char *bp = next; char *scan = next; char *body_end=NULL; char *after=NULL;
            while(scan && *scan){
                char *se=strchr(scan,'\n'); char *snext=se?se+1:NULL;
                char lb[1024]; int ll=se?(int)(se-scan):(int)strlen(scan);
                if(ll>=(int)sizeof(lb))ll=sizeof(lb)-1;
                memcpy(lb,scan,ll); lb[ll]=0;
                const char *er=pp_trim(lb);
                if(!strncmp(er,"%endrep",7) && (er[7]==' '||er[7]=='\t'||er[7]==0)){ body_end=scan; after=snext; break; }
                if(!snext){ body_end=scan+strlen(scan); after=NULL; break; }
                scan=snext;
            }
            if(!body_end) die("%rep without %endrep");
            int blen=(int)(body_end-bp);
            char *body=(char*)arena_alloc((size_t)blen+1);
            memcpy(body,bp,blen); body[blen]=0;
            /* Expand count times */
            for(int i=0;i<count;i++){
                char *l=body;
                while(*l){
                    char *eol=strchr(l,'\n');
                    int ll=eol?(int)(eol-l):(int)strlen(l);
                    char tmp[2048]; int ti=0;
                    for(int j=0;j<ll;j++) if(ti<(int)sizeof(tmp)-1) tmp[ti++]=l[j];
                    tmp[ti]=0;
                    pp_process_line(tmp, 0);
                    if(!eol) break;
                    l=eol+1;
                }
            }
            if(!after) break; p=after; continue;
        }

        /* ---- anonymous local labels: @@ / @F / @B ----
         * Replace "@@:" with a unique synthetic label, and @F/@B with the
         * corresponding synthetic name.  This gives NASM-compatible anonymous
         * local labels without changing the assembler's symbol table.
         * Author: F E R M I ∞ H A R T. */
        {
            static int pp_llabel = 0;
            char tmp[2048]; int ti = 0;
            const char *s = buf;
            int changed = 0;
            while (*s && *s != ';' && ti < (int)sizeof(tmp)-1 && ti < (int)sizeof(buf)-1) {
                if (s[0]=='@' && s[1]=='@' && (s[2]==':' || s[2]==' ' || s[2]=='\t' || s[2]=='\n' || s[2]=='\r' || s[2]==0)) {
                    int n = snprintf(tmp+ti, sizeof(tmp)-ti, "..@L.%d", pp_llabel++);
                    if (n < 0 || n >= (int)(sizeof(tmp)-ti)) die("local label overflow");
                    ti += n; s += 2; changed = 1;
                    if (*s == ':') { if (ti < (int)sizeof(tmp)-1) tmp[ti++] = *s; s++; }
                } else if (s[0]=='@' && s[1]=='F') {
                    int n = snprintf(tmp+ti, sizeof(tmp)-ti, "..@L.%d", pp_llabel);
                    if (n < 0 || n >= (int)(sizeof(tmp)-ti)) die("local label overflow");
                    ti += n; s += 2; changed = 1;
                } else if (s[0]=='@' && s[1]=='B') {
                    int n = snprintf(tmp+ti, sizeof(tmp)-ti, "..@L.%d", pp_llabel ? pp_llabel-1 : 0);
                    if (n < 0 || n >= (int)(sizeof(tmp)-ti)) die("local label overflow");
                    ti += n; s += 2; changed = 1;
                } else {
                    tmp[ti++] = *s++;
                }
            }
            if (changed) {
                tmp[ti] = 0;
                memcpy(buf, tmp, ti+1);
                q = pp_trim(buf);
            }
        }

        /* ---- [BITS n] : emit a bare `bits N` line so the ASSEMBLY-time
         * directive handler updates g_bits each pass. The preprocessor runs
         * once, but assemble_pass() resets g_bits=64 and re-scans the emitted
         * stream every pass; if we swallowed [BITS n] here, the bracketed form
         * (used by ap_trampoline's [BITS 16]/[BITS 32]) would never set the
         * mode at emission time -> wrong 0x66/0x67 prefixes and addressing.
         * Author: F E R M I ∞ H A R T. */
        if(strlen(q) >= 6 && q[0]=='[' && (q[1]=='b'||q[1]=='B') && (q[2]=='i'||q[2]=='I') &&
           (q[3]=='t'||q[3]=='T') && (q[4]=='s'||q[4]=='S')){
            const char *c=pp_trim(q+5);
            if(c[0]=='6'&&c[1]=='4'){ pp_emit_str("bits 64\n"); if(!next)break; p=next; continue; }
            if(c[0]=='3'&&c[1]=='2'){ pp_emit_str("bits 32\n"); if(!next)break; p=next; continue; }
            if(c[0]=='1'&&c[1]=='6'){ pp_emit_str("bits 16\n"); if(!next)break; p=next; continue; }
            die2("unsupported BITS directive", q);
        }

        /* ---- ordinary line: defines + macro invocation ---- */
        pp_process_line(buf, 0);
        if (!next) break;
        p = next;
    }
    if(fsp!=0) die("unterminated %if");
    pp_emit_ch(0);
    arena_reset();
    free(src);
    return pp_out;
}

/* ═════════════════════════════════════════════════════════════════════════
 * ADR-0023 Phase 2 — basm self-attestation
 *
 * Bind source .asm SHA → output .o SHA in a deterministic record. Composes
 * with bear-ld's .ldproof to form a verifiable chain from C source (via
 * .bearproof) to ASM source (via .basmproof) to ELF (via .ldproof).
 *
 * Inline SHA-256 (FIPS 180-4) — same primitive used by bear-ld; ~70 LoC.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>.
 * ═════════════════════════════════════════════════════════════════════════ */
/* SHA-256 (FIPS 180-4) with runtime SHA-NI dispatch.
 * Centralised in sha256_ni.h and imported here with the basm_ namespace. */
#define SHA256NI_CTX_TYPE basm_sha_ctx
#define SHA256NI_PREFIX   basm_sha_
#include "sha256_ni.h"
static void basm_sha_file(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path,"rb"); if (!f) { memset(out,0,32); return; }
    basm_sha_ctx c; basm_sha_init(&c); uint8_t b[4096]; size_t n;
    while (!feof(f) && !ferror(f)) {
        n = fread(b,1,sizeof(b),f);
        if (n > 0) basm_sha_update(&c,b,n);
    }
    if (ferror(f)) { fclose(f); memset(out,0,32); return; }
    fclose(f); basm_sha_final(&c,out);
}
static void basm_hex32(const uint8_t in[32], char out[65]) {
    static const char H[]="0123456789abcdef";
    for (int i=0;i<32;i++){out[i*2]=H[in[i]>>4]; out[i*2+1]=H[in[i]&15];}
    out[64]=0;
}

static const char *basm_self_exe_path(void);

static int basm_hex_eq32(const uint8_t h[32], const char *hex) {
    char got[65];
    basm_hex32(h, got);
    return hex && strlen(hex) >= 64 && memcmp(got, hex, 64) == 0;
}

static int basm_proof_value(const char *body, const char *key, char *out, size_t outsz) {
    size_t klen = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == body || p[-1] == '\n') && p[klen] == ':' && p[klen + 1] == ' ') {
            const char *v = p + klen + 2;
            const char *e = strchr(v, '\n');
            size_t n = e ? (size_t)(e - v) : strlen(v);
            if (n >= outsz) n = outsz - 1;
            memcpy(out, v, n);
            out[n] = 0;
            return 1;
        }
        p += klen;
    }
    return 0;
}

static char *basm_read_text_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    fclose(f);
    buf[n] = 0;
    if (out_len) *out_len = n;
    return buf;
}

static int verify_basm_attestation(const char *attest_path, int require_signature) {
    long n = 0;
    char *body = basm_read_text_file(attest_path, &n);
    if (!body) { dprintf(2, "basm: cannot read attestation '%s'\n", attest_path); return 1; }
    if (n < 20 || strncmp(body, "basm attestation v2\n", 20) != 0) {
        dprintf(2, "basm: bad attestation header '%s'\n", attest_path);
        free(body); return 1;
    }

    char src[1024], out[1024], fmt[64], src_hex[65], out_hex[65], tool_hex[65], merkle_hex[65], sig[128];
    int ok = 1;
    ok &= basm_proof_value(body, "source_path", src, sizeof(src));
    ok &= basm_proof_value(body, "output_path", out, sizeof(out));
    ok &= basm_proof_value(body, "output_format", fmt, sizeof(fmt));
    ok &= basm_proof_value(body, "source_sha256", src_hex, sizeof(src_hex));
    ok &= basm_proof_value(body, "output_sha256", out_hex, sizeof(out_hex));
    ok &= basm_proof_value(body, "tool_sha256", tool_hex, sizeof(tool_hex));
    ok &= basm_proof_value(body, "merkle_node_id", merkle_hex, sizeof(merkle_hex));
    ok &= basm_proof_value(body, "signature", sig, sizeof(sig));
    if (!ok) { dprintf(2, "basm: incomplete attestation '%s'\n", attest_path); free(body); return 1; }
    if (strcmp(fmt, "elf64") && strcmp(fmt, "bin")) {
        dprintf(2, "basm: unsupported attested format '%s'\n", fmt);
        free(body); return 1;
    }

    uint8_t th[32], sh[32], oh[32], mh[32];
    const char *self_path = basm_self_exe_path();
    basm_sha_file(self_path ? self_path : "", th);
    basm_sha_file(src, sh);
    basm_sha_file(out, oh);
    basm_sha_ctx merkle_ctx; basm_sha_init(&merkle_ctx);
    basm_sha_update(&merkle_ctx, th, 32);
    basm_sha_update(&merkle_ctx, sh, 32);
    basm_sha_update(&merkle_ctx, oh, 32);
    basm_sha_final(&merkle_ctx, mh);

    if (!basm_hex_eq32(th, tool_hex)) { dprintf(2, "basm: tool hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(sh, src_hex)) { dprintf(2, "basm: source hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(oh, out_hex)) { dprintf(2, "basm: output hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(mh, merkle_hex)) { dprintf(2, "basm: merkle hash mismatch in '%s'\n", attest_path); ok = 0; }

    if (require_signature || strcmp(sig, "unsigned") != 0) {
        extern int sign_verify_attestation(const char *path, uint8_t out_pub[32]);
        if (strcmp(sig, "unsigned") == 0) {
            dprintf(2, "basm: unsigned attestation rejected '%s'\n", attest_path);
            ok = 0;
        } else if (sign_verify_attestation(attest_path, NULL) != 0) {
            dprintf(2, "basm: attestation signature invalid '%s'\n", attest_path);
            ok = 0;
        }
    }

    free(body);
    return ok ? 0 : 1;
}

/* Best-effort path to the running executable.  Linux uses /proc/self/exe;
 * macOS uses _NSGetExecutablePath.  Falls back to an empty hash if neither
 * works. */
static const char *basm_self_exe_path(void) {
#ifdef BASM_NO_PROC_SELF_EXE
    static char path[4096];
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) == 0) return path;
    return NULL;
#else
    return "/proc/self/exe";
#endif
}

static void emit_basm_attestation(const char *attest_path, const char *src_path,
                                  const char *out_path, const char *fmt) {
    FILE *f = fopen(attest_path, "w");
    if (!f) { dprintf(2, "basm: cannot write attestation '%s'\n", attest_path); return; }
    uint8_t self_h[32], src_h[32], out_h[32];
    char self_hex[65], src_hex[65], out_hex[65];
    const char *self_path = basm_self_exe_path();
    basm_sha_file(self_path ? self_path : "", self_h); basm_hex32(self_h, self_hex);
    basm_sha_file(src_path, src_h); basm_hex32(src_h, src_hex);
    basm_sha_file(out_path, out_h); basm_hex32(out_h, out_hex);

    /* Merkle DAG node ID: binds tool || source || output hashes.
     * This is the cryptographic anchor that the nanokernel boot chain can
     * hang off a larger Merkle tree. */
    basm_sha_ctx merkle_ctx; basm_sha_init(&merkle_ctx);
    basm_sha_update(&merkle_ctx, self_h, 32);
    basm_sha_update(&merkle_ctx, src_h, 32);
    basm_sha_update(&merkle_ctx, out_h, 32);
    uint8_t merkle_h[32]; basm_sha_final(&merkle_ctx, merkle_h);
    char merkle_hex[65]; basm_hex32(merkle_h, merkle_hex);

    /* DDC (Diverse Double-Compiling) hooks: record the exact compiler that
     * built this basm binary, closing Ken Thompson's bootstrap paradox. */
    const char *ddc_hash = getenv("BASM_DDC_COMPILER_HASH");
    const char *ddc_path = getenv("BASM_DDC_COMPILER_PATH");

    /* Deterministic build timestamp.  SOURCE_DATE_EPOCH is the reproducible
     * build standard; falling back to wall-clock only when unset keeps the
     * attestation useful for CI forensics without breaking reproducibility. */
    const char *sde = getenv("SOURCE_DATE_EPOCH");
    unsigned long long build_epoch = 0;
    if (sde) build_epoch = strtoull(sde, NULL, 10);

    fprintf(f, "basm attestation v2\n");
    fprintf(f, "tool: basm\n");
    fprintf(f, "tool_sha256: %s\n", self_hex);
    fprintf(f, "source_path: %s\n", src_path);
    fprintf(f, "source_sha256: %s\n", src_hex);
    fprintf(f, "output_path: %s\n", out_path);
    fprintf(f, "output_sha256: %s\n", out_hex);
    fprintf(f, "output_format: %s\n", fmt);
    fprintf(f, "merkle_node_id: %s\n", merkle_hex);
    fprintf(f, "build_epoch: %llu\n", build_epoch);
    if (ddc_hash) fprintf(f, "ddc_compiler_sha256: %s\n", ddc_hash);
    if (ddc_path) fprintf(f, "ddc_compiler_path: %s\n", ddc_path);
    fprintf(f, "signature: unsigned\n");
    fclose(f);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    const char *out="a.out.o"; const char *in=NULL; const char *fmt="elf64";
    const char *attest = NULL;
    const char *sign_key = NULL;
    const char *verify_attest = NULL;
    int verify_attest_strict = 0;
    for (int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-f")){ if(++i>=argc)die("-f arg"); fmt=argv[i];
            if(strcmp(fmt,"elf64")&&strcmp(fmt,"bin"))die2("only elf64,bin",fmt); }
        else if(!strcmp(argv[i],"-o")){ if(++i>=argc)die("-o arg"); out=argv[i]; }
        else if(argv[i][0]=='-'&&argv[i][1]=='g'){}
        else if(!strcmp(argv[i],"-F")){ if(++i>=argc)die("-F arg"); }
        else if(!strcmp(argv[i],"--emit-attestation")){ if(++i>=argc)die("--emit-attestation arg"); attest=argv[i]; }
        else if(!strcmp(argv[i],"--sign")){ if(++i>=argc)die("--sign arg"); sign_key=argv[i]; }
        else if(!strcmp(argv[i],"--verify-attestation")){ if(++i>=argc)die("--verify-attestation arg"); verify_attest=argv[i]; }
        else if(!strcmp(argv[i],"--verify-attestation-strict")){ if(++i>=argc)die("--verify-attestation-strict arg"); verify_attest=argv[i]; verify_attest_strict=1; }
        else if(argv[i][0]=='-'&&argv[i][1]=='I'){
            /* -Ipath or -I path */
            if(argv[i][2]) { if(g_nincpaths<INCPATH_MAX) g_incpaths[g_nincpaths++]=argv[i]+2; }
            else { if(++i>=argc)die("-I arg"); if(g_nincpaths<INCPATH_MAX) g_incpaths[g_nincpaths++]=argv[i]; }
        }
        else in=argv[i];
    }
    if (verify_attest) return verify_basm_attestation(verify_attest, verify_attest_strict);
    if(!in){ dprintf(2,"usage: basm -f elf64 -o out.o [-Ipath] [--emit-attestation FILE] [--sign KEY] in.basm\n       basm --verify-attestation[-strict] FILE.basmproof\n"); return 1; }
    g_fmt = fmt;  /* set global format for cur_off() org handling */
    g_file=in;
    g_srcname=in;   /* STT_FILE symbol name (NASM parity) */
    /* record the source directory for incbin relative resolution */
    { const char *slash=strrchr(in,'/');
      if(slash){ size_t n=(size_t)(slash-in); if(n>=sizeof(g_srcdir))n=sizeof(g_srcdir)-1;
                 memcpy(g_srcdir,in,n); g_srcdir[n]=0; } }
    FILE*f=fopen(in,"rb"); if(!f){perror("fopen");return 1;}
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    if(sz<0){fclose(f);dprintf(2,"basm: cannot size input\n");return 1;}
    char*src=malloc((size_t)sz+1); if(!src){fclose(f);dprintf(2,"oom\n");return 1;}
    if(fread(src,1,(size_t)sz,f)!=(size_t)sz){fclose(f);free(src);dprintf(2,"read error\n");return 1;}
    src[sz]=0; fclose(f);

    /* NASM-subset preprocessor pass: expands %define/%macro, resolves
     * %if/%endif, and consumes [BITS 64]. The assembler proper then runs on
     * the expanded source, unchanged. */
    src = preprocess(src, sz);

    /* Pre-scan EQU definitions so simple constants (e.g. banner_len) used
     * as immediates in .text are known during the first assembly pass. This
     * prevents layout mismatch between sizing and final passes. */
    prescan_equ(src);

    /* Branch sizing fixpoint: NASM picks the shortest stable encoding. We
     * iterate to a fixed point — each iteration recomputes every branch size
     * optimistically (rel8 if it fits with CURRENT layout), and we repeat until
     * the size assignment stops changing. This converges to the minimal stable
     * encoding (same as NASM), unlike a monotonic-grow-only scheme. */
    memset(g_branch_long, 0, sizeof(g_branch_long));
    g_sizing = 1; g_pass = 1;
    for (int iter=0; iter<128; iter++) {
        assemble_pass(src);                 /* records branch positions + target syms */
        if (!branch_decide(g_branch_ord))   /* promote from this consistent layout */
            break;                          /* fixed point: no promotion this pass */
    }
    g_sizing = 0; g_pass = 2;
    assemble_pass(src);
    if (!strcmp(fmt,"bin")) write_bin(out); else write_elf(out);

    /* ADR-0023 Phase 2: optional self-attestation. */
    if (attest) {
        emit_basm_attestation(attest, in, out, fmt);
        /* ADR-0023 Phase 4: optional Ed25519 sign.
         * Inline the signing here to keep basm a single-file build —
         * sign.c is shared with bear-ld and bearverify but basm
         * historically links no external .c files.  Re-using sign_*
         * symbols would create a duplicate-definition conflict in the
         * shared-archive scenario.  Keep the path simple by shelling
         * out to bearverify when basm is invoked sovereign — but in
         * the standard host build we link sign.c too via the Makefile.
         *
         * For now: if --sign was passed, basm best-effort calls the
         * sibling helper.  See compiler/basm/Makefile.
         */
        if (sign_key) {
            extern int sign_load_seed(const char *path, uint8_t seed[32]);
            extern int sign_finalise_attestation(const char *path, const uint8_t seed[32]);
            uint8_t seed[32];
            if (sign_load_seed(sign_key, seed) != 0)
                dprintf(2, "basm: WARNING: cannot load signing key '%s'\n", sign_key);
            else if (sign_finalise_attestation(attest, seed) != 0)
                dprintf(2, "basm: WARNING: signing failed\n");
        }
    }

    free(src);
    return 0;
}
