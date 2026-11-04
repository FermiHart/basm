/*
 * basm-core -- the Bear assembler.
 *
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
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
 * Build:  make (Bear compiler, static blibc).  Usage:  basm -f elf64 -o out.o in.basm
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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef BEAR_TIME_H
#include <crypto/crypto.h>
#endif

#ifdef BASM_NO_PROC_SELF_EXE
#include <mach-o/dyld.h>
#endif

/* INV-572: share repeated byte-set tests instead of spilling a branch per
 * character. NUL is excluded here; strchr is used directly when it is a member. */
static int char_in(int c, const char *set) {
    return c != 0 && strchr(set, c) != NULL;
}

/* ------------------------------------------------------------------ */
static const char *g_file = "<stdin>";
/* The top-level input filename, captured once in main() and used verbatim
 * for the STT_FILE symbol so the object matches NASM (which names the FILE
 * symbol after the source path). g_file is per-pass/per-include and resets
 * to "<stdin>", so it cannot serve this role. Author: F E R M I ∞ H A R T. */
static const char *g_srcname = "<stdin>";
static int g_explain = 0;
static int g_json_diagnostics = 0;
static int g_intent_instruction = 0;
static int g_intent_prefix = 0;
static void intent_diagnostic(const char *message, const char *detail);
static void intent_location_expanded(int expanded_line);
static void die(const char *msg);
static char g_last_open_path[1024];

/* W04/W06: snapshots are owned by the preprocessor registry for one job.
 * Readers in earlier unity modules use these declarations; implementation is
 * in 05_preprocessor.inc. Source and binary data have separate admission caps. */
typedef struct {
    const char *path;
    const unsigned char *data;
    size_t len;
    int kind;
} BasmDependency;
enum { BASM_DEP_SOURCE=1, BASM_DEP_INCLUDE=2, BASM_DEP_INCBIN=3 };
static const BasmDependency *basm_snapshot_record(const char *,const void *,size_t,int);
static const BasmDependency *basm_snapshot_file(FILE *,const char *,int);
static const BasmDependency *basm_snapshot_open(const char *,int);
static size_t basm_dependency_count(void);
static const BasmDependency *basm_dependency_at(size_t);
static void basm_dependencies_reset(void);
static void basm_budget_input(size_t,int);

/* incbin / include search paths from -I. g_srcdir is the directory of the
 * top-level input file (NASM looks there first). Author: F E R M I ∞ H A R T. */
#define INCPATH_MAX 16
static const char *g_incpaths[INCPATH_MAX]; static int g_nincpaths = 0;
static char g_srcdir[512] = "";
/* Refuse static devices/FIFOs before stdio open; confirm the opened descriptor.
 * Replacing parent directories concurrently remains outside the local CLI
 * contract. This uses the same POSIX stat/fstat surface as proof validation. */
static FILE *basm_open_regular(const char *path) {
    struct stat st;
    if(stat(path,&st)!=0)return NULL;
    if(!S_ISREG(st.st_mode)){errno=EINVAL;return NULL;}
    FILE *f=fopen(path,"rb");
    if(!f)return NULL;
    if(fstat(fileno(f),&st)!=0 || !S_ISREG(st.st_mode)){
        fclose(f);errno=EINVAL;return NULL;
    }
    return f;
}
static FILE *incbin_open(const char *fn) {
    char path[1024];
    g_last_open_path[0]=0;
    FILE *bf = basm_open_regular(fn);      /* as given (absolute or CWD-relative) */
    if (bf) {
        if(strlen(fn)>=sizeof(g_last_open_path)){fclose(bf);die("include path too long");}
        memcpy(g_last_open_path,fn,strlen(fn)+1);
        return bf;
    }
    if (g_srcdir[0]) {                    /* relative to the source file's dir */
        int n=snprintf(path, sizeof(path), "%s/%s", g_srcdir, fn);
        if(n<0 || n>=(int)sizeof(path))die("include path too long");
        bf = basm_open_regular(path); if (bf) { memcpy(g_last_open_path,path,strlen(path)+1); return bf; }
    }
    for (int i=0;i<g_nincpaths;i++) {     /* -I search paths */
        int n=snprintf(path, sizeof(path), "%s/%s", g_incpaths[i], fn);
        if(n<0 || n>=(int)sizeof(path))die("include path too long");
        bf = basm_open_regular(path); if (bf) { memcpy(g_last_open_path,path,strlen(path)+1); return bf; }
    }
    return NULL;
}
static int g_line = 0;
static int g_pass; /* 1 or 2 */
static int g_fwd_unresolved; /* set to 1 in pass 1 if a forward ref is seen */
#ifdef BASM_PUBLIC_ONLY
#define g_bits 64
static int g_target_profile = 2;
#else
static int g_bits = 64; /* compatibility/bootstrap encoding mode */
static int g_target_profile = 0;
#endif
static int g_bootstrap = 0;
static const char *target_profile_name(void) {
    if (g_target_profile == 1) return "beyond";
    if (g_target_profile == 2) return "public";
    return "compatibility";
}
static const char *target_policy_id(void) { return "basm-profile-v1"; }
static int g_default_rel = 0; /* `default rel`: symbolic memory operands use RIP */
static uint64_t g_org = 0; /* origin address for flat binaries (org directive) */
static const char *g_fmt = "elf64"; /* output format: "elf64" or "bin" */

/* INV-579: pending atomic-publish temp. atexit(3) does not exist in the
 * sovereign blibc link, so every failure exit funnels through die()/die2()
 * below, which remove it only after exclusive creation established ownership.
 * A signal may strand our temp, never a corrupt final object. */
static char g_out_tmp[1050];
static int g_out_tmp_len = 0;
static void remove_out_tmp(void) {
    if (g_out_tmp_len > 0) { remove(g_out_tmp); g_out_tmp[0]=0; g_out_tmp_len=0; }
}

static void die(const char *msg) {
    if(g_json_diagnostics)intent_diagnostic(msg,NULL);
    else dprintf(2, "%s:%d: error: %s\n", g_file, g_line, msg);
    remove_out_tmp();
    exit(1);
}
static void die2(const char *msg, const char *detail) {
    if(g_json_diagnostics)intent_diagnostic(msg,detail);
    else dprintf(2, "%s:%d: error: %s '%s'\n", g_file, g_line, msg, detail);
    remove_out_tmp();
    exit(1);
}

/* W04: source files are byte sequences until this admission check. NUL is
 * never a source terminator supplied by an input, including compatibility and
 * deferred includes. Binary incbin data deliberately does not use this check. */
static void basm_validate_source_bytes(const char *bytes,size_t len) {
    if (len && (!bytes || memchr(bytes,0,len))) die("NUL in source");
}

/* INV-589: validate the complete directive after expansion, before any sizing
 * or fast encoding. The public build has no mutable non-long-mode state. */
static int target_bits_line(const char *line) {
    const char *p = line;
    while (char_in(*p, " \t")) p++;
    int bracket = (*p == '[');
    if (bracket) { p++; while (char_in(*p, " \t")) p++; }
    if (strlen(p) < 4 || (p[0] | 32) != 'b' || (p[1] | 32) != 'i' ||
        (p[2] | 32) != 't' || (p[3] | 32) != 's') return 0;
    if (p[4] && !char_in(p[4], " \t]")) return 0;
    p += 4;
    while (char_in(*p, " \t")) p++;
    int mode = 0;
    if (p[0] == '1' && p[1] == '6') mode = 16;
    else if (p[0] == '3' && p[1] == '2') mode = 32;
    else if (p[0] == '6' && p[1] == '4') mode = 64;
    if (!mode) die("target profile: BITS requires 16, 32 or 64");
    p += 2;
    while (char_in(*p, " \t")) p++;
    if (bracket) {
        if (*p != ']') die("target profile: malformed BITS directive");
        p++;
    }
    while (char_in(*p, " \t\r")) p++;
    if (*p && *p != ';') die("target profile: trailing BITS input");
    if (mode != 64 && !g_bootstrap) die("target profile requires BITS 64");
#ifndef BASM_PUBLIC_ONLY
    g_bits = mode;
#endif
    return 1;
}

/*=============================================================================
 * Wave A, B, C, D: Security Hardening (Constants and helpers)
 *===========================================================================*/
#define MAX_OPERAND_LEN 512
#define BASM_LINE_CAP 1024
/* `*` = SIB scale ([base+index*4]); `:` = segment override ([gs:0x10]). */
#define VALID_OPERAND_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[].\\-+_/0 *:()$"

static int validate_operand_len(const char *op) {
    if (op == NULL) return 0;
    if (strnlen(op, MAX_OPERAND_LEN + 1) > MAX_OPERAND_LEN) return 0;
    return 1;
}

static int checked_source_line_len(const char *start, const char *eol) {
    size_t len = eol ? (size_t)(eol - start) : strlen(start);
    if (len >= BASM_LINE_CAP) die("source line exceeds 1023 bytes"); /* INV-394 */
    return (int)len;
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

#define NAME_MAX 256   /* raised 64->256: symbols + UTF-8/box-drawing db strings
                          (Beyond is beautiful from the boot; ASCII-only is 1991) */
#define MAXTOK 32

/* Every destination here is a NAME_MAX-byte assembler-name slot. Preserve
 * all admitted bytes, including the final byte of a 255-byte name, under
 * both host libc and the sovereign fortified string-copy contracts. */
static void basm_name_copy(char *destination, const char *source) {
    size_t length=strnlen(source,NAME_MAX);
    if (length>=NAME_MAX) die("symbol name too long");
    memcpy(destination,source,length+1);
}

/* Relocation result compatibility fields. N03 reduces affine section/named
 * bases before publishing these to parse_expr_reloc callers. A non-linear
 * expression is refused for ELF, never silently baked as a section offset. */
static int  g_expr_symcount;
static int  g_expr_sym_section;
static long g_expr_sym_offset;
static char g_expr_sym_name[NAME_MAX];
static int  g_expr_sym_global;
static int  g_expr_contextual;
static int  g_layout_contextual_seen;

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
    int probes=0;
    while (tab[i].hash && probes<cap) { i=(i+1)&mask; probes++; }
    if (probes==cap) die("hash table capacity exhausted");
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
    if (nl >= NAME_MAX) return NULL;
    uint32_t h = str_hash(name, nl);
    int mask = MACRO_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    for (int probe=0; probe<MACRO_HT_CAP && g_macro_ht[i].hash; probe++) {
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
        if (vl >= sizeof(m->value)) die("macro value too long");
        memcpy(m->value, value, vl);
        m->value[vl] = 0;
        return;
    }
    if (g_nmacros >= MACRO_MAX) die("too many macros");
    int idx = g_nmacros++;
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) die("macro name too long");
    memcpy(g_macros[idx].name, name, nl);
    g_macros[idx].name[nl] = 0;
    size_t vl = strlen(value);
    if (vl >= sizeof(g_macros[idx].value)) die("macro value too long");
    memcpy(g_macros[idx].value, value, vl);
    g_macros[idx].value[vl] = 0;
    g_macros[idx].active = 1;
    ht_insert(g_macro_ht, MACRO_HT_CAP, str_hash(g_macros[idx].name, nl), (uint8_t)nl, idx);
}

/* Include stack for %include */
static struct { char *buf; char *p; char fname[1024]; } g_inc_stack[INCLUDE_DEPTH];
static int g_inc_depth = 0;

/* Conditional assembly state */
static int g_if_stack[64]; static int g_if_depth=0; static int g_if_active=1;

static char g_last_global[NAME_MAX]; /* most recent non-local label, for ".x" qualification */

/* W04: bounded assembly text must be rejected, never silently shortened. */
static size_t strbuf_append(char *dst, size_t sz, const char *src) {
    if (!sz) die("assembly text buffer overflow");
    size_t len = strlen(dst);
    if (len >= sz) die("assembly text buffer overflow");
    size_t room = sz - len - 1;
    size_t sl = strlen(src);
    if (sl > room) die("assembly text too long");
    memcpy(dst + len, src, sl);
    dst[len + sl] = 0;
    return len + sl;
}

/* ------------------------------------------------------------------ */
/* Section model                                                      */
/* ------------------------------------------------------------------ */
enum { SEC_NONE=-1, SEC_TEXT=0, SEC_DATA=1, SEC_BSS=2, SEC_NOTE=3, SEC_RODATA=4,
       SEC_CUSTOM0=5 };
static const char *g_fixed_sec_names[] = {".text", ".data", ".bss", ".note.GNU-stack", ".rodata"};
#define SEC_MAX 24         /* 5 fixed + up to CUSTOM_MAX(16) custom named sections.
                            * MUST be >= SEC_CUSTOM0(5)+CUSTOM_MAX, else arrays
                            * indexed by `sec` overflow for custom sections >2
                            * (garbage .rela.<name> headers). F E R M I HART. */

#define TEXT_MAX (1 << 22)
#define DATA_MAX (1 << 25)  /* 32 MiB safety ceiling per data section. */
#define RODATA_MAX (1 << 27) /* INV-BDM-ASSET-LINK-001: immutable boot resources. */
#define BASM_LONG_MAX ((long)(((unsigned long)-1) >> 1))
#define BASM_LONG_MIN (-BASM_LONG_MAX - 1L)
static uint8_t *g_text;   static int g_textlen = 0, g_textcap = 0;
static uint8_t *g_data;   static int g_datalen = 0, g_datacap = 0;
static uint8_t *g_rodata; static int g_rodatalen = 0, g_rodatacap = 0;
static long    g_bsslen = 0;      /* .bss is size-only */
static int     g_cur = SEC_TEXT;

#define FILE_SPAN_MAX 64
typedef struct {
    const unsigned char *data; /* W06: immutable registry-owned snapshot. */
    int section, section_offset;
    long file_offset, length;
} FileSpan;
static FileSpan g_file_spans[FILE_SPAN_MAX];
static int g_nfile_spans;

static void file_spans_reset(void) {
    g_nfile_spans=0; /* The dependency registry owns the bytes, across passes. */
}

static void file_span_add(const BasmDependency *dependency, int section,
                          int section_offset, long file_offset, long length) {
    if (!dependency || file_offset<0 || length<0 ||
        (uint64_t)file_offset>(uint64_t)dependency->len ||
        (uint64_t)length>(uint64_t)dependency->len-(uint64_t)file_offset)
        die("incbin snapshot range out of bounds");
    if(g_nfile_spans>=FILE_SPAN_MAX)die("too many incbin spans");
    FileSpan *span=&g_file_spans[g_nfile_spans++];
    span->data=dependency->data; span->section=section; span->section_offset=section_offset;
    span->file_offset=file_offset; span->length=length;
}

/* INV-539: Custom named sections (e.g. .multiboot, .ap_trampoline). Each gets its own
 * byte buffer, name, ELF sh_flags and sh_type. Author: F E R M I ∞ H A R T. */
#define CUSTOM_MAX 16   /* was 3 — crtend/crtbegin use .ctors/.dtors/.eh_frame/.jcr/... */
static char    g_custom_name[CUSTOM_MAX][NAME_MAX];
static uint8_t *g_custom_buf[CUSTOM_MAX];
static int     g_custom_len[CUSTOM_MAX];
static int     g_custom_cap[CUSTOM_MAX];
static uint64_t g_custom_flags[CUSTOM_MAX];  /* ELF sh_flags */
static uint32_t g_custom_type[CUSTOM_MAX];   /* ELF sh_type (1=PROGBITS,8=NOBITS) */
static int     g_custom_declalign[CUSTOM_MAX]; /* INV-741: declaration != later alignb. */
static int     g_ncustom = 0;
static int     custom_idx(int sec){ return sec - SEC_CUSTOM0; }  /* sec>=SEC_CUSTOM0 */

static void content_reserve(uint8_t **buf, int *current_cap, int need, int limit,
                            const char *overflow, const char *oom) {
    if (need < 0 || need > limit) die(overflow);
    if (need <= *current_cap) return;
    int cap = *current_cap ? *current_cap : 4096;
    while (cap < need) {
        if (cap > limit / 2) { cap=limit; break; }
        cap *= 2;
    }
    if (cap < need) die(overflow);
    uint8_t *p=(uint8_t*)realloc(*buf,(size_t)cap); /* INV-547 */
    if (!p) die(oom);
    *buf=p; *current_cap=cap;
}

/* section appearance order (NASM assigns indices by first `section` directive) */
static int g_secorder[SEC_MAX]; static int g_nsecorder = 0;
static int g_secalign[SEC_MAX] = {1,1,1,1,1,1,1,1}; /* max align directive seen per section */
static int g_secrequired[SEC_CUSTOM0]; /* INV-741: actual requirements, not default alignment. */
static void secorder_touch(int sec) {
    for (int i=0;i<g_nsecorder;i++) if (g_secorder[i]==sec) return;
    if (g_nsecorder >= SEC_MAX) die("too many sections");
    g_secorder[g_nsecorder++] = sec;
}

static void custom_reserve(int ci, int need) {
    if (ci < 0 || ci >= CUSTOM_MAX) die("bad custom section");
    content_reserve(&g_custom_buf[ci],&g_custom_cap[ci],need,DATA_MAX,
                    "custom section overflow","oom custom section");
}

/* emit into current section */
static void emit(uint8_t b) {
    if (g_cur == SEC_TEXT) {
        if(g_textlen>=g_textcap)
            content_reserve(&g_text,&g_textcap,g_textlen+1,TEXT_MAX,"text overflow","oom text");
        g_text[g_textlen++] = b;
    } else if (g_cur == SEC_DATA) {
        if(g_datalen>=g_datacap)
            content_reserve(&g_data,&g_datacap,g_datalen+1,DATA_MAX,"data overflow","oom data");
        g_data[g_datalen++] = b;
    } else if (g_cur == SEC_RODATA) {
        if(g_rodatalen>=g_rodatacap)
            content_reserve(&g_rodata,&g_rodatacap,g_rodatalen+1,RODATA_MAX,"rodata overflow","oom rodata");
        g_rodata[g_rodatalen++] = b;
    } else if (g_cur >= SEC_CUSTOM0) {
        int ci = custom_idx(g_cur);
        if(g_custom_len[ci]>=g_custom_cap[ci]) custom_reserve(ci, g_custom_len[ci] + 1);
        if (g_custom_len[ci] >= DATA_MAX) die("custom section overflow");
        g_custom_buf[ci][g_custom_len[ci]++] = b;
    } else die("cannot emit bytes into this section");
}
static void emit_span(const uint8_t *p, size_t n);
static void emit16(uint32_t v){ uint8_t b[2]={(uint8_t)v,(uint8_t)(v>>8)}; emit_span(b,2); }
static void emit32(uint32_t v){ uint8_t b[4]={(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24)}; emit_span(b,4); }
static void emit64(uint64_t v){
    uint8_t b[8];
    for(int i=0;i<8;i++) b[i]=(uint8_t)(v>>(i*8));
    emit_span(b,8); /* INV-548: reserve and copy each integer as one span. */
}

static void emit_span(const uint8_t *p, size_t n) {
    if (n == 0) return;
    if (g_cur == SEC_TEXT) {
        if (n > (size_t)(TEXT_MAX - g_textlen)) die("text overflow");
        if(g_textlen+(int)n>g_textcap)
            content_reserve(&g_text,&g_textcap,g_textlen+(int)n,TEXT_MAX,"text overflow","oom text");
        memcpy(g_text + g_textlen, p, n); g_textlen += (int)n; /* INV-539 */
    } else if (g_cur == SEC_DATA) {
        if (n > (size_t)(DATA_MAX - g_datalen)) die("data overflow");
        if(g_datalen+(int)n>g_datacap)
            content_reserve(&g_data,&g_datacap,g_datalen+(int)n,DATA_MAX,"data overflow","oom data");
        memcpy(g_data + g_datalen, p, n); g_datalen += (int)n;
    } else if (g_cur == SEC_RODATA) {
        if (n > (size_t)(RODATA_MAX - g_rodatalen)) die("rodata overflow");
        if(g_rodatalen+(int)n>g_rodatacap)
            content_reserve(&g_rodata,&g_rodatacap,g_rodatalen+(int)n,RODATA_MAX,"rodata overflow","oom rodata");
        memcpy(g_rodata + g_rodatalen, p, n); g_rodatalen += (int)n;
    } else if (g_cur >= SEC_CUSTOM0) {
        int ci = custom_idx(g_cur);
        if (n > (size_t)(DATA_MAX - g_custom_len[ci])) die("custom section overflow");
        custom_reserve(ci, g_custom_len[ci] + (int)n);
        memcpy(g_custom_buf[ci] + g_custom_len[ci], p, n); g_custom_len[ci] += (int)n; /* INV-539 */
    } else die("cannot emit bytes into this section");
}

/* INV-N20: checked fills reserve once and write directly to final storage.
 * No 4 KiB scratch buffer or per-chunk section dispatch is needed. */
static void emit_fill(uint8_t b, long n) {
    if (n < 0) die("negative fill size");
    if (!n) return;
    uint8_t *dst;
    if (g_cur == SEC_TEXT) {
        if (n > TEXT_MAX-g_textlen) die("text overflow");
        content_reserve(&g_text,&g_textcap,g_textlen+(int)n,TEXT_MAX,"text overflow","oom text");
        dst=g_text+g_textlen; g_textlen+=(int)n;
    } else if (g_cur == SEC_DATA) {
        if (n > DATA_MAX-g_datalen) die("data overflow");
        content_reserve(&g_data,&g_datacap,g_datalen+(int)n,DATA_MAX,"data overflow","oom data");
        dst=g_data+g_datalen; g_datalen+=(int)n;
    } else if (g_cur == SEC_RODATA) {
        if (n > RODATA_MAX-g_rodatalen) die("rodata overflow");
        content_reserve(&g_rodata,&g_rodatacap,g_rodatalen+(int)n,RODATA_MAX,"rodata overflow","oom rodata");
        dst=g_rodata+g_rodatalen; g_rodatalen+=(int)n;
    } else if (g_cur >= SEC_CUSTOM0) {
        int ci=custom_idx(g_cur);
        if (n > DATA_MAX-g_custom_len[ci]) die("custom section overflow");
        custom_reserve(ci,g_custom_len[ci]+(int)n);
        dst=g_custom_buf[ci]+g_custom_len[ci]; g_custom_len[ci]+=(int)n;
    } else { die("cannot emit bytes into this section"); return; }
    memset(dst,b,(size_t)n);
}

static void advance_content_len(long n) {
    if (n < 0) die("negative section advance");
    if (g_cur == SEC_TEXT) {
        if (n > TEXT_MAX - g_textlen) die("text overflow");
        g_textlen += (int)n;
    } else if (g_cur == SEC_DATA) {
        if (n > DATA_MAX - g_datalen) die("data overflow");
        g_datalen += (int)n;
    } else if (g_cur == SEC_RODATA) {
        if (n > RODATA_MAX - g_rodatalen) die("rodata overflow");
        g_rodatalen += (int)n;
    } else if (g_cur >= SEC_CUSTOM0) {
        int ci = custom_idx(g_cur);
        if (n > DATA_MAX - g_custom_len[ci]) die("custom section overflow");
        g_custom_len[ci] += (int)n;
    } else die("cannot advance this section");
}

static int cur_off(void) {
    /* W05: section symbols/relocations currently store 32-bit signed offsets. */
    if (g_cur==SEC_BSS && g_bsslen>2147483647L)
        die("bss offset exceeds supported symbol range");
    int off;
    if (g_cur >= SEC_CUSTOM0) off = g_custom_len[custom_idx(g_cur)];
    else off = (g_cur==SEC_TEXT)?g_textlen : (g_cur==SEC_DATA)?g_datalen :
               (g_cur==SEC_RODATA)?g_rodatalen : (g_cur==SEC_BSS)?(int)g_bsslen : 0;
    /* s->offset stores relative offset; g_org applied at emission time */
    return off;
}

static int sec_is_nobits(int sec) {
    return sec == SEC_BSS ||
           (sec >= SEC_CUSTOM0 && g_custom_type[custom_idx(sec)] == 8);
}

static void reserve_bytes(long n) {
    if (n < 0) die("negative reserve size");
    if (sec_is_nobits(g_cur)) {
        if (g_cur == SEC_BSS) {
            if (n > BASM_LONG_MAX - g_bsslen) die("bss overflow");
            g_bsslen += n;
        } else {
            int ci = custom_idx(g_cur);
            if (n > DATA_MAX - g_custom_len[ci]) die("custom section overflow");
            g_custom_len[ci] += (int)n;
        }
        return;
    }
    emit_fill(0, n);
}

/* ------------------------------------------------------------------ */
/* Symbols                                                            */
/* ------------------------------------------------------------------ */
#define SYM_MAX_INIT 64        /* one 4 KiB page of compact records, then grow */
#define CONST_MAX 512
/* INV-777: the symbol pool grows geometrically up to a hard bound instead of
 * dying at a fixed 2048 entries. Real translation units (stage2-lowering of
 * bear_opt emits 2374 live branch labels) are legitimate inputs; a fixed cap
 * merely re-labelled "refusal" of valid code. Growth must still be bounded:
 * a runaway must die, not OOM the host. */
#define SYM_HARD_CAP 262144

/* N09: Symbol spelling is interned once in non-moving arena blocks. Pool
 * growth only moves Sym records, so every name remains valid through forward
 * declarations, sizing passes and ELF emission. No per-name allocator header
 * or fixed 256-byte tail is paid for short labels. */
#define SYM_NAME_BLOCK_SIZE 4096
typedef struct SymNameBlock {
    struct SymNameBlock *next;
    size_t used;
    char bytes[SYM_NAME_BLOCK_SIZE];
} SymNameBlock;
static SymNameBlock *g_sym_name_blocks;

static const char *sym_name_copy(const char *name, size_t len) {
    if (len >= NAME_MAX) die2("symbol name too long", name);
    SymNameBlock *block=g_sym_name_blocks;
    if (!block || len+1 > sizeof(block->bytes)-block->used) {
        block=malloc(sizeof(*block));
        if (!block) die("out of memory allocating symbol names");
        block->next=g_sym_name_blocks; block->used=0;
        g_sym_name_blocks=block;
    }
    char *copy=block->bytes+block->used;
    memcpy(copy,name,len+1); block->used+=len+1;
    return copy;
}

/* N10: hot scalar state occupies one 64-byte record on the supported 64-bit
 * host ABI. Flags have small, explicit domains; offsets/generations retain
 * their original signed-int range and all ELF extents remain 64-bit. */
typedef struct {
    const char *name;
    uint64_t size;     /* explicit FUNC/NOTYPE extent; unspecified stays zero */
    char *size_expr;
    char *size_scope;  /* shares the size_expr allocation */
    int offset;       /* offset within its section */
    int defseq;       /* source-definition order, interleaved with constants */
    int defgen;       /* latest definition's assembly-pass generation */
    int size_line;
    int section;      /* SEC_NONE or SEC_TEXT/DATA/BSS/custom */
    uint8_t defined;  /* label definition is available */
    uint8_t global;   /* exported */
    uint8_t is_func;
    uint8_t is_object;
    uint8_t hidden;
    uint8_t binding_decl; /* current pass: 1 global, 2 explicitly static */
    uint8_t weak;
    uint8_t is_local; /* leading '.' local label */
    uint8_t name_len; /* accepted spellings have 0..255 bytes */
} Sym;
/* INV-777: heap-allocated, geometrically growing symbol storage. The fixed
 * 2048-symbol pool died on the legitimate stage2 lowering of bear_opt.c
 * (2374 live branch labels) — a capacity artifact, not an invalid input.
 * Growth doubles from a small SYM_MAX_INIT; SYM_HARD_CAP keeps runaway input dying
 * loudly instead of swapping the host. The hash table rehashes whenever the
 * pool doubles so lookup stays O(1) under growth. */
static Sym *g_syms;
static int g_sym_cap = 0;
static int g_nsyms = 0;
/* Parallel per-symbol annotation arrays, allocated and grown together with
 * g_syms. (Declared here so sym_grow keeps them in lockstep.) */
static int *g_wrt_line;
static int *g_pc32_line;
static unsigned char *g_extern_sym;
/* Monotonic definition counter shared by labels and equ-constants so the
 * output symbol table can reproduce NASM's source-definition ordering. */
static int g_defseq = 0;
/* Assemble-pass generation, bumped on every assemble_pass call (sizing
 * iterations and final alike). Symbols persist across passes by design —
 * the final pass needs the converged table — so per-pass duplicate
 * detection keys on this, not on `defined` alone. INV-578. */
static int g_sym_gen = 0;

/* N11: the symbol index has its own compact entries. A zero index_plus_one
 * denotes an empty slot; name lengths already live in the compact Sym record.
 * Macro/constant tables retain their independent representation and limits. */
typedef struct { uint32_t hash, index_plus_one; } SymHTEntry;
static SymHTEntry *g_sym_ht;
static int g_sym_ht_cap = 0;

static int sym_hash_slot(const char *name, size_t len, uint32_t hash) {
    int mask=g_sym_ht_cap-1;
    int slot=(int)(hash & (uint32_t)mask);
    for (int probes=0; probes<g_sym_ht_cap; probes++) {
        SymHTEntry *entry=&g_sym_ht[slot];
        if (!entry->index_plus_one) return slot;
        if (entry->hash==hash) {
            Sym *symbol=&g_syms[entry->index_plus_one-1];
            if (symbol->name_len==len && !memcmp(symbol->name,name,len)) return slot;
        }
        slot=(slot+1)&mask;
    }
    die("symbol hash table capacity exhausted");
    return 0;
}

static void sym_tables_init(void) {
    if (g_sym_cap) return;
    g_sym_cap = SYM_MAX_INIT;
    g_sym_ht_cap = SYM_MAX_INIT * 2;
    /* N10: only indices below g_nsyms are readable. sym_intern initializes
     * each live record and annotation before exposing it; capacity is not
     * touched merely because a future symbol might use it. */
    g_syms = malloc((size_t)g_sym_cap * sizeof(*g_syms));
    g_wrt_line = malloc((size_t)g_sym_cap * sizeof(*g_wrt_line));
    g_pc32_line = malloc((size_t)g_sym_cap * sizeof(*g_pc32_line));
    g_extern_sym = malloc((size_t)g_sym_cap * sizeof(*g_extern_sym));
    g_sym_ht = calloc((size_t)g_sym_ht_cap, sizeof(*g_sym_ht));
    if (!g_syms || !g_wrt_line || !g_pc32_line || !g_extern_sym || !g_sym_ht)
        die("out of memory allocating symbol tables");
}

/* N11: growth retains each admitted name's hash and dense index. Rebuilding
 * scans only compact slots, without strlen/FNV scans or name copies. No Sym*
 * may survive sym_intern: callers resolve/use immediately (INV-777). */
static void sym_grow(void) {
    if (g_sym_cap >= SYM_HARD_CAP) die("too many symbols");
    int newcap = g_sym_cap * 2;
    Sym *ns = realloc(g_syms, (size_t)newcap * sizeof(*ns));
    int *wl = realloc(g_wrt_line, (size_t)newcap * sizeof(*wl));
    int *pl = realloc(g_pc32_line, (size_t)newcap * sizeof(*pl));
    unsigned char *ex = realloc(g_extern_sym, (size_t)newcap * sizeof(*ex));
    if (!ns || !wl || !pl || !ex) die("out of memory growing symbol tables");
    g_syms = ns; g_wrt_line = wl; g_pc32_line = pl; g_extern_sym = ex;
    g_sym_cap = newcap;
    int hcap = newcap * 2;
    SymHTEntry *ht = calloc((size_t)hcap, sizeof(*ht));
    if (!ht) die("out of memory rehashing symbol table");
    for (int i=0; i<g_sym_ht_cap; i++) {
        SymHTEntry entry=g_sym_ht[i];
        if (!entry.index_plus_one) continue;
        int slot=(int)(entry.hash & (uint32_t)(hcap-1));
        int probes=0;
        while (ht[slot].index_plus_one && probes<hcap) {
            slot=(slot+1)&(hcap-1); probes++;
        }
        if (probes==hcap) die("symbol hash table capacity exhausted");
        ht[slot]=entry;
    }
    free(g_sym_ht);
    g_sym_ht = ht;
    g_sym_ht_cap = hcap;
}

static Sym *sym_find(const char *name) {
    if (!g_nsyms) return NULL;
    size_t len=strnlen(name,NAME_MAX);
    if (len>=NAME_MAX) return NULL; /* INV-542 */
    int slot=sym_hash_slot(name,len,str_hash(name,len));
    uint32_t index=g_sym_ht[slot].index_plus_one;
    return index ? &g_syms[index-1] : NULL;
}
static Sym *sym_intern(const char *name) {
    size_t len=strnlen(name,NAME_MAX);
    if (len>=NAME_MAX) die2("symbol name too long",name); /* INV-542 */
    uint32_t hash=str_hash(name,len);
    if (!g_sym_cap) sym_tables_init();
    int slot=sym_hash_slot(name,len,hash);
    uint32_t existing=g_sym_ht[slot].index_plus_one;
    if (existing) return &g_syms[existing-1];
    if (g_nsyms>=g_sym_cap) {
        sym_grow();
        slot=sym_hash_slot(name,len,hash); /* growth changes the slot mask */
    }
    int idx=g_nsyms;
    const char *copy=sym_name_copy(name,len);
    Sym *symbol=&g_syms[idx];
    memset(symbol,0,sizeof(*symbol));
    g_wrt_line[idx]=0; g_pc32_line[idx]=0; g_extern_sym[idx]=0;
    symbol->name=copy; symbol->name_len=(uint8_t)len;
    symbol->is_local=(name[0]=='.');
    symbol->section=SEC_NONE; symbol->defseq=-1;
    g_sym_ht[slot].hash=hash;
    g_sym_ht[slot].index_plus_one=(uint32_t)idx+1;
    g_nsyms++;
    return symbol;
}

/* assembler constants (NAME equ value). NASM emits each as a LOCAL NOTYPE ABS
 * symbol, in definition order, right after the section symbols. */
typedef struct { char name[NAME_MAX]; long value; int emit_sym; int defseq; } Const;
static Const g_consts[CONST_MAX]; static int g_nconsts = 0;

#define CONST_HT_CAP 1024
static HTEntry g_const_ht[CONST_HT_CAP];

static int const_lookup(const char *name, long *out) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) return 0;
    uint32_t h = str_hash(name, nl);
    int mask = CONST_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    for (int probe=0; probe<CONST_HT_CAP && g_const_ht[i].hash; probe++) {
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
    for (int probe=0; probe<CONST_HT_CAP && g_const_ht[i].hash; probe++) {
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
/* INV-BASM-RELOC-GROWTH-001: large translated TUs need more than4096 sites.
 * Allocate on demand under a fixed65536-entry metadata ceiling, not in BSS. */
#define RELOC_MAX 65536
typedef struct {
    int   offset;       /* offset where the field sits */
    int   section;      /* which section the field is IN (text/data/rodata) */
    int   reltype;      /* 2 = R_X86_64_PC32, 1 = R_X86_64_64 */
    int   sym_kind;     /* 0 = named symbol, 1 = section symbol */
    char  sym[NAME_MAX];
    int   target_sec;   /* section-symbol case: which section */
    long  addend;
} Reloc;
static Reloc *g_relocs;
static size_t g_reloc_capacity;
static int g_nrelocs = 0;
static const char *g_data_source; /* raw line: tokenize discards commas */

/* INV-586: one initializer preserves capacity and name checks for every kind. */
static void add_reloc(int offset, int in_section, int type, int target_sec,
                      const char *sym, long addend) {
    if (g_nrelocs >= RELOC_MAX) die("too many relocations");
    if ((size_t)g_nrelocs == g_reloc_capacity) {
        size_t capacity = g_reloc_capacity ? g_reloc_capacity * 2 : 256;
        if (capacity > RELOC_MAX) capacity = RELOC_MAX;
        if (capacity <= g_reloc_capacity || capacity > SIZE_MAX / sizeof(Reloc))
            die("relocation allocation overflow");
        Reloc *grown = realloc(g_relocs, capacity * sizeof(Reloc));
        if (!grown) die("cannot grow relocation metadata");
        g_relocs = grown;
        g_reloc_capacity = capacity;
    }
    Reloc *r = &g_relocs[g_nrelocs++];
    r->offset = offset; r->section = in_section; r->reltype = type;
    r->sym_kind = sym ? 0 : 1; r->target_sec = target_sec; r->addend = addend;
    if (sym) {
        size_t n = strlen(sym); if (n >= NAME_MAX) die2("relocation symbol name too long", sym); /* INV-542 */
        memcpy(r->sym, sym, n); r->sym[n] = 0;
    } else r->sym[0] = 0;
}
static void add_reloc_named(int offset, const char *sym, long addend) {
    add_reloc(offset,g_cur,2,SEC_NONE,sym,addend);
}
static void add_reloc_section(int offset, int section, long addend) {
    add_reloc(offset,g_cur,2,section,NULL,addend);
}
/* 64-bit absolute reloc against a named symbol, in the current data section. */
static void add_reloc_abs64(int offset, int in_section, const char *sym) {
    add_reloc(offset,in_section,1,SEC_NONE,sym,0);
}

/* 64-bit absolute reloc against a SECTION symbol + addend (NASM folds a
 * defined local symbol's offset into the addend, like the PC32 path). */
static void add_reloc_abs64_section(int offset, int in_section, int target_sec, long addend) {
    add_reloc(offset,in_section,1,target_sec,NULL,addend);
}

/* 32-bit absolute reloc (R_X86_64_32, type 10) against a SECTION symbol +
 * addend, in the given section. Used for absolute memory-operand
 * displacements [label+disp] and dd label+disp where the label lives in
 * another section — the linker resolves the final address, the constant
 * arithmetic rides in the addend (NASM behaviour). Author: F E R M I ∞ H A R T. */
static void add_reloc_abs32_section(int offset, int in_section, int target_sec, long addend) {
    add_reloc(offset,in_section,10,target_sec,NULL,addend);
}
static void add_reloc_abs32_named(int offset, int in_section, const char *sym, long addend) {
    add_reloc(offset,in_section,10,SEC_NONE,sym,addend);
}
static void add_reloc_abs32s_section(int offset, int in_section, int target_sec, long addend) {
    add_reloc(offset,in_section,11,target_sec,NULL,addend);
}
static void add_reloc_abs32s_named(int offset, int in_section, const char *sym, long addend) {
    add_reloc(offset,in_section,11,SEC_NONE,sym,addend);
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
/* N06: immutable perfect-hash data replaces runtime initialization. Each
 * slot packs the exact name length and one-based Reg index; zero is empty.
 * The hash selects a candidate only: length and every byte must still match.
 * This table covers the fixed 68-name vocabulary, not arbitrary identifiers. */
#define REG_HT_CAP 256
static const uint16_t g_reg_slots[REG_HT_CAP] = {
    0x000,0x000,0x000,0x000,0x000,0x000,0x443,0x000,
    0x000,0x000,0x209,0x20a,0x000,0x000,0x33e,0x226,
    0x000,0x000,0x000,0x222,0x000,0x32c,0x434,0x000,
    0x420,0x000,0x000,0x000,0x000,0x000,0x000,0x236,
    0x000,0x302,0x000,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x444,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x227,0x23c,0x000,0x308,
    0x223,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x237,0x000,0x303,0x000,
    0x000,0x000,0x000,0x000,0x32b,0x000,0x000,0x329,
    0x000,0x000,0x311,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x000,0x42f,0x000,0x41b,
    0x23b,0x000,0x307,0x000,0x000,0x000,0x32a,0x239,
    0x000,0x305,0x000,0x000,0x000,0x000,0x000,0x316,
    0x000,0x000,0x43f,0x000,0x000,0x000,0x000,0x314,
    0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x430,0x000,0x41c,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x440,
    0x000,0x000,0x000,0x000,0x312,0x000,0x000,0x30b,
    0x30c,0x30d,0x30e,0x30f,0x310,0x000,0x000,0x431,
    0x000,0x41d,0x000,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x318,0x000,0x000,0x000,0x000,0x000,
    0x000,0x000,0x000,0x000,0x441,0x000,0x000,0x000,
    0x000,0x313,0x000,0x000,0x000,0x225,0x000,0x000,
    0x000,0x221,0x000,0x000,0x432,0x000,0x41e,0x000,
    0x000,0x000,0x000,0x000,0x32d,0x235,0x319,0x301,
    0x000,0x000,0x000,0x000,0x000,0x317,0x000,0x000,
    0x000,0x442,0x000,0x000,0x315,0x000,0x000,0x000,
    0x000,0x33d,0x228,0x000,0x000,0x000,0x224,0x000,
    0x000,0x433,0x23a,0x41f,0x306,0x000,0x000,0x000,
    0x000,0x32e,0x238,0x31a,0x304,0x000,0x000,0x000,
};

static const Reg *reg_find_n(const char *s,size_t len) {
    if(!s || len<2 || len>4)return NULL;
    uint32_t h=24;
    for(size_t i=0;i<len;i++)h=h*37+(unsigned char)s[i];
    unsigned slot=g_reg_slots[h&(REG_HT_CAP-1)];
    if((slot>>8)!=len)return NULL;
    const Reg *r=&g_regs[(slot&255)-1];
    if(memcmp(s,r->name,len))return NULL;
    return r;
}

static const Reg *reg_find(const char *s) {
    /* A real GPR is at most four bytes. Reject long identifiers after five
     * bytes instead of hashing an entire symbol or expression on a miss. */
    return s ? reg_find_n(s,strnlen(s,5)) : NULL;
}

/* Segment-register index for mov Sreg forms, or -1. es=0 cs=1 ss=2 ds=3 fs=4 gs=5. */
static const char g_segment_letters[]="ecsdfg";
static int seg_reg(const char *s) {
    if (!*s || s[1]!='s' || s[2]) return -1;
    const char *p=strchr(g_segment_letters,*s);
    if (p) return (int)(p-g_segment_letters);
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
/* W05: data/immediate expressions are 64-bit bit patterns, independently of
 * host strtol saturation and C signed-overflow behavior. Size/count callers
 * select checked signed arithmetic and validate their final nonnegative range.
 * NASM >> is logical; see nasm.us/doc/nasm03.html#section-3.5.9. */
static int g_expr_checked;
static int g_expr_depth;
#define BASM_EXPR_DEPTH_MAX 128

static long basm_bits_to_long(uint64_t bits) {
    if (bits<=(uint64_t)BASM_LONG_MAX) return (long)bits;
    return -1L-(long)(~bits);
}

static uint64_t basm_parse_u64(const char **cursor) {
    const char *p=*cursor;
    unsigned base=10;
    if (p[0]=='0' && char_in(p[1],"xX")) { base=16; p+=2; }
    uint64_t value=0;
    const uint64_t cutoff=(~(uint64_t)0)/base;
    const unsigned last_digit=(unsigned)((~(uint64_t)0)%base);
    int digits=0;
    for (;;) {
        int digit=-1;
        if (*p>='0' && *p<='9') digit=*p-'0';
        else if (base==16 && *p>='a' && *p<='f') digit=*p-'a'+10;
        else if (base==16 && *p>='A' && *p<='F') digit=*p-'A'+10;
        if (digit<0) break;
        if (value>cutoff || (value==cutoff && (unsigned)digit>last_digit))
            die("integer literal exceeds 64 bits");
        value=value*base+(unsigned)digit;
        digits++; p++;
    }
    if (!digits) die("integer literal requires digits");
    *cursor=p;
    return value;
}

/* INV-BASM-STANDALONE-001: one bounded byte-escape grammar for backtick
 * strings and character expressions. Unsupported spellings must not silently
 * become different bytes. Unicode escapes require a separate UTF-8 contract. */
static uint8_t basm_escape_byte(const char **cursor) {
    const char *p=*cursor;
    if (!*p) die("unterminated character escape");
    unsigned int value=0;
    if (*p>='0' && *p<='7') {
        int digits=0;
        do {
            value=value*8+(unsigned int)(*p++-'0');
            digits++;
        } while (digits<3 && *p>='0' && *p<='7');
        if (value>255) die("octal escape exceeds one byte");
    } else if (*p=='x') {
        p++;
        int digits=0;
        while (digits<2) {
            int digit=-1;
            if (*p>='0' && *p<='9') digit=*p-'0';
            else if (*p>='a' && *p<='f') digit=*p-'a'+10;
            else if (*p>='A' && *p<='F') digit=*p-'A'+10;
            if (digit<0) break;
            value=value*16+(unsigned int)digit; p++; digits++;
        }
        if (!digits) die("hexadecimal escape requires one or two digits");
    } else {
        switch (*p++) {
        case 'a': value=7; break;
        case 'b': value=8; break;
        case 'e': value=27; break;
        case 'f': value=12; break;
        case 'n': value=10; break;
        case 'r': value=13; break;
        case 't': value=9; break;
        case 'v': value=11; break;
        case '\\': value='\\'; break;
        case '\'': value='\''; break;
        case '"': value='"'; break;
        case '`': value='`'; break;
        case '?': value='?'; break;
        default: die("unsupported backtick escape");
        }
    }
    *cursor=p;
    return (uint8_t)value;
}

static long basm_expr_add(long a,long b) {
    if (g_expr_checked && ((b>0 && a>BASM_LONG_MAX-b) ||
                          (b<0 && a<BASM_LONG_MIN-b)))
        die("size expression overflow");
    return basm_bits_to_long((uint64_t)a+(uint64_t)b);
}
static long basm_expr_sub(long a,long b) {
    if (g_expr_checked && ((b<0 && a>BASM_LONG_MAX+b) ||
                          (b>0 && a<BASM_LONG_MIN+b)))
        die("size expression overflow");
    return basm_bits_to_long((uint64_t)a-(uint64_t)b);
}
static long basm_expr_mul(long a,long b) {
    if (g_expr_checked) {
        uint64_t ua=a<0 ? (uint64_t)0-(uint64_t)a : (uint64_t)a;
        uint64_t ub=b<0 ? (uint64_t)0-(uint64_t)b : (uint64_t)b;
        uint64_t limit=((a<0)!=(b<0)) ? (uint64_t)BASM_LONG_MAX+1 : (uint64_t)BASM_LONG_MAX;
        if (ub && ua>limit/ub) die("size expression overflow");
    }
    return basm_bits_to_long((uint64_t)a*(uint64_t)b);
}

/* N03: bounded affine capture, independent of numeric 64-bit bit patterns.
 * Defined symbols share their section basis; only actual externs keep a name.
 * Pointers refer to interned symbol names during this expression (no intern or
 * pool growth occurs while parsing). A pending forward basis has no name and
 * cannot cancel speculatively. The decimal/literal fast paths clear counters
 * only; they neither visit nor clear this array. */
#define EXPR_BASIS_MAX 128
typedef struct { long coefficient; int section; const char *name; } ExprBasis;
static ExprBasis g_expr_basis[EXPR_BASIS_MAX];
static int g_expr_basis_count, g_expr_basis_invalid, g_expr_basis_pending;
static int g_expr_location_override=-1;

static void expr_basis_add(int section,const char *name) {
    if (g_expr_basis_count>=EXPR_BASIS_MAX) die("too many expression relocation terms");
    ExprBasis *b=&g_expr_basis[g_expr_basis_count++];
    b->coefficient=1; b->section=section; b->name=name;
    if (section==SEC_NONE && !name) g_expr_basis_pending=1;
}
static long expr_coefficient_add(long a,long b) {
    if ((b>0 && a>BASM_LONG_MAX-b) || (b<0 && a<BASM_LONG_MIN-b)) {
        g_expr_basis_invalid=1; return 0;
    }
    return a+b;
}
static long expr_coefficient_mul(long a,long b) {
    uint64_t ua=a<0 ? (uint64_t)0-(uint64_t)a : (uint64_t)a;
    uint64_t ub=b<0 ? (uint64_t)0-(uint64_t)b : (uint64_t)b;
    uint64_t limit=((a<0)!=(b<0)) ? (uint64_t)BASM_LONG_MAX+1 : (uint64_t)BASM_LONG_MAX;
    if (ub && ua>limit/ub) { g_expr_basis_invalid=1; return 0; }
    return basm_bits_to_long((uint64_t)a*(uint64_t)b);
}
static int expr_basis_equal(const ExprBasis *a,const ExprBasis *b) {
    if (a->section!=b->section) return 0;
    if (a->section!=SEC_NONE) return 1;
    return a->name && b->name && !strcmp(a->name,b->name);
}
static void expr_basis_reduce(int first) {
    int used=first;
    for (int i=first;i<g_expr_basis_count;i++) {
        ExprBasis b=g_expr_basis[i];
        int j=first;
        while (j<used && !expr_basis_equal(&g_expr_basis[j],&b)) j++;
        if (j<used) g_expr_basis[j].coefficient=expr_coefficient_add(g_expr_basis[j].coefficient,b.coefficient);
        else g_expr_basis[used++]=b;
    }
    int end=first;
    for (int i=first;i<used;i++) if (g_expr_basis[i].coefficient)
        g_expr_basis[end++]=g_expr_basis[i];
    g_expr_basis_count=end;
}
static void expr_basis_scale(int first,int end,long coefficient) {
    for (int i=first;i<end;i++)
        g_expr_basis[i].coefficient=expr_coefficient_mul(g_expr_basis[i].coefficient,coefficient);
}

/* N04: `$` is the beginning of the containing statement, `$$` the section
 * origin. Both carry the current section basis in ELF. A data list supplies
 * one anchor for all items; their relocation fields still have distinct P.
 * Flat output adds org to both, so subtraction cancels the origin normally. */
static long expr_position_value(int section_start) {
    long value=section_start ? 0 : (g_expr_location_override>=0 ? g_expr_location_override : cur_off());
    g_expr_contextual=1; g_layout_contextual_seen=1;
    g_expr_symcount++; g_expr_sym_section=g_cur; g_expr_sym_offset=value;
    g_expr_sym_global=0; g_expr_sym_name[0]=0;
    expr_basis_add(g_cur,NULL);
    if (!strcmp(g_fmt,"bin")) value=basm_expr_add(value,basm_bits_to_long(g_org));
    return value;
}

static long parse_or(const char **pp);
static long parse_term(const char **pp);
static long parse_term_inner(const char **pp) {
    const char *p=*pp;
    while (char_in(*p," \t")) p++;
    long v;
    if (char_in(*p,"+-")) {
        int negative=*p++=='-';
        while (char_in(*p," \t")) p++;
        /* -INT64_MIN's magnitude is representable only as an unsigned literal. */
        if (negative && g_expr_checked && isdigit((unsigned char)*p)) {
            uint64_t value=basm_parse_u64(&p);
            if (value>(uint64_t)BASM_LONG_MAX+1) die("size integer out of range");
            *pp=p; return basm_bits_to_long((uint64_t)0-value);
        }
        int first=g_expr_basis_count;
        *pp=p; v=parse_term(pp);
        if (!negative) return v;
        if (g_expr_checked && v==BASM_LONG_MIN) die("size expression overflow");
        expr_basis_scale(first,g_expr_basis_count,-1);
        expr_basis_reduce(first);
        return basm_bits_to_long((uint64_t)0-(uint64_t)v);
    }
    if (*p=='(') {
        p++; *pp=p; v=parse_or(pp); p=*pp;
        while (char_in(*p," \t")) p++;
        if (*p!=')') die("missing closing parenthesis in expression");
        *pp=p+1; return v;
    }
    if (*p=='\'') {
        p++;
        if (!*p || *p=='\'') die("character literal requires one byte");
        v=(unsigned char)*p++;
        if (*p!='\'') die("unterminated or multibyte character literal");
        *pp=p+1; return v;
    }
    if (*p=='`') {
        p++;
        if (!*p || *p=='`') die("character literal requires one byte");
        if (*p=='\\') {
            p++;
            v=basm_escape_byte(&p);
        } else v=(unsigned char)*p++;
        if (*p!='`') die("unterminated or multibyte character literal");
        *pp=p+1; return v;
    }
    if (isdigit((unsigned char)*p)) {
        uint64_t value=basm_parse_u64(&p);
        if (g_expr_checked && value>(uint64_t)BASM_LONG_MAX) die("size integer out of range");
        *pp=p; return basm_bits_to_long(value);
    }
    /* `$` = current position, `$$` = section start (NASM-compatible) */
    if (*p == '$') {
        p++;
        int section_start=*p=='$';
        if (section_start) p++;
        *pp=p; return expr_position_value(section_start);
    }
    /* identifier: a constant */
    char name[NAME_MAX]; int i=0;
    /* INV-703: a qualified label is one term, never its prefix before '.'. */
    while (isalnum((unsigned char)*p)||char_in(*p, "_.?@$#~")) {
        if (i>=NAME_MAX-1) die("expression symbol name too long");
        name[i++]=*p++;
    }
    name[i]=0;
    if (i==0) die("bad expression term");
    if (!const_lookup(name, &v)) {
        /* Try symbol lookup (labels), not just %define constants */
        char qname[NAME_MAX]; qualify(name, qname);
        Sym *s = sym_find(qname);
        if (s && s->defined && s->section != SEC_NONE) {
            v = s->offset; /* defined label: use its relative offset */
            /* For flat binaries, add org to get absolute address */
            if (!strcmp(g_fmt, "bin")) v = basm_expr_add(v,basm_bits_to_long(g_org));
            /* Capture for reloc emission: a real label (in a section) was
             * referenced. The caller decides whether to emit a reloc.
             * Author: F E R M I ∞ H A R T. */
            g_expr_symcount++;
            g_expr_sym_section = s->section;
            g_expr_sym_offset  = (long)s->offset;
            g_expr_sym_global  = s->global;
            basm_name_copy(g_expr_sym_name,qname);
            expr_basis_add(s->section,NULL);
        } else if (s && s->global && !s->defined && g_extern_sym[(int)(s-g_syms)]) {
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
            basm_name_copy(g_expr_sym_name,qname);
            expr_basis_add(SEC_NONE,s->name);
        } else if (g_pass == 1) {
            g_fwd_unresolved = 1; v = 0; /* forward ref: resolve in pass 2 */
            g_expr_symcount++;           /* a label (not yet defined) */
            g_expr_sym_section = SEC_NONE;
            basm_name_copy(g_expr_sym_name,qname);
            expr_basis_add(SEC_NONE,NULL);
        } else {
            die2("unknown symbol in expression", name);
        }
    }
    *pp = p; return v;
}
static long parse_term(const char **pp) {
    if (++g_expr_depth>BASM_EXPR_DEPTH_MAX) die("expression nesting too deep");
    long value=parse_term_inner(pp);
    g_expr_depth--;
    return value;
}
static long parse_product(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_term(pp);
    const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        if (*p!='*') break;
        p++; *pp=p;
        int right=g_expr_basis_count;
        long rhs=parse_term(pp);
        if (right>first && g_expr_basis_count>right) g_expr_basis_invalid=1;
        else if (right>first) expr_basis_scale(first,right,rhs);
        else expr_basis_scale(right,g_expr_basis_count,acc);
        expr_basis_reduce(first);
        acc=basm_expr_mul(acc,rhs); p=*pp;
    }
    *pp=p; return acc;
}
static long parse_sum(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_product(pp);
    const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        if (!char_in(*p,"+-")) break;
        int subtract=*p++=='-'; *pp=p;
        int right=g_expr_basis_count;
        long rhs=parse_product(pp);
        if (subtract) expr_basis_scale(right,g_expr_basis_count,-1);
        expr_basis_reduce(first);
        acc=subtract ? basm_expr_sub(acc,rhs) : basm_expr_add(acc,rhs); p=*pp;
    }
    *pp=p; return acc;
}
static long parse_shift(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_sum(pp);
    const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        int left=p[0]=='<' && p[1]=='<';
        int right=p[0]=='>' && p[1]=='>';
        if (!left && !right) break;
        p+=2; *pp=p; int rhs_basis=g_expr_basis_count; long shift=parse_sum(pp);
        if (g_expr_basis_count>first && (shift || g_expr_basis_count>rhs_basis)) g_expr_basis_invalid=1;
        if (shift<0 || shift>=64) die("shift out of range");
        if (left && g_expr_checked) {
            uint64_t magnitude=acc<0 ? (uint64_t)0-(uint64_t)acc : (uint64_t)acc;
            uint64_t limit=acc<0 ? (uint64_t)BASM_LONG_MAX+1 : (uint64_t)BASM_LONG_MAX;
            if (magnitude>(limit>>shift)) die("size expression overflow");
        }
        acc=basm_bits_to_long(left ? (uint64_t)acc<<shift : (uint64_t)acc>>shift);
        p=*pp;
    }
    *pp=p; return acc;
}
static long parse_and(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_shift(pp); const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        if (!(p[0]=='&' && p[1]!='&')) break;
        p++; *pp=p; acc&=parse_shift(pp); p=*pp;
        if (g_expr_basis_count>first) g_expr_basis_invalid=1;
    }
    *pp=p; return acc;
}
static long parse_xor(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_and(pp); const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        if (*p!='^') break;
        p++; *pp=p; acc^=parse_and(pp); p=*pp;
        if (g_expr_basis_count>first) g_expr_basis_invalid=1;
    }
    *pp=p; return acc;
}
static long parse_or(const char **pp) {
    int first=g_expr_basis_count;
    long acc=parse_xor(pp); const char *p=*pp;
    for (;;) {
        while (char_in(*p," \t")) p++;
        if (!(p[0]=='|' && p[1]!='|')) break;
        p++; *pp=p; acc|=parse_xor(pp); p=*pp;
        if (g_expr_basis_count>first) g_expr_basis_invalid=1;
    }
    *pp=p; return acc;
}
/* Simple expression cache: pure-constant expressions are evaluated many times
 * (especially in data directives and repeated operands). Short keys use exact
 * direct-mapped lookup; collisions replace instead of probing an unbounded
 * full table. Reset each assemble_pass because symbol values change between
 * passes. Author: F E R M I ∞ H A R T. */
#define EXPR_CACHE_CAP 1024
#define EXPR_CACHE_KEY_MAX 64
typedef struct {
    uint32_t hash;
    uint16_t len;
    char key[EXPR_CACHE_KEY_MAX];
    long value;
} ExprCacheEntry;
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

static int expr_cacheable_literal(const char *s) {
    char quote = 0;
    for (; *s; s++) {
        if (quote) {
            if (*s == '\\' && s[1]) { s++; continue; }
            if (*s == quote) quote = 0;
            continue;
        }
        if (char_in(*s, "'`\"")) { quote = *s; continue; }
        if (isalpha((unsigned char)*s) || char_in(*s, "_.$")) return 0;
    }
    return 1;
}

static int parse_decimal_literal(const char *s,long *out) {
    const char *p=s;
    int negative=*p=='-';
    if (char_in(*p,"+-")) p++;
    if (!isdigit((unsigned char)*p) || (p[0]=='0' && char_in(p[1],"xX"))) return 0;
    uint64_t value=basm_parse_u64(&p);
    if (*p) return 0;
    if (g_expr_checked && value>(uint64_t)BASM_LONG_MAX+(unsigned)negative)
        die("size integer out of range");
    *out=basm_bits_to_long(negative ? (uint64_t)0-value : value);
    return 1;
}

static long parse_expr(const char *s) {
    if (!s || !*s) die("missing expression");
    g_expr_depth=0;
    uint32_t h = 0;
    size_t key_len = 0;
    g_expr_symcount = 0; g_expr_sym_section = SEC_NONE;
    g_expr_sym_offset = 0; g_expr_sym_name[0] = 0; g_expr_sym_global = 0;
    g_expr_contextual = 0;
    g_expr_basis_count=0; g_expr_basis_invalid=0; g_expr_basis_pending=0;
    long decimal;
    if(parse_decimal_literal(s,&decimal)) return decimal; /* INV-554 */
    if (s[0]=='$' && (!s[1] || (s[1]=='$' && !s[2])))
        return expr_position_value(s[1]=='$'); /* N04: exact contextual fast path. */
    /* W16: a successful decimal parse has already returned. Only expressions
     * that still need the general parser pay literal-cache classification. */
    int cacheable = !g_expr_checked && expr_cacheable_literal(s);
    if (g_expr_cache_valid && cacheable) {
        key_len = strlen(s);
        if (key_len < EXPR_CACHE_KEY_MAX) {
            h = expr_hash(s);
            ExprCacheEntry *entry = &g_expr_cache[h & (EXPR_CACHE_CAP - 1)];
            if (entry->hash == h && entry->len == key_len &&
                memcmp(entry->key, s, key_len) == 0) {
                return entry->value;
            }
        }
    }
    const char *p = s;
    long v = parse_or(&p);
    while (char_in(*p, " \t")) p++;
    if (*p && *p!=';') die("trailing text in expression"); /* INV-703 */
    if(g_expr_contextual) g_layout_contextual_seen=1;
    if (g_expr_cache_valid && cacheable && g_expr_symcount == 0 &&
        !g_expr_contextual && key_len < EXPR_CACHE_KEY_MAX) {
        if (h == 0) h = expr_hash(s);
        ExprCacheEntry *entry = &g_expr_cache[h & (EXPR_CACHE_CAP - 1)];
        entry->value = v;
        entry->len = (uint16_t)key_len;
        memcpy(entry->key, s, key_len + 1);
        entry->hash = h; /* INV-391 */
    }
    return v;
}

/* W05: all size/count callers validate before narrowing or multiplying.
 * Checked evaluation bypasses the bit-pattern cache, so an earlier data
 * expression cannot conceal overflow in a later size use. */
static long basm_parse_count(const char *text,long maximum,const char *what) {
    int prior=g_expr_checked;
    g_expr_checked=1;
    long value=parse_expr(text);
    g_expr_checked=prior;
    if (value<0 || value>maximum) die2(what,text);
    return value;
}

/* N26: Const stores a scalar, not a relocation basis. Never turn an alias
 * into a plausible section offset or register an unresolved zero placeholder.
 * Genuine forward values defer to a later layout/final pass; differences of
 * known same-section symbols and contextual differences remain absolute. */
static int equ_constant_value(const char *expression,long *value) {
    *value=parse_expr(expression);
    expr_basis_reduce(0);
    if (g_expr_basis_pending && g_pass==1) return 0;
    if (g_expr_basis_invalid || g_expr_basis_count)
        die("relocatable EQU aliases are not supported; use the symbol directly");
    return 1;
}

/* Pre-scan for `name equ value` definitions so that simple constants
 * (e.g. `buffer_size equ 4096`) are available during pass-1 .text
 * processing. This prevents `mov r64,imm` forward-ref code from emitting
 * 10-byte movabs in the sizing pass but 5-byte `mov r32,imm32` in the
 * final pass, which desyncs the layout and corrupts branch displacements.
 * Only proven absolute, non-contextual values are registered here. Forward
 * and contextual definitions resolve at their real directive location in
 * the existing bounded layout passes. Author: F E R M I ∞ H A R T. */
static void prescan_equ(const char *src) {
    int save_pass = g_pass;
    g_pass = 1;
    const char *p = src;
    int expanded_line=1;
    while (*p) {
        if (char_in(*p, "\n\r")) { if(*p=='\n')expanded_line++; p++; continue; }
        if(g_explain)intent_location_expanded(expanded_line); /* INV-596 */
        const char *line = p;
        while (*p && !char_in(*p, "\n\r")) p++;
        size_t llen = (size_t)(p - line);
        if (llen > 4095) { continue; }
        char buf[4096]; memcpy(buf, line, llen); buf[llen] = 0;
        const char *s = buf;
        while (char_in(*s, " \t")) s++;
        if (!*s || *s == ';') continue;
        const char *eq = strstr(s, " equ ");
        if (!eq) eq = strstr(s, "\tequ ");
        if (!eq) eq = strstr(s, " equ\t");
        if (!eq) continue;
        const char *name_end = eq;
        while (name_end > s && char_in(name_end[-1], " \t"))
            name_end--;
        if (name_end <= s) continue;
        size_t nml = (size_t)(name_end - s);
        if (nml >= NAME_MAX) die("equ constant name too long");
        char name[NAME_MAX]; memcpy(name, s, nml); name[nml] = 0;
        const char *val = eq + 5;
        while (char_in(*val, " \t")) val++;
        if (!*val) continue;
        g_fwd_unresolved = 0;
        long v;
        if (equ_constant_value(val,&v) && !g_expr_contextual) const_set(name,v);
    }
    g_pass = save_pass;
}

/* INV-703: both preprocessing paths use the entire numeric condition. */
static int parse_condition(const char *text) {
    char sub[512]; size_t len=strlen(text);
    if(len>=sizeof(sub))die("condition too long");
    memcpy(sub,text,len+1);
    char *comment=strchr(sub,';'); if(comment)*comment=0;
    int depth=0;
    for (char *c=sub;*c;c++) {
        if (*c=='(') { depth++; continue; }
        if (*c==')') { depth--; continue; }
        if (depth) continue;
        if ((*c=='<' && c[1]=='<') || (*c=='>' && c[1]=='>')) { c++; continue; }
        if (char_in(*c, "<>") || (*c=='=' && c[1]=='=') || (*c=='!' && c[1]=='=')) {
            char op=*c; int equal=c[1]=='='; char *rhs=c+1+equal; *c=0;
            long left=parse_expr(sub), right=parse_expr(rhs);
            if(op=='<')return equal ? left<=right : left<right;
            if(op=='>')return equal ? left>=right : left>right;
            return op=='=' ? left==right : left!=right;
        }
    }
    return parse_expr(sub)!=0;
}

static long parse_expr_reloc(const char *s, int *has_sym, int *sec,
                             long *off, char *name, int *glob) {
    long v = parse_expr(s);
    expr_basis_reduce(0);
    *has_sym=0; *sec=SEC_NONE; *off=0; *glob=0; name[0]=0;
    /* N04: flat output has no linker. Check every remaining named basis
     * before dropping non-unit/multiple-basis metadata. Affine cancellation
     * to an absolute constant is safe and agrees with NASM's bin format. */
    if (!strcmp(g_fmt,"bin")) {
        for (int i=0;i<g_expr_basis_count;i++)
            if (g_expr_basis[i].section==SEC_NONE && g_expr_basis[i].name)
                die("external symbol requires ELF64 output");
    }
    if (g_expr_basis_pending && g_pass==1) {
        /* The pending marker forces a later layout/final pass. Do not infer a
         * constant from unknown label offsets or merge unknown bases. */
        *has_sym=1; g_expr_symcount=1;
        return v;
    }
    if (g_expr_basis_invalid || g_expr_basis_count>1 ||
        (g_expr_basis_count==1 && g_expr_basis[0].coefficient!=1)) {
        if (strcmp(g_fmt,"bin")) die("expression cannot be represented by one ELF relocation");
        g_expr_symcount=0; return v;
    }
    g_expr_symcount=g_expr_basis_count;
    if (!g_expr_basis_count) return v;
    ExprBasis *basis=&g_expr_basis[0];
    *has_sym=1; *sec=basis->section;
    if (basis->name) {
        *glob=1;
        size_t n=strlen(basis->name);
        if (n>=NAME_MAX) die("relocation expression symbol name too long");
        memcpy(name,basis->name,n+1);
    }
    g_expr_sym_section=*sec; g_expr_sym_offset=0; g_expr_sym_global=*glob;
    memcpy(g_expr_sym_name,name,strlen(name)+1);
    return v;
}

/* Emit a fixed-width numeric/relocatable field without losing external bases.
 * Section offsets are already folded into value; named bases have offset zero.
 * Pending forward values are sizing placeholders, never named empty symbols. */
static void emit_expr_field(int width,int type,long value,int has_sym,
                            int section,int global,const char *name) {
    if (has_sym) {
        if (!strcmp(g_fmt,"bin")) {
            if (section==SEC_NONE && global) die("external symbol requires ELF64 output");
        } else {
            if (section!=SEC_NONE) add_reloc(cur_off(),g_cur,type,section,NULL,value);
            else if (global) add_reloc(cur_off(),g_cur,type,SEC_NONE,name,value);
            else if (g_pass==2 || !g_fwd_unresolved) die("unresolved expression relocation basis");
            value=0;
        }
    }
    if (width==8) emit64((uint64_t)value);
    else if (width==4) emit32((uint32_t)value);
    else if (width==2) emit16((uint32_t)value);
    else emit((uint8_t)value);
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
static unsigned char g_tok_precomma[MAXTOK];
static int g_token_trailing_comma;
static int g_ntok = 0;

/* W04: no token slot survives a new line, and delimiters are consumed only
 * outside quotes/brackets. Escapes apply to backticks, as in the expression
 * and data readers; ordinary single/double quotes preserve their bytes. */
static void tokenize(char *line) {
    memset(g_tok,0,sizeof(g_tok));
    memset(g_tok_precomma,0,sizeof(g_tok_precomma));
    g_token_trailing_comma=0;
    g_ntok=0;
    int pending_comma=0;
    char *p=line;
    while (*p) {
        while (char_in(*p," \t,")) {
            if (*p==',' && ++pending_comma>1) die("empty comma-separated operand");
            p++;
        }
        if (!*p || char_in(*p,";\n\r")) break;
        char *start=p;
        char quote=0;
        int bracket=0;
        while (*p) {
            if (quote) {
                if (quote=='`' && *p=='\\') {
                    if (!p[1]) die("unterminated quoted escape");
                    p+=2; continue;
                }
                if (*p==quote) quote=0;
                p++; continue;
            }
            if (char_in(*p,"\"'`")) { quote=*p++; continue; }
            if (*p=='[') {
                if (bracket) die("nested memory brackets");
                bracket=1; p++; continue;
            }
            if (*p==']') {
                if (!bracket) die("unmatched closing bracket");
                bracket=0; p++; continue;
            }
            if (!bracket && char_in(*p," \t,;\n\r")) break;
            p++;
        }
        if (quote) die("unterminated quoted value");
        if (bracket) die("unterminated memory operand");
        if (g_ntok>=MAXTOK) die("too many tokens on line");
        char delim=*p;
        *p=0;
        Macro *m=g_nmacros ? macro_find(start) : NULL;
        g_tok_precomma[g_ntok]=(unsigned char)pending_comma;
        g_tok[g_ntok++]=m ? m->value : start;
        pending_comma=delim==',';
        if (!delim || char_in(delim,";\n\r")) break;
        p++;
    }
    g_token_trailing_comma=pending_comma;
}

/* Shared by directive domains, preserving whitespace between separate terms
 * instead of silently changing "1 2" into the number "12". */
static void basm_join_tokens(int first,int end,char *out,size_t capacity) {
    out[0]=0;
    for (int i=first;i<end;i++) {
        if (i>first) strbuf_append(out,capacity," ");
        strbuf_append(out,capacity,g_tok[i]);
    }
}
static void basm_token_arity(int minimum,int maximum) {
    if (g_ntok<minimum || g_ntok>maximum) die2("invalid directive operand count",g_tok[0]);
}
static void basm_require_symbol(const char *name) {
    size_t n=strlen(name);
    if (!n || n>=NAME_MAX || !(isalpha((unsigned char)name[0]) || char_in(name[0],"_.?@$")))
        die("invalid symbol name");
    for (const char *p=name;*p;p++)
        if (!(isalnum((unsigned char)*p) || char_in(*p,"_.?@$#~")))
            die2("invalid symbol name",name);
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
    basm_token_arity(2,2);
    basm_require_symbol(g_tok[1]);
    if (g_nstructs >= MAX_STRUCTS) die("too many structures");
    if (g_in_struc) die("nested struc not allowed");

    basm_name_copy(g_current_struc,g_tok[1]);

    if (find_struct(g_current_struc) >= 0) die2("duplicate structure", g_current_struc);

    g_in_struc = 1;
    g_struc_offset = 0;
}

static void handle_struc_field(void) {
    if (!g_in_struc) die("field outside struc");
    if (g_ntok < 3) die("field requires: name resb/resw/resd/resq size");
    basm_require_symbol(g_tok[0]);

    int struct_idx = g_nstructs;
    if (struct_idx >= MAX_STRUCTS) die("too many structures");

    StructDef *s = &g_structs[struct_idx];
    if (s->nfields == 0) {
        basm_name_copy(s->name,g_current_struc);
    }

    char field_name[NAME_MAX];
    basm_name_copy(field_name,g_tok[0]);

    int field_size = 0;
    int count = 1;

    if (!strcmp(g_tok[1], "resb")) field_size = 1;
    else if (!strcmp(g_tok[1], "resw")) field_size = 2;
    else if (!strcmp(g_tok[1], "resd")) field_size = 4;
    else if (!strcmp(g_tok[1], "resq")) field_size = 8;
    else die2("unknown field type", g_tok[1]);

    char count_expr[256]; basm_join_tokens(2,g_ntok,count_expr,sizeof(count_expr));
    count=(int)basm_parse_count(count_expr,(2147483647L-g_struc_offset)/field_size,
                               "structure field size out of range");
    /* W05: reserve fields are sequential, matching NASM and the direct
     * preprocessor path; no implicit ABI padding is introduced here. */

    if (s->nfields >= MAX_FIELDS) die("too many fields in structure");

    StructField *f = &s->fields[s->nfields];
    basm_name_copy(f->name,field_name);
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
    basm_token_arity(1,1);
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
    basm_token_arity(2,2);
    basm_require_symbol(g_tok[1]);
    if (g_istruc_depth >= MAX_ISTRUC_DEPTH) die("istruc nesting too deep");

    char name[NAME_MAX];
    basm_name_copy(name,g_tok[1]);

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
    if (strlen(g_tok[1])>=sizeof(field_name)) die("structure field name too long");
    memcpy(field_name,g_tok[1],strlen(g_tok[1])+1);

    int field_idx = find_field(frame->struct_idx, field_name);
    int at_offset = 0;
    if (field_idx >= 0) {
        at_offset = s->fields[field_idx].offset;
    } else {
        /* NASM semantics: STRUCT.field is a preprocessor define that
         * expands to the numeric offset before assembly, so accept a
         * plain numeric offset here too. */
        at_offset=(int)basm_parse_count(field_name,s->total_size,"unknown or out-of-range field");
    }

    /* Skip comma token */
    int value_tok = 2;
    if (!strcmp(g_tok[value_tok], ",")) value_tok++;

    if (value_tok >= g_ntok - 1) die("at requires a value");

    const char *type = g_tok[value_tok];

    /* Pad to field offset */
    if (at_offset>2147483647L-frame->base_offset) die("structure offset out of range");
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
    for (int i = 0; i < nvals; i++) {
        g_tok[1+i]=g_tok[value_tok+1+i];
        g_tok_precomma[1+i]=g_tok_precomma[value_tok+1+i];
    }
    g_tok_precomma[1]=0;
    g_ntok = 1 + nvals;
    data_define(unit, g_ntok);
}

static void handle_iend(void) {
    basm_token_arity(1,1);
    if (g_istruc_depth == 0) die("iend without istruc");

    IStrucFrame *frame = &g_istruc_stack[g_istruc_depth - 1];
    StructDef *s = &g_structs[frame->struct_idx];

    /* Pad to structure size */
    if (s->total_size>2147483647L-frame->base_offset) die("structure size out of range");
    int target_offset = frame->base_offset + s->total_size;
    int current_offset = cur_off();

    if (current_offset < target_offset) {
        int pad = target_offset - current_offset;
        for (int i = 0; i < pad; i++) emit(0);
    }

    g_istruc_depth--;
}

#include "isa/intent_forms.h"
#include "intent/trace.inc"
